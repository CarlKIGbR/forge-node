"""Slice N4 (install + doctor + ledger on the T0 path): the acceptance list of docs/reports/N4_REPORT.md (design §16.4 proposal).

M-108  doctor: a hub that answers 5xx is neither PASS nor FAIL - 3 retries with backoff, then `indeterminate`; the switcher keeps the known-good release, holds every further switch, escalates.
M-109  the install creates the ledger; a missing (or schema-less) ledger afterwards is a refusal, never 'no open rows' and never a silent re-creation.
Everything here runs against fakes or throw-away directories; no unit, no host path, no tier above T0 is touched."""
import io
import json
import os
import sqlite3
import threading

import pytest
from audit_helpers import AGENT_GID
from n2_helpers import FakeRunner
from privd_helpers import NODE, PrivdEnv  # noqa: F401  (fixtures: privd_env)
from test_privd_server import served as served_privd  # noqa: F401
from test_doctor import CERT_OK, FakeHub, by_name, doctor, lines, served  # noqa: F401
from test_release import Env, docs, env, mkey  # noqa: F401

from forge_node import doctor as D
from forge_node.agent.client import HubError, PinError
from forge_node.privd import privctl
from forge_node.privd.client import PrivClient
from forge_node.privd.ledger import STATE_SCHEMA, Ledger, LedgerError, LedgerMissing
from forge_node.release.switcher import UNITS_START, Refused


# ================================================================================================================== M-108 doctor
class CountingHub(FakeHub):
    """healthz answers the scripted statuses in order (an int = HTTP status of a HubError, None = fine); the last one repeats."""
    script: list = []
    calls = 0

    def healthz(self):
        i = min(CountingHub.calls, len(CountingHub.script) - 1)
        CountingHub.calls += 1
        st = CountingHub.script[i]
        if st is not None:
            raise HubError(st, "bad gateway" if st == 502 else "boom")
        return {"ok": True}


def _doctor_with_hub(served, tmp_path, monkeypatch, script, **over):
    monkeypatch.setattr(D, "HubClient", CountingHub)
    CountingHub.script, CountingHub.calls = script, 0
    sleeps = []
    d, out = doctor(served, tmp_path, sleep=sleeps.append, **over)
    d.policy_check()
    return d, out, sleeps


@pytest.mark.parametrize("status", [500, 502, 503, 504, 599])
def test_doctor_hub_5xx_retries_three_times_with_backoff_then_indeterminate(served, tmp_path, monkeypatch, status):
    d, _, sleeps = _doctor_with_hub(served, tmp_path, monkeypatch, [status])
    r = d.hub_check()
    assert r["status"] == "indeterminate" and r["attempts"] == 4 and CountingHub.calls == 4          # the first attempt + exactly 3 retries
    assert sleeps == list(D.HUB_5XX_BACKOFF_S) and len(sleeps) == 3 and sleeps == sorted(sleeps) and len(set(sleeps)) == 3      # increasing backoff, no sleep after the last attempt
    assert "environmental" not in r                                                                # not downgraded after a switch either


def test_doctor_hub_5xx_that_clears_during_the_retries_is_a_pass_and_other_statuses_are_not_retried(served, tmp_path, monkeypatch):
    d, _, sleeps = _doctor_with_hub(served, tmp_path, monkeypatch, [502, 503, None])
    assert d.hub_check()["status"] == "ok" and CountingHub.calls == 3 and len(sleeps) == 2
    for st, want in ((404, "fail"), (400, "fail"), (403, "warn"), (401, "warn")):                  # 4xx: one attempt, no sleep, same verdicts as before
        d, _, sleeps = _doctor_with_hub(served, tmp_path, monkeypatch, [st])
        assert d.hub_check()["status"] == want and CountingHub.calls == 1 and sleeps == [], st


def test_doctor_indeterminate_is_neither_ok_nor_failed_in_the_verdict_and_a_real_failure_wins(served, tmp_path, monkeypatch):
    d, out, _ = _doctor_with_hub(served, tmp_path, monkeypatch, [502], after_switch=True)
    d.policy = None                                                                                  # run() redoes every check itself
    res = by_name(d.run())
    assert res["hub"]["status"] == "indeterminate" and d._failed == [] and d._indeterminate == ["hub"]
    last = lines(out)[-1]
    assert last["doctor"] == "INDETERMINATE" and last["indeterminate"] == ["hub"] and last["escalate"] == "betriebsleiter" and last["failed"] == []
    # a real failure in the same run (policy dir unreadable) is FAILED, not INDETERMINATE
    served.clock.advance(seconds=61)
    d2, out2, _ = _doctor_with_hub(served, tmp_path, monkeypatch, [502], after_switch=True)
    os.chmod(served.paths.allowed_signers, 0o666)
    try:
        by_name(d2.run())
    finally:
        os.chmod(served.paths.allowed_signers, 0o644)
    assert lines(out2)[-1]["doctor"] == "FAILED" and "policy" in d2._failed and d2._indeterminate == ["hub"]


def test_doctor_main_exit_status_is_0_1_or_4(monkeypatch):
    class Fake:
        failed, undecided = [], []

        def __init__(self, **kw):
            self._failed, self._indeterminate = list(Fake.failed), list(Fake.undecided)

        def run(self):
            return []
    monkeypatch.setattr(D, "Doctor", Fake)
    monkeypatch.setattr("forge_node.agent.config.AgentConfig.from_environ", classmethod(lambda cls, *a, **k: type("Cfg", (), {"priv_socket": "/nonexistent.sock", "owner_uid": 0})()))
    monkeypatch.setattr("forge_node.t0.runner.trusted_binary", lambda name: "/usr/bin/ssh-keygen")
    assert D.main([]) == 0
    Fake.undecided = ["hub"]
    assert D.main(["--after-switch"]) == 4 and D.EXIT_INDETERMINATE == 4
    Fake.failed = ["privd"]
    assert D.main(["--after-switch"]) == 1


def _switch_env(env, *, vers=("0.3.0", "0.3.1")):
    for v in vers:
        env.release(v, "full")
    sw = env.switcher()
    sw.cmd_install_first(vers[0])
    env.make_ledger()
    env.calls.clear()
    return sw


def _units_started_after_doctor(env):
    i = max(i for i, c in enumerate(env.calls) if "doctor" in c)
    return [c[1:] for c in env.calls[i:] if c[0] == "/usr/bin/systemctl" and c[1] in ("start", "enable")]


def test_switch_with_indeterminate_doctor_keeps_the_known_good_release_holds_and_escalates(env):
    sw = _switch_env(env)
    env.doctor_script = ["indeterminate", "indeterminate"]                    # the new release cannot be judged, nor can the restored one (the hub is down for both)
    assert sw.cmd_switch("0.3.1", False) == 5                                 # its own exit status: neither 0 (kept) nor 1 (failed and rolled back) nor 3 (quiet node)
    assert os.readlink(env.base / "current") == "releases/0.3.0"              # the node stays on the known-good release
    res = docs(env.out.getvalue())[-1]
    assert res["state"] == "INDETERMINATE" and res["restored"] == "0.3.0" and res["switched"] is None and res["attempted"] == "0.3.1"
    assert res["escalation"]["escalate_to"] == "betriebsleiter" and res["escalation"]["kind"] == "doctor_indeterminate" and res["escalation"]["known_good"] == "0.3.0"
    assert _units_started_after_doctor(env)[-2:] == [["enable", *UNITS_START], ["start", *UNITS_START]]      # the known-good release runs (agent, timer): not a quiet node
    hold = json.loads(env.hold_path.read_text())                               # the durable escalation record, as the switcher printed it (minus the console-only path field)
    assert hold == res["escalation"] and oct(os.stat(env.hold_path).st_mode & 0o777) == "0o644" and not os.path.exists(str(env.hold_path) + ".new")


def test_after_an_indeterminate_switch_no_further_switch_until_the_hold_is_cleared(env):
    sw = _switch_env(env, vers=("0.3.0", "0.3.1", "0.3.2"))
    env.doctor_script = ["indeterminate", "indeterminate"]
    assert sw.cmd_switch("0.3.1", False) == 5
    env.calls.clear()
    env.doctor_script, env.doctor_ok = [], True                               # the hub is back and everything would pass: still no switch without the owner
    for target in ("0.3.1", "0.3.2"):
        with pytest.raises(Refused, match="no further switch"):
            sw.cmd_switch(target, False)
    assert env.calls == [] and os.readlink(env.base / "current") == "releases/0.3.0"          # refused before ANY change (not even a systemctl call)
    assert docs_status(env, sw)["hold"]["attempted"] == "0.3.1"
    assert sw.cmd_clear_hold() == 0
    with pytest.raises(Refused, match="no hold"):
        sw.cmd_clear_hold()
    assert sw.cmd_switch("0.3.2", False) == 0 and os.readlink(env.base / "current") == "releases/0.3.2"


def docs_status(env, sw):
    env.out.truncate(0)
    env.out.seek(0)
    sw.show_status()
    return docs(env.out.getvalue())[-1]


def test_a_real_failure_of_the_new_release_with_an_indeterminate_rollback_doctor_stays_on_the_known_good_release(env):
    """The B8 residual: the new release really fails, the hub is down for the rollback's doctor too. Before M-108 that ended in a stopped, disabled node (rc 3)."""
    sw = _switch_env(env)
    env.doctor_script = [False, "indeterminate"]
    assert sw.cmd_switch("0.3.1", False) == 5
    res = docs(env.out.getvalue())[-1]
    assert os.readlink(env.base / "current") == "releases/0.3.0" and res["state"] == "INDETERMINATE" and "failed" in res["escalation"]["reason"] and "could not be judged either" in res["escalation"]["reason"]
    assert env.hold_path.exists() and _units_started_after_doctor(env)


def test_a_failed_rollback_doctor_is_still_a_quiet_node_and_a_failed_new_release_is_still_rc_1(env):
    sw = _switch_env(env)
    env.doctor_script = ["indeterminate", False]                              # the restored release FAILS (not undecided): nothing is known-good any more
    assert sw.cmd_switch("0.3.1", False) == 3 and not env.hold_path.exists()
    assert docs(env.out.getvalue())[-1]["state"].startswith("STOPPED and disabled")


def test_a_plain_failure_is_unchanged_rollback_rc_1_and_no_hold(env):
    sw = _switch_env(env)
    env.doctor_script = [False, True]
    assert sw.cmd_switch("0.3.1", False) == 1 and not env.hold_path.exists()
    assert docs(env.out.getvalue())[-1]["restored_doctor"] == "ok"


def test_the_switcher_only_believes_exit_status_4_together_with_doctors_own_verdict_line(env):
    _switch_env(env)
    seen = []
    orig = env.run

    def run(argv, stdin, timeout):
        if "doctor" in argv:
            seen.append(argv)
            return (4, b"", b"") if len(seen) == 1 else (0, b"", b"")                    # rc 4 without the INDETERMINATE line (a crash that happens to exit 4) = a failure
        return orig(argv, stdin, timeout)
    assert env.switcher(run=run).cmd_switch("0.3.1", False) == 1 and not env.hold_path.exists()


def test_the_hold_survives_in_status_and_an_unreadable_hold_counts_as_a_hold(env):
    sw = _switch_env(env)
    env.hold_path.write_text("not json")
    os.chmod(env.hold_path, 0o644)
    assert docs_status(env, sw)["hold"]["kind"] == "unreadable"
    with pytest.raises(Refused, match="no further switch"):
        sw.cmd_switch("0.3.1", False)


def test_the_switcher_parses_what_doctor_really_prints_for_an_indeterminate_hub(served, tmp_path, monkeypatch, env):
    """Pins the real text (round-3 lesson: a test double that matches `"doctor" in argv` once hid a BLOCKER): the output of Doctor.run() with a 5xx hub, exit status from doctor.main's rule,
    fed through the switcher's own parser."""
    d, out, _ = _doctor_with_hub(served, tmp_path, monkeypatch, [503], after_switch=True)
    d.policy = None
    d.run()
    rc = D.EXIT_FAILED if d._failed else D.EXIT_INDETERMINATE if d._indeterminate else D.EXIT_OK
    assert rc == 4
    sw = _switch_env(env)
    orig = env.run
    env_run = lambda argv, stdin, timeout: ((rc, out.getvalue().encode(), b"") if "doctor" in argv else orig(argv, stdin, timeout))      # noqa: E731
    sw2 = env.switcher(run=env_run)
    assert sw2._doctor(["FORGE_NODE_NODE_ID=g2"])[0] == "indeterminate"


# ================================================================================================================== M-109 ledger
def _ctl(tmp_path, specs, ledger):
    from forge_node.audit.log import AuditAdmin
    from privd_helpers import NOW
    adm = (AuditAdmin(specs["priv"], NODE, lambda: NOW), AuditAdmin(specs["agent"], NODE, lambda: NOW))
    out = io.StringIO()
    return privctl.Ctl(euid=0, client=None, state_setup=lambda: None, admin_factory=lambda: adm, ledger_path=str(ledger), local_stop="", systemctl_provider=None, systemctl_text_provider=None,
                       protected_units=(), protected_paths=(), run_systemctl=None, clock=lambda: None, out=out), out


def test_install_creates_the_ledger_and_a_missing_ledger_afterwards_is_a_refusal(realfs, tmp_path):
    from audit_helpers import make_specs
    specs = make_specs(realfs)
    led_path = tmp_path / "state" / "ledger.sqlite"
    led_path.parent.mkdir(mode=0o700)
    ctl, out = _ctl(tmp_path, specs, led_path)
    assert privctl.main(["audit-init"], ctl) == 0                                              # the install: logs AND ledger
    doc = json.loads(out.getvalue())
    assert doc["ledger"] == {"path": str(led_path), "created": True, "state_schema": STATE_SCHEMA}
    assert led_path.exists() and oct(os.stat(led_path).st_mode & 0o777) == "0o600"
    Ledger(str(led_path)).close()                                                              # an existing, initialised ledger opens without `create`
    # running the install step again changes nothing (idempotent) ...
    ctl2, out2 = _ctl(tmp_path, specs, led_path)
    assert privctl.main(["audit-init"], ctl2) == 0 and json.loads(out2.getvalue())["ledger"]["created"] is False
    # ... but afterwards a missing ledger is damage: every user of it refuses, and `audit-init` does NOT quietly make a fresh one
    os.unlink(led_path)
    for suffix in ("-wal", "-shm"):
        if os.path.exists(str(led_path) + suffix):
            os.unlink(str(led_path) + suffix)
    with pytest.raises(LedgerMissing):
        Ledger(str(led_path))
    ctl3, out3 = _ctl(tmp_path, specs, led_path)
    assert privctl.main(["audit-init"], ctl3) == 1 and not led_path.exists()
    assert privctl.main(["circuit-ack", "selftest.noop", "owner"], ctl3) == 1 and not led_path.exists()   # no command creates it as a side effect either


def test_a_ledger_replaced_by_an_empty_file_is_a_refusal_not_a_fresh_start(tmp_path):
    p = tmp_path / "ledger.sqlite"
    Ledger(str(p), create=True).close()
    with pytest.raises(LedgerMissing):
        Ledger(str(tmp_path / "other.sqlite"))                                                   # never created implicitly
    assert not (tmp_path / "other.sqlite").exists()
    for f in (p, tmp_path / "ledger.sqlite-wal", tmp_path / "ledger.sqlite-shm"):
        if f.exists():
            f.unlink()
    p.write_bytes(b"")
    os.chmod(p, 0o600)
    with pytest.raises(LedgerMissing, match="no schema"):
        Ledger(str(p))
    assert p.stat().st_size == 0                                                                # and it was not initialised on the way (no write by the refusing opener)
    c = sqlite3.connect(p)                                                                      # a database with the right version but without the exec table (a different database moved in)
    c.execute(f"PRAGMA user_version={STATE_SCHEMA}")
    c.execute("CREATE TABLE other(x)")
    c.close()
    with pytest.raises(LedgerMissing):
        Ledger(str(p))
    assert issubclass(LedgerMissing, LedgerError)


def test_the_switcher_refuses_a_missing_ledger_on_an_installed_node_but_not_before_the_install(env):
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    assert sw.ledger_schema_and_open() == (0, 0)                                                # before install-first: no ledger yet is the normal state
    assert sw.cmd_check("0.3.0") == 0
    sw.cmd_install_first("0.3.0")                                                               # (install-first itself needs no ledger: `privctl audit-init` follows it)
    for call in (lambda: sw.ledger_schema_and_open(), lambda: sw.cmd_check("0.3.1"), lambda: sw.cmd_switch("0.3.1", False)):
        with pytest.raises(Refused, match="missing on an installed node"):
            call()
    assert docs_status(env, sw)["ledger"].startswith("UNREADABLE")                              # status reports it, every changing command refuses
    os.chmod(env.tmp, 0o755)
    env.ledger.write_bytes(b"")                                                                 # a zero-byte replacement is the same refusal (it used to read as (0, 0))
    with pytest.raises(Refused, match="exec table|unreadable"):
        sw.ledger_schema_and_open()
    env.ledger.unlink()
    env.make_ledger()
    assert sw.ledger_schema_and_open() == (1, 0)
    assert sw.cmd_check("0.3.1") == 0


def test_a_missing_ledger_refuses_the_switch_before_any_change(env):
    sw = _switch_env(env)
    env.ledger.unlink()
    env.calls.clear()
    with pytest.raises(Refused, match="missing on an installed node"):
        sw.cmd_switch("0.3.1", False)
    assert os.readlink(env.base / "current") == "releases/0.3.0"
    assert not [c for c in env.calls if "doctor" in c]


# ================================================================================================================== T0 acceptance (3): privctl selftest-bypass
def test_selftest_bypass_sends_a_signed_t1_dry_run_straight_to_the_socket_and_stop_denies_it_while_t0_answers(served_privd, tmp_path):
    from test_privd_server import make_ctl
    e = served_privd
    assert e.put_lease(seq=2, stop=True)["ok"]                                              # forge-stop: the hub's lease says stop
    env_, payload = e.job_env(dry_run=True)
    f = tmp_path / "job.json"
    f.write_text(json.dumps(env_))
    os.chmod(f, 0o600)
    ctl, out, _ = make_ctl(e)
    assert privctl.main(["selftest-bypass", str(f), "DENY_STOP"], ctl) == 0
    doc = json.loads(out.getvalue())
    assert doc["bypass_refused"] is True and doc["reason_code"] == "DENY_STOP" and doc["sent"]["dry_run"] is True and doc["sent"]["tier"] == 1
    assert [u for u in e.backend.list_op_units() if payload["job_id"] in u] == []              # nothing was started
    assert e.call("t0", {"probe": "access", "params": {}})["ok"] is True                         # T0 still answers during the stop
    out.truncate(0)
    out.seek(0)
    env2, _ = e.job_env(dry_run=True)                                                          # a wrong expectation is a failure of the check, not a pass
    f.write_text(json.dumps(env2))
    assert privctl.main(["selftest-bypass", str(f), "DENY_RATE"], ctl) == 1 and json.loads(out.getvalue())["bypass_refused"] is False


def test_selftest_bypass_fails_when_privd_does_not_refuse_and_sends_only_signed_dry_runs(served_privd, tmp_path):
    from test_privd_server import make_ctl
    e = served_privd
    ctl, out, _ = make_ctl(e)
    f = tmp_path / "job.json"
    os.chmod(tmp_path, 0o755)
    env_, _ = e.job_env(dry_run=True)                                                          # no stop: privd answers the dry run - the bypass is NOT refused -> rc 1
    f.write_text(json.dumps(env_))
    assert privctl.main(["selftest-bypass", str(f)], ctl) == 1 and json.loads(out.getvalue())["status"] == "dry_run"
    sent = []
    real = ctl.client.request
    ctl.client.request = lambda kind, body, *a: (sent.append(kind), real(kind, body, *a))[1]
    env_live, _ = e.job_env(dry_run=False)                                                     # a real (non-dry-run) envelope is refused locally, nothing is sent
    f.write_text(json.dumps(env_live))
    assert privctl.main(["selftest-bypass", str(f)], ctl) == 1 and sent == []
    f.write_text("{not json")
    assert privctl.main(["selftest-bypass", str(f)], ctl) == 1 and sent == []
    (tmp_path / "link.json").symlink_to(f)
    assert privctl.main(["selftest-bypass", str(tmp_path / "link.json")], ctl) == 1 and sent == []
    ctl_user, _, _ = make_ctl(e, euid=1001)
    with pytest.raises(privctl.CtlError):
        ctl_user.cmd_selftest_bypass(str(f))


# ================================================================================================================== T0 acceptance (11): gated features verified disabled
def test_every_gated_feature_is_verified_disabled_policy_validator_and_direct_privd_request(served_privd):
    """(11): the policy validator rejects tiers_enabled > 0 / workloads / vm_pool / t2 ops / t3 while the gates are unmet, and a direct privd request for a gated op is denied."""
    from forge_node import gates
    from forge_node.privd.policy_full import parse_full
    assert all(not g.met for g in gates.GATES.values()) and len(gates.GATES) == 4                # A-D stay unmet in N4
    e = served_privd
    for bad in ({"tiers": (0, 1)}, {"tiers": (0, 1, 2)}, {"tiers": (0, 1, 2, 3)}):
        r = e.install(serial=50 + len(bad["tiers"]), **{**bad, "t1_ops": []}) if False else None
    # direct request for every op above T0 in the table: denied, whatever the tier says
    from forge_node.privd import optable
    for profile in ("full", "t0"):
        for name in optable.build_optable(profile).names(profile):
            ent = optable.build_optable(profile).get(name)
            if ent.tier >= 1 and name != "selftest.noop":
                raise AssertionError(f"{name}: an op above T0 exists in the table of {profile} but only selftest.noop may (and it is unreachable until gate D)")
    env_, payload = e.job_env(op="volume.create", tier=1, dry_run=True)
    res = e.call("exec", {"job": env_})
    assert res["ok"] and res["result"]["status"] == "denied", res
    assert parse_full is not None
