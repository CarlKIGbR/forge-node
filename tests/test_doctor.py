"""`doctor`: the install-time proof (Design 4.4, 13.C C7). Real privd on a real socket and real ext4; probes/ops run their selfchecks as separate processes (LocalProcessBackend). What only a
real systemd unit can show (sandbox properties actually in force) is NOT proven here: that is exactly what `doctor` is for on the node - see the N3 report."""
import io
import json
import os
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest
from audit_helpers import AGENT_GID, AGENT_UID
from n2_helpers import FakeRunner
from privd_helpers import NODE, PrivdEnv

from forge_node import doctor as D
from forge_node.agent.client import HubError, HubUnreachable, PinError
from forge_node.agent.config import AgentConfig
from forge_node.privd.client import PrivClient, PrivUnavailable
from forge_node.privd.server import Server, listen
from forge_node.t0 import hardening
from forge_node.t0.runner import Run

CERT_OK = "notAfter=Jan  1 00:00:00 2030 GMT\nsubject=CN=forge-node-g2\nsha256 Fingerprint=AB:CD:EF\n"


@pytest.fixture
def served(privd_env, monkeypatch):
    monkeypatch.setattr(hardening, "RO_PROBES", {k: v for k, v in hardening.RO_PROBES.items() if k in ("vms", "access")})
    e = privd_env
    assert e.install(tiers=(0,))["ok"]
    assert e.put_lease()["ok"]
    sock = listen(e.paths.socket, AGENT_GID)
    srv = Server(e.ctx)
    threading.Thread(target=srv.serve, args=(sock,), daemon=True).start()
    yield e
    srv.stop()
    sock.close()


@pytest.fixture
def served_all_probes(privd_env):
    e = privd_env
    assert e.install(tiers=(0,))["ok"]
    assert e.put_lease()["ok"]
    sock = listen(e.paths.socket, AGENT_GID)
    srv = Server(e.ctx)
    threading.Thread(target=srv.serve, args=(sock,), daemon=True).start()
    yield e
    srv.stop()
    sock.close()


def doctor(e, tmp_path, *, runner=None, op_names=(), mountinfo=None, **over):
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    key = tmp_path / "node.key"
    key.write_text("k")
    os.chmod(key, 0o600)
    (tmp_path / "node.crt").write_text("c")
    (tmp_path / "ca.crt").write_text("c")
    cfg = AgentConfig("g2", "127.0.0.1", 1, str(tmp_path / "node.crt"), str(key), str(tmp_path / "ca.crt"), e.paths.policy_dir, e.paths.allowed_signers, str(state), e.paths.socket, 0, os.getuid())
    runner = runner or FakeRunner({"timedatectl": "Timezone=Europe/Berlin\nNTPSynchronized=yes\nNTP=yes\n", "openssl_x509_file": CERT_OK})
    out = io.StringIO()
    kw = dict(cfg=cfg, clock=e.clock, runner=runner, ssh_keygen=e.ssh_keygen, priv=PrivClient(e.paths.socket, 0, 60), sleep=lambda s: None, op_names=op_names, after_switch=False, mountinfo=mountinfo, out=out)
    kw.update(over)
    return D.Doctor(**kw), out


def lines(out):
    return [json.loads(x) for x in out.getvalue().splitlines()]


def by_name(results):
    return {r["check"]: r for r in results}


class FakeHub:
    behaviour = None

    def __init__(self, *a, **k):
        pass

    def healthz(self):
        if FakeHub.behaviour:
            raise FakeHub.behaviour
        return {"ok": True}

    def close(self):
        pass


def test_a_healthy_node_passes_every_check_including_the_selfchecks_in_the_units(served, tmp_path, monkeypatch):
    monkeypatch.setattr(D, "HubClient", FakeHub)
    FakeHub.behaviour = None
    d, out = doctor(served, tmp_path)
    res = by_name(d.run())
    assert {k: v["status"] for k, v in res.items()} == {"clock": "ok", "identity": "ok", "policy": "ok", "privd": "ok", "hub": "ok", "audit": "ok", "forge_root": "skip",
                                                         "probe:access": "ok", "probe:vms": "ok"}
    assert "ext4" in json.dumps(res["audit"]["fstype"]) and res["identity"]["fingerprint"] == "AB:CD:EF"
    assert lines(out)[-1] == {"doctor": "OK", "failed": [], "warnings": []}
    assert d._failed == []


def test_doctor_fails_on_denied_selfcheck_path(served, tmp_path, monkeypatch):
    """test_ops_run_in_real_transient_units_selfcheck / test_doctor_fails_on_denied_selfcheck_path: the selfcheck of selftest.noop is run by privd in its unit class; when the unit
    cannot write its work directory (here: run as an unprivileged uid) doctor says FAIL and the exit status is non-zero."""
    monkeypatch.setattr(D, "HubClient", FakeHub)
    FakeHub.behaviour = None
    d, out = doctor(served, tmp_path, op_names=("selftest.noop",))
    # the rate limit of privd's selfcheck bucket (12/min) is respected: 2 probes + 1 op + audit = 4 calls
    res = by_name(d.run())
    assert res["op:selftest.noop"]["status"] == "ok", res["op:selftest.noop"]
    real = served.backend.run_pipe

    def as_nobody(name, props, argv, stdin, timeout):
        if argv[-2] == "selfcheck":
            r = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout, user=AGENT_UID, group=AGENT_GID)
            return r.returncode, r.stdout, r.stderr
        return real(name, props, argv, stdin, timeout)
    served.backend.run_pipe = as_nobody
    served.clock.advance(seconds=61)
    d2, out2 = doctor(served, tmp_path, op_names=("selftest.noop",))
    res2 = by_name(d2.run())
    assert res2["op:selftest.noop"]["status"] == "fail" and d2._failed == ["op:selftest.noop"]
    assert lines(out2)[-1]["doctor"] == "FAILED"


def test_each_failure_mode_is_reported_and_none_is_swallowed(served, tmp_path, monkeypatch):
    monkeypatch.setattr(D, "HubClient", FakeHub)
    # clock not synchronised
    d, _ = doctor(served, tmp_path, runner=FakeRunner({"timedatectl": "Timezone=Europe/Berlin\nNTPSynchronized=no\nNTP=yes\n", "openssl_x509_file": CERT_OK}))
    assert d.clock_check()["status"] == "fail"
    # certificate expired / about to / unreadable
    d, _ = doctor(served, tmp_path, runner=FakeRunner({"timedatectl": "NTPSynchronized=yes\n", "openssl_x509_file": "notAfter=Jan  1 00:00:00 2020 GMT\nsha256 Fingerprint=AA\n"}))
    assert d.identity_check()["status"] == "fail"
    d, _ = doctor(served, tmp_path, runner=FakeRunner({"timedatectl": "NTPSynchronized=yes\n", "openssl_x509_file": "notAfter=Nov 10 00:00:00 2026 GMT\nsha256 Fingerprint=AA\n"}))
    assert d.identity_check()["status"] == "warn"
    d, _ = doctor(served, tmp_path, runner=FakeRunner({"timedatectl": "NTPSynchronized=yes\n", "openssl_x509_file": Run(False, "nonzero")}))
    assert d.identity_check()["status"] == "fail"
    # key readable by others
    d, _ = doctor(served, tmp_path)
    os.chmod(tmp_path / "node.key", 0o640)
    assert d.identity_check()["status"] == "fail" and "key" in d.identity_check()["detail"]
    os.chmod(tmp_path / "node.key", 0o600)
    os.unlink(tmp_path / "ca.crt")
    assert d.identity_check()["status"] == "fail" and "CA missing" in d.identity_check()["detail"]
    # no policy / broken policy
    served.ctx.policies.allowed_signers = "/nonexistent"
    os.chmod(served.paths.allowed_signers, 0o666)
    d, _ = doctor(served, tmp_path)
    assert d.policy_check()["status"] == "fail" and d.hub_check()["status"] == "skip"
    os.chmod(served.paths.allowed_signers, 0o644)
    # hub
    d, _ = doctor(served, tmp_path)
    d.policy_check()
    for exc, want in ((PinError("x"), "fail"), (HubUnreachable("down"), "fail"), (HubError(403, "unregistered"), "warn"), (HubError(500, "boom"), "fail")):
        FakeHub.behaviour = exc
        assert d.hub_check()["status"] == want, exc
    # privd unreachable / policy disagreement
    d_dead, _ = doctor(served, tmp_path, priv=PrivClient(str(tmp_path / "nosuch.sock"), 0, 2))
    assert d_dead.privd_check()["status"] == "fail" and d_dead.audit_check()["status"] == "fail"
    d_wrong, _ = doctor(served, tmp_path, priv=PrivClient(served.paths.socket, 12345, 2))
    assert d_wrong.privd_check()["status"] == "fail"                                         # the peer is not the expected user
    d, _ = doctor(served, tmp_path)
    d.policy = SimpleNamespace(serial=99)
    assert d.privd_check()["status"] == "fail" and "differs" in d.privd_check()["detail"]


def test_audit_check_reports_which_proof_step_failed(served, tmp_path):
    d, _ = doctor(served, tmp_path, priv=SimpleNamespace(request=lambda kind, body, timeout=None: {"ok": True, "selfcheck": {"target": "audit", "ok": False, "detail": {
        "priv": {"fstype": "tmpfs", "ok": False, "checks": {"set_append_flag": {"ok": False}, "chmod_refused": {"ok": True}}}, "agent": None}}}))
    r = d.audit_check()
    assert r["status"] == "fail" and "set_append_flag" in r["detail"] and "chmod_refused" not in r["detail"]


def test_forge_root_checks(served, tmp_path):
    served.ctx.policies.devof = lambda p: 1                                                  # the test tree is not on the container's root device; doctor's re-check below uses its own stat
    r = served.install(tiers=(0,), serial=2, forge_roots=[{"path": "/srv/forge/node", "quota_backend": "loop_fs", "backing_image": str(tmp_path / "img"), "size_bytes": 1 << 30,
                                                          "log_budget_bytes": 1 << 20, "min_free_bytes": 1 << 30}])
    assert r["ok"], r
    good = [{"target": "/srv/forge/node", "fstype": "ext4", "source": "/dev/loop3", "options": "rw,nodev,nosuid,relatime"}]
    (tmp_path / "img").write_text("x")
    for mounts, want, frag in ((good, "ok", ""), ([], "fail", "not a mount point"), ([{**good[0], "fstype": "xfs"}], "fail", "need ext4"), ([{**good[0], "source": "/dev/sda1"}], "fail", "loop"),
                               ([{**good[0], "options": "rw,relatime"}], "fail", "nodev,nosuid")):
        d, _ = doctor(served, tmp_path, mountinfo=lambda m=mounts: m, fs_stat=lambda p: SimpleNamespace(st_dev=1, st_mode=0o600, st_uid=os.getuid()))
        d.policy_check()
        assert d.policy is not None and d.policy.serial == 2
        r = d.forge_root_check()[0]
        assert r["status"] == want and frag in r["detail"], (mounts, r)
    d, _ = doctor(served, tmp_path, mountinfo=lambda: good, fs_stat=lambda p: SimpleNamespace(st_dev=5 if p == "/" else 6, st_mode=0o600, st_uid=os.getuid()))
    d.policy_check()
    assert d.forge_root_check()[0]["status"] == "fail" and "root filesystem" in d.forge_root_check()[0]["detail"]


def test_main_without_configuration_exits_2(monkeypatch, capsys):
    for k in [k for k in os.environ if k.startswith("FORGE_NODE_")]:
        monkeypatch.delenv(k)
    assert D.main([]) == 2
    assert "FORGE_NODE_NODE_ID" in capsys.readouterr().err


def test_doctor_paces_every_selfcheck_so_that_the_real_set_of_14_requests_never_hits_the_rate_limit(served_all_probes, tmp_path, monkeypatch):
    """Review: 12 probes + the op + the audit request go into ONE bucket of 12 per minute. With a sleep that really advances time (privd's clock here) the doctor must never be denied."""
    e = served_all_probes
    monkeypatch.setattr(D, "HubClient", FakeHub)
    FakeHub.behaviour = None
    advance = lambda s: e.clock.advance(seconds=s)                   # noqa: E731 - a sleep that moves the clock the rate buckets read
    d, out = doctor(e, tmp_path, op_names=("selftest.noop",), sleep=advance)
    res = d.run()
    unit = [r for r in res if r["check"].startswith(("probe:", "op:"))]
    assert len(unit) == len(hardening.RO_PROBES) + 1 and len(unit) + 1 == 14                  # every probe, the op, and the audit request
    denied = [r for r in res if "DENY_RATE" in r["detail"]]
    assert not denied, denied
    # and the proof that the test can fail: without any pacing the same run is rate limited
    e.clock.advance(seconds=120)
    d2, _ = doctor(e, tmp_path, op_names=("selftest.noop",), sleep=lambda s: None)
    assert [r["check"] for r in d2.run() if "DENY_RATE" in r["detail"]]


def test_after_a_switch_only_what_a_release_can_break_fails_the_doctor(served, tmp_path, monkeypatch):
    """The switcher rolls a release back when doctor fails. A hub outage, an unsynchronised clock or an old certificate are not the release's fault."""
    FakeHub.behaviour = D.HubUnreachable("no route")
    monkeypatch.setattr(D, "HubClient", FakeHub)
    runner = FakeRunner({"timedatectl": "Timezone=Europe/Berlin\nNTPSynchronized=no\nNTP=yes\n", "openssl_x509_file": CERT_OK})
    d, out = doctor(served, tmp_path, runner=runner, after_switch=True)
    res = by_name(d.run())
    assert res["hub"]["status"] == "warn" and res["clock"]["status"] == "warn" and "not a reason to roll back" in res["hub"]["detail"]
    assert d._failed == [] and lines(out)[-1]["doctor"] == "OK"
    d2, _ = doctor(served, tmp_path, runner=runner, after_switch=False)
    d2.run()
    assert sorted(d2._failed) == ["clock", "hub"]
    # a release-attributable failure still fails after a switch
    served.clock.advance(seconds=61)
    d3, _ = doctor(served, tmp_path, runner=runner, after_switch=True, priv=PrivClient(served.paths.socket, 12345, 2))
    d3.run()
    assert "privd" in d3._failed
    FakeHub.behaviour = None


def test_doctor_main_accepts_only_the_after_switch_flag(monkeypatch, capsys):
    assert D.main(["--bogus"]) == 2 and "usage" in capsys.readouterr().err


def test_after_a_switch_a_hub_that_answers_but_is_refused_still_fails_and_so_does_a_broken_policy(served, tmp_path, monkeypatch):
    """Round 2: every hub failure was downgraded after a switch - a release that breaks the agent's TLS client (wrong pin handling, 5xx) would have passed. Only unreachability is environmental."""
    monkeypatch.setattr(D, "HubClient", FakeHub)
    for behaviour in (PinError("not pinned"), HubError(500, "boom")):
        FakeHub.behaviour = behaviour
        d, _ = doctor(served, tmp_path, after_switch=True)
        res = by_name(d.run())
        assert res["hub"]["status"] == "fail" and "hub" in d._failed, behaviour
    FakeHub.behaviour = HubUnreachable("no route")
    d, _ = doctor(served, tmp_path, after_switch=True)
    assert by_name(d.run())["hub"]["status"] == "warn"                                           # the environmental one
    FakeHub.behaviour = None
    # a policy the release cannot read is the release's problem
    served.clock.advance(seconds=61)
    d, _ = doctor(served, tmp_path, after_switch=True)
    d.cfg = d.cfg.__class__(*[(str(tmp_path / "no-policy") if i == 6 else v) for i, v in enumerate(dataclass_values(d.cfg))])
    res = by_name(d.run())
    assert res["policy"]["status"] == "fail" and "policy" in d._failed


def dataclass_values(obj):
    import dataclasses
    return [getattr(obj, f.name) for f in dataclasses.fields(obj)]


def test_doctor_main_exits_with_the_verdict_the_switcher_depends_on(monkeypatch, tmp_path):
    """Round 2: the switcher rolls back on a non-zero exit; only usage errors were tested."""
    import sys as _sys
    class FakeDoctor:
        failed = []
        seen = {}

        def __init__(self, **kw):
            FakeDoctor.seen = kw
            self._failed = list(FakeDoctor.failed)

        def run(self):
            return []
    monkeypatch.setattr(D, "Doctor", FakeDoctor)
    monkeypatch.setattr("forge_node.agent.config.AgentConfig.from_environ", classmethod(lambda cls, *a, **k: type("Cfg", (), {"priv_socket": "/nonexistent.sock", "owner_uid": 0})()))
    monkeypatch.setattr("forge_node.t0.runner.trusted_binary", lambda name: "/usr/bin/ssh-keygen")
    FakeDoctor.failed = []
    assert D.main(["--after-switch"]) == 0 and FakeDoctor.seen["after_switch"] is True
    assert D.main([]) == 0 and FakeDoctor.seen["after_switch"] is False
    FakeDoctor.failed = ["privd"]
    assert D.main(["--after-switch"]) == 1


def test_unit_checks_carry_their_own_long_timeout_per_request(served, tmp_path, monkeypatch):
    """Round 2: 'per-request selfcheck timeout dropped' survived - an op's selfcheck runs a real unit and takes seconds."""
    monkeypatch.setattr(D, "HubClient", FakeHub)
    FakeHub.behaviour = None
    seen = []
    real = PrivClient(served.paths.socket, 0, 60)

    class Spy:
        def request(self, kind, body, timeout=None):
            seen.append((body.get("target"), timeout))
            return real.request(kind, body, timeout) if timeout else real.request(kind, body)
    d, _ = doctor(served, tmp_path, op_names=("selftest.noop",), priv=Spy())
    d.unit_checks()
    assert seen and all(t == 150 for target, t in seen if target and target != "audit")
