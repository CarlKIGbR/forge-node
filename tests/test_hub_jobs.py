"""Hub: Job-Warteschlange, Zustellung (Signatur), Idempotenz/Wiederzustellung, Lease, Poll-Heartbeat, STOP unter dem Dispatch-Lock, Ergebnisse. Braucht Postgres."""
import json
import os
import subprocess
import threading
import time
import uuid
from pathlib import Path

import pytest

from conftest import add_node
from forge_node import gates, protocol
from forge_node.hub import killswitch
from forge_node.hub.core import Hub, JobConflict, JobDenied, JobRequest, Signer
from forge_node.protocol import ProtoError

pytestmark = pytest.mark.db

JID = lambda: str(uuid.uuid4())  # noqa: E731
HEX = "ab" * 32


def _poll(open_jobs=(), wait_s=0, **kw):
    b = {"v": 1, "version": "0.1.0", "policy": {"serial": 0, "sha256": ""}, "clock": "2026-10-31T13:40:10Z", "spool_depth": 0, "audit_heads": {}, "open_jobs": list(open_jobs), "wait_s": wait_s}
    b.update(kw)
    return b


def _result(**kw):
    b = {"attempt": 1, "status": "committed", "reason_code": None, "output": "ok", "audit_seq_range": None, "plan_hash": None}
    b.update(kw)
    return b


def _deliver(hub, gate_keys, node="g2"):
    r = hub.poll(node, _poll())
    assert len(r["jobs"]) == 1
    return protocol.verify_job(r["jobs"][0], gate_keys, node, hub.clock(), ssh_keygen="ssh-keygen"), r


# ================================================================================================================== enqueue / gates
def test_t0_job_roundtrip_signed_for_node_and_verifiable(hub, gate_keys):
    e = hub.enqueue_job(JobRequest("g2", 0, "inv.host"))
    assert e.created and e.state == "queued"
    job, r = _deliver(hub, gate_keys)
    assert job["job_id"] == e.job_id and job["op"] == "inv.host" and job["tier"] == 0 and job["delivery_seq"] == 1 and job["node"] == "g2"
    assert protocol.parse_ts(job["expires_at"]) - protocol.parse_ts(job["issued_at"]) == protocol.timedelta(seconds=120)
    assert hub.job_state(e.job_id)["state"] == "issued"
    assert r["lease"] and protocol.verify_lease(r["lease"], gate_keys, "g2", hub.clock(), 0, ssh_keygen="ssh-keygen")["seq"] >= 1


def test_job_for_another_node_cannot_be_verified_by_this_node(hub, gate_keys):
    hub.enqueue_job(JobRequest("g2", 0, "inv.host"))
    r = hub.poll("g2", _poll())
    with pytest.raises(ProtoError):
        protocol.verify_job(r["jobs"][0], gate_keys, "g1", hub.clock(), ssh_keygen="ssh-keygen")
    assert hub.poll("g1", _poll())["jobs"] == []


@pytest.mark.parametrize("op", sorted(o for o, s in gates.OPS.items() if s.tier > 0))
def test_n1_hub_queues_and_signs_nothing_above_t0(hub, op, adm):
    spec = gates.OPS[op]
    with pytest.raises(JobDenied) as e:
        hub.enqueue_job(JobRequest("g2", spec.tier, op, {"kind": "unit_action"} if op == "t3.exec" else {}))
    assert e.value.code == "DENY_TIER_DISABLED"
    assert adm.execute("SELECT count(*) AS n FROM node.jobs").fetchone()["n"] == 0
    assert hub.poll("g2", _poll())["jobs"] == []


def test_t0_profile_node_rejects_non_t0_even_with_open_gates(hub, hubcfg, hubdb, gate, clock, open_gates):
    h = Hub(hubcfg, hubdb, Signer(gate["priv"], gate["id"]), clock=clock, gate_set=open_gates)
    with pytest.raises(JobDenied) as e:
        h.enqueue_job(JobRequest("g1", 1, "dir.ensure"))
    assert e.value.code == "DENY_TIER_DISABLED" and "t0 profile" in e.value.detail
    assert h.enqueue_job(JobRequest("g1", 0, "inv.host")).created


@pytest.mark.parametrize("req,code", [
    (JobRequest("g2", 0, "rm.rf"), "DENY_OP_UNKNOWN"),
    (JobRequest("g2", 1, "inv.host"), "DENY_PARAM"),
    (JobRequest("g2", 9, "inv.host"), "DENY_PARAM"),
    (JobRequest("zz", 0, "inv.host"), "DENY_NOT_ALLOWLISTED"),
    (JobRequest("g2", 0, "inv.host", {"x": 1}), "DENY_PARAM"),
    (JobRequest("g2", 0, "inv.host", {"x": 1.5}), "DENY_PARAM"),
    (JobRequest("g2", 0, "inv.host", job_id="not-a-uuid"), "DENY_PARAM"),
    (JobRequest("g2", 0, "inv.host", plan_hash="short"), "DENY_PARAM"),
    (JobRequest("g2", 0, "inv.host", requester={"identity": "x"}), "DENY_PARAM"),
    (JobRequest("g2", 0, "logs.unit", {"unit": "../etc/passwd"}), "DENY_PARAM"),
    (JobRequest("g2", 0, "logs.unit", {"unit": "forge-edge.service\n"}), "DENY_PARAM"),
    (JobRequest("g2", 0, "logs.unit", {"unit": "forge-edge.service", "lines": 501}), "DENY_PARAM"),
    (JobRequest("g2", 0, "logs.unit", {"unit": "forge-edge.service", "since_s": 8 * 86400}), "DENY_PARAM"),
    (JobRequest("g2", 0, "inv.usage", {"window_h": 73}), "DENY_PARAM"),
    (JobRequest("g2", 0, "inv.host", {"pad": "x" * 20000}), "DENY_PARAM"),
])
def test_enqueue_rejects(hub, req, code):
    with pytest.raises(JobDenied) as e:
        hub.enqueue_job(req)
    assert e.value.code == code


def test_valid_t0_params_accepted(hub):
    hub.enqueue_job(JobRequest("g2", 0, "logs.unit", {"unit": "forge-edge.service", "since_s": 3600, "lines": 200}))
    hub.enqueue_job(JobRequest("g2", 0, "inv.usage", {"window_h": 72}))


def test_pending_or_revoked_node_gets_no_jobs(hub, adm):
    adm.execute("INSERT INTO node.nodes (node_id, profile) VALUES ('g3','full')")
    with pytest.raises(JobDenied) as e:
        hub.enqueue_job(JobRequest("g3", 0, "inv.host"))
    assert e.value.code == "DENY_NOT_ALLOWLISTED"
    adm.execute("UPDATE node.nodes SET status='revoked' WHERE node_id='g1'")
    with pytest.raises(JobDenied):
        hub.enqueue_job(JobRequest("g1", 0, "inv.host"))


def test_every_denial_is_audited_on_the_hub_chain(hub, adm):
    with pytest.raises(JobDenied):
        hub.enqueue_job(JobRequest("g2", 1, "dir.ensure"))
    rows = adm.execute("SELECT record FROM node.audit WHERE node_id='g2' AND source='hub' AND type='denial'").fetchall()
    assert len(rows) == 1 and rows[0]["record"]["reason_code"] == "DENY_TIER_DISABLED" and rows[0]["record"]["op"] == "dir.ensure"
    assert hub.verify_chains("g2") == []


# ================================================================================================= idempotency / redelivery (T-LEDGER, Hub-Seite)
def test_same_job_id_same_request_is_idempotent_different_request_conflicts(hub):
    j = JID()
    a = hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j))
    b = hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j))
    assert a.created and not b.created and b.state == "queued"
    with pytest.raises(JobConflict):
        hub.enqueue_job(JobRequest("g2", 0, "inv.disks", job_id=j))
    with pytest.raises(JobConflict):
        hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j, requester={"identity": "other", "planner_call_id": None, "run_id": None, "project": None}))


def test_hub_never_issues_new_job_id_while_node_nonterminal(hub, gate_keys, adm):       # test_hub_never_issues_new_job_id_while_node_nonterminal
    j = JID()
    hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j))
    job, _ = _deliver(hub, gate_keys)
    # Der Knoten meldet den Job als laufend: kein weiterer Versuch, auch nicht nach Ablauf der Zustellung
    for _ in range(3):
        hub.clock.advance(200) if hasattr(hub.clock, "advance") else None
        r = hub.poll("g2", _poll(open_jobs=[{"job_id": j, "state": "started", "attempt": 1}]))
        assert r["jobs"] == []
        assert hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j)).state == "in_progress"
    assert hub.job_state(j)["state"] == "in_progress"
    assert adm.execute("SELECT count(*) AS n, max(delivery_seq) AS d FROM node.jobs").fetchone() == {"n": 1, "d": 1}


def test_expired_unclaimed_delivery_is_redelivered_with_same_job_id_and_next_delivery_seq(hub, gate_keys, clock):
    j = JID()
    hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j))
    first, _ = _deliver(hub, gate_keys)
    assert hub.poll("g2", _poll())["jobs"] == []                                # noch gueltig: keine Doppelzustellung
    clock.advance(121)                                                          # abgelaufen, Knoten meldet nichts
    second, _ = _deliver(hub, gate_keys)
    assert second["job_id"] == j and second["delivery_seq"] == 2 and second["issued_at"] > first["issued_at"]


def test_retryable_denial_allows_new_delivery_same_job_id(hub, gate_keys):               # test_retryable_denial_allows_new_delivery_same_job_id
    j = JID()
    hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j))
    _deliver(hub, gate_keys)
    out = hub.accept_result("g2", j, _result(status="denied", reason_code="DENY_STOP"))
    assert out["state"] == "denied_retryable"
    assert hub.poll("g2", _poll())["jobs"] == []                                # nicht automatisch
    e = hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j))
    assert e.requeued and e.state == "queued"
    job, _ = _deliver(hub, gate_keys)
    assert job["job_id"] == j and job["delivery_seq"] == 2


def test_terminal_denial_does_not(hub, gate_keys):                                          # test_terminal_denial_does_not
    j = JID()
    hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j))
    _deliver(hub, gate_keys)
    assert hub.accept_result("g2", j, _result(status="denied", reason_code="DENY_PROTECTED"))["state"] == "denied"
    e = hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j))
    assert e.state == "denied" and not e.requeued
    assert hub.poll("g2", _poll())["jobs"] == []


def test_aborted_safe_is_retryable_committed_is_not(hub, gate_keys):
    a, b = JID(), JID()
    for j in (a, b):
        hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j))
        _deliver(hub, gate_keys)
    hub.accept_result("g2", a, _result(status="aborted_safe", reason_code="FAIL_PRECHECK"))
    hub.accept_result("g2", b, _result(status="committed"))
    assert hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=a)).requeued
    assert not hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=b)).requeued and hub.job_state(b)["state"] == "committed"


def test_indeterminate_blocks_redelivery_until_resolved(hub, gate_keys, adm):
    j = JID()
    hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j))
    _deliver(hub, gate_keys)
    hub.accept_result("g2", j, _result(status="indeterminate", reason_code="INDETERMINATE"))
    assert hub.job_state(j)["state"] == "indeterminate"
    assert not hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j)).requeued
    hub.clock.advance(500)
    assert hub.poll("g2", _poll())["jobs"] == []
    assert adm.execute("SELECT kind FROM node.alerts").fetchone()["kind"] == "indeterminate_job"
    hub.accept_result("g2", j, _result(status="committed", attempt=2))                  # Rekonziliation loest auf
    assert hub.job_state(j)["state"] == "committed"


def test_queue_deadline_expires_undelivered_jobs(hub, clock):
    j = JID()
    hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j))
    clock.advance(3601)
    assert hub.poll("g2", _poll())["jobs"] == []
    assert hub.job_state(j)["state"] == "expired"
    assert hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j)).state == "expired"


def test_one_job_per_poll_in_queue_order(hub, gate_keys):
    ids = [JID() for _ in range(3)]
    for j in ids:
        hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j))
        hub.clock.advance(1)
    got = [protocol.verify_job(hub.poll("g2", _poll())["jobs"][0], gate_keys, "g2", hub.clock(), ssh_keygen="ssh-keygen")["job_id"] for _ in range(3)]
    assert got == ids
    assert hub.poll("g2", _poll())["jobs"] == []


# ======================================================================================================================== lease
def test_lease_seq_strictly_increases_and_survives_hub_restart(hub, hubcfg, hubdb, gate, clock, gate_keys):
    seqs = [protocol.verify_lease(hub.poll("g2", _poll())["lease"], gate_keys, "g2", clock(), 0, ssh_keygen="ssh-keygen")["seq"] for _ in range(3)]
    assert seqs == sorted(set(seqs)) and seqs[0] >= 1
    h2 = Hub(hubcfg, hubdb, Signer(gate["priv"], gate["id"]), clock=clock)
    assert protocol.verify_lease(h2.poll("g2", _poll())["lease"], gate_keys, "g2", clock(), seqs[-1], ssh_keygen="ssh-keygen")["seq"] == seqs[-1] + 1


def test_lease_validity_is_60s_and_signed_for_the_node(hub, gate_keys, clock):
    p = protocol.verify_lease(hub.poll("g2", _poll())["lease"], gate_keys, "g2", clock(), 0, ssh_keygen="ssh-keygen")
    assert protocol.parse_ts(p["valid_until"]) - protocol.parse_ts(p["issued_at"]) == protocol.timedelta(seconds=60)
    assert p["node"] == "g2" and p["stop"] is False and p["quarantine"] is False and p["stopped_projects"] == []


def test_lease_carries_stop_projects_and_quarantine(hub, hubcfg, gate_keys, clock, adm):
    (hubcfg.control_dir / "STOP").write_text("STOP\n")
    (hubcfg.control_dir / "stop.d").mkdir()
    (hubcfg.control_dir / "stop.d" / "proj-b").write_text("")
    (hubcfg.control_dir / "stop.d" / "proj-a").write_text("")
    (hubcfg.control_dir / "stop.d" / "Bad Name").write_text("")        # ungueltiger Slug wird ignoriert
    hub.quarantine("g2", "chain_break", "k", {"x": 1})
    p = protocol.verify_lease(hub.poll("g2", _poll())["lease"], gate_keys, "g2", clock(), 0, ssh_keygen="ssh-keygen")
    assert p["stop"] and p["quarantine"] and p["stopped_projects"] == ["proj-a", "proj-b"]


def test_lease_stop_fails_closed_when_control_dir_missing_or_unreadable(hub, hubcfg, gate_keys, clock):
    os.rmdir(hubcfg.control_dir) if not any(hubcfg.control_dir.iterdir()) else None
    assert protocol.verify_lease(hub.poll("g2", _poll())["lease"], gate_keys, "g2", clock(), 0, ssh_keygen="ssh-keygen")["stop"] is True
    hubcfg.control_dir.mkdir()
    p = protocol.verify_lease(hub.poll("g2", _poll())["lease"], gate_keys, "g2", clock(), 0, ssh_keygen="ssh-keygen")
    assert p["stop"] is False


def test_lease_stop_when_project_dir_unreadable(hub, hubcfg, gate_keys, clock):
    d = hubcfg.control_dir / "stop.d"
    d.write_text("not a directory")
    assert protocol.verify_lease(hub.poll("g2", _poll())["lease"], gate_keys, "g2", clock(), 0, ssh_keygen="ssh-keygen")["stop"] is True


def test_t0_jobs_still_delivered_during_stop(hub, hubcfg, gate_keys):
    (hubcfg.control_dir / "STOP").write_text("STOP\n")
    hub.enqueue_job(JobRequest("g2", 0, "inv.host"))
    r = hub.poll("g2", _poll())
    assert len(r["jobs"]) == 1 and protocol.verify_lease(r["lease"], gate_keys, "g2", hub.clock(), 0, ssh_keygen="ssh-keygen")["stop"]


# ===================================================================================== STOP and the dispatch lock (tier >= 1 pipeline)
@pytest.fixture
def t1hub(hubcfg, hubdb, gate, clock, open_gates, adm):
    add_node(adm, "g2", "full", cert="a" * 64)
    return Hub(hubcfg, hubdb, Signer(gate["priv"], gate["id"]), clock=clock, gate_set=open_gates, sleep=lambda s: clock.advance(s))


def test_stop_denies_enqueue_and_delivery_for_t1_not_for_t0(t1hub, hubcfg, gate_keys):
    j = JID()
    assert t1hub.enqueue_job(JobRequest("g2", 1, "dir.ensure", {}, job_id=j)).created
    (hubcfg.control_dir / "STOP").write_text("STOP\n")
    with pytest.raises(JobDenied) as e:
        t1hub.enqueue_job(JobRequest("g2", 1, "dir.ensure"))
    assert e.value.code == "DENY_STOP"
    assert t1hub.poll("g2", _poll())["jobs"] == [] and t1hub.job_state(j)["state"] == "queued"      # bleibt liegen, nichts signiert
    (hubcfg.control_dir / "STOP").unlink()                                                         # Freigabe durch den Owner (nicht durch den Hub)
    assert len(t1hub.poll("g2", _poll())["jobs"]) == 1


def test_project_stop_blocks_only_that_project(t1hub, hubcfg):
    (hubcfg.control_dir / "stop.d").mkdir()
    (hubcfg.control_dir / "stop.d" / "proj-a").write_text("")
    mk = lambda p: JobRequest("g2", 1, "dir.ensure", {}, requester={"identity": "meta", "planner_call_id": None, "run_id": None, "project": p})  # noqa: E731
    with pytest.raises(JobDenied) as e:
        t1hub.enqueue_job(mk("proj-a"))
    assert e.value.code == "DENY_STOP"
    assert t1hub.enqueue_job(mk("proj-b")).created


def test_quarantine_blocks_t1_enqueue_and_delivery(t1hub, hubcfg):
    j = JID()
    t1hub.enqueue_job(JobRequest("g2", 1, "dir.ensure", {}, job_id=j))
    t1hub.quarantine("g2", "chain_break", "x", {})
    with pytest.raises(JobDenied) as e:
        t1hub.enqueue_job(JobRequest("g2", 1, "dir.ensure"))
    assert e.value.code == "DENY_QUARANTINE"
    assert t1hub.poll("g2", _poll())["jobs"] == []
    assert t1hub.enqueue_job(JobRequest("g2", 0, "inv.host")).created          # T0 bleibt moeglich (Beweise lesen)


def _forge_stop(ctrl: Path):
    """Verhalten von forge-stop/forge-release (forge-ops): flock auf control/.dispatch.lock, dann STOP anlegen."""
    code = ("import fcntl,os,sys;fd=os.open(sys.argv[1]+'/.dispatch.lock',os.O_RDWR|os.O_CREAT,0o664);fcntl.flock(fd,fcntl.LOCK_EX);"
            "open(sys.argv[1]+'/STOP','w').write('STOP test\\n')")
    return subprocess.Popen(["python3", "-c", code, str(ctrl)])


def test_stop_blocks_issue_under_dispatch_lock(hubcfg, hubdb, gate, clock, open_gates, adm, gate_keys):      # test_stop_blocks_issue_under_dispatch_lock
    """Ein Stop wirkt entweder vor der Pruefung (Job nicht signiert) oder erst NACH dem committeten Job - nie dazwischen."""
    add_node(adm, "g2", "full", cert="a" * 64)
    entered, release = threading.Event(), threading.Event()

    class SlowSigner(Signer):
        def seal(self, payload):
            if payload["typ"] == "job":
                entered.set()
                assert release.wait(10)
            return super().seal(payload)

    hub = Hub(hubcfg, hubdb, SlowSigner(gate["priv"], gate["id"]), clock=clock, gate_set=open_gates)
    j1, j2 = JID(), JID()
    hub.enqueue_job(JobRequest("g2", 1, "dir.ensure", {}, job_id=j1))
    hub.enqueue_job(JobRequest("g2", 1, "dir.ensure", {}, job_id=j2))
    t = threading.Thread(target=lambda: hub.deliver_next("g2"))
    t.start()
    assert entered.wait(10)                                    # der Hub haelt jetzt das Lock zwischen letzter STOP-Pruefung und Commit
    p = _forge_stop(hubcfg.control_dir)
    time.sleep(0.6)
    assert p.poll() is None and not (hubcfg.control_dir / "STOP").exists()          # Stop wartet auf das Lock
    release.set()
    t.join(10)
    assert p.wait(10) == 0 and (hubcfg.control_dir / "STOP").exists()
    assert hub.job_state(j1)["state"] == "issued"               # der Job war vor dem Stop committet ...
    assert hub.deliver_next("g2") is None                       # ... der naechste wird nach dem Stop nicht mehr signiert
    assert hub.job_state(j2)["state"] == "queued"


def test_delivery_refuses_when_the_lock_cannot_be_taken(t1hub, hubcfg):
    j = JID()
    t1hub.enqueue_job(JobRequest("g2", 1, "dir.ensure", {}, job_id=j))
    import fcntl

    fd = os.open(hubcfg.control_dir / ".dispatch.lock", os.O_RDWR | os.O_CREAT, 0o664)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        t0 = time.monotonic()
        assert t1hub.deliver_next("g2") is None                  # Timeout (2 s im Test) => nichts signiert
        assert time.monotonic() - t0 >= 1.5
    finally:
        os.close(fd)
    assert t1hub.job_state(j)["state"] == "queued"


def test_delivery_refuses_when_control_dir_is_missing(t1hub, hubcfg):
    j = JID()
    t1hub.enqueue_job(JobRequest("g2", 1, "dir.ensure", {}, job_id=j))
    (hubcfg.control_dir / ".dispatch.lock").unlink(missing_ok=True)
    os.rmdir(hubcfg.control_dir)
    assert t1hub.deliver_next("g2") is None and t1hub.job_state(j)["state"] == "queued"


def test_hub_killswitch_module_cannot_set_or_release_stop():                    # test_stop_release_not_possible_from_node (Modul)
    names = {n for n in dir(killswitch) if not n.startswith("_")}
    assert not names & {"engage", "release", "set_stop", "clear_stop", "touch"}
    src = Path(killswitch.__file__).read_text()
    assert "unlink" not in src and "os.remove" not in src and "rmdir" not in src and "O_TRUNC" not in src and "write(" not in src
    pkg = Path(killswitch.__file__).parent
    for f in pkg.glob("*.py"):
        text = f.read_text()
        for bad in ("unlink(", "os.remove(", "rmdir(", "rmtree(", "os.rename(", "os.replace(", "os.mkdir(", "mkdir("):
            assert bad not in text, f"{f.name} must not modify the filesystem ({bad})"


def test_clock_skew_above_60s_withholds_t1_jobs_and_alerts(t1hub, adm):
    j = JID()
    t1hub.enqueue_job(JobRequest("g2", 1, "dir.ensure", {}, job_id=j))
    t1hub.poll("g2", _poll(clock="2026-10-31T13:42:10Z"))                  # Knoten geht 120 s vor
    assert t1hub.job_state(j)["state"] == "queued"
    assert adm.execute("SELECT kind FROM node.alerts").fetchone()["kind"] == "clock_skew"
    t1hub.poll("g2", _poll(clock="2026-10-31T13:40:10Z"))
    assert t1hub.job_state(j)["state"] == "issued"


# ======================================================================================================================== poll
def test_poll_stores_heartbeat(hub, adm):
    hub.poll("g2", _poll(version="0.1.7", policy={"serial": 3, "sha256": HEX}, clock="2026-10-31T13:40:40Z"))
    n = adm.execute("SELECT agent_version, policy_serial, policy_sha256, clock_skew_s, last_seen FROM node.nodes WHERE node_id='g2'").fetchone()
    assert (n["agent_version"], n["policy_serial"], n["policy_sha256"], n["clock_skew_s"]) == ("0.1.7", 3, HEX, 30) and n["last_seen"] == hub.clock()


def test_open_jobs_mirror_states_and_clear_when_unlisted(hub, gate_keys):
    j = JID()
    hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j))
    _deliver(hub, gate_keys)
    hub.poll("g2", _poll(open_jobs=[{"job_id": j, "state": "started", "attempt": 1}]))
    s = hub.job_state(j)
    assert s["state"] == "in_progress" and s["reported_state"] == "started"
    hub.poll("g2", _poll(open_jobs=[{"job_id": j, "state": "effect_done", "attempt": 1}]))
    assert hub.job_state(j)["reported_state"] == "effect_done"
    hub.poll("g2", _poll())
    assert hub.job_state(j)["reported_state"] is None and hub.job_state(j)["state"] == "in_progress"


def test_unknown_open_job_raises_alert_and_other_nodes_job_is_unknown(hub, adm, gate_keys):
    ghost = JID()
    hub.poll("g2", _poll(open_jobs=[{"job_id": ghost, "state": "started", "attempt": 1}]))
    j = JID()
    hub.enqueue_job(JobRequest("g1", 0, "inv.host", job_id=j))
    hub.poll("g2", _poll(open_jobs=[{"job_id": j, "state": "started", "attempt": 1}]))
    assert adm.execute("SELECT count(*) AS n FROM node.alerts WHERE kind='unknown_open_job'").fetchone()["n"] == 2
    assert hub.job_state(j)["state"] == "queued"


def test_node_reported_indeterminate_blocks_target(hub, gate_keys, adm):
    j = JID()
    hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j))
    _deliver(hub, gate_keys)
    hub.poll("g2", _poll(open_jobs=[{"job_id": j, "state": "indeterminate", "attempt": 1}]))
    assert hub.job_state(j)["state"] == "indeterminate"
    assert adm.execute("SELECT kind FROM node.alerts").fetchone()["kind"] == "indeterminate_job"


def test_reconcile_request_for_long_running_and_rate_limited(hub, gate_keys, clock):
    j = JID()
    hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j))
    _deliver(hub, gate_keys)
    ol = [{"job_id": j, "state": "started", "attempt": 1}]
    assert hub.poll("g2", _poll(open_jobs=ol))["reconcile"] == []
    clock.advance(301)
    assert hub.poll("g2", _poll(open_jobs=ol))["reconcile"] == [j]
    assert hub.poll("g2", _poll(open_jobs=ol))["reconcile"] == []             # nicht bei jedem Poll
    clock.advance(61)
    assert hub.poll("g2", _poll(open_jobs=ol))["reconcile"] == [j]


def test_poll_reports_latest_policy_serial_from_signed_files_only(hub, hubcfg):
    d = hubcfg.policy_dir / "g2"
    d.mkdir()
    assert hub.poll("g2", _poll())["policy_serial_latest"] == 0
    (d / "policy-2.json").write_text("{}")
    assert hub.poll("g2", _poll())["policy_serial_latest"] == 0           # ohne .sig zaehlt es nicht
    (d / "policy-2.json.sig").write_text("sig")
    (d / "policy-7.json").write_text("{}")
    (d / "policy-7.json.sig").write_text("sig")
    (d / "policy-x.json").write_text("{}")
    assert hub.poll("g2", _poll())["policy_serial_latest"] == 7


def test_long_poll_returns_as_soon_as_a_job_arrives(hub, gate_keys, clock):
    calls = []

    def sleeper(s):
        calls.append(s)
        clock.advance(s)
        if len(calls) == 2:
            hub.enqueue_job(JobRequest("g2", 0, "inv.host"))

    hub.sleep = sleeper
    r = hub.poll("g2", _poll(wait_s=30))
    assert len(r["jobs"]) == 1 and len(calls) == 2


def test_long_poll_waits_at_most_the_requested_time_and_never_more_than_the_cap(hub):
    hub.sleep = time.sleep
    t0 = time.monotonic()
    r = hub.poll("g2", _poll(wait_s=2))
    dt = time.monotonic() - t0
    assert r["jobs"] == [] and 1.8 <= dt < 4
    t0 = time.monotonic()
    hub.poll("g2", _poll(wait_s=0))
    assert time.monotonic() - t0 < 1.5
    hub.cfg = type(hub.cfg)(**{**hub.cfg.__dict__, "long_poll_max_s": 1})            # Konfigurationsdeckel gilt vor dem Wunsch des Knotens
    t0 = time.monotonic()
    hub.poll("g2", _poll(wait_s=30))
    assert time.monotonic() - t0 < 3


def test_long_poll_returns_early_when_stop_flips(hub, hubcfg, gate_keys, clock):
    seen = []

    def sleeper(s):
        seen.append(s)
        (hubcfg.control_dir / "STOP").write_text("STOP\n")

    hub.sleep = sleeper
    r = hub.poll("g2", _poll(wait_s=30))
    assert len(seen) == 1 and protocol.verify_lease(r["lease"], gate_keys, "g2", clock(), 0, ssh_keygen="ssh-keygen")["stop"]


def test_audit_head_behind_or_forked_quarantines(hub, adm):
    from forge_node import chain

    r1 = chain.seal_record({"ts": "2026-10-31T13:40:10Z", "node": "g2", "type": "t0"}, 1, chain.GENESIS_HASH)
    assert hub.ingest_audit("g2", {"source": "priv", "records": [r1]})["acked"] == {"priv": 1}
    hub.poll("g2", _poll(audit_heads={"priv": {"seq": 1, "hash": r1["hash"]}}))
    assert not adm.execute("SELECT quarantine FROM node.nodes WHERE node_id='g2'").fetchone()["quarantine"]
    hub.poll("g2", _poll(audit_heads={"priv": {"seq": 0, "hash": "0" * 64}}))                # Log zurueckgesetzt/verloren
    assert adm.execute("SELECT quarantine FROM node.nodes WHERE node_id='g2'").fetchone()["quarantine"]
    adm.execute("UPDATE node.nodes SET quarantine=false")
    hub.poll("g2", _poll(audit_heads={"priv": {"seq": 1, "hash": "e" * 64}}))                # gleiche seq, anderer Hash
    assert adm.execute("SELECT quarantine FROM node.nodes WHERE node_id='g2'").fetchone()["quarantine"]


# ===================================================================================================================== results
def test_result_commits_and_duplicate_is_idempotent(hub, gate_keys):
    j = JID()
    hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j))
    _deliver(hub, gate_keys)
    r = hub.accept_result("g2", j, _result(output="hello", audit_seq_range=[1, 2]))
    assert r == {"ok": True, "state": "committed", "duplicate": False}
    assert hub.accept_result("g2", j, _result(output="hello", audit_seq_range=[1, 2]))["duplicate"]
    s = hub.job_state(j)
    assert s["state"] == "committed" and s["result_output"] == "hello"


def test_conflicting_result_for_terminal_job_quarantines(hub, gate_keys, adm):
    j = JID()
    hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j))
    _deliver(hub, gate_keys)
    hub.accept_result("g2", j, _result())
    with pytest.raises(ProtoError):
        hub.accept_result("g2", j, _result(status="failed", reason_code="FAIL_EXEC"))
    assert adm.execute("SELECT quarantine, quarantine_reason FROM node.nodes WHERE node_id='g2'").fetchone()["quarantine"]
    assert hub.job_state(j)["state"] == "committed"


def test_result_for_undelivered_foreign_or_unknown_job_rejected(hub, gate_keys):
    j = JID()
    hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j))
    with pytest.raises(ProtoError):
        hub.accept_result("g2", j, _result())                                       # nie zugestellt
    _deliver(hub, gate_keys)
    with pytest.raises(ProtoError):
        hub.accept_result("g1", j, _result())                                       # fremder Knoten
    with pytest.raises(ProtoError):
        hub.accept_result("g2", JID(), _result())
    with pytest.raises(ProtoError):
        hub.accept_result("g2", "nope", _result())


def test_stale_attempt_result_is_ignored(hub, gate_keys):
    j = JID()
    hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j))
    _deliver(hub, gate_keys)
    hub.accept_result("g2", j, _result(status="aborted_safe", reason_code="FAIL_PRECHECK", attempt=2))
    r = hub.accept_result("g2", j, _result(status="failed", reason_code="FAIL_EXEC", attempt=1))
    assert r.get("stale") and hub.job_state(j)["state"] == "aborted_safe"


def test_redaction_canaries_never_stored(hub, gate_keys, adm):         # test_redaction_canaries_never_stored
    a, b = JID(), JID()
    hub.enqueue_job(JobRequest("g2", 0, "logs.unit", {"unit": "forge-edge.service"}, job_id=a))
    hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=b))
    for _ in range(2):
        _deliver(hub, gate_keys)
    blob = "line password=CANARYhunter2 ghp_CANARYabcdef123456 rev " + "0123456789abcdef" * 3
    hub.accept_result("g2", a, _result(output=blob))
    hub.accept_result("g2", b, _result(output=blob))
    out_a, out_b = (hub.job_state(x)["result_output"] for x in (a, b))
    assert "CANARY" not in out_a and "CANARY" not in out_b
    assert "0123456789abcdef0123456789abcdef" not in out_a            # Log: auch lange Hex-Folgen
    assert "0123456789abcdef0123456789abcdef" in out_b                # Inventar: Revisionen bleiben lesbar
    dump = json.dumps([dict(r) for r in adm.execute("SELECT * FROM node.audit")], default=str) + json.dumps([dict(r) for r in adm.execute("SELECT * FROM node.jobs")], default=str)
    assert "CANARY" not in dump


def test_hub_audit_records_job_lifecycle_and_chain_verifies(hub, gate_keys, adm):
    j = JID()
    hub.enqueue_job(JobRequest("g2", 0, "inv.host", job_id=j))
    _deliver(hub, gate_keys)
    hub.accept_result("g2", j, _result())
    types = [r["type"] for r in adm.execute("SELECT type FROM node.audit WHERE node_id='g2' AND source='hub' ORDER BY seq")]
    assert types == ["job_issue", "job_issue", "job_result"]
    assert hub.verify_chains("g2") == []


def test_authenticate_requires_active_node_and_matching_fingerprint(hub, adm):
    with hub.db.tx() as c:
        assert hub.authenticate(c, "g2", "a" * 64)["node_id"] == "g2"
        from forge_node.hub.core import AuthError

        for node, fp in (("g2", "f" * 64), ("g1", "a" * 64), ("nope", "a" * 64)):
            with pytest.raises(AuthError):
                hub.authenticate(c, node, fp)
    adm.execute("UPDATE node.nodes SET status='revoked' WHERE node_id='g2'")
    with hub.db.tx() as c, pytest.raises(AuthError):
        hub.authenticate(c, "g2", "a" * 64)


def test_too_many_project_stops_fail_closed(hub, hubcfg, gate_keys, clock):
    d = hubcfg.control_dir / "stop.d"
    d.mkdir()
    for i in range(300):
        (d / f"p{i:03d}").write_text("")
    p = protocol.verify_lease(hub.poll("g2", _poll())["lease"], gate_keys, "g2", clock(), 0, ssh_keygen="ssh-keygen")
    assert p["stop"] is True and len(p["stopped_projects"]) == 256


def test_pool_based_db_with_the_real_least_privilege_role(dsn, hubcfg, gate, clock, adm):
    """Produktionspfad: Db (psycopg_pool), direkt als Rolle forge_nodehub verbunden (kein SET ROLE)."""
    from forge_node.hub.db import Db

    add_node(adm, "g2", "full", cert="a" * 64)
    db = Db(dsn.replace("user=postgres", "").strip() + " user=forge_nodehub")
    try:
        h = Hub(hubcfg, db, Signer(gate["priv"], gate["id"]), clock=clock)
        e = h.enqueue_job(JobRequest("g2", 0, "inv.host"))
        r = h.poll("g2", _poll())
        assert len(r["jobs"]) == 1 and h.job_state(e.job_id)["state"] == "issued"
        assert h.verify_chains("g2") == []
    finally:
        db.close()
