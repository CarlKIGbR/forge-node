"""Durable execution ledger and worker-aware reconciliation (Design 9.4, T-LEDGER) with REAL processes: a killable privd, op workers that outlive it, the effect lock, the fence."""
import dataclasses
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from audit_helpers import AGENT_UID
from privd_helpers import NOW, SRC, PrivdEnv, attach, gates_with

from forge_node import protocol
from forge_node.privd import optable as optable_mod, reconcile
from forge_node.privd.ledger import Ledger
from forge_node.privd.units import LocalProcessBackend, UnitError, op_unit_name

HERE = Path(__file__).resolve().parent
RUNNER = str(HERE / "privd_runner.py")
BLOCKING = str(HERE / "privd_blocking_worker.py")


def result(r):
    assert r["ok"] is True and "result" in r, r
    return r["result"]


def waitfor(pred, what, timeout=15.0):
    t_end = time.monotonic() + timeout
    while time.monotonic() < t_end:
        v = pred()
        if v:
            return v
        time.sleep(0.02)
    raise AssertionError(f"timeout waiting for {what}")


@pytest.fixture
def fifo(tmp_path, monkeypatch):
    p = tmp_path / "gate.fifo"
    os.mkfifo(p)
    monkeypatch.setenv("FN_TEST_FIFO", str(p))
    monkeypatch.setenv("FN_TEST_NOW", "2026-10-31T13:40:10")
    monkeypatch.setenv("FN_TEST_SRC", SRC)
    class Fifo:
        path = p

        @staticmethod
        def release():
            with open(p, "wb") as f:                      # a worker parked in wait() reads one byte and goes on
                f.write(b"x")
    return Fifo


def spawn_privd(env, body, worker=BLOCKING, cmd="exec"):
    e = dict(os.environ, FN_TEST_WORKER=worker)
    return subprocess.Popen([sys.executable, RUNNER, env.base, cmd, json.dumps(body)], env=e, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def marks(env):
    return [d for d in os.listdir(env.paths.work) if os.path.exists(f"{env.paths.work}/{d}/effect.mark")]


def apply_job(env, note="n"):
    plan = result(env.exec(dry_run=True, params={"note": note})[0])
    jenv, job = env.job_env(plan_hash=plan["plan_hash"], params={"note": note})
    return {"job": jenv}, job


def active(env, job):
    info = env.backend.show(op_unit_name(job["job_id"], 1))
    return info is not None and info.is_active


# ---------------------------------------------------------------------------------------------------------------------- crash scenarios
def test_privd_killed_worker_survives_reattach_on_restart_no_second_attempt(privd_env, fifo, monkeypatch):
    e = privd_env.ready()
    body, job = apply_job(e)
    monkeypatch.setenv("FN_TEST_BLOCK", "mid")
    p = spawn_privd(e, body)
    waitfor(lambda: marks(e), "the effect to happen")                                    # the worker has done its effect and waits (before status.json)
    p.kill()                                                                              # kill -9 privd mid-effect
    p.wait()
    assert active(e, job), "the worker unit must outlive privd"
    assert e.ledger.get(job["job_id"]).state == "started"
    fresh = e.restart()                                                                # privd restarts
    rep = reconcile.recover_all(fresh.ctx)
    assert rep["attached"] == [job["job_id"]] and not rep["reconciled"]                   # re-attached, NOT reconciled, no probe, no new attempt
    assert fresh.ledger.get(job["job_id"]).fence == 1 and fresh.ledger.get(job["job_id"]).attempt == 1
    fifo.release()                                                                        # the worker goes on and writes its status
    fresh.ctx.join_monitors(30)
    row = fresh.ledger.get(job["job_id"])
    assert row.state == "committed" and row.attempt == 1 and row.result["status"] == "committed"
    assert len(marks(e)) == 1, marks(e)                                                   # exactly one effect, ever
    assert fresh.types(job["job_id"]) == ["intent", "result"]
    # the duplicate delivery after the restart gets the stored result, no second worker
    n_units = len(fresh.backend.list_op_units())
    again = fresh.call("exec", {"job": fresh.job_env(job_id=job["job_id"], params={"note": "n"}, plan_hash=job["plan_hash"], delivery_seq=2)[0]})
    assert result(again)["status"] == "committed" and len(fresh.backend.list_op_units()) == n_units


def test_privd_killed_after_effect_commits_from_status_json_no_second_effect(privd_env, fifo, monkeypatch):
    e = privd_env.ready()
    body, job = apply_job(e)
    monkeypatch.setenv("FN_TEST_BLOCK", "mid")
    p = spawn_privd(e, body)
    waitfor(lambda: marks(e), "the effect")
    p.kill()
    p.wait()
    fifo.release()
    waitfor(lambda: not active(e, job), "the worker to finish")
    assert (Path(e.paths.work) / f"{job['job_id']}-1" / "status.json").exists()
    assert e.ledger.get(job["job_id"]).state == "started"                                 # privd died before it could commit
    fresh = e.restart()
    rep = reconcile.recover_all(fresh.ctx)
    assert rep["reconciled"] == [(job["job_id"], "committed")]
    assert fresh.ledger.get(job["job_id"]).state == "committed" and len(marks(e)) == 1
    assert fresh.ledger.get(job["job_id"]).fence == 1                                     # finished work is committed, not "reconciled" (no fence bump, no probe)


def test_privd_killed_before_effect_surviving_worker_fenced_no_effect(privd_env, fifo, monkeypatch):
    e = privd_env.ready()
    body, job = apply_job(e)
    monkeypatch.setenv("FN_TEST_BLOCK", "before")
    p = spawn_privd(e, body)
    wd = Path(e.paths.work) / f"{job['job_id']}-1"
    waitfor(lambda: (wd / "parked").exists(), "the worker to park before the fence check")
    p.kill()
    p.wait()
    # another privd instance reconciles (fence bump) while the old worker is still parked - the case the fence exists for
    fresh = e.restart()
    assert fresh.ledger.begin_reconcile(job["job_id"], fresh.clock()).fence == 2
    fifo.release()
    waitfor(lambda: (wd / "status.json").exists(), "the fenced worker to exit")
    st = json.loads((wd / "status.json").read_text())
    assert st["outcome"] == "fenced" and st["code"] == "FAIL_FENCED" and st["ledger_fence"] == 2
    assert not (wd / "effect.mark").exists()
    waitfor(lambda: not active(e, job), "the fenced worker process to be gone")
    kind, res = reconcile.reconcile_job(fresh.ctx, job["job_id"])
    assert kind == "aborted_safe" and fresh.ledger.get(job["job_id"]).state == "aborted_safe"
    assert any(r["type"] == "recovery" and r["verdict"] == "aborted_safe" for r in fresh.priv_records())
    # a new attempt may start only from aborted_safe, through the claim path, with attempt+1 and the bumped fence
    monkeypatch.setenv("FN_TEST_BLOCK", "none")
    fresh.worker_script = BLOCKING
    fresh.clock.advance(seconds=1)
    jenv, _ = fresh.job_env(job_id=job["job_id"], params={"note": "n"}, plan_hash=job["plan_hash"], delivery_seq=2)
    res = result(fresh.call("exec", {"job": jenv}))
    row = fresh.ledger.get(job["job_id"])
    assert res["status"] == "committed" and res["attempt"] == 2 and row.attempt == 2 and row.fence == 3      # one bump by the other instance, one by this reconcile: the fence only grows
    assert len(marks(e)) == 1 and marks(e)[0].endswith("-2")


def test_reconcile_never_runs_while_worker_active(privd_env, fifo, monkeypatch):
    e = privd_env.ready()
    body, job = apply_job(e)
    monkeypatch.setenv("FN_TEST_BLOCK", "before")
    p = spawn_privd(e, body)
    wd = Path(e.paths.work) / f"{job['job_id']}-1"
    waitfor(lambda: (wd / "parked").exists(), "park")
    p.kill()
    p.wait()
    fresh = e.restart()
    for _ in range(3):
        r = fresh.call("reconcile", {"job_id": job["job_id"]}, uid=1001)
        assert r["ok"] and r["reconcile"] == "in_progress"
    row = fresh.ledger.get(job["job_id"])
    assert row.fence == 1 and row.state == "started" and active(e, job)               # fence untouched, worker untouched
    fifo.release()
    waitfor(lambda: (wd / "status.json").exists(), "status")
    waitfor(lambda: not active(e, job), "exit")
    kind, res = reconcile.reconcile_job(fresh.ctx, job["job_id"])
    assert kind == "committed" and len(marks(e)) == 1


def test_reconcile_stops_worker_and_confirms_dead_before_probe(privd_env, fifo, monkeypatch):
    e = privd_env.ready()
    body, job = apply_job(e)
    monkeypatch.setenv("FN_TEST_BLOCK", "before")
    p = spawn_privd(e, body)
    wd = Path(e.paths.work) / f"{job['job_id']}-1"
    waitfor(lambda: (wd / "parked").exists(), "park")
    p.kill()
    p.wait()
    fresh = e.restart()
    seen = {}
    entry = fresh.table.get("selftest.noop")

    def probe(work_dir):
        info = fresh.backend.show(op_unit_name(job["job_id"], 1))
        seen["active"], seen["cgroup_empty"] = info.is_active, info.cgroup_empty
        seen["fence"] = fresh.ledger.get(job["job_id"]).fence
        seen["state"] = fresh.ledger.get(job["job_id"]).state
        return optable_mod.VERDICTS[1] if not os.path.exists(f"{work_dir}/effect.mark") else "applied"
    fresh.ctx.optable = optable_mod.OpTable([dataclasses.replace(entry, probe=probe)])
    fresh.clock.advance(seconds=31)                                                       # past the op's time budget: reconciliation is now allowed
    kind, res = reconcile.reconcile_job(fresh.ctx, job["job_id"])
    assert kind == "aborted_safe"
    assert seen == {"active": False, "cgroup_empty": True, "fence": 2, "state": "reconciling"}      # dead + fence bumped BEFORE the probe looked at the world
    assert not (wd / "effect.mark").exists() and not active(e, job)


def test_unconfirmable_worker_death_is_indeterminate(privd_env, fifo, monkeypatch):
    e = privd_env.ready()
    body, job = apply_job(e)
    monkeypatch.setenv("FN_TEST_BLOCK", "before")
    p = spawn_privd(e, body)
    wd = Path(e.paths.work) / f"{job['job_id']}-1"
    waitfor(lambda: (wd / "parked").exists(), "park")
    p.kill()
    p.wait()
    fresh = e.restart()
    fresh.backend.stop = lambda name: None                                                # the unit cannot be stopped
    reconcile.STOP_WAIT_S, old = 0.3, reconcile.STOP_WAIT_S
    try:
        fresh.clock.advance(seconds=31)
        kind, res = reconcile.reconcile_job(fresh.ctx, job["job_id"])
    finally:
        reconcile.STOP_WAIT_S = old
    assert kind == "indeterminate" and res["reason_code"] == "INDETERMINATE"
    assert fresh.ledger.get(job["job_id"]).state == "indeterminate"
    assert fresh.ledger.target_lock("selftest.noop")["job_id"] == job["job_id"]
    # every further op on the target is denied until resolved
    fresh.put_lease(seq=77)
    r2 = result(fresh.exec(dry_run=True)[0])
    assert r2["reason_code"] == "DENY_TARGET_LOCKED"
    # the agent identity cannot resolve; root can, with the inspection attached
    assert fresh.call("reconcile", {"job_id": job["job_id"], "resolve": {"verdict": "aborted_safe", "inspection": "inspected the work dir: no effect.mark"}}, uid=1001)["code"] == "DENY_NEEDS_OWNER_SIG"
    assert fresh.call("reconcile", {"job_id": job["job_id"], "resolve": {"verdict": "aborted_safe", "inspection": "short"}})["code"] == "DENY_PARAM"
    r = fresh.call("reconcile", {"job_id": job["job_id"], "resolve": {"verdict": "aborted_safe", "inspection": "inspected the work dir: no effect.mark"}})
    assert result(r)["status"] == "aborted_safe" and fresh.ledger.target_lock("selftest.noop") is None
    assert any(x["type"] == "recovery" and x["verdict"] == "resolved_aborted_safe" and len(x["inspection_sha256"]) == 64 for x in fresh.priv_records())
    del fresh.backend.stop                                                                # back to the real stop(): clean up the parked worker
    fresh.backend.stop(op_unit_name(job["job_id"], 1))


def _died_without_status(e, entry_changes):
    """A started row whose unit is gone and which left no status.json: what a worker that died mid-effect looks like. Returns the reconciliation outcome and the audit trail."""
    import uuid
    e.ctx.optable = optable_mod.OpTable([dataclasses.replace(e.table.get("selftest.noop"), **entry_changes)])
    jid = str(uuid.uuid4())
    e.ledger.claim(jid, 1, "selftest.noop", "selftest.noop", "0" * 64, False, "meta", e.clock())
    wd = Path(e.paths.work) / f"{jid}-1"
    wd.mkdir(mode=0o700)
    e.ledger.mark_started(jid, 1, op_unit_name(jid, 1), str(wd), None, None, False, False, e.clock())
    kind, res = reconcile.reconcile_job(e.ctx, jid)
    return jid, kind, res


def test_crash_midway_probe_unknown_is_indeterminate(privd_env):
    """The probe cannot tell (unknown, or partial): never retried automatically, the target is locked, a `recovery` record says so."""
    e = privd_env.ready()
    for verdict in ("unknown", "partial"):
        jid, kind, res = _died_without_status(e, dict(probe=lambda wd, v=verdict: v))
        assert kind == "indeterminate" and res["reason_code"] == "INDETERMINATE", verdict
        assert e.ledger.get(jid).state == "indeterminate" and e.ledger.target_lock("selftest.noop")["job_id"] == jid
        recs = [r for r in e.priv_records() if r.get("job_id") == jid]
        assert [r["type"] for r in recs] == ["recovery"] and recs[0]["verdict"] == "indeterminate"
        e.ledger.unlock_target("selftest.noop", jid)


def test_opaque_crash_always_indeterminate(privd_env):
    """Idempotency class `opaque`: effects unknown, so a crash is indeterminate even when a probe would say 'not applied'."""
    e = privd_env.ready()
    jid, kind, res = _died_without_status(e, dict(idempotency="opaque", probe=lambda wd: "not_applied"))      # even a probe that says 'not applied' is not believed for an opaque op
    assert kind == "indeterminate" and e.ledger.get(jid).state == "indeterminate"
    e.ledger.unlock_target("selftest.noop", jid)
    jid0, kind0, _ = _died_without_status(e, dict(idempotency="opaque", probe=None))
    assert kind0 == "indeterminate"
    e.ledger.unlock_target("selftest.noop", jid0)
    jid2, kind2, _ = _died_without_status(e, dict(idempotency="probe", probe=lambda wd: "not_applied"))
    assert kind2 == "aborted_safe"                                                          # the same crash with an observable effect IS safely retryable


def test_indeterminate_locks_target_until_resolved(privd_env):
    e = privd_env.ready()
    jid, kind, _ = _died_without_status(e, dict(probe=lambda wd: "unknown"))
    assert kind == "indeterminate" and e.ledger.target_lock("selftest.noop")
    e.put_lease(seq=300)
    res = result(e.exec(dry_run=True)[0])
    assert res["status"] == "denied" and res["reason_code"] == "DENY_TARGET_LOCKED" and "DENY_TARGET_LOCKED" in __import__("forge_node.protocol", fromlist=["x"]).RETRYABLE_DENIALS
    # (a) the agent identity cannot resolve it, (b) root can, with the inspection attached; (c) the lock is gone afterwards
    body = {"job_id": jid, "resolve": {"verdict": "aborted_safe", "inspection": "inspected the work directory: no effect.mark, unit gone"}}
    assert e.call("reconcile", body, uid=1001)["code"] == "DENY_NEEDS_OWNER_SIG" and e.ledger.target_lock("selftest.noop")
    assert result(e.call("reconcile", body))["status"] == "aborted_safe" and e.ledger.target_lock("selftest.noop") is None
    e.put_lease(seq=301)
    assert result(e.exec(dry_run=True)[0])["status"] == "dry_run"


def test_delegated_pending_systemd_job_settles_before_probe(privd_env):
    e = privd_env.ready()
    entry = e.table.get("selftest.noop")
    import uuid
    calls = []
    for settled, expect in ((False, "indeterminate"), (True, "aborted_safe")):
        e.ctx.optable = optable_mod.OpTable([dataclasses.replace(entry, settle=lambda wd, s=settled: calls.append(("settle", s)) or s,
                                                                    probe=lambda wd: calls.append(("probe",)) or "not_applied")])
        jid = str(uuid.uuid4())
        e.ledger.claim(jid, 1, "selftest.noop", "selftest.noop", "0" * 64, False, "meta", e.clock())
        wd = Path(e.paths.work) / f"{jid}-1"
        wd.mkdir(mode=0o700)
        e.ledger.mark_started(jid, 1, op_unit_name(jid, 1), str(wd), None, None, False, False, e.clock())
        kind, _ = reconcile.reconcile_job(e.ctx, jid)
        assert kind == expect
        e.ledger.unlock_target("selftest.noop", jid)
    assert calls == [("settle", False), ("settle", True), ("probe",)]                     # no probe ran for the unsettled one


def test_orphan_op_unit_without_row_stopped_and_alerted(privd_env, tmp_path):
    e = privd_env.ready()
    import uuid
    jid = str(uuid.uuid4())
    name = op_unit_name(jid, 1)
    e.backend.start(name, {"ProtectSystem": "strict"}, [sys.executable, "-c", "import time; time.sleep(60)"])
    assert e.backend.show(name).is_active
    rep = reconcile.recover_all(e.ctx)
    assert rep["orphans"] == [name] and not e.backend.show(name).is_active
    assert any(r["type"] == "recovery" and r.get("orphan_unit") == name for r in e.priv_records())


def test_lost_result_returns_ledger_result_without_reexecution(privd_env):
    e = privd_env.ready()
    plan = result(e.exec(dry_run=True, params={"note": "x"})[0])
    r1, job = e.exec(plan_hash=plan["plan_hash"], params={"note": "x"})
    res1 = result(r1)
    n_marks, n_audit = len(marks(e)), len(e.priv_records())
    for seq in (2, 3):                                                                    # the hub never saw the result: it re-delivers the same job_id
        env2, _ = e.job_env(job_id=job["job_id"], plan_hash=plan["plan_hash"], params={"note": "x"}, delivery_seq=seq)
        res2 = result(e.call("exec", {"job": env2}))
        assert res2 == res1
    assert len(marks(e)) == n_marks and len(e.priv_records()) == n_audit                  # no second effect, nothing new in the audit log
    # same job_id, different request: conflict, not a second execution
    env3, _ = e.job_env(job_id=job["job_id"], plan_hash=plan["plan_hash"], params={"note": "DIFFERENT"}, delivery_seq=4)
    r3 = e.call("exec", {"job": env3})
    assert r3["ok"] is False and r3["code"] == "DENY_PARAM" and len(marks(e)) == n_marks and e.ledger.get(job["job_id"]).state == "committed"


def test_terminal_denial_does_not(privd_env):
    """A terminal denial (DENY_PARAM) is the job's answer for good: a re-delivery gets the stored denial, nothing new is audited."""
    e = privd_env.ready()
    env, job = e.job_env(params={"bogus": 1}, dry_run=True)
    first = result(e.call("exec", {"job": env}))
    assert first["reason_code"] == "DENY_PARAM" and e.ledger.get(job["job_id"]).state == "denied"
    n = len(e.priv_records())
    env2, _ = e.job_env(job_id=job["job_id"], params={"bogus": 1}, dry_run=True, delivery_seq=2)
    assert result(e.call("exec", {"job": env2})) == first and len(e.priv_records()) == n


def test_retryable_denial_allows_new_delivery_same_job_id(privd_env):
    e = privd_env.ready()
    open(e.paths.local_stop, "w").close()
    env3, job3 = e.job_env(dry_run=True)
    assert result(e.call("exec", {"job": env3}))["reason_code"] == "DENY_LOCAL_STOP"
    assert e.ledger.get(job3["job_id"]).state == "denied_retryable"
    os.unlink(e.paths.local_stop)
    env4, _ = e.job_env(job_id=job3["job_id"], dry_run=True, delivery_seq=2)
    assert result(e.call("exec", {"job": env4}))["status"] == "dry_run" and e.ledger.get(job3["job_id"]).state == "committed"


def test_replayed_old_delivery_rejected_after_expiry(privd_env):
    e = privd_env.ready()
    env, job = e.job_env(dry_run=True, ttl=30)
    assert result(e.call("exec", {"job": env}))["status"] == "dry_run"
    e.clock.advance(seconds=31)
    e.put_lease(seq=8)
    r = e.call("exec", {"job": env})
    assert r["ok"] is False and r["code"] == "DENY_JOB_EXPIRED"


def test_concurrent_duplicate_delivery_second_gets_in_progress_single_worker(privd_env, fifo, monkeypatch):
    e = privd_env.ready()
    body, job = apply_job(e)
    monkeypatch.setenv("FN_TEST_BLOCK", "before")
    e.worker_script = BLOCKING
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("first", e.call("exec", body)))
    t.start()
    wd = Path(e.paths.work) / f"{job['job_id']}-1"
    waitfor(lambda: (wd / "parked").exists(), "the first delivery's worker to park")
    for _ in range(3):
        r = e.call("exec", body)
        assert r == {"ok": True, "in_progress": True, "job_id": job["job_id"]}
    assert len(e.backend.list_op_units()) == 2 and len([u for u in e.backend.list_op_units() if job["job_id"] in u]) == 1       # one unit for the job
    fifo.release()
    t.join(30)
    assert result(out["first"])["status"] == "committed" and len(marks(e)) == 1


def test_ledger_atomic_claim_single_execution_under_concurrent_delivery(tmp_path):
    led = Ledger(str(tmp_path / "l.sqlite"))
    kinds = []
    lock = threading.Lock()

    def go(i):
        c = led.claim("0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b", i, "selftest.noop", "k", "0" * 64, False, "meta", NOW)
        with lock:
            kinds.append(c.kind)
    ts = [threading.Thread(target=go, args=(i + 1,)) for i in range(16)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert kinds.count("new") == 1 and kinds.count("in_progress") == 15
    # a second process on the same file sees the same row
    led2 = Ledger(str(tmp_path / "l.sqlite"))
    assert led2.claim("0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b", 99, "selftest.noop", "k", "0" * 64, False, "meta", NOW).kind == "in_progress"
    assert led2.claim("0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b", 99, "selftest.noop", "k", "1" * 64, False, "meta", NOW).kind == "conflict"


def test_stale_received_row_of_a_dead_handler_is_picked_up_by_the_next_delivery(privd_env):
    """privd died between the claim and `started`: no worker exists. The next delivery (which holds the job lock) proceeds instead of waiting for a handler that is gone."""
    e = privd_env.ready()
    env, job = e.job_env(dry_run=True)
    e.ledger.claim(job["job_id"], 1, "selftest.noop", "selftest.noop", __import__("forge_node.canon", fromlist=["x"]).digest(job["params"]), True, "meta", e.clock())
    assert e.ledger.get(job["job_id"]).state == "received"
    assert result(e.call("exec", {"job": env}))["status"] == "dry_run"


def test_fence_mismatch_worker_exits_without_effect(privd_env, tmp_path):
    """worker.run() on its own: row.fence != request.fence => FAIL_FENCED, nothing done, status.json says why."""
    from forge_node.privd import ops, worker
    e = privd_env
    import uuid
    jid = str(uuid.uuid4())
    e.ledger.claim(jid, 1, "selftest.noop", "k1", "0" * 64, False, "meta", e.clock())
    wd = Path(e.paths.work) / f"{jid}-1"
    wd.mkdir(mode=0o700)
    e.ledger.mark_started(jid, 1, op_unit_name(jid, 1), str(wd), None, None, False, False, e.clock())
    req = {"job_id": jid, "attempt": 1, "fence": 1, "op": "selftest.noop", "params": {"note": ""}, "dry_run": False, "plan_hash": None, "effect_key": "k1", "ledger_path": e.paths.ledger,
           "lock_dir": e.paths.locks, "priv_state": e.paths.priv_state}
    (wd / "request.json").write_text(json.dumps(req))
    os.chmod(wd / "request.json", 0o600)
    e.ledger.begin_reconcile(jid, e.clock())                                              # fence 2
    assert worker.run(str(wd), ops.EFFECTS, owner_uid=0) == 0
    st = worker.read_status(str(wd))
    assert st["outcome"] == "fenced" and st["code"] == "FAIL_FENCED" and not (wd / "effect.mark").exists()
    # the fence on its own (row still `started`, only the number differs - the check does not rely on the state machine never producing this)
    e.ledger._c.execute("UPDATE exec SET state='started', fence=7 WHERE job_id=?", (jid,))
    req["fence"] = 6
    (wd / "request.json").write_text(json.dumps(req))
    os.unlink(wd / "status.json")
    assert worker.run(str(wd), ops.EFFECTS, owner_uid=0) == 0
    st = worker.read_status(str(wd))
    assert st["outcome"] == "fenced" and st["ledger_fence"] == 7 and not (wd / "effect.mark").exists()
    os.unlink(wd / "status.json")
    req["fence"] = 7                                                                      # ... and with the matching fence the same worker acts
    (wd / "request.json").write_text(json.dumps(req))
    assert worker.run(str(wd), ops.EFFECTS, owner_uid=0) == 0 and worker.read_status(str(wd))["outcome"] == "done" and (wd / "effect.mark").exists()
    os.unlink(wd / "status.json")
    os.unlink(wd / "effect.mark")
    e.ledger._c.execute("UPDATE exec SET state='reconciling', fence=2 WHERE job_id=?", (jid,))
    # a worker for a row that is not `started`, or an unknown row, is fenced too
    req["fence"] = 2
    (wd / "request.json").write_text(json.dumps(req))
    assert worker.run(str(wd), ops.EFFECTS, owner_uid=0) == 0 and worker.read_status(str(wd))["outcome"] == "fenced"


def test_effect_lock_serializes_workers_of_the_same_effect_key(privd_env, tmp_path):
    import fcntl
    from forge_node.privd import worker
    e = privd_env
    lp = worker.lock_path(e.paths.locks, "same-key")
    holder = os.open(lp, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(holder, fcntl.LOCK_EX)
    other = os.open(lp, os.O_RDWR)
    with pytest.raises(BlockingIOError):
        fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert worker.lock_path(e.paths.locks, "other-key") != lp
    os.close(holder)
    fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_rate_clock_rollback_does_not_refund_events(tmp_path):
    led = Ledger(str(tmp_path / "l.sqlite"))
    t = 1_000_000.0
    assert led.rate_take("b", [(2, 600)], t, None) and led.rate_take("b", [(2, 600)], t + 1, None)
    assert not led.rate_take("b", [(2, 600)], t + 2, None)
    assert not led.rate_take("b", [(2, 600)], t - 3000, None)                              # clock stepped back an hour: the events are still in the window
    assert not led.rate_take("b", [(2, 600)], t + 599, None)
    assert led.rate_take("b", [(2, 600)], t + 602, None)


def test_ledger_schema_version_and_window(tmp_path):
    import sqlite3
    from forge_node.privd.ledger import STATE_SCHEMA, SchemaTooNew
    p = str(tmp_path / "l.sqlite")
    Ledger(p).close()
    c = sqlite3.connect(p)
    assert c.execute("PRAGMA user_version").fetchone()[0] == STATE_SCHEMA
    c.execute(f"PRAGMA user_version={STATE_SCHEMA + 1}")
    c.close()
    with pytest.raises(SchemaTooNew):
        Ledger(p)
    assert os.stat(p).st_mode & 0o777 == 0o600


def test_local_backend_has_no_collect_names_are_never_reused(tmp_path):
    b = LocalProcessBackend(str(tmp_path / "u"))
    import uuid
    name = op_unit_name(str(uuid.uuid4()), 1)
    b.start(name, {"ProtectSystem": "strict"}, [sys.executable, "-c", "pass"])
    with pytest.raises(UnitError):
        b.start(name, {}, [sys.executable, "-c", "pass"])
    with pytest.raises(UnitError):
        b.start("not-a-unit.service", {}, ["/bin/true"])


def test_audit_failure_after_the_effect_is_not_reported_as_a_denial(privd_env):
    """The worker did its effect; then the audit log refuses the `result` record. Reporting `denied/retryable` would make the hub re-run an effect that already happened. The reply is
    in_progress, the row stays open (effect_done), a re-delivery gets in_progress, and once the log is back reconcile commits from status.json - one effect, ever."""
    from forge_node.privd.core import Deny
    e = privd_env.ready()
    plan = result(e.exec(dry_run=True)[0])
    real, broken = e.ctx.audit, {"on": True}

    def flaky(type_, fields):
        if broken["on"] and type_ == "result":
            raise Deny("DENY_AUDIT_DOWN", "log refused the result record")
        return real(type_, fields)
    e.ctx.audit = flaky
    env, job = e.job_env(plan_hash=plan["plan_hash"])
    assert e.call("exec", {"job": env}) == {"ok": True, "in_progress": True, "job_id": job["job_id"]}
    row = e.ledger.get(job["job_id"])
    assert row.state == "effect_done" and row.result is None and len(marks(e)) == 1
    assert e.call("exec", {"job": env}) == {"ok": True, "in_progress": True, "job_id": job["job_id"]}          # the hub's re-delivery does not start a second worker
    assert len(marks(e)) == 1 and len([u for u in e.backend.list_op_units() if job["job_id"] in u]) == 1
    broken["on"] = False
    kind, res = reconcile.reconcile_job(e.ctx, job["job_id"])
    assert kind == "committed" and res["status"] == "committed" and len(marks(e)) == 1
    assert e.ledger.get(job["job_id"]).state == "committed" and e.types(job["job_id"]) == ["intent", "result"]


def test_effect_lock_blocks_a_worker_until_it_is_released(privd_env):
    """The worker takes the effect lock BEFORE it looks at the ledger and acts; while another process holds it the worker produces nothing, afterwards it runs normally."""
    import fcntl
    import uuid
    from forge_node.privd import worker
    e = privd_env
    jid = str(uuid.uuid4())
    e.ledger.claim(jid, 1, "selftest.noop", "k-lock", "0" * 64, False, "meta", e.clock())
    wd = Path(e.paths.work) / f"{jid}-1"
    wd.mkdir(mode=0o700)
    e.ledger.mark_started(jid, 1, op_unit_name(jid, 1), str(wd), None, None, False, False, e.clock())
    req = {"job_id": jid, "attempt": 1, "fence": 1, "op": "selftest.noop", "params": {"note": ""}, "dry_run": False, "plan_hash": None, "effect_key": "k-lock", "ledger_path": e.paths.ledger,
           "lock_dir": e.paths.locks, "priv_state": e.paths.priv_state}
    (wd / "request.json").write_text(json.dumps(req))
    os.chmod(wd / "request.json", 0o600)
    holder = os.open(worker.lock_path(e.paths.locks, "k-lock"), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(holder, fcntl.LOCK_EX)
    p = subprocess.Popen([sys.executable, "-m", "forge_node.privd.opworker", "run", str(wd)], env=dict(os.environ), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        time.sleep(1.0)
        assert p.poll() is None and not (wd / "status.json").exists() and not (wd / "effect.mark").exists()        # parked on the lock
        fcntl.flock(holder, fcntl.LOCK_UN)
        assert p.wait(30) == 0
    finally:
        os.close(holder)
        if p.poll() is None:
            p.kill()
    st = worker.read_status(str(wd))
    assert st["outcome"] == "done" and (wd / "effect.mark").exists()


def test_retention_prunes_only_old_terminal_rows_with_their_work_dirs_and_locks(privd_env):
    from datetime import timedelta
    from forge_node.privd import maintenance
    e = privd_env.ready()
    old_ok = result(e.exec(dry_run=True)[0])["job_id"]                                           # committed (dry_run)
    e.clock.advance(seconds=61)
    e.put_lease(seq=50)
    keep_recent = result(e.exec(dry_run=True)[0])["job_id"]
    # a retryable and an indeterminate row must survive any age
    open(e.paths.local_stop, "w").close()
    retry = result(e.exec(dry_run=True)[0])["job_id"]
    os.unlink(e.paths.local_stop)
    import uuid
    ind = str(uuid.uuid4())
    e.ledger.claim(ind, 1, "selftest.noop", "selftest.noop", "0" * 64, False, "meta", e.clock())
    e.ledger.finish(ind, 1, "indeterminate", {"attempt": 1, "status": "indeterminate", "reason_code": "INDETERMINATE", "output": "", "audit_seq_range": None, "plan_hash": None}, e.clock(), frm=("received",))
    assert maintenance.prune(e.ctx) == {"rows": 0, "work_dirs": 0, "locks": 0, "plans": 0}          # nothing is 90 days old yet
    e.clock.advance(seconds=1)
    for jid in (old_ok, keep_recent):
        e.ledger._c.execute("UPDATE exec SET updated_at=? WHERE job_id=?", ("2026-06-01T00:00:00Z" if jid == old_ok else "2026-10-31T13:40:00Z", jid))
    e.ledger._c.execute("UPDATE exec SET updated_at='2026-01-01T00:00:00Z' WHERE job_id IN (?,?)", (retry, ind))
    wd_old = Path(e.paths.work) / f"{old_ok}-1"
    assert wd_old.is_dir() and os.path.exists(f"{e.paths.locks}/job-{old_ok}.lock")
    rep = maintenance.prune(e.ctx)
    assert rep["rows"] == 1 and rep["work_dirs"] == 1 and rep["locks"] == 1
    assert e.ledger.get(old_ok) is None and not wd_old.exists() and not os.path.exists(f"{e.paths.locks}/job-{old_ok}.lock")
    for jid in (keep_recent, retry, ind):
        assert e.ledger.get(jid) is not None
    assert os.path.exists(f"{e.paths.locks}/job-{keep_recent}.lock")
    # a lock somebody holds is not unlinked
    import fcntl
    fd = os.open(f"{e.paths.locks}/job-{keep_recent}.lock", os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX)
    e.ledger._c.execute("UPDATE exec SET updated_at='2026-06-01T00:00:00Z' WHERE job_id=?", (keep_recent,))
    rep = maintenance.prune(e.ctx)
    os.close(fd)
    assert rep["rows"] == 1 and rep["locks"] == 0 and os.path.exists(f"{e.paths.locks}/job-{keep_recent}.lock")


def test_startup_recovery_survives_a_damaged_or_locked_log(privd_env):
    """privd comes up even when the agent's log is locked by a hostile agent process (the agent can lock its own audit.lock) or the priv log is damaged: the failure is reported, every
    mutating op is then denied DENY_AUDIT_DOWN, status still answers."""
    import fcntl
    e = privd_env.ready()
    fd = os.open(e.specs["agent"].lock, os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX)
    from forge_node.audit import spec as audit_spec
    old, audit_spec.LOCK_TIMEOUT_S = audit_spec.LOCK_TIMEOUT_S, 0.3
    import forge_node.audit.log as audit_log
    audit_log.LOCK_TIMEOUT_S = 0.3
    try:
        rep = reconcile.recover_all(e.ctx)
    finally:
        audit_log.LOCK_TIMEOUT_S = old
        audit_spec.LOCK_TIMEOUT_S = old
        os.close(fd)
    assert "agent" in rep["audit_errors"] and "priv" not in rep["audit_errors"] and "lock busy" in rep["audit_errors"]["agent"]
    os.unlink(f"{e.specs['priv'].dir}/CURRENT")
    rep = reconcile.recover_all(e.ctx)
    assert "priv" in rep["audit_errors"]
    r = e.exec(dry_run=True)[0]
    assert (r.get("code") or result(r)["reason_code"]) == "DENY_AUDIT_DOWN"
    assert e.call("status", {}, uid=AGENT_UID)["ok"] is True


def test_leftover_work_directory_of_a_dead_handler_does_not_fail_the_job_for_good(privd_env):
    """privd died after creating the attempt's work directory and before the ledger said `started`: the next delivery rebuilds it (no worker can exist for a `received` row)."""
    import uuid
    e = privd_env.ready()
    env, job = e.job_env(dry_run=True)
    jid = job["job_id"]
    e.ledger.claim(jid, 1, "selftest.noop", "selftest.noop", __import__("forge_node.canon", fromlist=["x"]).digest(job["params"]), True, "meta", e.clock())
    wd = Path(e.paths.work) / f"{jid}-1"
    wd.mkdir(mode=0o700)
    (wd / "request.json").write_text("{half written")
    (wd / "junk").write_text("x")
    assert result(e.call("exec", {"job": env}))["status"] == "dry_run"
    assert e.ledger.get(jid).state == "committed" and not (wd / "junk").exists()
    # but a directory that is not a plain directory (a symlink planted there) is refused
    env2, job2 = e.job_env(dry_run=True)
    e.ledger.claim(job2["job_id"], 1, "selftest.noop", "selftest.noop", __import__("forge_node.canon", fromlist=["x"]).digest(job2["params"]), True, "meta", e.clock())
    os.symlink("/tmp", Path(e.paths.work) / f"{job2['job_id']}-1")
    r = result(e.call("exec", {"job": env2}))
    assert r["status"] == "failed" and r["reason_code"] == "FAIL_PRECHECK"


def test_privd_killed_between_started_and_the_unit_start_is_aborted_safe_and_retried_as_attempt_2(privd_env):
    """The window after `mark_started` and before `systemd-run`: the row says started, no unit exists. Startup recovery reconciles it (fence bump, nothing to stop, the probe sees no
    effect) to aborted_safe; the hub's re-delivery runs it as attempt 2 - one effect in total."""
    e = privd_env.ready()
    plan = result(e.exec(dry_run=True)[0])
    env, job = e.job_env(plan_hash=plan["plan_hash"])
    e.ctx.backend.start = lambda *a: (_ for _ in ()).throw(SystemExit("privd killed right here"))        # the process dies before the unit exists
    with pytest.raises(SystemExit):
        e.call("exec", {"job": env})
    row = e.ledger.get(job["job_id"])
    assert row.state == "started" and row.worker_invocation_id is None and not marks(e)
    fresh = e.restart()
    rep = reconcile.recover_all(fresh.ctx)
    assert rep["reconciled"] == [(job["job_id"], "aborted_safe")] and fresh.ledger.get(job["job_id"]).state == "aborted_safe"
    fresh.clock.advance(seconds=61)
    fresh.put_lease(seq=77)
    env2, _ = fresh.job_env(job_id=job["job_id"], plan_hash=plan["plan_hash"], delivery_seq=2)
    res = result(fresh.call("exec", {"job": env2}))
    assert res["status"] == "committed" and res["attempt"] == 2 and len(marks(e)) == 1
