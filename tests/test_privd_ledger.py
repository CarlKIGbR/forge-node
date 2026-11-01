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


def test_unconfirmable_worker_death_is_indeterminate_and_locks_the_target(privd_env, fifo, monkeypatch):
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


def test_crash_midway_probe_unknown_and_opaque_are_indeterminate(privd_env):
    """A worker that died without status.json whose probe cannot tell (unknown/partial), and an `opaque` op that crashed at all: never retried automatically, the target is locked."""
    import uuid
    e = privd_env.ready()
    entry = e.table.get("selftest.noop")
    for name, repl in (("unknown", dict(probe=lambda wd: "unknown")), ("partial", dict(probe=lambda wd: "partial")), ("opaque", dict(idempotency="opaque", probe=None))):
        e.ctx.optable = optable_mod.OpTable([dataclasses.replace(entry, **repl)])
        jid = str(uuid.uuid4())
        e.ledger.claim(jid, 1, "selftest.noop", "selftest.noop", "0" * 64, False, "meta", e.clock())
        wd = Path(e.paths.work) / f"{jid}-1"
        wd.mkdir(mode=0o700)
        e.ledger.mark_started(jid, 1, op_unit_name(jid, 1), str(wd), None, None, False, e.clock())          # the unit never existed / is gone
        kind, res = reconcile.reconcile_job(e.ctx, jid)
        assert kind == "indeterminate" and res["reason_code"] == "INDETERMINATE", name
        assert e.ledger.get(jid).state == "indeterminate" and e.ledger.target_lock("selftest.noop")["job_id"] == jid
        recs = [r for r in e.priv_records() if r.get("job_id") == jid]
        assert [r["type"] for r in recs] == ["recovery"] and recs[0]["verdict"] == "indeterminate"
        e.ledger.unlock_target("selftest.noop", jid)


def test_delegated_effects_must_settle_before_any_probe(privd_env):
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
        e.ledger.mark_started(jid, 1, op_unit_name(jid, 1), str(wd), None, None, False, e.clock())
        kind, _ = reconcile.reconcile_job(e.ctx, jid)
        assert kind == expect
        e.ledger.unlock_target("selftest.noop", jid)
    assert calls == [("settle", False), ("settle", True), ("probe",)]                     # no probe ran for the unsettled one


def test_orphan_op_unit_without_row_is_stopped_and_recorded(privd_env, tmp_path):
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


def test_terminal_denial_does_not_allow_a_new_delivery_retryable_does(privd_env):
    e = privd_env.ready()
    env, job = e.job_env(params={"bogus": 1}, dry_run=True)
    assert result(e.call("exec", {"job": env}))["reason_code"] == "DENY_PARAM"
    assert e.ledger.get(job["job_id"]).state == "denied"
    env2, _ = e.job_env(job_id=job["job_id"], params={"bogus": 1}, dry_run=True, delivery_seq=2)
    again = result(e.call("exec", {"job": env2}))
    assert again["reason_code"] == "DENY_PARAM" and again["audit_seq_range"] == result(e.call("exec", {"job": env}))["audit_seq_range"]      # the stored denial
    # retryable
    open(e.paths.local_stop, "w").close()
    env3, job3 = e.job_env(dry_run=True)
    assert result(e.call("exec", {"job": env3}))["reason_code"] == "DENY_LOCAL_STOP"
    assert e.ledger.get(job3["job_id"]).state == "denied_retryable"
    os.unlink(e.paths.local_stop)
    env4, _ = e.job_env(job_id=job3["job_id"], dry_run=True, delivery_seq=2)
    assert result(e.call("exec", {"job": env4}))["status"] == "dry_run"


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


def test_fence_mismatch_worker_exits_without_effect_unit(privd_env, tmp_path):
    """worker.run() on its own: row.fence != request.fence => FAIL_FENCED, nothing done, status.json says why."""
    from forge_node.privd import ops, worker
    e = privd_env
    import uuid
    jid = str(uuid.uuid4())
    e.ledger.claim(jid, 1, "selftest.noop", "k1", "0" * 64, False, "meta", e.clock())
    wd = Path(e.paths.work) / f"{jid}-1"
    wd.mkdir(mode=0o700)
    e.ledger.mark_started(jid, 1, op_unit_name(jid, 1), str(wd), None, None, False, e.clock())
    req = {"job_id": jid, "attempt": 1, "fence": 1, "op": "selftest.noop", "params": {"note": ""}, "dry_run": False, "plan_hash": None, "effect_key": "k1", "ledger_path": e.paths.ledger,
           "lock_dir": e.paths.locks, "priv_state": e.paths.priv_state}
    (wd / "request.json").write_text(json.dumps(req))
    os.chmod(wd / "request.json", 0o600)
    e.ledger.begin_reconcile(jid, e.clock())                                              # fence 2
    assert worker.run(str(wd), ops.EFFECTS, owner_uid=0) == 0
    st = worker.read_status(str(wd))
    assert st["outcome"] == "fenced" and st["code"] == "FAIL_FENCED" and not (wd / "effect.mark").exists()
    # a worker for a row that is not `started`, or an unknown row, is fenced too
    req["fence"] = 2
    (wd / "request.json").write_text(json.dumps(req))
    os.unlink(wd / "status.json")
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
