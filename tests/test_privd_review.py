"""privd: the cases an independent review found (socket exhaustion, raising hooks, unit-start uncertainty, orphan detection, selfcheck)."""
import dataclasses
import json
import os
import socket
import threading
import time
import uuid
from pathlib import Path

import pytest
from audit_helpers import AGENT_GID, AGENT_UID, run_as_agent
from privd_helpers import PrivdEnv

from forge_node import canon
from forge_node.privd import optable as optable_mod
from forge_node.privd import reconcile, server as server_mod
from forge_node.privd.server import Server, listen
from forge_node.privd.units import UnitMaybeStarted, op_unit_name


def result(r):
    assert r["ok"] is True and "result" in r, r
    return r["result"]


def waitfor(cond, what, timeout=15.0):
    t_end = time.monotonic() + timeout
    while time.monotonic() < t_end:
        if cond():
            return
        time.sleep(0.02)
    raise AssertionError(f"timeout waiting for {what}")


@pytest.fixture
def serve(privd_env, monkeypatch):
    started = []

    def make(**consts):
        for k, v in consts.items():
            monkeypatch.setattr(server_mod, k, v)
        e = privd_env.ready()
        sock = listen(e.paths.socket, AGENT_GID)
        srv = Server(e.ctx)
        t = threading.Thread(target=srv.serve, args=(sock,), daemon=True)
        t.start()
        started.append((srv, t, sock))
        return e, srv
    yield make
    for srv, t, sock in started:
        srv.stop()
        t.join(5)
        sock.close()


def _status_call(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(path)
    s.sendall(canon.canonical({"req": "status"}) + b"\n")
    buf = b""
    while not buf.endswith(b"\n"):
        c = s.recv(65536)
        if not c:
            break
        buf += c
    s.close()
    return json.loads(buf)


# --------------------------------------------------------------------------------------------------------------------------------- socket
def test_a_trickling_client_is_cut_off_at_the_overall_deadline(serve):
    """Review M4: one byte every 0.3 s kept a connection (and its slot) alive for ever when the timeout applied per recv()."""
    e, srv = serve(READ_TIMEOUT_S=0.8)

    def trickle():
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(e.paths.socket)
        t0 = time.monotonic()
        for _ in range(30):
            try:
                s.send(b" ")
                time.sleep(0.3)
                s.settimeout(0.01)
                try:
                    if s.recv(1) == b"":
                        return time.monotonic() - t0
                except socket.timeout:
                    pass
            except (BrokenPipeError, ConnectionResetError):
                return time.monotonic() - t0
        return 99.0
    took = run_as_agent(trickle)
    assert took < 2.5, took
    waitfor(lambda: srv._sems["agent"]._value == server_mod.AGENT_CONNECTIONS, "the slot to be released")


def test_root_still_has_a_slot_when_the_agent_uid_has_used_all_of_its_own(serve):
    e, srv = serve(AGENT_CONNECTIONS=2, ROOT_CONNECTIONS=1)
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:                                                                             # the agent uid: holds two idle connections, then asks for a third
        os.close(r)
        os.setgroups([AGENT_GID])
        os.setgid(AGENT_GID)
        os.setuid(AGENT_UID)
        held = []
        for _ in range(2):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(e.paths.socket)
            held.append(s)
        time.sleep(0.2)
        third = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        third.settimeout(3)
        third.connect(e.paths.socket)
        os.write(w, third.recv(4096))
        os.write(w, b"|")
        os.close(w)
        time.sleep(3)
        os._exit(0)
    os.close(w)
    got = b""
    while not got.endswith(b"|"):
        got += os.read(r, 4096)
    assert b"too many connections" in got
    st = _status_call(e.paths.socket)                                                         # root (this process) is served although the agent pool is full
    assert st["ok"] is True
    os.kill(pid, 9)
    os.waitpid(pid, 0)


def test_a_client_that_does_not_read_its_reply_cannot_pin_a_thread(serve, monkeypatch):
    e, srv = serve(SEND_TIMEOUT_S=0.5)
    monkeypatch.setattr(Server, "dispatch", lambda self, line, peer: b"x" * (16 * 1024 * 1024) + b"\n")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(e.paths.socket)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    s.sendall(canon.canonical({"req": "status"}) + b"\n")                                      # ... and never reads
    waitfor(lambda: srv._sems["root"]._value == server_mod.ROOT_CONNECTIONS, "the stuck sender to be released", 10)
    s.close()


def test_the_agents_junk_requests_do_not_use_up_roots_budget(privd_env):
    """Review M4: the buckets are per caller uid."""
    e = privd_env.ready()
    for _ in range(32):
        e.call("policy.apply", {"policy_b64": "anVuaw==", "sig": "x"}, uid=AGENT_UID)
        e.call("reconcile", {"job_id": str(uuid.uuid4())}, uid=AGENT_UID)
    assert e.call("policy.apply", {"policy_b64": "anVuaw==", "sig": "x"}, uid=AGENT_UID)["code"] == "DENY_RATE"
    assert e.call("reconcile", {"job_id": str(uuid.uuid4())}, uid=AGENT_UID)["code"] == "DENY_RATE"
    r = e.install(serial=5, t1_ops=[{"op": "selftest.noop", "mode": "enforce"}])
    assert r["ok"], r                                                                         # root's revocation path is unaffected
    assert e.call("reconcile", {"job_id": str(uuid.uuid4())})["ok"] is True


# --------------------------------------------------------------------------------------------------------------------- reconcile hooks
def _interrupted(e, **entry_changes):
    e.ctx.optable = optable_mod.OpTable([dataclasses.replace(e.table.get("selftest.noop"), **entry_changes)])
    jid = str(uuid.uuid4())
    e.ledger.claim(jid, 1, "selftest.noop", "selftest.noop", "0" * 64, False, "meta", e.clock())
    wd = Path(e.paths.work) / f"{jid}-1"
    wd.mkdir(mode=0o700)
    e.ledger.mark_started(jid, 1, op_unit_name(jid, 1), str(wd), None, None, False, False, e.clock())
    return jid


def test_a_probe_that_raises_makes_the_job_indeterminate_not_stuck_in_reconciling(privd_env):
    def boom(wd):
        raise RuntimeError("probe exploded")
    e = privd_env.ready()
    jid = _interrupted(e, probe=boom)
    kind, res = reconcile.reconcile_job(e.ctx, jid)
    assert kind == "indeterminate" and e.ledger.get(jid).state == "indeterminate"
    assert e.ledger.target_lock("selftest.noop")["job_id"] == jid
    assert e.ledger.busy_with_other("some-other-job") is None                            # a `reconciling` row would have blocked every mutating op of the node


def test_a_settle_hook_that_raises_makes_the_job_indeterminate(privd_env):
    def boom(wd):
        raise OSError("cannot look")
    e = privd_env.ready()
    jid = _interrupted(e, settle=boom)
    kind, _ = reconcile.reconcile_job(e.ctx, jid)
    assert kind == "indeterminate" and e.ledger.get(jid).state == "indeterminate"


def test_a_probe_answering_nonsense_is_unknown(privd_env):
    e = privd_env.ready()
    jid = _interrupted(e, probe=lambda wd: "applied-ish")
    assert reconcile.reconcile_job(e.ctx, jid)[0] == "indeterminate"


# ------------------------------------------------------------------------------------------------------------------ unit start uncertainty
def test_a_start_that_may_have_happened_is_neither_failed_nor_denied_and_ends_committed(privd_env):
    """Review M6: systemd-run answered ambiguously (timeout / no InvocationID yet). The unit DID start; the job must not be recorded as failed."""
    e = privd_env.ready()
    real = e.backend.start

    def start_then_doubt(*a):
        real(*a)
        raise UnitMaybeStarted("systemd-run timed out")
    e.backend.start = start_then_doubt
    r, job = e.exec(dry_run=True)
    assert r == {"ok": True, "in_progress": True, "job_id": job["job_id"]}, r
    waitfor(lambda: e.ledger.get(job["job_id"]).state == "committed", "the monitor to commit the job from the worker's status")
    assert e.types(job["job_id"]) == ["intent", "result"]


def test_a_start_that_never_happened_is_a_clean_failure(privd_env):
    from forge_node.privd.units import UnitError
    e = privd_env.ready()
    e.backend.start = lambda *a: (_ for _ in ()).throw(UnitError("systemd-run failed"))
    r, job = e.exec(dry_run=True)
    assert result(r)["status"] == "failed" and result(r)["reason_code"] == "FAIL_EXEC"


# ---------------------------------------------------------------------------------------------------------------------------- orphans
def test_the_failed_unit_of_a_finished_job_is_not_an_orphan_after_a_restart(privd_env):
    e = privd_env.ready()
    r, job = e.exec(dry_run=True)
    assert result(r)["status"] == "dry_run"
    unit = op_unit_name(job["job_id"], 1)
    assert unit in e.backend.list_op_units()                                           # the unit of a terminal job is still around (no --collect)
    ghost = op_unit_name(str(uuid.uuid4()), 1)
    e.backend.start(ghost, {}, ["/bin/sleep", "30"])                                    # a unit nobody has a row for
    rep = reconcile.recover_all(e.ctx)
    assert rep["orphans"] == [ghost]
    assert not any(r.get("orphan_unit") == unit for r in e.priv_records())


# ---------------------------------------------------------------------------------------------------------------------------- selfcheck
def test_selfcheck_audit_reads_the_live_logs_and_leaves_no_trace_in_them(privd_env):
    e = privd_env.ready()
    before = {n: (os.listdir(spec.dir)) for n, spec in e.specs.items()}
    r = e.call("selfcheck", {"target": "audit"}, uid=AGENT_UID)
    assert r["ok"] and r["selfcheck"]["ok"], r
    live = r["selfcheck"]["detail"]["live"]
    assert live["priv"]["ok"] and live["agent"]["ok"]
    after = {n: (os.listdir(spec.dir)) for n, spec in e.specs.items()}
    assert before == after                                                             # no scratch directory left behind
    # a live log that cannot be appended to is reported
    for f in Path(e.specs["agent"].dir).glob("audit.*/audit.*.jsonl"):
        from forge_node.audit import fsflags
        fd = os.open(f, os.O_RDONLY)
        fsflags.add_flags(fd, fsflags.IMMUTABLE)
        os.close(fd)
    e.clock.advance(seconds=61)
    r = e.call("selfcheck", {"target": "audit"}, uid=AGENT_UID)
    assert r["ok"] and not r["selfcheck"]["ok"] and r["selfcheck"]["detail"]["live"]["agent"]["ok"] is False
    for f in Path(e.specs["agent"].dir).glob("audit.*/audit.*.jsonl"):
        fd = os.open(f, os.O_RDONLY)
        fsflags.clear_flags(fd, fsflags.IMMUTABLE)
        os.close(fd)


# ----------------------------------------------------------------------------------------------------------- G28: fresh evidence (policy)
def test_a_policy_change_between_started_and_the_unit_start_is_seen(privd_env):
    """Review: _fresh_stop_check re-read only LOCAL_STOP and the lease. A policy applied meanwhile that disables the op, makes it dry-run-only or revokes the hub gate key must stop the
    start of the (irreversible) unit."""
    from g28_race import Interleaver, hook_after
    e = privd_env.ready()
    starts = []
    real = e.backend.start
    e.backend.start = lambda *a: starts.append(a) or real(*a)
    good = [{"op": "selftest.noop", "mode": "enforce"}]
    other_key = [{"id": "hub-gate-2", "pub": e.gate_key["pub"], "not_after": "2099-12-31"}]
    cases = (("DENY_TIER_DISABLED", dict(t1_ops=[])),                                                       # the op is no longer enabled
             ("DENY_TIER_DISABLED", dict(t1_ops=[{"op": "selftest.noop", "mode": "dry_run_only"}])),         # the apply may only dry-run now
             ("DENY_STALE_LEASE", dict(t1_ops=good, gate_keys=other_key)))                                   # hub-gate-1 is revoked: the stored lease no longer verifies
    serial = 10
    for n, (code, change) in enumerate(cases):
        serial += 2
        e.clock.advance(seconds=61)
        assert e.install(serial=serial, t1_ops=good)["ok"] and e.put_lease(seq=100 + 10 * n)["ok"]
        plan = result(e.exec(dry_run=True)[0])
        e.clock.advance(seconds=61)
        assert e.put_lease(seq=105 + 10 * n)["ok"]
        il = Interleaver()
        hook_after(e.ledger, "mark_started", il, "A.started", only_thread="A")
        env, job = e.job_env(plan_hash=plan["plan_hash"])
        before = len(starts)
        il.start("A", lambda: e.call("exec", {"job": env}))
        il.wait_parked("A.started")
        r = e.install(serial=serial + 1, **change)
        assert r["ok"], r
        il.release("A.started")
        res = result(il.join("A"))
        del e.ledger.mark_started                                                                           # drop the instance hook again
        assert res["reason_code"] == code, (n, res)
        assert len(starts) == before, "the unit was started although the policy had changed"
        assert e.ledger.get(job["job_id"]).state in ("denied", "denied_retryable")
        serial += 1


def test_a_policy_installed_while_the_audit_log_was_down_is_recorded_late_and_shown_in_status(privd_env):
    e = privd_env.ready()
    real = e.ctx.audit
    broken = {"on": True}

    def flaky(type_, fields):
        if broken["on"] and type_ == "policy":
            from forge_node.privd.core import Deny
            raise Deny("DENY_AUDIT_DOWN", "down")
        return real(type_, fields)
    e.ctx.audit = flaky
    r = e.install(serial=5, t1_ops=[{"op": "selftest.noop", "mode": "enforce"}])
    assert r["ok"] and r["audit_seq"] is None
    assert e.call("status", {})["status"]["policy_audit_pending"] is True
    broken["on"] = False
    r = e.install(serial=6, t1_ops=[{"op": "selftest.noop", "mode": "enforce"}])
    assert r["ok"] and r["audit_seq"] is not None
    pol = [x for x in e.priv_records() if x["type"] == "policy" and x.get("action") == "apply"]
    assert [(x["serial"], x.get("late", False)) for x in pol][-2:] == [(5, True), (6, False)]
    assert e.call("status", {})["status"]["policy_audit_pending"] is False


def test_failures_of_the_op_itself_count_towards_the_circuit_not_only_worker_failures(privd_env):
    from forge_node.privd.units import UnitError
    e = privd_env.ready()
    e.backend.start = lambda *a: (_ for _ in ()).throw(UnitError("systemd-run failed"))
    for i in range(3):
        e.clock.advance(seconds=61)
        assert e.put_lease(seq=300 + i)["ok"]
        res = result(e.exec(dry_run=True)[0])
        assert res["reason_code"] == "FAIL_EXEC"
    assert e.ledger.circuit("selftest.noop")["state"] == "open"


def test_a_wall_clock_that_jumps_forward_does_not_make_a_live_worker_look_overdue(privd_env, monkeypatch):
    """Review: reconcile measured the worker's time budget with the wall clock; a step forward stopped a worker that was still inside its budget."""
    e = privd_env.ready()
    jid = str(uuid.uuid4())
    e.ledger.claim(jid, 1, "selftest.noop", "selftest.noop", "0" * 64, False, "meta", e.clock())
    wd = Path(e.paths.work) / f"{jid}-1"
    wd.mkdir(mode=0o700)
    unit = op_unit_name(jid, 1)
    e.ledger.mark_started(jid, 1, unit, str(wd), None, None, False, False, e.clock())
    inv = e.backend.start(unit, {}, ["/bin/sleep", "30"])
    e.ledger.set_invocation(jid, 1, inv, e.clock())
    e.ctx.worker_started[(jid, 1)] = e.ctx.monotonic()                                         # what s_effect records when THIS process started the unit
    e.clock.advance(seconds=3600)                                                              # NTP steps the wall clock an hour forward
    kind, _ = reconcile.reconcile_job(e.ctx, jid)
    assert kind == "in_progress" and e.backend.show(unit).is_active
    e.ctx.worker_started.pop((jid, 1))                                                         # a restarted privd has no monotonic reference: it falls back to the wall clock
    kind, _ = reconcile.reconcile_job(e.ctx, jid)
    assert kind != "in_progress"
    e.backend.stop(unit)
