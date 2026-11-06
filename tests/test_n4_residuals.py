"""M-110: the eight named residuals of the N3 report ('Round 3'). For each one either a fix with a test (B7, B10, and the findings of the independent review of the round-3 code) or a test
that SHOWS no non-root uid gains a privileged effect (A4, A7, A8). B8 and B9 are M-108 / M-109 (tests/test_n4.py). The table is in docs/reports/N4_REPORT.md."""
import ast
import errno
import fcntl
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
from audit_helpers import AGENT_GID, AGENT_UID, NODE, admin, appender, make_specs, run_as_agent
from privd_helpers import SRC
from test_n4 import _switch_env, docs  # noqa: F401
from test_release import env, mkey  # noqa: F401

from forge_node.audit import fsflags
from forge_node.audit.spec import AuditDown
from forge_node.release import switcher
from forge_node.release.switcher import UNITS_START, UNITS_STOP

SRC_ROOT = Path(SRC) / "forge_node"


# ============================================================================================================= residual 1 (A4): the purge window
def test_a4_a_descriptor_reopened_for_writing_in_the_purge_window_has_no_lasting_or_path_visible_effect(realfs, monkeypatch):
    """The window between 'flags cleared' and unlinkat of a purge cannot be closed from the code. What is shown here is what a non-root uid GAINS from it: it can write into the inode that
    is being deleted (hub-acknowledged data, >= 90 days old, removed one instruction later) and nothing else - the inode ends with no name, the directory is root-owned so it cannot be given
    a new one (linkat from /proc/self/fd fails), the surviving chain verifies, and the live file is untouched."""
    from datetime import timedelta
    from audit_helpers import Clock
    sub = make_specs(os.path.join(realfs, "a4"), max_file_bytes=10 ** 7)["agent"]
    a = admin(sub)
    a.init()
    for _ in range(4):
        a.append("t0", {})
        a.rotate()
    a.append("t0", {})
    gen1 = f"{sub.dir}/{sub.prefix}.000001/{sub.prefix}.000001.jsonl"
    held = os.open(gen1, os.O_RDONLY)                                       # the descriptor a hostile agent-uid process collected before the purge (the agent log is group-readable)
    seen = {}
    real = fsflags.clear_flags

    def clear_then_probe(fd, mask):
        real(fd, mask)
        if os.fstat(fd).st_ino == os.fstat(held).st_ino:
            def probe():
                out = {}
                try:
                    w = os.open(f"/proc/self/fd/{held}", os.O_WRONLY)
                    os.write(w, b"HOSTILE")
                    out["write"] = "possible"                                # the residual itself
                except OSError as e:
                    out["write"] = errno.errorcode[e.errno]
                try:
                    os.link(f"/proc/self/fd/{held}", f"{sub.dir}/stolen", follow_symlinks=True)
                    out["link"] = "possible"
                except OSError as e:
                    out["link"] = errno.errorcode[e.errno]
                return out
            seen.update(run_as_agent(probe))
    monkeypatch.setattr(fsflags, "clear_flags", clear_then_probe)
    removed = a.purge(a.head()[0], Clock()() + timedelta(days=200))
    monkeypatch.undo()
    assert removed and seen["link"] != "possible", seen                      # (the errno differs by kernel/mount: EXDEV here; the structural reason is the next line)
    st = os.stat(sub.dir)
    assert st.st_uid == 0 and not st.st_mode & 0o022                         # the log directory is root-owned and not writable by the agent uid: it can never give the inode a name
    assert not os.path.exists(gen1) and not os.path.exists(f"{sub.dir}/stolen")
    assert os.fstat(held).st_nlink == 0                                     # whatever was written went into an inode that has no name any more
    after = os.open(f"/proc/self/fd/{held}", os.O_WRONLY) if seen["write"] == "possible" else None
    if after is not None:
        os.close(after)
    assert not os.path.exists(gen1)                                         # and writing again does not bring it back
    assert a.verify() == [] and not [x for x in os.listdir(sub.dir) if x == "stolen"]
    os.close(held)


# ============================================================================================================= residual 2 (A7): the agent-writable ack file
def test_a7_no_privileged_component_reads_the_agent_writable_ack_file():
    """The ack file lives in the agent's state directory. Root-side code (privd, the audit writer/admin, the release switcher, privctl, doctor's privileged parts) must never take a value from it:
    `privctl audit-purge` gets its acknowledged sequences as arguments, read by the owner from the hub. A compromised agent can therefore only stop SHIPPING (the hub's audit_heads
    cross-check is the alarm), never influence what root purges, rotates or accepts."""
    for sub in ("privd", "audit", "release"):
        for f in (SRC_ROOT / sub).glob("*.py"):
            text = f.read_text()
            assert "audit-acks" not in text and "ACK_FILE" not in text and "shipper" not in text, f
            tree = ast.parse(text)
            for n in ast.walk(tree):
                if isinstance(n, (ast.Import, ast.ImportFrom)):
                    assert "shipper" not in (getattr(n, "module", "") or "") and not any("shipper" in a.name for a in n.names), f
    assert "audit-purge" in (SRC_ROOT / "privd" / "privctl.py").read_text()
    import inspect
    from forge_node.privd import privctl
    assert list(inspect.signature(privctl.Ctl.cmd_audit_purge).parameters)[1:] == ["acked_priv", "acked_agent"]       # arguments, not files


# ============================================================================================================= residual 3 (A8): hostile lock holder / capacity
def test_a8_a_hostile_flock_holder_makes_the_agent_log_fail_closed_and_does_not_touch_the_priv_log(realfs, monkeypatch):
    """A holder of the agent log's lock file (0660, its own file) blocks appends to THAT log: AuditDown (fail closed, nothing written, never a privileged effect). The priv log has its own
    root-only lock in a root-only directory: unaffected. When the holder goes away everything continues on an unbroken chain."""
    from forge_node.audit import log as auditlog
    specs = make_specs(os.path.join(realfs, "a8"))
    for k in ("priv", "agent"):
        admin(specs[k]).init()
    monkeypatch.setattr(auditlog, "LOCK_TIMEOUT_S", 0.5)
    r, w = os.pipe()
    ready_r, ready_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.setgroups([AGENT_GID])
        os.setgid(AGENT_GID)
        os.setuid(AGENT_UID)
        fd = os.open(specs["agent"].lock, os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(ready_w, b"x")
        os.read(r, 1)
        os._exit(0)
    assert os.read(ready_r, 1) == b"x"
    try:
        ap, pp = appender(specs["agent"]), appender(specs["priv"])
        with pytest.raises(AuditDown):
            ap.append("t0", {"n": 1})
        assert pp.append("t0", {"n": 1})["type"] == "t0"                    # the priv chain does not depend on anything the agent uid can hold
    finally:
        os.write(w, b"x")
        os.waitpid(pid, 0)
    monkeypatch.undo()
    rec = appender(specs["agent"]).append("t0", {"n": 2})
    assert rec["type"] == "t0" and admin(specs["agent"]).verify() == [] and admin(specs["priv"]).verify() == []


# ============================================================================================================= residual 4 (B7): lockdown during a switch
def test_b7_a_lockdown_during_the_switch_is_not_undone_by_the_switch(env):
    sw = _switch_env(env)
    env.on_doctor = lambda: env.local_stop.write_text("")                     # `privctl lockdown` runs while doctor is running (it can take minutes)
    assert sw.cmd_switch("0.3.1", False) == 3
    started = [c[1:] for c in env.calls if c[0] == "/usr/bin/systemctl" and c[1] in ("enable", "start") and c[2:] and "forge-node-agent.service" in c[2:]]
    assert started == [], started                                            # the agent and the timer were never enabled/started after the lockdown appeared
    assert [c[1:] for c in env.calls if c[0] == "/usr/bin/systemctl"][-2:] == [["stop", *UNITS_STOP], ["disable", *UNITS_START]]
    res = docs(env.out.getvalue())[-1]
    assert res["state"].startswith("LOCKDOWN") and env.local_stop.exists()


def test_b7_a_lockdown_that_appears_while_the_way_back_is_taken_also_wins(env):
    sw = _switch_env(env)
    env.doctor_script = [False, True]
    calls = {"n": 0}

    def lock_on_second():
        calls["n"] += 1
        if calls["n"] == 2:
            env.local_stop.write_text("")
    env.on_doctor = lock_on_second
    assert sw.cmd_switch("0.3.1", False) == 3
    assert not [c for c in env.calls if c[0] == "/usr/bin/systemctl" and c[1] == "start" and "forge-node-agent.service" in c[2:]]
    assert docs(env.out.getvalue())[-1]["state"].startswith("LOCKDOWN")


# ============================================================================================================= residual 7 (B10): doctor timeout
def test_b10_a_timeout_kills_the_whole_process_group_not_only_the_direct_child(tmp_path):
    pidfile = tmp_path / "grandchild.pid"
    script = f"sleep 300 & echo $! > {pidfile}; wait"
    rc, out, err = switcher.run_process(["/bin/sh", "-c", script], None, 1)
    assert rc == 124
    gpid = int(pidfile.read_text())
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            os.kill(gpid, 0)
            with open(f"/proc/{gpid}/stat") as f:
                if f.read().split(") ")[1][0] == "Z":
                    break
        except (ProcessLookupError, FileNotFoundError):
            break
        time.sleep(0.1)
    else:
        os.kill(gpid, signal.SIGKILL)
        pytest.fail("the grandchild of a timed-out command is still running")


def test_b10_the_doctor_timeout_covers_the_worst_case_of_paced_requests_and_hub_retries(env):
    from forge_node import doctor as D
    worst_pacing = 14 * D.PACE_S + sum(D.HUB_5XX_BACKOFF_S) + (len(D.HUB_5XX_BACKOFF_S) + 1) * 15.0
    assert switcher.DOCTOR_TIMEOUT_S >= 10 * worst_pacing
    sw = _switch_env(env)
    seen = []
    orig = env.run
    env.switcher_run = lambda argv, stdin, timeout: (seen.append(timeout) if "doctor" in argv else None) or orig(argv, stdin, timeout)
    assert env.switcher(run=env.switcher_run).cmd_switch("0.3.1", False) == 0
    assert seen == [switcher.DOCTOR_TIMEOUT_S]
    env.release("0.3.2", "full")
    env.doctor_script = [None]
    assert switcher.DOCTOR_TIMEOUT_S == 1800 and sw  # (the constant is the contract: a change must be a decision)


# ============================================================================================================= residual 8: findings of the independent review of the round-3 code
def _fake_systemctl(env, *, active=(), stop_rc=0):
    """Wrap env.run: `is-active <unit>` answers like systemd (stdout + rc), `stop` can be made to fail like a not-loaded unit."""
    orig = env.run

    def run(argv, stdin, timeout):
        if argv[0] == "/usr/bin/systemctl" and argv[1] == "is-active":
            env.calls.append(list(argv))
            up = argv[2] in active
            return (0, b"active\n", b"") if up else (3, b"inactive\n", b"")
        if argv[0] == "/usr/bin/systemctl" and argv[1] == "stop" and stop_rc:
            env.calls.append(list(argv))
            return stop_rc, b"", b"Failed to stop: Unit not loaded."
        return orig(argv, stdin, timeout)
    return run


def test_r8_a_refused_switch_restarts_only_what_was_running_before(env):
    """Review finding 1 (MAJOR): the pre-change refusal ran `start` on all three units - on a node left quiet by an earlier rc 3 that started the release that had failed."""
    sw = _switch_env(env)
    env.make_ledger(state="started")                                          # an op in flight: the switch is refused after the node was quiesced
    for active, want in (((), []), (("forge-node-agent.service",), [["start", "forge-node-agent.service"]])):
        env.calls.clear()
        sw2 = env.switcher(run=_fake_systemctl(env, active=active))
        with pytest.raises(switcher.Refused, match="not terminal"):
            sw2.cmd_switch("0.3.1", False)
        starts = [c[1:] for c in env.calls if c[0] == "/usr/bin/systemctl" and c[1] == "start"]
        assert starts == want, (active, starts)
    assert sw


def test_r8_a_node_left_quiet_by_an_earlier_rollback_failure_can_be_switched_again(env):
    """Review finding 2: `disable` removes the unit links, so the next switch's `stop` fails with 'not loaded'; that must not make the documented recovery ('fix, then switch') impossible."""
    sw = _switch_env(env)
    run = _fake_systemctl(env, active=(), stop_rc=5)
    assert env.switcher(run=run).cmd_switch("0.3.1", False) == 0 and os.readlink(env.base / "current") == "releases/0.3.1"
    # ... but a stop that fails while a unit is (or may be) active stays a refusal: no 'inactive' answer, no switch
    env.release("0.3.2", "full")
    env.calls.clear()
    run2 = _fake_systemctl(env, active=("forge-node-privd.service",), stop_rc=1)
    with pytest.raises(switcher.Refused, match="quiesced"):
        env.switcher(run=run2).cmd_switch("0.3.2", False)
    assert sw


def test_r8_a_dead_stdout_does_not_change_the_verdict_and_an_oserror_in_the_stop_path_is_reported(env):
    """Review findings 4 and 5: BrokenPipe on the report turned rc 3 ('quiet node') into rc 1 ('restored'); an OSError from `run` escaped the stop/start helpers."""
    class Dead:
        def write(self, _):
            raise BrokenPipeError(errno.EPIPE, "pipe")
    sw = _switch_env(env)
    env.doctor_ok = False
    orig = env.run

    def run(argv, stdin, timeout):
        if argv[0] == "/usr/bin/systemctl" and argv[1] == "disable":
            raise OSError(errno.EAGAIN, "cannot fork")
        return orig(argv, stdin, timeout)
    sw2 = env.switcher(run=run, out=Dead())
    assert sw2.cmd_switch("0.3.1", False) in (1, 3)                          # no traceback; the rollback path ran to its end with a dead stdout
    env.doctor_ok = True
    assert sw


def test_r8_tail_repair_terminates_a_tail_that_a_hostile_writer_extended_three_times(realfs, monkeypatch):
    """Review finding (audit, MINOR): the repair loop wrote its newline up to MAX_TERMINATE_TRIES times and never looked after the last write, so a tail that WAS terminated by the last
    newline still raised AuditDown. A hostile uid extending the tail right after each of our first three newlines must not make the repair give up."""
    from test_audit_review import append_raw, live

    from forge_node.audit import log as auditlog
    spec = make_specs(os.path.join(realfs, "tr"))["agent"]
    admin(spec).init()
    ap = appender(spec)
    ap.append("t0", {"n": 1})
    append_raw(live(spec), b"HOSTILE")                                      # unterminated damage at the tail
    real, injected = auditlog._write_all, [0]

    def write_then_extend(fd, data):
        real(fd, data)
        if data == b"\n" and injected[0] < auditlog.MAX_TERMINATE_TRIES - 1:
            injected[0] += 1
            append_raw(live(spec), b"H")                                    # the tail is unterminated again
    monkeypatch.setattr(auditlog, "_write_all", write_then_extend)
    rec = ap.append("t0", {"n": 2})
    monkeypatch.undo()
    assert injected[0] == auditlog.MAX_TERMINATE_TRIES - 1 and rec["type"] == "t0"
    assert admin(spec).verify() == []
