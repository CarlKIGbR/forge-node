"""Gate D acceptance (Design "Gated features", D): audit sealing on a REAL filesystem (ext4, chattr +a/+i), live writer processes holding descriptors across the rotation, crash
recovery with a SIGKILL at every mutating system call of the rotation, and the structural proof that no log file is ever writable without a flag.

Named tests required by the gate: test_rotation_real_ext4_chattr_a_live_writer_descriptor_cannot_append_after_seal, test_seal_never_calls_chmod_on_append_only_inode,
test_rotation_crash_recovery_kill_at_every_step, test_rotation_has_no_writable_window_on_live_file (test_mutating_ops_denied_until_gate_d: tests/test_privd_gate.py)."""
import json
import os
import signal
import subprocess
import sys
import time

import pytest
from audit_helpers import AGENT_GID, AGENT_UID, NODE, Clock, admin, appender, check_no_unflagged_reachable_file, errno_of, in_child, make_specs, run_as_agent, tree_state

from forge_node import chain
from forge_node.audit import fsflags
from forge_node.audit.spec import AuditCorrupt, AuditDown


@pytest.fixture
def specs(realfs):
    return make_specs(realfs)


def live(spec, gen):
    return f"{spec.dir}/{spec.prefix}.{gen:06d}/{spec.prefix}.{gen:06d}.jsonl"


def recs(path):
    """Valid chain records only (a hostile writer's junk lines are skipped)."""
    out = []
    for x in open(path, "rb").read().split(b"\n"):
        try:
            r = json.loads(x)
        except ValueError:
            continue
        if isinstance(r, dict) and "hash" in r:
            out.append(r)
    return out


def flags_of(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        return fsflags.get_flags(fd)
    finally:
        os.close(fd)


# -------------------------------------------------------------------------------------------------------------------- the seal itself
def test_rotation_real_ext4_chattr_a_live_writer_descriptor_cannot_append_after_seal(specs):
    """Live writer PROCESSES (agent uid, agent log) hold O_APPEND descriptors on the live file across the rotation, plus a cooperative Appender in each. After the seal nobody can add
    a byte to the old file - through the old descriptor, through a fresh open, or as root - while the cooperative writers continue in the new file."""
    s = specs["agent"]
    a = admin(s)
    a.init()
    a.append("t0", {"before": True})
    old = live(s, 1)
    n_writers = 3
    chans = []
    pids = []
    for i in range(n_writers):
        up_r, up_w = os.pipe()
        dn_r, dn_w = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.setgroups([AGENT_GID]); os.setgid(AGENT_GID); os.setuid(AGENT_UID)
                ap = appender(s)
                ap.append("relay", {"writer": i, "phase": "before"})
                fd = os.open(old, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)      # a descriptor that outlives the rotation
                os.write(up_w, b"r")
                os.read(dn_r, 1)                                                  # parent: rotation done
                forged = errno_of(lambda: os.write(fd, b'{"forged":"after the seal"}\n'))
                fresh = errno_of(lambda: os.close(os.open(old, os.O_WRONLY | os.O_APPEND)))
                rec = ap.append("relay", {"writer": i, "phase": "after"})        # the cooperative path continues in the NEW file
                os.write(up_w, bytes([forged or 0, fresh or 0]) + str(rec["seq"]).encode())
                os._exit(0)
            except BaseException as e:  # noqa: BLE001
                os.write(up_w, b"E" + repr(e).encode())
                os._exit(4)
        chans.append((up_r, dn_w))
        pids.append(pid)
    for up_r, _ in chans:
        assert os.read(up_r, 1) == b"r"
    size_before = os.path.getsize(old)
    assert a.rotate() == 2
    sealed_size = os.path.getsize(old)
    assert sealed_size >= size_before
    for _, dn_w in chans:
        os.write(dn_w, b"g")
    results = [os.read(up_r, 64) for up_r, _ in chans]
    for pid in pids:
        assert os.waitpid(pid, 0)[1] == 0
    for r in results:
        assert not r.startswith(b"E"), r
        assert r[0] == 1 and r[1] == 1, r                                       # EPERM, EPERM
    assert os.path.getsize(old) == sealed_size and b"forged" not in open(old, "rb").read()
    # root cannot append to it either, and the flags are exactly +a +i
    assert errno_of(lambda: os.close(os.open(old, os.O_WRONLY | os.O_APPEND))) == 1
    assert fsflags.is_sealed(flags_of(old))
    assert fsflags.is_live(flags_of(live(s, 2)))
    assert a.verify() == []
    new = recs(live(s, 2))
    assert new[0]["type"] == "chain_link" and sum(1 for r in new if r.get("phase") == "after") == n_writers
    check_no_unflagged_reachable_file(s.dir)


def test_seal_never_calls_chmod_on_append_only_inode(specs, monkeypatch):
    """The kernel refuses chmod/chown/truncate on an append-only inode (EPERM) and the design's old step 4 (`fchmod 0440`) is superseded. Spy on every call that could change mode,
    owner, size or times and fail if its target carries +a at the time of the call - across init, appends, a rotation, recovery and a purge."""
    from datetime import timedelta
    calls = []
    real = {n: getattr(os, n) for n in ("chmod", "fchmod", "chown", "fchown", "truncate", "ftruncate", "utime")}

    def flags_for(target, dir_fd=None):
        try:
            if isinstance(target, int):
                return fsflags.get_flags(target)
            fd = real_open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd) if dir_fd is not None else real_open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                return fsflags.get_flags(fd)
            finally:
                os.close(fd)
        except OSError:
            return 0
    real_open = os.open

    def spy(name):
        def f(target, *a, **k):
            fl = flags_for(target, k.get("dir_fd"))
            calls.append((name, target if not isinstance(target, int) else f"fd:{target}", fl))
            assert not fl & (fsflags.APPEND | fsflags.IMMUTABLE), f"{name} on an append-only/immutable inode: {target}"
            return real[name](target, *a, **k)
        return f
    for n in real:
        monkeypatch.setattr(os, n, spy(n))
    s = specs["priv"]
    a = admin(s)
    a.init()
    for i in range(3):
        a.append("t0", {"i": i})
    a.rotate()
    a.append("t0", {})
    a.rotate()
    a.append("t0", {})
    a.recover()
    a.purge(10 ** 6, Clock()() + timedelta(days=200))
    assert a.verify() == []
    assert calls, "the spy saw no mode/owner/size change at all: it is not wired"
    # and statically: the audit package never changes mode/owner/size by PATH, only on descriptors of objects it has just created (unflagged) or on directories
    src = open(os.path.join(os.path.dirname(fsflags.__file__), "log.py")).read()
    for banned in ("os.chmod(", "os.chown(", "os.truncate(", "os.ftruncate(", "os.utime("):
        assert banned not in src, banned


def test_kernel_refuses_mode_owner_size_changes_on_the_sealed_and_the_live_file(specs):
    s = specs["priv"]
    a = admin(s)
    a.init()
    live1 = live(s, 1)
    for target in (live1,):
        assert errno_of(lambda: os.chmod(target, 0o440)) == 1
        assert errno_of(lambda: os.chown(target, 0, 0)) == 1
        assert errno_of(lambda: os.truncate(target, 0)) == 1
    a.rotate()
    assert errno_of(lambda: os.chmod(live1, 0o440)) == 1
    assert errno_of(lambda: os.truncate(live1, 0)) == 1
    assert errno_of(lambda: os.unlink(live1)) == 1
    assert errno_of(lambda: os.rename(live1, live1 + ".x")) == 1


def test_a_descriptor_opened_before_the_append_flag_would_stay_writable_so_new_files_are_unreachable_until_flagged(specs):
    """The reason for the 0700 generation directory (documented kernel behaviour, observed here): without it an agent could hold a plain O_WRONLY descriptor from before +a."""
    s = specs["agent"]
    admin(s).init()
    d = f"{s.dir}/probe"
    os.mkdir(d, 0o755)
    f = f"{d}/f"
    open(f, "wb").write(b"0123456789")
    os.chmod(f, 0o666)
    plain = os.open(f, os.O_WRONLY)
    fd = os.open(f, os.O_RDONLY)
    fsflags.add_flags(fd, fsflags.APPEND)
    assert os.pwrite(plain, b"X", 0) == 1                      # +a does NOT stop it (permissions and the flag are checked at open())
    fsflags.add_flags(fd, fsflags.IMMUTABLE)
    assert errno_of(lambda: os.pwrite(plain, b"Y", 0)) == 1    # +i does
    fsflags.clear_flags(fd, fsflags.APPEND | fsflags.IMMUTABLE)
    os.close(fd)
    os.close(plain)
    # and the protocol never hands out such a descriptor: see test_rotation_has_no_writable_window_on_live_file


def test_rotation_has_no_writable_window_on_live_file(specs):
    """(1) Structural: after every single mutating system call of a rotation (SIGKILL there), every log file that exists is +a, and a file without +a exists only inside a root-only
    generation directory. (2) Behavioural: an agent-uid process hammers the directory with open-for-write attempts (O_WRONLY with and without O_APPEND) during rotations; the only
    successful open is O_APPEND on a +a file, and no write ever lands in a sealed file."""
    s = specs["agent"]
    a = admin(s)
    a.init()
    a.append("t0", {})
    probe = _scenario(specs, "wprobe")
    killed, total, log = in_child(lambda: admin(probe).rotate())
    assert not killed and total > 8
    for k in range(1, total + 1):
        for when in ("before", "after"):
            sub = _scenario(specs, f"w{k}{when}")
            kd, _, _ = in_child(lambda: admin(sub).rotate(), kill_at=k, when=when)
            assert kd
            check_no_unflagged_reachable_file(sub.dir)
    # (2) concurrent hostile opener
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        os.setgroups([AGENT_GID]); os.setgid(AGENT_GID); os.setuid(AGENT_UID)
        bad = 0
        n = 0
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            n += 1
            try:
                gens = sorted(g for g in os.listdir(s.dir) if g.startswith("audit."))
            except OSError:
                continue
            for g in gens:
                p = f"{s.dir}/{g}/{g}.jsonl"
                for flags in (os.O_WRONLY, os.O_RDWR, os.O_WRONLY | os.O_TRUNC):
                    try:
                        fd = os.open(p, flags)
                    except OSError:
                        continue
                    bad += 1                                      # a successful non-append write open at ANY time is a window
                    os.close(fd)
                try:
                    fd = os.open(p, os.O_WRONLY | os.O_APPEND)
                except OSError:
                    continue
                try:
                    os.write(fd, b'{"forged":1}\n')
                except OSError:
                    pass
                os.close(fd)
        os.write(w, json.dumps({"bad": bad, "n": n}).encode())
        os._exit(0)
    os.close(w)
    for _ in range(25):
        a.append("t0", {})
        a.rotate()
        time.sleep(0.05)
    out = json.loads(os.read(r, 100))
    os.waitpid(pid, 0)
    assert out["bad"] == 0 and out["n"] > 50, out
    # the forged lines the agent appended to the file while it was live are DAMAGE: the next append accounted for them with a tail_repair record, and nothing else is wrong
    a.append("t0", {})
    assert a.verify() == []
    accounted = [r for g in range(1, 60) if os.path.exists(live(s, g)) for r in recs(live(s, g))
                 if r.get("type") == "tail_repair" or r.get("prev_damaged_bytes")]
    assert accounted, "the hostile appends were neither repaired nor accounted for by a chain_link"


# ---------------------------------------------------------------------------------------------------------------------- crash recovery
def _scenario(specs, name, appends=2):
    sub = make_specs(os.path.join(os.path.dirname(specs["priv"].dir), name), max_file_bytes=10 ** 7)["priv"]
    a = admin(sub)
    a.init()
    for i in range(appends):
        a.append("t0", {"i": i})
    a.close()
    return sub


def _check_recovered(sub, *, expect_gen_at_least=1):
    r = admin(sub)
    actions = r.recover()
    assert r.verify() == [], r.verify()
    # idempotent: a second recovery finds nothing to do and appends nothing
    head = r.head()
    assert r.recover() == []
    assert r.head() == head
    check_no_unflagged_reachable_file(sub.dir)
    cur = r._read_current()
    assert cur >= expect_gen_at_least
    # exactly one live file, every older one sealed
    for e in tree_state(sub.dir):
        gen = int(e["gen"].split(".")[1])
        assert fsflags.is_live(e["flags"]) if gen == cur else fsflags.is_sealed(e["flags"]), e
        assert e["dir_mode"] == sub.dir_mode
    # the log works again and the chain continues across everything that happened
    rec = r.append("t0", {"after": "recovery"})
    assert rec["seq"] == head[0] + 1
    assert r.verify() == []
    return actions, cur


def test_rotation_crash_recovery_kill_at_every_step(specs):
    """SIGKILL the rotating process before AND after every mutating system call (mkdir, create, write, fsync, fchmod, fchown, rename, unlink, rmdir, flag ioctl). From each of those
    states: (a) an Appender never writes into a sealed file and never breaks the chain, (b) recovery rolls the rotation forward idempotently and records what it did, (c) the log
    verifies and keeps working."""
    probe = _scenario(specs, "probe")
    killed, total, calls = in_child(lambda: admin(probe).rotate())
    assert not killed and total >= 14, (total, calls)
    seen_states = set()
    for k in range(1, total + 1):
        for when in ("before", "after"):
            sub = _scenario(specs, f"k{k}{when}")
            before_head = admin(sub).head()
            kd, _, _ = in_child(lambda: admin(sub).rotate(), kill_at=k, when=when)
            assert kd, (k, when)
            check_no_unflagged_reachable_file(sub.dir)
            # (a) an unprivileged writer in whatever state the crash left
            st = tree_state(sub.dir)
            try:
                ap = appender(sub)
                try:
                    rec = ap.append("t0", {"during": "crash-state"})
                    outcome = "append-ok"
                    # it must have gone into a live file, never into a sealed one
                    for e in tree_state(sub.dir):
                        if e["flags"] is not None and fsflags.is_sealed(e["flags"]) and e["gen"].endswith("1"):
                            assert recs(f"{sub.dir}/{e['gen']}/{e['file']}")[-1]["seq"] <= before_head[0]
                except AuditDown:
                    outcome = "append-refused"
                ap.close()
            except AuditDown:
                outcome = "append-refused"
            seen_states.add((tuple(sorted((e["gen"], (e["flags"] or 0) & 0x30, e["dir_mode"]) for e in st)), outcome))
            # (b)+(c)
            switched_already = admin(sub)._read_current() == 2
            actions, cur = _check_recovered(sub)
            rolled = any(e["gen"].endswith("2") for e in tree_state(sub.dir))
            if rolled:
                assert cur == 2
                if switched_already:
                    assert not actions, (k, when, actions)                 # killed after CURRENT was switched: nothing left to do
                else:
                    assert actions, (k, when)
                    last = [r for r in recs(live(sub, 2)) if r["type"] == "recovery"]
                    assert last and last[-1]["actions"] == actions
            else:
                assert cur == 1 and all("CURRENT.tmp" in x for x in actions), actions       # killed before the seal: the old file is simply still live
    # the sweep really visited the interesting states
    assert len(seen_states) >= 6, seen_states


def test_recovery_itself_is_crash_safe(specs):
    """Kill the recovery of a rotation that was interrupted at several points, before and after EVERY system call of the recovery; recover again; the result is the consistent log."""
    probe = _scenario(specs, "rprobe")
    _, total, _ = in_child(lambda: admin(probe).rotate())
    points = sorted({3, total // 3, total // 2, (2 * total) // 3, total - 1})
    visited = 0
    for k in points:
        for when in ("before", "after"):
            j = 1
            while True:
                base = _scenario(specs, f"r{k}{when}{j}")
                kd, _, _ = in_child(lambda: admin(base).rotate(), kill_at=k, when="after")
                assert kd
                killed, n, _ = in_child(lambda: admin(base).recover(), kill_at=j, when=when)
                if not killed:
                    break                                                     # the recovery has fewer than j calls: every call has been covered
                visited += 1
                check_no_unflagged_reachable_file(base.dir)
                _check_recovered(base)
                j += 1
                assert j < 80
    assert visited >= 20, visited


def test_crash_state_with_torn_new_file_is_rebuilt(specs):
    """A half-written chain_link in the (unreachable, unflagged) successor file is removed and rebuilt, not trusted."""
    sub = _scenario(specs, "torn-successor")
    a = admin(sub)
    a.close()
    # find the call index of the write of the new file's chain_link and kill right after a partial write is not possible with the syscall hook, so build the state by hand:
    # seal generation 1, create generation 2 with a torn first line
    fd = os.open(live(sub, 1), os.O_RDONLY)
    fsflags.add_flags(fd, fsflags.IMMUTABLE)
    os.close(fd)
    os.mkdir(f"{sub.dir}/priv.000002", 0o700)
    open(f"{sub.dir}/priv.000002/priv.000002.jsonl", "wb").write(b'{"fmt":1,"ts":"2026')
    os.chmod(f"{sub.dir}/priv.000002/priv.000002.jsonl", 0o640)
    os.chown(f"{sub.dir}/priv.000002/priv.000002.jsonl", 0, AGENT_GID)
    r = admin(sub)
    actions = r.recover()
    assert any("incomplete successor file" in x for x in actions), actions
    assert r.verify() == [] and r._read_current() == 2


def test_successor_that_does_not_match_the_sealed_predecessor_is_quarantined(specs):
    sub = _scenario(specs, "mismatch")
    admin(sub).close()
    fd = os.open(live(sub, 1), os.O_RDONLY)
    fsflags.add_flags(fd, fsflags.IMMUTABLE)
    os.close(fd)
    # a perfectly valid-looking generation 2 that continues from a DIFFERENT head
    other = _scenario(specs, "other-log")
    a_other = admin(other)
    a_other.append("t0", {"x": 1})
    a_other.rotate()
    os.rename(f"{other.dir}/priv.000002", f"{sub.dir}/priv.000002")
    with pytest.raises(AuditCorrupt):
        admin(sub).recover()


def test_live_file_with_a_successor_or_unsealed_predecessor_is_corrupt(specs):
    sub = _scenario(specs, "live-successor")
    os.mkdir(f"{sub.dir}/priv.000002", 0o700)
    with pytest.raises(AuditCorrupt):
        admin(sub).recover()


def test_missing_append_flag_on_the_active_file_is_set_by_recovery(specs):
    sub = _scenario(specs, "noflag")
    a = admin(sub)
    f = live(sub, 1)
    fd = os.open(f, os.O_RDONLY)
    fsflags.clear_flags(fd, fsflags.APPEND)
    os.close(fd)
    with pytest.raises(AuditDown):
        appender(sub).append("t0", {})                                      # an Appender cannot and must not fix it
    actions = a.recover()
    assert any("append-only flag" in x for x in actions)
    assert fsflags.is_live(flags_of(f))
    assert a.verify() == []


def test_sealed_active_file_after_a_crash_is_never_appended_by_the_appender(specs):
    sub = _scenario(specs, "sealed-active")
    f = live(sub, 1)
    fd = os.open(f, os.O_RDONLY)
    fsflags.add_flags(fd, fsflags.IMMUTABLE)
    os.close(fd)
    size = os.path.getsize(f)
    with pytest.raises(AuditDown):
        appender(sub).append("t0", {})
    assert os.path.getsize(f) == size
    admin(sub).recover()
    assert appender(sub).append("t0", {})["seq"] > 3
