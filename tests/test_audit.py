"""Audit log core (Design 8, gate D): single serialized writer, root-owned layout, chain, torn tails, hostile directory entries. Real ext4 with chattr +a / +i (conftest `realfs`)."""
import json
import os
import threading

import pytest
from audit_helpers import AGENT_GID, AGENT_UID, NODE, Clock, admin, appender, check_no_unflagged_reachable_file, errno_of, make_specs, run_as_agent, tree_state

from forge_node import canon, chain
from forge_node.audit import fsflags, fsproof
from forge_node.audit.scan import parse_record, tail_state, verify_file
from forge_node.audit.spec import AuditCorrupt, AuditDown, AuditNotInitialised


@pytest.fixture
def specs(realfs):
    return make_specs(realfs)


@pytest.fixture
def priv(specs):
    a = admin(specs["priv"])
    a.init()
    yield a
    a.close()


def live_path(spec, gen=1):
    return f"{spec.dir}/{spec.prefix}.{gen:06d}/{spec.prefix}.{gen:06d}.jsonl"


def records(path):
    return [json.loads(x) for x in open(path, "rb").read().split(b"\n") if x]


def test_fsproof_on_the_real_filesystem(realfs):
    rep = fsproof.prove(realfs)
    assert rep["ok"], rep
    assert rep["fstype"] == "ext4", rep["fstype"]
    assert rep["cleanup"] and os.listdir(realfs) == []
    got = {k: v["got"] for k, v in rep["checks"].items()}
    # the facts the protocol rests on
    assert got["fresh_open_for_write_without_append_refused"] == got["chmod_refused"] == got["sealed_append_via_old_append_descriptor_refused"] == 1
    assert rep["checks"]["preexisting_nonappend_descriptor_can_still_overwrite"]["got"] is True       # why a file is never reachable before +a


def test_init_creates_genesis_chain_link_with_owner_modes_and_flags(specs, priv):
    s = specs["priv"]
    assert priv.init() == 1                                                # idempotent
    f = live_path(s)
    st = os.stat(f)
    assert (st.st_uid, st.st_gid, st.st_mode & 0o7777) == (0, AGENT_GID, 0o640)
    d = os.stat(os.path.dirname(f))
    assert (d.st_uid, d.st_mode & 0o7777) == (0, 0o750)
    cur = os.stat(f"{s.dir}/CURRENT")
    assert (cur.st_uid, cur.st_gid, cur.st_mode & 0o7777) == (0, AGENT_GID, 0o644)
    assert canon.loads(open(f"{s.dir}/CURRENT", "rb").read().rstrip(b"\n")) == {"dir": "priv.000001", "file": "priv.000001.jsonl", "fmt": 1, "gen": 1}
    lk = os.stat(s.lock)
    assert (lk.st_uid, lk.st_mode & 0o7777) == (0, 0o600)
    (r,) = records(f)
    assert r["type"] == "chain_link" and r["seq"] == 1 and r["prev_hash"] == chain.GENESIS_HASH and r["prev_file"] is None and r["gen"] == 1
    fd = os.open(f, os.O_RDONLY)
    try:
        assert fsflags.is_live(fsflags.get_flags(fd))
    finally:
        os.close(fd)
    assert priv.verify() == []


def test_append_chain_is_gapless_and_validated(specs, priv):
    for i in range(5):
        priv.append("intent", {"job_id": "0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b", "attempt": i + 1, "op": "selftest.noop"})
    rs = records(live_path(specs["priv"]))
    assert [r["seq"] for r in rs] == [1, 2, 3, 4, 5, 6]
    assert chain.verify_chain(rs) == []
    assert priv.head() == (6, rs[-1]["hash"])
    with pytest.raises(ValueError):
        priv.append("intent", {"seq": 99})
    with pytest.raises(chain.RecordError):
        priv.append("not-a-type-for-priv", {})              # the source's type set is enforced at write time
    assert len(records(live_path(specs["priv"]))) == 6


def test_uninitialised_log_is_audit_down_not_created_by_the_appender(specs):
    # an Appender refuses to create its own lock/CURRENT: with no lock file it cannot even be constructed
    with pytest.raises(AuditDown):
        appender(specs["priv"])
    adm = admin(specs["priv"])
    with pytest.raises(AuditNotInitialised):
        adm.append("t0", {})
    adm.init()
    a2 = appender(specs["priv"])
    a2.append("t0", {"x": 1})
    assert a2.head()[0] == 2


def test_appender_open_is_fail_closed_on_wrong_owner_mode_or_untrusted_directory(specs, priv):
    s = specs["priv"]
    a = appender(s)
    a.append("t0", {})
    a.close()
    os.chmod(s.dir, 0o770)                                                 # group-writable log directory
    with pytest.raises(AuditDown):
        appender(s)
    os.chmod(s.dir, 0o750)
    os.chown(os.path.dirname(s.dir), AGENT_UID, 0)                        # agent-owned parent in the privileged path
    with pytest.raises(AuditDown):
        appender(s)
    os.chown(os.path.dirname(s.dir), 0, 0)
    os.chmod(s.lock, 0o666)
    with pytest.raises(AuditDown):
        appender(s)
    os.chmod(s.lock, 0o600)
    appender(s).close()


def test_no_agent_owned_or_writable_directory_on_privileged_path(specs, priv):
    """Static walk of every directory the privileged writer touches (log directory, lock directory, generation directories): owned by root, not writable by group/others,
    from the file up to the trust anchor."""
    from forge_node.audit.log import trusted_chain
    for name in ("priv", "agent"):
        s = specs[name]
        admin(s).init()
        for p in (s.dir, os.path.dirname(s.lock)):
            assert trusted_chain(p, 0, s.trust_anchor), p
        for g in os.listdir(s.dir):
            gp = os.path.join(s.dir, g)
            if os.path.isdir(gp):
                st = os.stat(gp)
                assert st.st_uid == 0 and not st.st_mode & 0o022, gp
    # a single agent-owned or group-writable directory anywhere above is detected
    from forge_node.audit.log import trusted_chain as tc
    os.chmod(specs["priv"].dir, 0o775)
    assert not tc(specs["priv"].dir, 0, specs["priv"].trust_anchor)
    os.chmod(specs["priv"].dir, 0o750)
    assert not tc(specs["priv"].dir, 0, "/srv")                            # an anchor that is not an ancestor never validates


def test_concurrent_appends_unique_seq_and_unbroken_chain(specs, priv):
    """Many processes and threads, agent log and priv log: every seq exactly once, chain intact."""
    for name in ("priv", "agent"):
        s = specs[name]
        if name == "agent":
            admin(s).init()
        per_proc, procs, threads_n = 25, 4, 3
        pids = []
        for p in range(procs):
            pid = os.fork()
            if pid == 0:
                try:
                    if name == "agent":
                        os.setgroups([AGENT_GID]); os.setgid(AGENT_GID); os.setuid(AGENT_UID)
                    ap = appender(s)
                    ths = [threading.Thread(target=lambda: [ap.append("t0", {"p": p}) for _ in range(per_proc)]) for _ in range(threads_n)]
                    [t.start() for t in ths]
                    [t.join() for t in ths]
                    os._exit(0)
                except BaseException:  # noqa: BLE001
                    os._exit(3)
            pids.append(pid)
        assert [os.waitpid(p, 0)[1] for p in pids] == [0] * procs
        a = admin(s)
        assert a.verify() == []
        rs = records(live_path(s))
        assert [r["seq"] for r in rs] == list(range(1, procs * threads_n * per_proc + 2))
        assert chain.verify_chain(rs) == []


def test_second_writer_instance_cannot_allocate_same_seq_flock(specs, priv):
    """Writer A is parked inside its critical section (seq allocated, record not yet written); a second instance must wait on the flock, then continue the chain."""
    from g28_race import Interleaver, hook_before
    s = specs["priv"]
    a, b = appender(s), appender(s)
    il = Interleaver()
    hook_before(a, "_emit", il, "A.before_write", only_thread="A")
    il.start("A", lambda: a.append("t0", {"who": "A"}))
    il.wait_parked("A.before_write")
    il.start("B", lambda: b.append("t0", {"who": "B"}))
    # B cannot finish while A holds the lock (B polls the flock; give it the chance to try)
    assert il._threads["B"].is_alive() or il.error("B") is not None
    assert threading.active_count() >= 2
    il.release("A.before_write")
    ra, rb = il.join("A"), il.join("B")
    assert {ra["seq"], rb["seq"]} == {2, 3} and ra["seq"] != rb["seq"]
    assert chain.verify_chain(records(live_path(s))) == []
    # the lock itself: while A holds it, a non-blocking flock from a third descriptor fails
    import fcntl
    fd = os.open(s.lock, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def test_head_cache_revalidated_by_inode_and_size(specs, priv):
    s = specs["priv"]
    a, b = appender(s), appender(s)
    a.append("t0", {"n": 1})
    b.append("t0", {"n": 2})                                               # another writer moved the head behind a's cache
    r = a.append("t0", {"n": 3})
    assert r["seq"] == 4                                                   # a re-scanned the tail (size changed) instead of reusing seq 3
    assert chain.verify_chain(records(live_path(s))) == []
    # the cache is also dropped when the file is replaced by rotation (new inode)
    priv.rotate()
    r2 = a.append("t0", {"n": 4})
    assert r2["seq"] == 6 and records(live_path(s, 2))[0]["type"] == "chain_link"      # 1 genesis + 3 appends (t0, t0) ... + chain_link + this one
    assert priv.verify() == []


def test_torn_tail_gets_tail_repair_marker_chain_continues(specs, priv):
    s = specs["priv"]
    a = appender(s)
    a.append("t0", {"n": 1})
    f = live_path(s)
    # a crash in the middle of a write: part of a line, no newline (written as the fixture's O_APPEND descriptor would)
    fd = os.open(f, os.O_WRONLY | os.O_APPEND)
    os.write(fd, b'{"fmt":1,"ts":"2026-10-31T13:40:10Z","node":"g2","seq":3,"ty')
    os.close(fd)
    size_damaged = os.path.getsize(f)
    r = a.append("t0", {"n": 2})
    assert r["seq"] == 4                                                   # seq 3 = tail_repair
    raw = open(f, "rb").read()
    assert raw[:size_damaged].endswith(b'"ty')                              # nothing was rewritten or truncated
    lines = [ln for ln in raw.split(b"\n") if ln]
    tr = [json.loads(ln) for ln in lines if b'"tail_repair"' in ln][0]
    import hashlib
    assert tr["inserted_newline"] is True and tr["bytes"] == len(b'{"fmt":1,"ts":"2026-10-31T13:40:10Z","node":"g2","seq":3,"ty')
    assert tr["sha256"] == hashlib.sha256(b'{"fmt":1,"ts":"2026-10-31T13:40:10Z","node":"g2","seq":3,"ty').hexdigest()
    assert priv.verify() == []                                             # every byte is accounted for
    # a hostile writer appends whole junk lines to its own log: the same mechanism covers it
    fd = os.open(f, os.O_WRONLY | os.O_APPEND)
    os.write(fd, b"garbage line\nmore garbage\n")
    os.close(fd)
    assert any("damaged" in p for p in priv.verify())
    r2 = a.append("t0", {"n": 3})
    assert r2["seq"] == 6
    assert priv.verify() == []
    tr2 = [json.loads(ln) for ln in open(f, "rb").read().split(b"\n") if b'"tail_repair"' in ln][1]
    assert tr2["inserted_newline"] is False and tr2["bytes"] == len(b"garbage line\nmore garbage\n")


def test_missing_result_gets_recovery_record_not_rewrite(specs, priv):
    """Design 8.4: nothing is rewritten; a `recovery` record is appended after the intent."""
    job = "0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b"
    priv.append("intent", {"job_id": job, "attempt": 1})
    before = open(live_path(specs["priv"]), "rb").read()
    priv.append("recovery", {"job_id": job, "attempt": 1, "verdict": "aborted_safe"})
    after = open(live_path(specs["priv"]), "rb").read()
    assert after.startswith(before) and len(after) > len(before)


def test_agent_log_accepts_recovery_and_refuses_priv_only_types(specs):
    a = admin(specs["agent"])
    a.init()
    a.append("recovery", {"actions": ["x"]})
    with pytest.raises(chain.RecordError):
        a.append("intent", {})


# ------------------------------------------------------------------------------------------------------------ hostile agent
def test_log_directories_and_lock_files_not_replaceable_by_agent(specs):
    for name in ("priv", "agent"):
        s = specs[name]
        a = admin(s)
        a.init()
        a.append("t0", {})
        gen = f"{s.dir}/{s.prefix}.000001"
        f = f"{gen}/{s.prefix}.000001.jsonl"

        def attempts():
            e = {}
            e["create_in_dir"] = errno_of(lambda: os.close(os.open(f"{s.dir}/evil", os.O_CREAT | os.O_WRONLY, 0o600)))
            e["mkdir_in_dir"] = errno_of(lambda: os.mkdir(f"{s.dir}/evil", 0o700))
            e["symlink_in_dir"] = errno_of(lambda: os.symlink("/etc/passwd", f"{s.dir}/evil"))
            e["rename_current"] = errno_of(lambda: os.rename(f"{s.dir}/CURRENT", f"{s.dir}/CURRENT.old"))
            e["unlink_current"] = errno_of(lambda: os.unlink(f"{s.dir}/CURRENT"))
            e["write_current"] = errno_of(lambda: os.close(os.open(f"{s.dir}/CURRENT", os.O_WRONLY)))
            e["create_in_gen"] = errno_of(lambda: os.close(os.open(f"{gen}/evil", os.O_CREAT | os.O_WRONLY, 0o600)))
            e["rename_live_file"] = errno_of(lambda: os.rename(f, f + ".x"))
            e["unlink_live_file"] = errno_of(lambda: os.unlink(f))
            e["hardlink_live_file"] = errno_of(lambda: os.link(f, f"{s.dir}/evil"))
            e["truncate_live_file"] = errno_of(lambda: os.truncate(f, 0))
            e["chmod_live_file"] = errno_of(lambda: os.chmod(f, 0o666))
            e["open_nonappend"] = errno_of(lambda: os.close(os.open(f, os.O_WRONLY)))
            e["lock_unlink"] = errno_of(lambda: os.unlink(s.lock))
            e["lock_rename"] = errno_of(lambda: os.rename(s.lock, s.lock + ".x"))
            return e
        got = run_as_agent(attempts)
        for k, v in got.items():
            assert v is not None, f"{name}: agent succeeded at {k}"
        assert admin(s).verify() == []


def test_sealed_file_not_writable_by_agent(specs):
    s = specs["agent"]
    a = admin(s)
    a.init()
    a.append("t0", {})
    old = live_path(s)

    def holder():
        fd = os.open(old, os.O_WRONLY | os.O_APPEND)                       # the agent's legitimate descriptor on the live file
        return fd
    # hold the descriptor in the SAME forked child across the rotation using pipes
    r1, w1 = os.pipe()
    r2, w2 = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.setgroups([AGENT_GID]); os.setgid(AGENT_GID); os.setuid(AGENT_UID)
        fd = os.open(old, os.O_WRONLY | os.O_APPEND)
        os.write(fd, b"")                                                  # works while live
        os.write(w1, b"r")
        os.read(r2, 1)
        res = errno_of(lambda: os.write(fd, b"forged after the seal\n"))
        res2 = errno_of(lambda: os.close(os.open(old, os.O_WRONLY | os.O_APPEND)))
        os.write(w1, bytes([res or 0, res2 or 0]))
        os._exit(0)
    os.read(r1, 1)
    a.rotate()
    os.write(w2, b"g")
    out = os.read(r1, 2)
    os.waitpid(pid, 0)
    assert out == bytes([1, 1])                                            # EPERM both through the old descriptor and through a fresh open
    assert admin(s).verify() == []
    assert b"forged" not in open(old, "rb").read()


def test_rotation_hostile_entry_replacement_rename_unlink_symlink_hardlink_fails_chain_intact(specs):
    s = specs["agent"]
    a = admin(s)
    a.init()
    a.append("t0", {})
    barrier = []

    def hostile():
        # tries to plant things where rotation will create/replace files; every attempt must fail
        e = {}
        e["pre_create_next_gen_dir"] = errno_of(lambda: os.mkdir(f"{s.dir}/{s.prefix}.000002", 0o755))
        e["pre_plant_symlink_gen"] = errno_of(lambda: os.symlink("/tmp", f"{s.dir}/{s.prefix}.000002"))
        e["pre_plant_current_tmp"] = errno_of(lambda: os.close(os.open(f"{s.dir}/CURRENT.tmp", os.O_CREAT | os.O_WRONLY, 0o666)))
        return e
    got = run_as_agent(hostile)
    assert all(v is not None for v in got.values()), got
    a.rotate()
    assert a.verify() == []
    assert records(live_path(s, 2))[0]["type"] == "chain_link"


def test_rotation_first_record_is_chain_link_continuing_hash(specs, priv):
    s = specs["priv"]
    for i in range(3):
        priv.append("t0", {"i": i})
    old = records(live_path(s))
    import hashlib
    assert priv.rotate() == 2
    new = records(live_path(s, 2))
    first = new[0]
    assert first["type"] == "chain_link" and first["seq"] == len(old) + 1 and first["prev_hash"] == old[-1]["hash"]
    assert first["prev_file"] == "priv.000001/priv.000001.jsonl" and first["prev_seq"] == len(old)
    assert first["prev_file_sha256"] == hashlib.sha256(open(live_path(s), "rb").read()).hexdigest()
    assert first["prev_file_bytes"] == os.path.getsize(live_path(s)) and first["prev_damaged_bytes"] == 0
    priv.append("t0", {"i": 9})
    assert priv.verify() == []
    assert chain.verify_chain(old + new) == []
    # old file sealed, new file live
    for g, want in ((1, "sealed"), (2, "live")):
        fd = os.open(live_path(s, g), os.O_RDONLY)
        try:
            fl = fsflags.get_flags(fd)
            assert (fsflags.is_sealed(fl) if want == "sealed" else fsflags.is_live(fl)), (g, hex(fl))
        finally:
            os.close(fd)


def test_current_pointing_at_file_without_chain_link_quarantines(specs, priv):
    s = specs["priv"]
    priv.append("t0", {})
    # hand-craft a "generation 2" whose file has no chain_link and make CURRENT point at it (what tampering by root would look like)
    gdir = f"{s.dir}/priv.000002"
    os.mkdir(gdir, 0o750)
    open(f"{gdir}/priv.000002.jsonl", "wb").write(b'{"not":"a record"}\n')
    os.chmod(f"{gdir}/priv.000002.jsonl", 0o640)
    os.chown(f"{gdir}/priv.000002.jsonl", 0, AGENT_GID)
    fd = os.open(f"{gdir}/priv.000002.jsonl", os.O_RDONLY)
    fsflags.add_flags(fd, fsflags.APPEND)
    os.close(fd)
    open(f"{s.dir}/CURRENT.tmp", "wb").write(canon.canonical({"fmt": 1, "gen": 2, "dir": "priv.000002", "file": "priv.000002.jsonl"}) + b"\n")
    os.chmod(f"{s.dir}/CURRENT.tmp", 0o644)
    os.chown(f"{s.dir}/CURRENT.tmp", 0, AGENT_GID)
    os.rename(f"{s.dir}/CURRENT.tmp", f"{s.dir}/CURRENT")
    for who in (admin(s), appender(s)):
        with pytest.raises(AuditCorrupt):
            who.append("t0", {})
    with pytest.raises(AuditCorrupt):
        admin(s).recover()
    with pytest.raises(AuditCorrupt):
        admin(s).rotate()


def test_current_missing_or_forged_is_corrupt_not_silently_reinitialised(specs, priv):
    s = specs["priv"]
    os.unlink(f"{s.dir}/CURRENT")
    with pytest.raises(AuditCorrupt):
        admin(s).recover()
    with pytest.raises(AuditNotInitialised):
        appender(s).append("t0", {})
    open(f"{s.dir}/CURRENT", "wb").write(b'{"gen":1}\n')
    os.chmod(f"{s.dir}/CURRENT", 0o644)
    with pytest.raises(AuditCorrupt):
        admin(s).recover()


def test_purge_refuses_unacked_rotated_files(specs, priv):
    from datetime import timedelta
    s = specs["priv"]
    for _ in range(3):
        priv.append("t0", {})
        priv.rotate()
    now = Clock()() + timedelta(days=100)
    assert priv.purge(acked_seq=0, now=now) == []                         # nothing acknowledged
    last_seq_gen1 = records(live_path(s, 1))[-1]["seq"]
    assert priv.purge(acked_seq=last_seq_gen1 - 1, now=now) == []        # acknowledged short of the file's last seq
    young = Clock()()
    assert priv.purge(acked_seq=10 ** 6, now=young) == []                # acknowledged but younger than 90 days
    removed = priv.purge(acked_seq=10 ** 6, now=now)
    assert removed == ["priv.000001", "priv.000002"]                      # never the active generation (4) nor its direct predecessor (3)
    assert sorted(x for x in os.listdir(s.dir) if x.startswith("priv.")) == ["priv.000003", "priv.000004"]
    assert priv.verify() == []                                            # the chain continues from the oldest remaining file
    for bad in (-1, True, "5"):
        with pytest.raises(ValueError):
            priv.purge(acked_seq=bad, now=now)


def test_rotation_due_by_size(realfs):
    specs = make_specs(realfs, max_file_bytes=2000)
    a = admin(specs["priv"])
    a.init()
    assert not a.due()
    for _ in range(10):
        a.append("t0", {"pad": "x" * 100})
    assert a.due()
    a.rotate()
    assert not a.due()
