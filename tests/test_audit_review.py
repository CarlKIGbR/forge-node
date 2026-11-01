"""Gate D, the cases an independent review found: forged records that rewind the chain, damage of any size, purge/init crash states, a sealed file that ends in a fragment,
the head cache against a writer that appends between our write and our look. Real ext4 (`realfs`)."""
import os

import pytest
from audit_helpers import NODE, Clock, admin, appender, check_no_unflagged_reachable_file, in_child, make_specs, tree_state
from test_audit_gate_d import _check_recovered, _scenario

from forge_node import canon, chain
from forge_node.audit import fsflags, reader
from forge_node.audit.log import AuditAdmin
from forge_node.audit.spec import AuditCorrupt, AuditDown


@pytest.fixture
def specs(realfs):
    return make_specs(realfs)


def live(spec, gen=1):
    return f"{spec.dir}/{spec.prefix}.{gen:06d}/{spec.prefix}.{gen:06d}.jsonl"


def append_raw(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_APPEND)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def read_chain(spec, after=0):
    cur = reader.start_cursor(spec.dir, spec.prefix, NODE, spec.source, after)
    assert cur is not None
    return reader.read_batch(spec.dir, spec.prefix, NODE, spec.source, cur, after, 10 ** 6)


def forged(seq, prev, type_="t0"):
    return canon.canonical(chain.seal_record({"ts": "2026-10-31T13:40:10Z", "node": NODE, "type": type_}, seq, prev)) + b"\n"


def file_records(path):
    """The parseable records of a file (junk lines skipped)."""
    out = []
    for ln in open(path, "rb").read().split(b"\n"):
        try:
            out.append(canon.loads(ln))
        except canon.CanonError:
            pass
    return out


def agent_log(specs, n=5):
    a = admin(specs["agent"])
    a.init()
    for i in range(n):
        a.append("t0", {"i": i})
    return a


# ----------------------------------------------------------------------------------------------------- forgeries cannot move the head
@pytest.mark.parametrize("cold", [False, True])
def test_a_forged_record_that_rewinds_the_chain_is_damage_not_the_head(specs, cold):
    """A record with seq = (an EARLIER record's seq) + 1 and prev_hash = that record's hash is valid-looking; it must not become the head."""
    s = specs["agent"]
    a = agent_log(specs)
    rs = file_records(live(s))
    assert [r["seq"] for r in rs] == [1, 2, 3, 4, 5, 6]
    append_raw(live(s), forged(rs[2]["seq"] + 1, rs[2]["hash"]))
    if cold:
        a.close()
        a = admin(s)
    r = a.append("t0", {"after": "forgery"})
    assert r["seq"] == 8 and r["prev_hash"] != rs[2]["hash"]                          # seq 7 = the tail_repair that names the forgery
    assert a.verify() == []
    shipped = read_chain(s)
    assert [x["seq"] for x in shipped] == list(range(1, 9)) and chain.verify_chain(shipped) == []
    r2 = a.append("t0", {})
    assert r2["seq"] == 9 and [x["seq"] for x in read_chain(s)] == list(range(1, 10))     # and shipping goes on, it does not stall


def test_an_invented_chain_of_two_records_cannot_take_the_head_either(specs):
    s = specs["agent"]
    a = agent_log(specs)
    fake1 = chain.seal_record({"ts": "2026-10-31T13:40:10Z", "node": NODE, "type": "t0"}, 5000, "a" * 64)
    fake2 = chain.seal_record({"ts": "2026-10-31T13:40:10Z", "node": NODE, "type": "t0"}, 5001, fake1["hash"])
    append_raw(live(s), canon.canonical(fake1) + b"\n" + canon.canonical(fake2) + b"\n")
    r = a.append("t0", {})
    assert r["seq"] == 8
    assert a.verify() == [] and [x["seq"] for x in read_chain(s)] == list(range(1, 9))


def test_a_forged_continuation_of_the_true_head_is_the_head_and_a_second_branch_is_damage(specs):
    """What a forger CAN do - append a valid next record - is indistinguishable from a legitimate writer by content; the chain stays gapless and verifiable, a rival branch is damage."""
    s = specs["agent"]
    a = agent_log(specs)
    head = a.head()
    append_raw(live(s), forged(head[0] + 1, head[1]))
    r = a.append("t0", {})
    assert r["seq"] == head[0] + 2
    assert a.verify() == []


# ----------------------------------------------------------------------------------------------------- damage of any size
@pytest.mark.parametrize("terminated", [True, False])
def test_megabytes_of_junk_neither_brick_the_log_nor_stop_rotation(specs, terminated):
    s = specs["agent"]
    a = agent_log(specs)
    junk = (b"x" * 4095 + b"\n") * 768 if terminated else b"y" * (3 * 1024 * 1024)
    append_raw(live(s), junk)
    r = a.append("t0", {"after": "junk"})
    tr = [x for x in file_records(live(s)) if x["type"] == "tail_repair"][0]
    assert tr["bytes"] == len(junk) and tr["inserted_newline"] is (not terminated)
    assert r["seq"] == tr["seq"] + 1
    assert a.rotate() == 2
    assert a.verify() == [] and a.recover() == []
    assert [x["seq"] for x in read_chain(s)] == list(range(1, r["seq"] + 2))               # + the chain_link of generation 2


@pytest.mark.parametrize("what", [b"y" * (3 * 1024 * 1024), b"x" * 100 + b"\n" + b'{"torn":', b'{"torn":'], ids=["huge-no-newline", "lines-then-fragment", "fragment"])
def test_damage_that_lands_between_the_repair_and_the_seal_is_described_by_the_chain_link_and_shipping_goes_on(specs, monkeypatch, what):
    s = specs["agent"]
    a = agent_log(specs)
    real = AuditAdmin._repair_tail_locked

    def repair_then_a_hostile_append(self):
        out = real(self)
        append_raw(live(s), what)                                                         # after the repair, before the seal: nobody has repaired this yet
        return out

    monkeypatch.setattr(AuditAdmin, "_repair_tail_locked", repair_then_a_hostile_append)
    assert a.rotate() == 2
    monkeypatch.undo()
    first = file_records(live(s, 2))[0]
    assert first["type"] == "chain_link" and first["prev_damaged_bytes"] == len(what)
    assert a.verify() == [] and a.recover() == []
    a.append("t0", {"in": 2})
    got = read_chain(s)
    assert [x["seq"] for x in got] == list(range(1, got[-1]["seq"] + 1)) and got[-1]["seq"] >= 8 and chain.verify_chain(got) == []        # the reader does not stall in generation 1


def test_a_sealed_file_ending_in_a_fragment_does_not_stall_the_reader_from_a_cursor(specs, monkeypatch):
    s = specs["agent"]
    a = agent_log(specs, 3)
    cur = reader.start_cursor(s.dir, s.prefix, NODE, s.source, 0)
    first = reader.read_batch(s.dir, s.prefix, NODE, s.source, cur, 0, 2)
    assert [x["seq"] for x in first] == [1, 2]
    real = AuditAdmin._repair_tail_locked
    monkeypatch.setattr(AuditAdmin, "_repair_tail_locked", lambda self: (real(self), append_raw(live(s), b'{"torn":'))[0])
    a.rotate()
    monkeypatch.undo()
    a.append("t0", {})
    rest = reader.read_batch(s.dir, s.prefix, NODE, s.source, cur, 0, 100)
    assert [x["seq"] for x in first + rest] == list(range(1, 7))


# ----------------------------------------------------------------------------------------------------- the head cache is not blind to a racing writer
def test_a_hostile_append_between_our_write_and_our_look_is_not_swallowed_into_the_cache(specs, monkeypatch):
    s = specs["agent"]
    a = agent_log(specs, 2)
    a.append("t0", {"warm": "cache"})
    real_fsync, armed = os.fsync, [False]

    def fsync_then_hostile(fd):
        real_fsync(fd)
        if armed[0]:
            armed[0] = False
            append_raw(live(s), b"HOSTILE\n")                                              # lands after our write, before our fstat

    monkeypatch.setattr(os, "fsync", fsync_then_hostile)
    armed[0] = True
    r1 = a.append("t0", {"n": 1})
    monkeypatch.undo()
    r2 = a.append("t0", {"n": 2})
    recs = file_records(live(s))
    tr = [x for x in recs if x["type"] == "tail_repair"]
    assert len(tr) == 1 and tr[0]["bytes"] == len(b"HOSTILE\n") and tr[0]["seq"] == r1["seq"] + 1 and r2["seq"] == r1["seq"] + 2
    assert a.verify() == []


# ----------------------------------------------------------------------------------------------------- purge is crash-safe
def _purge_scenario(specs, name):
    sub = make_specs(os.path.join(os.path.dirname(specs["priv"].dir), name), max_file_bytes=10 ** 7)["priv"]
    a = admin(sub)
    a.init()
    for _ in range(4):
        a.append("t0", {})
        a.rotate()
    a.append("t0", {})
    a.close()
    return sub


def test_purge_killed_at_every_step_is_recovered_and_never_leaves_a_writable_reachable_file(specs):
    from datetime import timedelta
    now = Clock()() + timedelta(days=200)
    probe = _purge_scenario(specs, "pprobe")
    phead = admin(probe).head()[0]
    killed, total, _ = in_child(lambda: admin(probe).purge(phead, now))
    assert not killed and total >= 6
    visited = 0
    for k in range(1, total + 1):
        for when in ("before", "after"):
            sub = _purge_scenario(specs, f"p{k}{when}")
            head = admin(sub).head()[0]
            kd, _, _ = in_child(lambda: admin(sub).purge(head, now), kill_at=k, when=when)
            assert kd
            visited += 1
            check_no_unflagged_reachable_file(sub.dir)                                   # a flagless file only ever sits in a root-only directory
            r = admin(sub)
            r.recover()
            r.purge(head, now)                                                          # the purge can be run again and finishes the job
            assert r.verify() == [], (k, when, r.verify())
            names = sorted(x for x in os.listdir(sub.dir) if x.startswith("priv."))
            assert names == ["priv.000004", "priv.000005"], (k, when, names)
            check_no_unflagged_reachable_file(sub.dir)
            for e in tree_state(sub.dir):
                assert e["dir_mode"] == sub.dir_mode and (fsflags.is_live(e["flags"]) if e["gen"].endswith("5") else fsflags.is_sealed(e["flags"])), (k, when, e)
            assert r.recover() == []
    assert visited >= 12


def test_a_purge_leftover_directory_does_not_break_verify_or_purge(specs):
    from datetime import timedelta
    now = Clock()() + timedelta(days=200)
    sub = _purge_scenario(specs, "leftover")
    a = admin(sub)
    head = a.head()[0]
    gdir = f"{sub.dir}/priv.000001"
    os.fchmod(os.open(gdir, os.O_RDONLY), 0o700)
    fd = os.open(f"{gdir}/priv.000001.jsonl", os.O_RDONLY)
    fsflags.clear_flags(fd, fsflags.APPEND | fsflags.IMMUTABLE)
    os.close(fd)
    os.unlink(f"{gdir}/priv.000001.jsonl")                                              # the state after "unlink, before rmdir"
    assert any("without a log file" in p for p in a.verify())                           # reported, not a traceback
    assert a.purge(head, now) == ["priv.000001", "priv.000002", "priv.000003"]
    assert a.verify() == []


def test_purge_refuses_an_acknowledgement_beyond_the_head_of_the_log(specs):
    from datetime import timedelta
    sub = _purge_scenario(specs, "typo")
    a = admin(sub)
    with pytest.raises(ValueError):
        a.purge(a.head()[0] + 1, Clock()() + timedelta(days=200))
    assert sorted(x for x in os.listdir(sub.dir) if x.startswith("priv."))[0] == "priv.000001"


# ----------------------------------------------------------------------------------------------------- init is crash-safe
def test_init_killed_at_every_step_is_finished_by_the_next_init(specs, realfs):
    probe = make_specs(os.path.join(realfs, "iprobe"))["priv"]
    killed, total, _ = in_child(lambda: admin(probe).init())
    assert not killed and total >= 15
    visited = 0
    for k in range(1, total + 1):
        for when in ("before", "after"):
            sub = make_specs(os.path.join(realfs, f"i{k}{when}"))["priv"]
            kd, _, _ = in_child(lambda: admin(sub).init(), kill_at=k, when=when)
            assert kd
            visited += 1
            check_no_unflagged_reachable_file(sub.dir)
            a = admin(sub)
            assert a.init() == 1
            assert a.verify() == [] and a.recover() == []
            assert a.append("t0", {})["seq"] == 2
            check_no_unflagged_reachable_file(sub.dir)
    assert visited >= 30


def test_init_never_adopts_a_used_log_whose_current_vanished(specs):
    sub = _scenario(specs, "used")
    os.unlink(f"{sub.dir}/CURRENT")
    with pytest.raises(AuditCorrupt):
        admin(sub).init()


# ----------------------------------------------------------------------------------------------------- rotation after an interrupted rotation
def test_rotate_after_an_interrupted_rotation_completes_it_and_does_not_rotate_again(specs):
    probe = _scenario(specs, "rr-probe")
    _, total, _ = in_child(lambda: admin(probe).rotate())
    for k in range(1, total + 1):
        sub = _scenario(specs, f"rr{k}")
        kd, _, _ = in_child(lambda: admin(sub).rotate(), kill_at=k, when="after")
        assert kd
        a = admin(sub)
        before = a._read_current()
        got = a.rotate()
        assert got == (2 if before == 1 else 3), (k, before, got)
        assert a.verify() == [], (k, a.verify())
        _check_recovered(sub)


def test_appender_is_unchanged_by_all_of_this(specs):
    """(guard) the unprivileged appender still refuses a sealed file and never repairs CURRENT."""
    s = specs["priv"]
    a = admin(s)
    a.init()
    a.append("t0", {})
    ap = appender(s)
    ap.append("t0", {})
    assert ap.head()[0] == 3
    ap.close()
    a.close()


# ----------------------------------------------------------------------------------------------------- the filesystem proof
def test_fsproof_covers_the_live_file_escape_routes_and_does_not_demand_the_kernels_weak_behaviour(realfs):
    from forge_node.audit import fsproof
    rep = fsproof.prove(realfs)
    assert rep["ok"] and rep["cleanup"], rep
    c = rep["checks"]
    for k in ("live_punch_hole_refused", "live_zero_range_refused", "live_collapse_range_refused", "live_insert_range_refused", "live_clear_o_append_then_overwrite_refused",
              "live_rwf_noappend_overwrite_refused"):
        assert c[k]["ok"] and c[k]["got"] == "refused", (k, c[k])                                  # on this ext4 the route EXISTS (the unflagged control performs it) and is refused when flagged
    for k in ("live_overwrite_via_pwrite_on_append_descriptor_leaves_the_bytes", "append_through_descriptor_opened_after_flag"):
        assert c[k]["ok"], (k, c[k])
    assert c["append_through_descriptor_opened_before_flag"]["expected"] == "informational"            # a stricter future kernel must not make doctor fail


def test_fsproof_fails_when_a_live_escape_route_works(realfs, monkeypatch):
    from forge_node.audit import fsproof
    monkeypatch.setattr(fsproof, "_fallocate", lambda *a: None)                                       # as if the kernel let every range operation through (the control succeeds too)
    rep = fsproof.prove(realfs)
    assert not rep["ok"] and not rep["checks"]["live_punch_hole_refused"]["ok"]


def test_fsproof_removes_the_canary_of_a_proof_that_was_killed(realfs):
    from forge_node.audit import fsproof
    def dying():
        fsproof.prove(realfs)
    real = fsproof._try
    n = [0]

    def killer(fn):
        n[0] += 1
        if n[0] == 6:
            os.kill(os.getpid(), 9)
        return real(fn)

    pid = os.fork()
    if pid == 0:
        fsproof._try = killer
        dying()
        os._exit(0)
    os.waitpid(pid, 0)
    left = [x for x in os.listdir(realfs) if x.startswith(".fsproof-")]
    assert left, "the killed proof left nothing behind: the test does not test anything"
    rep = fsproof.prove(realfs)
    assert rep["ok"] and os.listdir(realfs) == []


def test_a_damaged_tail_is_repaired_inside_the_file_before_the_seal_so_the_chain_link_has_nothing_to_describe(specs):
    """Rotation step 1 (design 8.3): the damage that exists when rotation starts gets its tail_repair record IN the old file; only damage that appears after that is described by the
    chain_link. (Both would verify - the difference is where the evidence lives.)"""
    s = specs["agent"]
    a = agent_log(specs)
    append_raw(live(s), b'{"torn":')
    assert a.rotate() == 2
    old = file_records(live(s, 1))
    assert old[-1]["type"] == "tail_repair" and old[-1]["bytes"] == len(b'{"torn":')
    link = file_records(live(s, 2))[0]
    assert link["type"] == "chain_link" and link["prev_damaged_bytes"] == 0 and link["prev_damaged_sha256"] is None and link["prev_seq"] == old[-1]["seq"]
    assert a.verify() == []


def test_recovery_never_deletes_an_unflagged_file_in_a_reachable_directory(specs):
    """Review (minor 3): on a filesystem with weaker ordering a crash could leave a REACHABLE generation directory around a file without +a - a hostile descriptor may exist. Recovery
    must quarantine, not unlink and rebuild (the only safe case for removal is the 0700 directory)."""
    s = specs["priv"]
    a = admin(s)
    a.init()
    a.append("t0", {})
    fd = os.open(live(s, 1), os.O_RDONLY)
    fsflags.add_flags(fd, fsflags.IMMUTABLE)                                  # generation 1 sealed, CURRENT still names it: "n sealed, n+1 …"
    os.close(fd)
    os.mkdir(f"{s.dir}/priv.000002", 0o750)
    os.chown(f"{s.dir}/priv.000002", 0, s.gid)
    open(live(s, 2), "wb").close()                                            # unflagged, empty (incomplete), in a directory the agent can traverse
    os.chmod(live(s, 2), 0o640)
    os.chown(live(s, 2), 0, s.gid)
    for _ in range(2):
        with pytest.raises(AuditCorrupt, match="reachable"):
            admin(s).recover()
        assert os.path.exists(live(s, 2))                                      # nothing was deleted
    # the same file in a 0700 directory is the ordinary crash state and is rebuilt
    os.chmod(f"{s.dir}/priv.000002", 0o700)
    assert any("rebuilt" in x or "removed the incomplete" in x or "built generation 2" in x for x in admin(s).recover())
    assert admin(s).verify() == []


# ----------------------------------------------------------------------------------------------------- round 2: the window BEFORE our write
def _hostile_before_the_write(monkeypatch, s, payload, skip=0):
    """Make `payload` land in the log file after the writer looked at the tail and before its write() (the `skip`-th write of the writer, 0 = the first)."""
    from forge_node.audit import log as audit_log
    real = audit_log._write_all
    fired = []
    count = []

    def hostile_then_real(fd, data):
        count.append(1)
        if not fired and len(count) > skip:
            fired.append(1)
            append_raw(live(s), payload() if callable(payload) else payload)
        return real(fd, data)
    monkeypatch.setattr(audit_log, "_write_all", hostile_then_real)
    return fired


@pytest.mark.parametrize("kind", ["valid-continuation", "fragment"])
def test_a_forged_head_that_wins_the_race_before_our_write_makes_the_append_fail_instead_of_losing_the_record(specs, monkeypatch, kind):
    """Round 2 (MAJOR): the O_APPEND write went after the forger's bytes, the writer cached its own record as the head and kept 'recording' records that were not in the chain. A valid
    forged continuation takes the head; an unterminated fragment merges with our line. Either way our record is not chained: AuditDown, nothing claimed, the retry works."""
    s = specs["agent"]
    a = agent_log(specs)
    head = a.head()
    payload = (lambda: forged(head[0] + 1, head[1])) if kind == "valid-continuation" else b'{"junk":'
    fired = _hostile_before_the_write(monkeypatch, s, payload)
    with pytest.raises(AuditDown, match="concurrent writer"):
        a.append("t0", {"lost": "race"})
    assert fired
    monkeypatch.undo()
    r = a.append("t0", {"after": "race"})
    shipped = read_chain(s)
    assert shipped[-1]["seq"] == r["seq"] and chain.verify_chain(shipped) == []
    assert a.head()[0] == r["seq"] == admin(s).head()[0]                                  # a warm and a cold writer agree on the head


def test_junk_before_our_write_does_not_fail_the_append_and_both_views_of_the_head_agree(specs, monkeypatch):
    s = specs["agent"]
    a = agent_log(specs)
    _hostile_before_the_write(monkeypatch, s, b"GARBAGE LINE\n")
    r = a.append("t0", {"x": 1})
    monkeypatch.undo()
    assert a.head()[0] == r["seq"] == admin(s).head()[0] and [x["seq"] for x in read_chain(s)][-1] == r["seq"]
    assert a.verify() == []                                                               # the agent log tolerates (and counts) bytes it did not write


def test_the_same_race_while_repairing_a_tail(specs, monkeypatch):
    """The torn tail is first terminated (write 1) and then accounted for (write 2). A forger who takes the repair record's chain position before write 2 lands: AuditDown, nothing claimed."""
    s = specs["agent"]
    a = agent_log(specs)
    append_raw(live(s), b'{"torn":')
    head = a.head()
    _hostile_before_the_write(monkeypatch, s, lambda: forged(head[0] + 1, head[1]), skip=1)
    with pytest.raises(AuditDown, match="concurrent writer"):
        a.append("t0", {"during": "repair"})
    monkeypatch.undo()
    r = a.append("t0", {"after": "repair"})
    assert [x["seq"] for x in read_chain(s)][-1] == r["seq"] and chain.verify_chain(read_chain(s)) == []


def test_a_forger_in_front_of_the_newline_that_terminates_a_torn_tail_is_followed_not_collided_with(specs, monkeypatch):
    """The forger wins the race against the terminating newline: its record becomes the head, the repair and our record continue IT; nothing is lost and the views agree."""
    s = specs["agent"]
    a = agent_log(specs)
    append_raw(live(s), b'{"torn":')
    head = a.head()
    _hostile_before_the_write(monkeypatch, s, lambda: b"\n" + forged(head[0] + 1, head[1]))
    r = a.append("t0", {"during": "repair"})
    monkeypatch.undo()
    assert a.head()[0] == r["seq"] == admin(s).head()[0] and [x["seq"] for x in read_chain(s)][-1] == r["seq"]
    assert chain.verify_chain(read_chain(s)) == [] and a.verify() == []


def test_a_valid_record_without_its_newline_does_not_fork_the_writer_from_the_readers(specs):
    """Round 3 (BLOCKER): a hostile agent-uid process appends a VALID continuation (seq N+1, prev = head) without its newline. The writer treated it as damage and wrote "\n" + tail_repair(N+1):
    the newline completed the forged line, so the forged record took N+1, the tail_repair and everything after it became damage to every cold reader, while the warm writer kept 'recording'.
    Now the newline is its own write, the chain is followed again, and the forged record IS the head the writer continues."""
    s = specs["agent"]
    a = agent_log(specs)
    head = a.head()
    forged_rec = forged(head[0] + 1, head[1])
    append_raw(live(s), forged_rec.rstrip(b"\n"))
    rs = [a.append("t0", {"n": i}) for i in range(3)]
    assert [r["seq"] for r in rs] == [head[0] + 2, head[0] + 3, head[0] + 4]               # they continue the forged record
    cold = admin(s)
    assert cold.head() == a.head() == (rs[-1]["seq"], rs[-1]["hash"])                    # warm writer and cold reader agree
    assert [x["seq"] for x in read_chain(s)][-1] == rs[-1]["seq"] and chain.verify_chain(read_chain(s)) == []
    assert a.verify() == []


def test_a_torn_valid_looking_record_that_is_not_a_continuation_is_still_accounted_for(specs):
    s = specs["agent"]
    a = agent_log(specs)
    head = a.head()
    append_raw(live(s), forged(head[0] + 5, head[1]).rstrip(b"\n"))                      # valid-looking but does not continue the chain
    r = a.append("t0", {"x": 1})
    assert admin(s).head() == a.head() == (r["seq"], r["hash"]) and r["seq"] == head[0] + 2
    assert a.verify() == [] and any(x["type"] == "tail_repair" and x["inserted_newline"] for x in read_chain(s))


def test_fsproof_says_so_when_a_route_cannot_be_observed_instead_of_passing_it_silently(realfs, monkeypatch):
    """Round 2: three checks were vacuous (EINVAL on any file, a missing constant) and read 'refused' whatever the kernel did. Now a positive control on an unflagged file decides."""
    from forge_node.audit import fsproof

    def always_einval(fd, mode, off, ln):
        raise OSError(22, "EINVAL")
    monkeypatch.setattr(fsproof, "_fallocate", always_einval)
    rep = fsproof.prove(realfs)
    c = rep["checks"]["live_punch_hole_refused"]
    assert rep["ok"] and c["got"].startswith("not observable here") and "EINVAL" in c["got"]


def test_fsproof_controls_prove_the_routes_work_on_an_unflagged_file(realfs):
    """The ranges are block-aligned on a multi-block file: the same calls succeed on an unflagged file of this filesystem."""
    import ctypes
    from forge_node.audit import fsproof
    path = os.path.join(realfs, "ctl")
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    os.write(fd, b"\0" * (4 * fsproof.BLOCK))
    for name, (mode, off, ln) in fsproof.FALLOC.items():
        fsproof._fallocate(fd, mode, off, ln)                                          # raises if the parameters are not valid for this filesystem
    fsproof._noappend_overwrite(fd)
    fsproof._clear_append_then_overwrite(fd)
    os.close(fd)
    os.unlink(path)


# ----------------------------------------------------------------------------------------------------- round 2: recovery and purge corner cases
def _killed_rotation_before_current(specs, name):
    """Rotation killed right before CURRENT is switched: generation 2 complete, flagged and REACHABLE, CURRENT still names generation 1 (sealed)."""
    sub = _scenario(specs, name)
    probe = _scenario(specs, name + "-probe")
    killed, total, calls = in_child(lambda: admin(probe).rotate())
    assert not killed
    idx = max(i for i, c in enumerate(calls, 1) if c == "rename")                           # the CURRENT.tmp -> CURRENT rename is the last rename of a rotation
    kd, _, _ = in_child(lambda: admin(sub).rotate(), kill_at=idx, when="before")
    assert kd and admin(sub)._read_current() == 1
    return sub


def test_agent_bytes_in_the_reachable_but_not_yet_switched_successor_are_damage_not_a_quarantine(specs):
    """Round 2 (MINOR): between step 5 (reachable) and step 6 (CURRENT) a hostile agent can append to its own new file; a crash there used to leave the agent log un-recoverable."""
    sub = _killed_rotation_before_current(specs, "m2")
    append_raw(live(sub, 2), b'{"junk":1}\n')
    actions = admin(sub).recover()
    assert any("rotation to generation 2" in a for a in actions)
    r = admin(sub)
    assert r.verify() == []                                                                 # the junk was accounted for by a tail_repair, before the recovery record
    assert [x["type"] for x in file_records(live(sub, 2)) if "hash" in x][:3] == ["chain_link", "tail_repair", "recovery"]
    assert r.append("t0", {})["seq"] > 1


def test_a_successor_that_holds_chained_records_was_used_and_is_not_adopted(specs):
    sub = _killed_rotation_before_current(specs, "m2b")
    a = admin(sub)
    # a forger (or a bug) wrote a VALID continuation of the chain_link into the not-yet-current file
    link = file_records(live(sub, 2))[0]
    append_raw(live(sub, 2), forged(link["seq"] + 1, link["hash"]))
    with pytest.raises(AuditCorrupt, match="has been used"):
        a.recover()


def test_recovery_refuses_to_reseal_a_generation_that_changed_while_it_had_no_flags(specs):
    """Round 2 (MINOR): a descriptor that predates the seal can write once purge has cleared the flags; recover() re-sealed whatever was there."""
    from datetime import timedelta
    sub = _purge_scenario_for(specs, "m3")
    gdir = f"{sub.dir}/priv.000001"
    os.chmod(gdir, 0o700)
    ro = os.open(f"{gdir}/priv.000001.jsonl", os.O_RDONLY)
    fsflags.clear_flags(ro, fsflags.APPEND | fsflags.IMMUTABLE)
    old_fd = os.open(f"{gdir}/priv.000001.jsonl", os.O_RDWR)                                # a descriptor that PREDATES the seal (permissions are checked at open())
    fsflags.add_flags(ro, fsflags.APPEND | fsflags.IMMUTABLE)                               # ... the generation is sealed again, as it was
    fsflags.clear_flags(ro, fsflags.APPEND | fsflags.IMMUTABLE)                             # purge clears the flags, then dies before the unlink
    os.pwrite(old_fd, b"X", 5)                                                              # the old descriptor writes
    os.close(old_fd)
    os.close(ro)
    actions = admin(sub).recover()                                                           # round 3: NOT a quarantine of the whole log - the generation is sealed first, then looked at
    assert any("DOES NOT MATCH" in x for x in actions)
    fd = os.open(f"{gdir}/priv.000001.jsonl", os.O_RDONLY)
    assert fsflags.is_sealed(fsflags.get_flags(fd))                                          # frozen as evidence
    os.close(fd)
    assert [p for p in admin(sub).verify() if p.startswith("generation 1")]                    # ... and verify names the break loudly (generation 1 no longer parses)
    admin(sub).append("t0", {})                                                              # the log goes on
    with pytest.raises(OSError):
        os.open(f"{gdir}/priv.000001.jsonl", os.O_WRONLY)


def test_an_unmodified_flagless_generation_is_resealed(specs):
    sub = _purge_scenario_for(specs, "m3ok")
    gdir = f"{sub.dir}/priv.000001"
    os.chmod(gdir, 0o700)
    fd = os.open(f"{gdir}/priv.000001.jsonl", os.O_RDONLY)
    fsflags.clear_flags(fd, fsflags.APPEND | fsflags.IMMUTABLE)
    os.close(fd)
    assert any("re-sealed generation 1" in a for a in admin(sub).recover())
    assert admin(sub).verify() == []


def _purge_scenario_for(specs, name):
    sub = make_specs(os.path.join(os.path.dirname(specs["priv"].dir), name), max_file_bytes=10 ** 7)["priv"]
    a = admin(sub)
    a.init()
    for _ in range(4):
        a.append("t0", {})
        a.rotate()
    a.append("t0", {})
    a.close()
    return sub


def test_a_recovery_that_was_killed_after_it_changed_something_is_still_recorded(specs):
    """Round 2 (MINOR): killed between the CURRENT switch and the `recovery` record, the next recovery found nothing to do and the record never existed."""
    sub = _killed_rotation_before_current(specs, "m4")
    probe = _killed_rotation_before_current(specs, "m4p")
    killed, total, calls = in_child(lambda: admin(probe).recover())
    assert not killed
    cur_switch = max(i for i, c in enumerate(calls, 1) if c == "rename")                    # the recovery's own CURRENT rename
    kd, _, _ = in_child(lambda: admin(sub).recover(), kill_at=cur_switch, when="after")
    assert kd and admin(sub)._read_current() == 2                                          # CURRENT was switched; the record was not written
    assert not [r for r in file_records(live(sub, 2)) if r["type"] == "recovery"]
    actions = admin(sub).recover()
    assert actions and "interrupted" in actions[0]
    rec = [r for r in file_records(live(sub, 2)) if r["type"] == "recovery"]
    assert len(rec) == 1 and "interrupted" in rec[0]["actions"][0]
    assert admin(sub).recover() == [] and not os.path.exists(f"{sub.dir}/RECOVERY.pending")


def test_verify_reads_sealed_generations_without_the_lock_and_the_live_one_with_it(specs, monkeypatch):
    """Round 2 (minor): verify() held the log's lock across every generation; a 64 MiB file takes seconds and the writers wait 10."""
    import fcntl
    from forge_node.audit import log as audit_log
    s = specs["priv"]
    a = admin(s)
    a.init()
    for _ in range(3):
        a.append("t0", {})
        a.rotate()
    a.append("t0", {})
    real = audit_log.verify_file
    seen = []

    def spy(fd, *args, **kw):
        probe = os.open(s.lock, os.O_RDWR)
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            seen.append("free")
            fcntl.flock(probe, fcntl.LOCK_UN)
        except BlockingIOError:
            seen.append("held")
        finally:
            os.close(probe)
        return real(fd, *args, **kw)
    monkeypatch.setattr(audit_log, "verify_file", spy)
    assert a.verify() == []
    assert seen == ["free", "free", "free", "held"]                                               # three sealed generations, then the live one


def test_the_reader_returns_what_it_read_when_the_next_generation_is_not_reachable_yet(specs):
    """Round 2 (minor): a hidden successor (rotation between steps 4 and 5, a purge in progress) raised PermissionError and threw away the records already read from the previous file."""
    s = specs["agent"]
    a = agent_log(specs, 3)
    os.mkdir(f"{s.dir}/audit.000002", 0o700)                                                      # a successor the agent uid could not enter
    os.chown(f"{s.dir}/audit.000002", 0, 0)
    fd = os.open(live(s, 1), os.O_RDONLY)
    fsflags.add_flags(fd, fsflags.IMMUTABLE)
    os.close(fd)

    def as_agent():
        cur = reader.start_cursor(s.dir, s.prefix, NODE, s.source, 0)
        got = reader.read_batch(s.dir, s.prefix, NODE, s.source, cur, 0, 100)
        return [x["seq"] for x in got]
    from audit_helpers import run_as_agent
    assert run_as_agent(as_agent) == [1, 2, 3, 4]
    fd = os.open(live(s, 1), os.O_RDONLY)
    fsflags.clear_flags(fd, fsflags.IMMUTABLE)
    os.close(fd)
    os.rmdir(f"{s.dir}/audit.000002")


# ----------------------------------------------------------------------------------------------------- round 2: tests that claimed more than they proved
def sealed_record(typ, seq, prev, **fields):
    return canon.canonical(chain.seal_record({"ts": "2026-10-31T13:40:10Z", "node": NODE, "type": typ, **fields}, seq, prev)) + b"\n"


@pytest.mark.parametrize("kind", ["right-seq-wrong-prev", "right-prev-wrong-seq"])
def test_a_forgery_that_matches_only_half_of_the_chain_position_is_damage(specs, kind):
    """Round 2: the earlier forgery tests got BOTH fields wrong at once, so a head finder that ignored one of them still passed."""
    s = specs["agent"]
    a = agent_log(specs)
    head = a.head()
    forged_line = sealed_record("t0", head[0] + 1, "e" * 64) if kind == "right-seq-wrong-prev" else sealed_record("t0", head[0] + 7, head[1])
    append_raw(live(s), forged_line)
    r = a.append("t0", {"after": kind})
    assert r["seq"] == head[0] + 2 and r["prev_hash"] != head[1] or r["seq"] == head[0] + 2                      # seq head+1 is the tail_repair that names the forgery
    shipped = read_chain(s)
    assert [x["seq"] for x in shipped] == list(range(1, head[0] + 3)) and chain.verify_chain(shipped) == []
    assert admin(s).head() == a.head()


@pytest.mark.parametrize("kind", ["right-seq-wrong-prev", "right-prev-wrong-seq"])
def test_verify_does_not_accept_a_half_matching_record_into_the_chain(specs, kind):
    s = specs["priv"]
    a = admin(s)
    a.init()
    a.append("t0", {})
    head = a.head()
    append_raw(live(s), sealed_record("t0", head[0] + 1, "e" * 64) if kind == "right-seq-wrong-prev" else sealed_record("t0", head[0] + 7, head[1]))
    problems = a.verify()
    assert any("damaged bytes" in p for p in problems), problems                                  # it is trailing damage, not a chain record


def test_the_priv_log_is_strict_damage_between_chain_records_without_a_tail_repair_is_a_problem(specs):
    s = specs["priv"]
    a = admin(s)
    a.init()
    a.append("t0", {})
    head = a.head()
    append_raw(live(s), b"JUNK LINE\n")
    append_raw(live(s), sealed_record("t0", head[0] + 1, head[1]))                              # a valid next record, hand-written: no tail_repair names the junk
    assert any("not accounted for" in p for p in a.verify())
    # the agent log tolerates and counts the same thing
    s2 = specs["agent"]
    b = agent_log(specs, 1)
    h2 = b.head()
    append_raw(live(s2), b"JUNK LINE\n")
    append_raw(live(s2), sealed_record("t0", h2[0] + 1, h2[1]))
    assert b.verify() == []


def test_a_tail_repair_that_does_not_describe_the_damage_is_a_problem(specs):
    s = specs["priv"]
    a = admin(s)
    a.init()
    a.append("t0", {})
    head = a.head()
    append_raw(live(s), b"TORN")
    append_raw(live(s), b"\n" + sealed_record("tail_repair", head[0] + 1, head[1], bytes=4, inserted_newline=True, sha256="0" * 64))      # the right length, the wrong digest
    assert any("does not describe" in p for p in a.verify())


def test_verify_notices_a_sealed_predecessor_that_no_longer_matches_the_chain_link(specs):
    s = specs["priv"]
    a = admin(s)
    a.init()
    a.append("t0", {})
    a.rotate()
    fd = os.open(live(s, 1), os.O_RDONLY)
    fsflags.clear_flags(fd, fsflags.APPEND | fsflags.IMMUTABLE)
    append_raw(live(s, 1), b"X")                                                                  # the sealed file changes after its successor recorded its sha256
    fsflags.add_flags(fd, fsflags.APPEND | fsflags.IMMUTABLE)
    os.close(fd)
    assert any("chain_link does not match the sealed predecessor" in p for p in a.verify())


def test_purge_never_removes_a_generation_that_is_not_sealed(specs):
    from datetime import timedelta
    sub = _purge_scenario(specs, "unsealed")
    a = admin(sub)
    fd = os.open(f"{sub.dir}/priv.000001/priv.000001.jsonl", os.O_RDONLY)
    fsflags.clear_flags(fd, fsflags.APPEND | fsflags.IMMUTABLE)
    os.close(fd)
    assert a.purge(a.head()[0], Clock()() + timedelta(days=200)) == []
    assert os.path.exists(f"{sub.dir}/priv.000001/priv.000001.jsonl")


def test_recovery_will_not_touch_a_reachable_generation_that_lost_its_seal(specs):
    sub = _purge_scenario(specs, "lostseal")
    fd = os.open(f"{sub.dir}/priv.000001/priv.000001.jsonl", os.O_RDONLY)
    fsflags.clear_flags(fd, fsflags.APPEND | fsflags.IMMUTABLE)
    os.close(fd)
    with pytest.raises(AuditCorrupt, match="lost its seal while reachable"):
        admin(sub).recover()


def _sealed_gen1_with_a_hand_made_successor(specs, name, successor_bytes):
    s = _scenario(specs, name)
    a = admin(s)
    fd = os.open(live(s, 1), os.O_RDONLY)
    fsflags.add_flags(fd, fsflags.IMMUTABLE)
    prev = a._sealed_description(fd)
    os.close(fd)
    fields, seq, prev_hash = a._chain_link_fields(2, prev)
    os.mkdir(f"{s.dir}/priv.000002", 0o700)
    os.chown(f"{s.dir}/priv.000002", 0, s.gid)
    with open(live(s, 2), "wb") as f:
        f.write(successor_bytes(fields, seq, prev_hash))
    os.chmod(live(s, 2), s.file_mode)
    os.chown(live(s, 2), 0, s.gid)
    return s


def test_an_incomplete_successor_in_the_private_directory_is_rebuilt_even_when_it_has_extra_bytes(specs):
    """The unflagged successor sits in a 0700 directory: it must be EXACTLY its chain_link, else it is a torn write and is rebuilt."""
    s = _sealed_gen1_with_a_hand_made_successor(specs, "torn2", lambda fields, seq, prev_hash: sealed_record("chain_link", seq, prev_hash, **fields) + b"x")
    actions = admin(s).recover()
    assert any("removed the incomplete successor" in a for a in actions) and admin(s).verify() == []


def test_a_successor_whose_chain_link_has_the_right_fields_but_a_wrong_prev_hash_is_quarantined_once_it_is_flagged(specs):
    """An UNFLAGGED wrong successor in the 0700 directory is simply rebuilt; a FLAGGED one (+a: it may have been live) is never touched - it is quarantined."""
    s = _sealed_gen1_with_a_hand_made_successor(specs, "wrongprev", lambda fields, seq, prev_hash: sealed_record("chain_link", seq, "f" * 64, **fields))
    fd = os.open(live(s, 2), os.O_RDONLY)
    fsflags.add_flags(fd, fsflags.APPEND)
    os.close(fd)
    with pytest.raises(AuditCorrupt, match="chain_link mismatch"):
        admin(s).recover()
    assert os.path.exists(live(s, 2))


# ================================================================================================================= round 3
def test_a_hostile_uid_cannot_make_the_scan_cost_one_python_iteration_per_two_bytes(tmp_path):
    """Round 3 (MAJOR): `x\\n` * 8M cost 37 s in `follow()` - under the agent log's flock, so root's rotation/recovery/peek timed out (AuditDown) for as long as the scan ran."""
    import time
    from forge_node.audit import scan
    path = tmp_path / "junk"
    with open(path, "wb") as f:
        f.write(b"x\n" * (8 << 20))
    fd = os.open(path, os.O_RDONLY)
    t0 = time.monotonic()
    t = scan.follow(fd, NODE, "agent", None)
    took = time.monotonic() - t0
    os.close(fd)
    assert t.seq is None and took < 5, took                                                  # 0.2 s measured; 37 s before


@pytest.mark.parametrize("chunk", [1 << 20, 4096, 997, 61])
def test_linescan_yields_exactly_the_records_whatever_the_chunking_and_the_junk(tmp_path, monkeypatch, chunk):
    import random
    from forge_node.audit import scan
    monkeypatch.setattr(scan, "READ_CHUNK", chunk)
    rnd = random.Random(7)
    buf, expect, seq, prev = bytearray(), [], 0, chain.GENESIS_HASH
    for _ in range(120):
        for _ in range(rnd.randint(0, 4)):
            buf += rnd.choice([b"x\n", b"\n\n\n", b"y" * rnd.randint(1, 20000) + b"\n", b"z" * 170 + b"\n", b"q" * (scan.MAX_LINE + 5) + b"\n", b"torn\n"])
        rec = chain.seal_record({"ts": "2026-10-31T13:40:10Z", "node": NODE, "type": "chain_link" if seq == 0 else "t0"}, seq + 1, prev) if seq == 0 else forged_rec(seq + 1, prev)
        line = canon.canonical(rec)
        expect.append((line, len(buf)))
        buf += line + b"\n"
        seq, prev = seq + 1, rec["hash"]
    buf += b"unterminated rest"
    path = tmp_path / "f"
    path.write_bytes(bytes(buf))
    fd = os.open(path, os.O_RDONLY)
    sc = scan.LineScan(fd, 0, len(buf))
    got = [(ln, st) for ln, st, _n in sc if scan.parse_record(ln, NODE, "agent")]
    os.close(fd)
    assert got == expect and sc.scanned_to == len(buf) - len(b"unterminated rest")


def forged_rec(seq, prev):
    return chain.seal_record({"ts": "2026-10-31T13:40:10Z", "node": NODE, "type": "t0"}, seq, prev)


def test_no_record_can_be_shorter_than_the_scan_minimum():
    """LineScan skips lines shorter than MIN_RECORD_LINE in bulk: that is only sound if no valid record can be that short."""
    from forge_node import protocol
    from forge_node.audit import scan
    shortest = None
    for source, types in chain.SOURCE_TYPES.items():
        for t in types:
            for node in ("a", "g1", "ab"):
                if not protocol.is_node_id(node):
                    continue
                rec = chain.seal_record({"ts": "2026-10-31T13:40:10Z", "node": node, "type": t}, 1, chain.GENESIS_HASH)
                n = len(canon.canonical(rec))
                shortest = n if shortest is None else min(shortest, n)
    assert shortest is not None and shortest >= scan.MIN_RECORD_LINE + 40, (shortest, scan.MIN_RECORD_LINE)       # and real ones carry more fields than these bare ones


def test_recovery_seals_and_rotates_a_reachable_file_without_the_append_flag(specs):
    """Round 3 (MAJOR): recovery only re-added +a; a writable descriptor of the group-writable agent log that predates the flag stays able to pwrite until the next rotation."""
    s = specs["agent"]
    a = agent_log(specs, 3)
    path = live(s)
    ro = os.open(path, os.O_RDONLY)
    fsflags.clear_flags(ro, fsflags.APPEND | fsflags.IMMUTABLE)                              # an operator's `chattr -a`
    old_fd = os.open(path, os.O_RDWR)                                                        # no O_APPEND: can pwrite once the file is merely +a
    a.close()
    actions = admin(s).recover()
    assert any("sealed a live log file that lacked the append-only flag" in x for x in actions) and any("rotation to generation 2" in x for x in actions)
    with pytest.raises(OSError):
        os.pwrite(old_fd, b"X", 10)                                                          # +a +i: no descriptor, however old, can write
    os.close(old_fd)
    os.close(ro)
    r = admin(s)
    assert r.verify() == [] and r._read_current() == 2 and fsflags.is_live(fsflags.get_flags(os.open(live(s, 2), os.O_RDONLY)))
    assert r.append("t0", {})["seq"] > 3


def test_verify_is_repeated_when_a_rotation_overtakes_it(specs, monkeypatch):
    """Round 3 (MINOR): CURRENT and the generation list were read once; a rotation during the pass made the previously live file 'not live' - a false alarm."""
    from forge_node.audit import log as audit_log
    sub = _scenario(specs, "v3")
    a = admin(sub)
    a.rotate()                                                                               # generations 1 (sealed) and 2 (live)
    real, fired = audit_log.verify_file, []

    def overtaken(fd, node, source, **kw):
        if not fired:
            fired.append(1)
            admin(sub).rotate()                                                              # while generation 1 (sealed, read WITHOUT the lock) is being verified
        return real(fd, node, source, **kw)
    monkeypatch.setattr(audit_log, "verify_file", overtaken)
    assert a.verify() == [] and fired


def test_a_chained_record_in_the_unswitched_agent_successor_is_the_agents_own_use_and_not_a_quarantine(specs):
    """Round 3 (MINOR): a crash between 'reachable' and 'CURRENT switched', then one chained record appended by the agent uid to its own new file, made every later recovery raise."""
    s = specs["agent"]
    a = admin(s)
    a.init()
    for i in range(2):
        a.append("t0", {"i": i})
    probe = make_specs(os.path.join(os.path.dirname(s.dir), "m5p"), max_file_bytes=10 ** 7)["agent"]
    ap = admin(probe)
    ap.init()
    ap.append("t0", {})
    killed, total, calls = in_child(lambda: ap.rotate())
    assert not killed
    a.close()
    sub = make_specs(os.path.join(os.path.dirname(s.dir), "m5"), max_file_bytes=10 ** 7)["agent"]
    b = admin(sub)
    b.init()
    b.append("t0", {})
    b.close()
    idx = max(i for i, c in enumerate(calls, 1) if c == "rename")
    kd, _, _ = in_child(lambda: admin(sub).rotate(), kill_at=idx, when="before")
    assert kd and admin(sub)._read_current() == 1
    link = file_records(live(sub, 2))[0]
    append_raw(live(sub, 2), forged(link["seq"] + 1, link["hash"]))
    actions = admin(sub).recover()
    assert any("rotation to generation 2" in x for x in actions)
    r = admin(sub)
    assert r.verify() == [] and r.append("t0", {})["seq"] > link["seq"] + 1                  # the appender continues after the agent's own record


def test_fsproof_has_a_positive_control_for_every_flagged_route(realfs, monkeypatch):
    """Round 3 (MINOR): chmod/chown/truncate/unlink/rename/link counted EPERM as 'refused' without showing that the same call works on an unflagged file (a missing capability is EPERM too)."""
    from forge_node.audit import fsproof
    rep = fsproof.prove(realfs)
    assert rep["ok"] and rep["unobservable"] == [], rep
    real_chown = os.fchown

    def no_cap(fd, uid, gid):                                                                # as inside a unit without CAP_CHOWN
        raise PermissionError(1, "EPERM")
    monkeypatch.setattr(os, "fchown", no_cap)
    rep = fsproof.prove(realfs)
    monkeypatch.setattr(os, "fchown", real_chown)
    assert rep["ok"] and rep["unobservable"] == ["chown_refused"], rep                       # reported, not silently passed
    assert rep["checks"]["chown_refused"]["got"].startswith("not observable here")


def test_the_shipper_says_so_when_the_agent_writable_ack_file_makes_it_stop(tmp_path, specs):
    """Round 3 (MINOR): an ack of 1e9 (or a reset one after a purge) made start_cursor return None and the shipper skipped the log without a word."""
    from forge_node.agent.shipper import AuditShipper
    a = agent_log(specs, 3)
    lines = []
    state = tmp_path / "state"
    state.mkdir()
    (state / "audit-acks.json").write_bytes(b'{"agent": 1000000000}')
    sh = AuditShipper(specs={"agent": specs["agent"]}, node=NODE, state_dir=str(state), log=lines.append)

    class Hub:
        def post_audit(self, body):
            raise AssertionError("nothing may be sent")
    assert sh.ship_once(Hub()) == {"agent": 0} and sh.ship_once(Hub()) == {"agent": 0}
    assert len([x for x in lines if "ahead of the log" in x]) == 1                              # said once, not every cycle
    a.close()


@pytest.mark.parametrize("torn", [b'{"torn":', b"", b"GARBAGE\n", "forged-unterminated"], ids=["fragment", "nothing-torn", "junk-line", "forged-unterminated"])
def test_the_tail_repair_is_crash_safe_at_every_system_call(specs, torn):
    """Round 3: the repair is now two writes (the terminating newline, then the tail_repair record). SIGKILL before and after every mutating call of an append that has to repair: the next
    append succeeds, nothing is lost or forked, verify is clean and the tail is accounted for."""
    def fresh(name):
        sub = make_specs(os.path.join(os.path.dirname(specs["agent"].dir), name), max_file_bytes=10 ** 7)["agent"]
        a = admin(sub)
        a.init()
        for i in range(2):
            a.append("t0", {"i": i})
        head = a.head()
        a.close()
        if torn == "forged-unterminated":
            append_raw(live(sub), forged(head[0] + 1, head[1]).rstrip(b"\n"))
        elif torn:
            append_raw(live(sub), torn)
        return sub
    probe = fresh("tr-probe")
    killed, total, calls = in_child(lambda: admin(probe).append("t0", {"x": 1}))
    assert not killed and total >= 2, (total, calls)
    for idx in range(1, total + 1):
        for when in ("before", "after"):
            sub = fresh(f"tr-{idx}-{when}")
            kd, _, _ = in_child(lambda: admin(sub).append("t0", {"x": 1}), kill_at=idx, when=when)
            assert kd
            check_no_unflagged_reachable_file(sub.dir)
            r = admin(sub)
            r.append("t0", {"after": "crash"})
            assert r.verify() == [], (idx, when, r.verify())
            assert admin(sub).head() == r.head()
            seqs = [x["seq"] for x in file_records(live(sub))]
            assert seqs == sorted(set(seqs))                                               # no seq twice: nothing forked


def test_recovery_seals_the_flagless_generation_before_it_hashes_it(specs, monkeypatch):
    """Round 3 (MINOR): the content was hashed first and sealed afterwards - a write through a descriptor that predates the seal could land in between and be sealed as 'verified'."""
    from forge_node.audit import log as audit_log
    sub = _purge_scenario_for(specs, "m3toctou")
    gdir = f"{sub.dir}/priv.000001"
    path = f"{gdir}/priv.000001.jsonl"
    os.chmod(gdir, 0o700)
    ro = os.open(path, os.O_RDONLY)
    fsflags.clear_flags(ro, fsflags.APPEND | fsflags.IMMUTABLE)
    old_fd = os.open(path, os.O_RDWR)                                                        # predates the seal
    before = open(path, "rb").read()
    real, outcome = audit_log.file_summary, []

    def summary_then_a_late_write(fd):
        r = real(fd)
        if not outcome:
            try:
                os.pwrite(old_fd, b"LATE", 5)
                outcome.append("written")
            except OSError:
                outcome.append("refused")
        return r
    monkeypatch.setattr(audit_log, "file_summary", summary_then_a_late_write)
    actions = admin(sub).recover()
    monkeypatch.undo()
    os.close(old_fd)
    os.close(ro)
    assert outcome == ["refused"] and open(path, "rb").read() == before                      # already sealed when the hash was taken: nothing can change what was hashed
    assert any("verified against the next chain_link" in x for x in actions)


def test_audit_verify_of_one_log_that_cannot_run_does_not_hide_the_other(tmp_path):
    """Round 3 (MINOR): a dict comprehension over both logs lost the priv result when the agent log's verify raised (a hostile holder of the agent log's lock)."""
    import io
    import json
    from forge_node.privd import privctl

    class A:
        def __init__(self, res):
            self.res = res

        def verify(self):
            if isinstance(self.res, Exception):
                raise self.res
            return self.res
    out = io.StringIO()
    ctl = privctl.Ctl(euid=0, client=None, state_setup=lambda: None, admin_factory=lambda: (A(["generation 1: not sealed"]), A(AuditDown("busy"))), ledger_path="", local_stop="",
                      systemctl_provider=None, systemctl_text_provider=None, protected_units=(), protected_paths=(), run_systemctl=None, clock=lambda: None, out=out)
    assert ctl.cmd_audit_verify() == 1
    doc = json.loads(out.getvalue())
    assert doc["priv"] == ["generation 1: not sealed"] and "verification could not run" in doc["agent"][0]
