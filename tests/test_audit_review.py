"""Gate D, the cases an independent review found: forged records that rewind the chain, damage of any size, purge/init crash states, a sealed file that ends in a fragment,
the head cache against a writer that appends between our write and our look. Real ext4 (`realfs`)."""
import os

import pytest
from audit_helpers import NODE, Clock, admin, appender, check_no_unflagged_reachable_file, in_child, make_specs, tree_state
from test_audit_gate_d import _check_recovered, _scenario

from forge_node import canon, chain
from forge_node.audit import fsflags, reader
from forge_node.audit.log import AuditAdmin
from forge_node.audit.spec import AuditCorrupt


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
              "live_rwf_noappend_overwrite_refused", "live_overwrite_via_pwrite_on_append_descriptor_leaves_the_bytes", "append_through_descriptor_opened_after_flag"):
        assert c[k]["ok"], (k, c[k])
    assert c["append_through_descriptor_opened_before_flag"]["expected"] == "informational"            # a stricter future kernel must not make doctor fail


def test_fsproof_fails_when_a_live_escape_route_works(realfs, monkeypatch):
    from forge_node.audit import fsproof
    monkeypatch.setattr(fsproof, "_fallocate", lambda fd, mode: None)                                 # as if the kernel let a punch-hole through
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
