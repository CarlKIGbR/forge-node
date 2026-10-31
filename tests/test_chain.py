import copy

import pytest

from forge_node import chain


def _mk(n, source_types=("t0",)):
    recs, prev = [], chain.GENESIS_HASH
    for i in range(1, n + 1):
        r = chain.seal_record({"ts": "2026-10-31T13:40:10Z", "node": "g2", "type": source_types[0], "note": f"r{i}"}, i, prev)
        recs.append(r)
        prev = r["hash"]
    return recs


def test_chain_detects_edit():           # test_chain_detects_edit
    recs = _mk(5)
    assert chain.verify_chain(recs) == []
    bad = copy.deepcopy(recs)
    bad[2]["note"] = "tampered"
    assert chain.verify_chain(bad)[0].startswith("seq 3: hash does not match content")


def test_chain_detects_reorder_gap_duplicate_and_prev_break():
    recs = _mk(4)
    assert "gap" in chain.verify_chain([recs[0], recs[2], recs[3]])[0]
    assert "gap" in chain.verify_chain([recs[0], recs[0], recs[1]])[0]
    assert "gap" in chain.verify_chain([recs[1], recs[0]])[0]
    fork = copy.deepcopy(recs)
    fork[1] = chain.seal_record({"ts": "2026-10-31T13:40:10Z", "node": "g2", "type": "t0", "x": 1}, 2, "f" * 64)
    assert "prev_hash" in chain.verify_chain([fork[0], fork[1]])[0]


def test_chain_can_continue_from_a_later_start():
    recs = _mk(4)
    assert chain.verify_chain(recs[2:], start_seq=3, start_prev=recs[1]["hash"]) == []


def test_hash_covers_every_field_but_hash():
    r = _mk(1)[0]
    assert chain.record_hash(r) == r["hash"]
    r2 = dict(r, extra=1)
    assert chain.record_hash(r2) != r["hash"]


def test_seal_refuses_preset_chain_fields_and_floats():
    with pytest.raises(chain.RecordError):
        chain.seal_record({"ts": "2026-10-31T13:40:10Z", "node": "g2", "type": "t0", "seq": 9}, 1, chain.GENESIS_HASH)
    with pytest.raises(Exception):
        chain.seal_record({"ts": "2026-10-31T13:40:10Z", "node": "g2", "type": "t0", "x": 1.5}, 1, chain.GENESIS_HASH)


@pytest.mark.parametrize("mut", [
    {"fmt": 2}, {"ts": "2026-10-31 13:40:10"}, {"ts": "2026-13-31T13:40:10Z"}, {"node": "G2"}, {"seq": 0}, {"seq": True}, {"prev_hash": "zz"}, {"job_id": "not-a-uuid"}, {"attempt": -1}, {"type": ""},
])
def test_validate_record_rejects_malformed(mut):
    r = _mk(1)[0]
    r.update(mut)
    with pytest.raises(chain.RecordError):
        chain.validate_record(r, None, None)


def test_validate_record_node_and_source_type_binding():
    r = _mk(1)[0]
    chain.validate_record(r, "g2", "priv")
    with pytest.raises(chain.RecordError):
        chain.validate_record(r, "g3", "priv")
    for src, typ, ok in (("agent", "intent", False), ("priv", "intent", True), ("priv", "job_issue", False), ("hub", "job_issue", True), ("agent", "relay", True), ("hub", "t0", False)):
        rr = dict(r, type=typ)
        if ok:
            chain.validate_record(rr, "g2", src)
        else:
            with pytest.raises(chain.RecordError):
                chain.validate_record(rr, "g2", src)


def test_record_size_limit():
    with pytest.raises(chain.RecordError):
        chain.seal_record({"ts": "2026-10-31T13:40:10Z", "node": "g2", "type": "t0", "blob": "x" * 20000}, 1, chain.GENESIS_HASH)
