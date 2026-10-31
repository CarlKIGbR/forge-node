import pytest

from forge_node import canon


def test_canonical_sorts_keys_and_is_compact_utf8():
    assert canon.canonical({"b": 1, "a": [True, None, "ä"]}) == '{"a":[true,null,"ä"],"b":1}'.encode()


def test_floats_nan_and_big_ints_rejected():
    for bad in (1.5, float("nan"), {"a": 0.1}, [1e3], 2**60):
        with pytest.raises(canon.CanonError):
            canon.canonical(bad)
    for bad in ('{"a":1.5}', '{"a":1e3}', "NaN", "Infinity"):
        with pytest.raises(canon.CanonError):
            canon.loads(bad)


def test_duplicate_keys_and_invalid_utf8_rejected():
    with pytest.raises(canon.CanonError):
        canon.loads('{"a":1,"a":2}')
    with pytest.raises(canon.CanonError):
        canon.loads(b'{"a":"\xff"}')


def test_non_string_keys_and_unknown_types_rejected():
    with pytest.raises(canon.CanonError):
        canon.canonical({1: 2})
    with pytest.raises(canon.CanonError):
        canon.canonical({"a": {1, 2}})


def test_depth_limit():
    deep = []
    cur = deep
    for _ in range(100):
        nxt = []
        cur.append(nxt)
        cur = nxt
    with pytest.raises(canon.CanonError):
        canon.canonical(deep)
    with pytest.raises(canon.CanonError):
        canon.loads("[" * 5000 + "]" * 5000)


def test_is_canonical_roundtrip():
    t = canon.canonical_text({"x": 1, "a": {"z": [1, 2], "b": "c"}})
    assert canon.is_canonical(t)
    assert not canon.is_canonical('{"x": 1}')
    assert not canon.is_canonical('{"b":1,"a":2}')


def test_lone_surrogate_rejected():
    with pytest.raises(canon.CanonError):
        canon.canonical({"a": "\ud800"})


def test_nul_rejected_in_values_and_keys():
    for bad in ({"a": "x\x00y"}, {"a\x00": 1}, ["\x00"]):
        with pytest.raises(canon.CanonError):
            canon.canonical(bad)
    with pytest.raises(canon.CanonError):
        canon.loads('{"a":"x\\u0000y"}')
