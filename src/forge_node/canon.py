"""Kanonisches JSON (Design 7.1/4.6): Schluessel sortiert, UTF-8, keine Floats, keine doppelten Schluessel. Alle Signaturen und Hash-Ketten laufen ueber diese Bytes."""
import hashlib
import json

MAX_INT = 2**53 - 1


class CanonError(ValueError):
    pass


def _check(o, depth=0):
    if depth > 32:
        raise CanonError("too deeply nested")
    if isinstance(o, str):
        if "\x00" in o:
            raise CanonError("NUL is not allowed in strings")      # jsonb kann \u0000 nicht speichern; kein legitimer Inhalt
        return
    if o is None or isinstance(o, bool):
        return
    if isinstance(o, int):
        if abs(o) > MAX_INT:
            raise CanonError("integer out of range")
        return
    if isinstance(o, float):
        raise CanonError("floats are not allowed")
    if isinstance(o, (list, tuple)):
        for x in o:
            _check(x, depth + 1)
        return
    if isinstance(o, dict):
        for k, v in o.items():
            if not isinstance(k, str):
                raise CanonError("object keys must be strings")
            _check(k, depth + 1)
            _check(v, depth + 1)
        return
    raise CanonError(f"unsupported type {type(o).__name__}")


def canonical(obj) -> bytes:
    _check(obj)
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except UnicodeEncodeError as e:
        raise CanonError("string is not valid unicode") from e


def canonical_text(obj) -> str:
    return canonical(obj).decode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(obj) -> str:
    return sha256_hex(canonical(obj))


def _no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise CanonError(f"duplicate key {k!r}")
        d[k] = v
    return d


def _no_float(s):
    raise CanonError("floats are not allowed")


def _no_const(s):
    raise CanonError("non-finite number")


def loads(data: bytes | str):
    """Strikter Parser: keine doppelten Schluessel, keine Floats/NaN; Ergebnis besteht den canonical()-Check."""
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError as e:
            raise CanonError("invalid utf-8") from e
    try:
        obj = json.loads(data, object_pairs_hook=_no_dupes, parse_float=_no_float, parse_constant=_no_const)
    except json.JSONDecodeError as e:
        raise CanonError(f"invalid json: {e.msg}") from e
    except RecursionError as e:
        raise CanonError("too deeply nested") from e
    _check(obj)
    return obj


def is_canonical(text: str) -> bool:
    try:
        return canonical_text(loads(text)) == text
    except CanonError:
        return False


__all__ = ["canonical", "canonical_text", "sha256_hex", "digest", "loads", "is_canonical", "CanonError"]
