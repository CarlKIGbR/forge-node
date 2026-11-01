"""Hash-Kette der Audit-Logs (Design 8.1): hash = sha256(canonical(record ohne 'hash')); prev_hash verkettet, seq lueckenlos ab 1; Genesis-prev = 64 Nullen.

Die Kette laeuft pro (node, source) ueber Dateigrenzen hinweg: die erste Zeile einer rotierten Datei ist ein chain_link-Record, der seq/hash der Vorgaengerdatei fortsetzt.
Gemeinsam genutzt vom Hub (Pruefung/Senke, N1) und von den Node-Schreibern (agent/privd, N3)."""
import re
from datetime import datetime

from . import canon

FMT = 1
GENESIS_HASH = "0" * 64
MAX_RECORD_BYTES = 16 * 1024

SOURCES = ("agent", "priv", "hub")
SOURCE_TYPES = {
    "priv": frozenset("intent result denial t0 chain_link recovery tail_repair lease policy release_switch".split()),
    "agent": frozenset("relay denial t0 chain_link recovery tail_repair lease policy release_switch".split()),
    "hub": frozenset("job_issue job_result denial quarantine anomaly".split()),
}
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_HEX64 = re.compile(r"^[0-9a-f]{64}\Z")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_NODE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}\Z")


class RecordError(ValueError):
    pass


def record_hash(rec: dict) -> str:
    return canon.sha256_hex(canon.canonical({k: v for k, v in rec.items() if k != "hash"}))


def seal_record(fields: dict, seq: int, prev_hash: str) -> dict:
    """fields: ts, node, type und freie Felder. Setzt fmt, seq, prev_hash, hash."""
    for k in ("fmt", "seq", "prev_hash", "hash"):
        if k in fields:
            raise RecordError(f"{k} is set by the chain")
    rec = {**fields, "fmt": FMT, "seq": seq, "prev_hash": prev_hash}
    rec["hash"] = record_hash(rec)
    validate_record(rec, None, None)
    return rec


def validate_record(rec, node: str | None, source: str | None) -> dict:
    """Struktur eines Records. node/source None = nicht pruefen (z. B. beim Siegeln); sonst muss der Record dazu passen."""
    if not isinstance(rec, dict):
        raise RecordError("record must be an object")
    for k in ("fmt", "ts", "node", "seq", "type", "prev_hash", "hash"):
        if k not in rec:
            raise RecordError(f"missing {k}")
    if rec["fmt"] != FMT or isinstance(rec["fmt"], bool):
        raise RecordError("unsupported fmt")
    if not isinstance(rec["ts"], str) or not _TS_RE.match(rec["ts"]):
        raise RecordError("ts must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        datetime.strptime(rec["ts"], "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as e:
        raise RecordError("invalid ts") from e
    if not isinstance(rec["node"], str) or not _NODE.match(rec["node"]) or (node is not None and rec["node"] != node):
        raise RecordError("node mismatch")
    if isinstance(rec["seq"], bool) or not isinstance(rec["seq"], int) or rec["seq"] < 1:
        raise RecordError("seq must be an integer >= 1")
    for k in ("prev_hash", "hash"):
        if not isinstance(rec[k], str) or not _HEX64.match(rec[k]):
            raise RecordError(f"{k} must be sha256 hex")
    if source is not None:
        if source not in SOURCE_TYPES or rec["type"] not in SOURCE_TYPES[source]:
            raise RecordError(f"type {rec['type']!r} not allowed for source {source!r}")
    elif not isinstance(rec["type"], str) or not rec["type"]:
        raise RecordError("type missing")
    if "job_id" in rec and rec["job_id"] is not None and (not isinstance(rec["job_id"], str) or not _UUID.match(rec["job_id"])):
        raise RecordError("job_id must be a uuid")
    if "attempt" in rec and rec["attempt"] is not None and (isinstance(rec["attempt"], bool) or not isinstance(rec["attempt"], int) or rec["attempt"] < 0):
        raise RecordError("attempt must be a non-negative integer")
    try:
        size = len(canon.canonical(rec))
    except canon.CanonError as e:
        raise RecordError(f"not canonical json: {e}") from e
    if size > MAX_RECORD_BYTES:
        raise RecordError("record too large")
    return rec


def verify_chain(records: list[dict], start_seq: int = 1, start_prev: str = GENESIS_HASH) -> list[str]:
    """Leere Liste = Kette in Ordnung. Sonst Probleme in Reihenfolge (erstes Problem = Bruchstelle)."""
    problems: list[str] = []
    seq, prev = start_seq, start_prev
    for r in records:
        try:
            if r["seq"] != seq:
                problems.append(f"seq gap/duplicate: expected {seq}, got {r['seq']}")
                break
            if r["prev_hash"] != prev:
                problems.append(f"seq {seq}: prev_hash does not match predecessor")
                break
            if record_hash(r) != r["hash"]:
                problems.append(f"seq {seq}: hash does not match content")
                break
        except (KeyError, canon.CanonError, TypeError) as e:
            problems.append(f"seq {seq}: unreadable record ({type(e).__name__})")
            break
        prev, seq = r["hash"], seq + 1
    return problems
