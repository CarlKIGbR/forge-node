"""Reading audit files: the tail of a live file (head sequence/hash, torn or foreign bytes after the last valid record) and the complete verification of a file or a whole log.

A line is a RECORD only if it is strict canonical JSON, passes chain.validate_record for the log's node and source, and its hash matches its content. Anything else is DAMAGE (a torn write
after a crash, or bytes a hostile writer appended to its own log). Damage is never deleted (+a forbids it); the next writer appends a `tail_repair` record that names it:
  {"bytes": N, "inserted_newline": bool, "sha256": sha256(damaged bytes)}  - the damaged bytes are exactly the N bytes between the end of the last valid record and the start of the repair line
(minus one inserted b"\\n" when the damage did not end with a newline), so a verifier can account for every byte of the file."""
import hashlib
import os
from dataclasses import dataclass, field

from .. import canon, chain
from .spec import MAX_DAMAGED_TAIL, AuditCorrupt

READ_CHUNK = 1 << 20
FIRST_WINDOW = 64 * 1024


@dataclass(frozen=True)
class Tail:
    seq: int | None            # None: the file has no valid record
    hash: str | None
    end: int                   # byte offset just after the last valid record's newline (0 if none)
    size: int
    damaged: int               # size - end

    @property
    def clean(self) -> bool:
        return self.damaged == 0


def parse_record(line: bytes, node: str, source: str) -> dict | None:
    """`line` WITHOUT the trailing newline. None = not a record."""
    if not line or len(line) > chain.MAX_RECORD_BYTES + 64:
        return None
    try:
        rec = canon.loads(line)
        if not isinstance(rec, dict) or canon.canonical(rec) != line:
            return None
        chain.validate_record(rec, node, source)
        if chain.record_hash(rec) != rec["hash"]:
            return None
    except (canon.CanonError, chain.RecordError, ValueError, TypeError):
        return None
    return rec


def _pread_all(fd: int, off: int, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        b = os.pread(fd, n - len(out), off + len(out))
        if not b:
            break
        out += b
    return bytes(out)


def tail_state(fd: int, node: str, source: str) -> Tail:
    """Head of the file from its tail only (cheap). Looks back from the end for the last valid record; the window doubles until one is found, the file start is reached, or the damaged
    part exceeds MAX_DAMAGED_TAIL (then AuditCorrupt: that is not a crash artefact)."""
    size = os.fstat(fd).st_size
    window = FIRST_WINDOW
    while True:
        start = max(0, size - window)
        data = _pread_all(fd, start, size - start)
        # complete lines inside the window; the first (possibly cut) line is only usable if the window starts at 0
        pieces = data.split(b"\n")
        # pieces[-1] is the unterminated rest (possibly empty); pieces[0] is cut unless start == 0
        lines = pieces[:-1]
        offsets, off = [], start
        for ln in lines:
            offsets.append(off)
            off += len(ln) + 1
        usable_from = 0 if start == 0 else 1
        for i in range(len(lines) - 1, usable_from - 1, -1):
            rec = parse_record(lines[i], node, source)
            if rec is not None:
                end = offsets[i] + len(lines[i]) + 1
                if size - end > MAX_DAMAGED_TAIL:
                    raise AuditCorrupt("damaged tail larger than the allowed limit")
                return Tail(rec["seq"], rec["hash"], end, size, size - end)
        if start == 0:
            if size > MAX_DAMAGED_TAIL:
                raise AuditCorrupt("no valid record in a large file")
            return Tail(None, None, 0, size, size)
        if size - start > MAX_DAMAGED_TAIL + FIRST_WINDOW:
            raise AuditCorrupt("damaged tail larger than the allowed limit")
        window *= 2


def last_record(fd: int, tail: Tail, node: str, source: str) -> dict | None:
    """The record that ends at tail.end (the last valid one)."""
    if tail.seq is None:
        return None
    start = max(0, tail.end - chain.MAX_RECORD_BYTES - 64)
    data = _pread_all(fd, start, tail.end - start)
    line = data[:-1].rsplit(b"\n", 1)[-1] if data.endswith(b"\n") else b""
    return parse_record(line, node, source)


def file_summary(fd: int) -> tuple[str, int]:
    """(sha256 hex, size) of the whole file through the open descriptor."""
    h, off = hashlib.sha256(), 0
    while True:
        b = os.pread(fd, READ_CHUNK, off)
        if not b:
            return h.hexdigest(), off
        h.update(b)
        off += len(b)


@dataclass
class FileReport:
    records: int = 0
    first: dict | None = None
    head_seq: int | None = None
    head_hash: str | None = None
    problems: list[str] = field(default_factory=list)
    repaired: list[dict] = field(default_factory=list)       # tail_repair records seen
    size: int = 0
    foreign_bytes: int = 0                                   # bytes between a valid record and a tail_repair that the repair did not describe (a hostile writer racing the repair)
    trailing_bytes: int = 0                                  # damage after the last valid record (a torn write not yet repaired, or the damage a successor's chain_link accounts for)
    trailing_sha256: str | None = None

    @property
    def ok(self) -> bool:
        return not self.problems


def verify_file(fd: int, node: str, source: str, *, start_seq: int | None, start_prev: str | None, strict: bool) -> FileReport:
    """Reads the whole file. `start_seq`/`start_prev`: what the first record must continue (None/None: the first record must be a genesis chain_link, seq 1, genesis hash).
    Damaged byte ranges inside the file are accepted only where the NEXT valid record is a tail_repair whose `bytes`/`sha256` describe the first `bytes` of them. Bytes beyond that
    prefix were appended by someone racing the repair: a problem when `strict` (priv log: nobody else writes it), counted in `foreign_bytes` otherwise (agent log: the agent can append
    to its own log). Damage at the very end is reported in trailing_bytes/sha256; whether it is acceptable depends on the file (live: not yet repaired; sealed: the successor's chain_link must account for it)."""
    rep = FileReport()
    rep.size = os.fstat(fd).st_size
    expect_seq = 1 if start_seq is None else start_seq
    expect_prev = chain.GENESIS_HASH if start_prev is None else start_prev
    data_off = 0
    damaged = bytearray()
    buf = b""
    pos = 0                                           # absolute offset of buf[0]
    first = True
    while True:
        chunk = os.pread(fd, READ_CHUNK, data_off)
        data_off += len(chunk)
        buf += chunk
        while True:
            nl = buf.find(b"\n")
            if nl < 0:
                break
            line, buf = buf[:nl], buf[nl + 1:]
            line_start, pos = pos, pos + nl + 1
            rec = parse_record(line, node, source)
            if rec is None:
                damaged += line + b"\n"
                if len(damaged) > MAX_DAMAGED_TAIL:
                    rep.problems.append(f"offset {line_start}: damaged region larger than the limit")
                    return rep
                continue
            if first:
                rep.first, first = rec, False
            if rec["type"] == "tail_repair" and damaged:
                n = rec.get("bytes")
                ins = rec.get("inserted_newline")
                ok = isinstance(n, int) and isinstance(ins, bool) and rec.get("sha256") is not None
                raw = bytes(damaged)
                extra = len(raw) - n - (1 if ins else 0) if ok else -1
                if ok and (extra < 0 or (ins and not raw.endswith(b"\n")) or hashlib.sha256(raw[:n]).hexdigest() != rec["sha256"]):
                    ok = False
                if not ok:
                    rep.problems.append(f"seq {rec['seq']}: tail_repair does not describe the damaged bytes before it")
                    return rep
                if extra:
                    if strict:
                        rep.problems.append(f"seq {rec['seq']}: {extra} damaged bytes before the tail_repair are not described by it")
                        return rep
                    rep.foreign_bytes += extra
                rep.repaired.append(rec)
                damaged.clear()
            elif damaged:
                if strict:
                    rep.problems.append(f"offset {line_start}: {len(damaged)} damaged bytes not accounted for by a tail_repair record")
                    return rep
                rep.foreign_bytes += len(damaged)               # a hostile writer slipped bytes in between the writer's last look at the tail and its write; the chain itself is intact
                damaged.clear()
            if rec["seq"] != expect_seq:
                rep.problems.append(f"seq gap/duplicate: expected {expect_seq}, got {rec['seq']}")
                return rep
            if rec["prev_hash"] != expect_prev:
                rep.problems.append(f"seq {rec['seq']}: prev_hash does not match predecessor")
                return rep
            rep.records += 1
            rep.head_seq, rep.head_hash = rec["seq"], rec["hash"]
            expect_seq, expect_prev = rec["seq"] + 1, rec["hash"]
        if not chunk:
            break
    if buf:                                                         # an unterminated last line
        damaged += buf
    if damaged:
        rep.trailing_bytes, rep.trailing_sha256 = len(damaged), hashlib.sha256(bytes(damaged)).hexdigest()
    if rep.first is None:
        rep.problems.append("no record in file")
    elif rep.first["type"] != "chain_link":
        rep.problems.append("first record is not a chain_link")
    return rep
