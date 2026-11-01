"""Reading audit files: the head of a live file (sequence/hash, torn or foreign bytes after the last chain record) and the complete verification of a file or a whole log.

A line is a RECORD only if it is strict canonical JSON, passes chain.validate_record for the log's node and source, and its hash matches its content. A record is part of the CHAIN only if
it CONTINUES it: first record of a file = a chain_link at offset 0; every later one has seq = previous seq + 1 and prev_hash = previous hash. Everything else is DAMAGE (a torn write after a
crash, junk or a forged self-consistent record a hostile writer appended to its own log). The head of a file is therefore found by FOLLOWING the chain forward from a known point (the
file start, or the writer's cached head) - never by looking for 'the last valid-looking record', which a forger could place anywhere. Damage is never deleted (+a forbids it); the next
writer appends a `tail_repair` record that names it:
  {"bytes": N, "inserted_newline": bool, "sha256": sha256(the first N damaged bytes)}  - the N bytes the repairing writer OBSERVED between the end of the last chain record and its own
write; bytes a hostile writer slips in after that observation but before the repair line lands are 'foreign' extras (tolerated and counted for the agent log, a problem for the priv log).
No size limit applies to damage: it is streamed, never held in memory."""
import hashlib
import os
import re
from dataclasses import dataclass, field

from .. import canon, chain
from .spec import AuditCorrupt

READ_CHUNK = 1 << 20
MAX_LINE = chain.MAX_RECORD_BYTES + 64
MIN_RECORD_LINE = 160                                               # the smallest valid record is > 200 bytes (fmt, two 64-hex hashes, ts, node, seq, type); pinned by a test
_CANDIDATE = re.compile(rb"(?<![^\n])([^\n]{%d,%d})\n" % (MIN_RECORD_LINE, MAX_LINE))


@dataclass(frozen=True)
class Tail:
    seq: int | None            # None: the file has no chain record
    hash: str | None
    end: int                   # byte offset just after the last chain record's newline (0 if none)
    size: int
    damaged: int               # size - end

    @property
    def clean(self) -> bool:
        return self.damaged == 0


def parse_record(line: bytes, node: str, source: str) -> dict | None:
    """`line` WITHOUT the trailing newline. None = not a record."""
    if not line or len(line) > MAX_LINE:
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


def region_digest(fd: int, start: int, length: int) -> str:
    """sha256 of file[start:start+length], streamed."""
    h, off, left = hashlib.sha256(), start, length
    while left > 0:
        b = os.pread(fd, min(READ_CHUNK, left), off)
        if not b:
            break
        h.update(b)
        off += len(b)
        left -= len(b)
    return h.hexdigest()


class LineScan:
    """The COMPLETE lines in [start, size) that can be a record: at least MIN_RECORD_LINE and at most MAX_LINE bytes. Everything else - empty lines, short junk, an over-long line - can never
    be a record and is skipped IN BULK by the regex engine: the cost of a scan is bounded by the number of bytes, not by the number of lines (a hostile process of the agent uid must not
    be able to make the scan cost one Python iteration per two bytes while it holds the log's lock: `x\\n` * 8M cost 37 s). An unterminated rest is not yielded (the writer may still be
    writing it). Iterating yields (line, line_start, next_offset); `scanned_to` is the offset after the last COMPLETE line looked at (valid when the iteration ran to its end)."""

    def __init__(self, fd: int, start: int, size: int):
        self.fd, self.start, self.size = fd, start, size
        self.scanned_to = start

    def __iter__(self):
        fd, off, size = self.fd, self.start, self.size
        carry, carry_off, discarding = b"", off, False                 # carry: the unterminated rest of the previous window, starting at carry_off; discarding: inside a line already too long
        while off < size:
            chunk = os.pread(fd, min(READ_CHUNK, size - off), off)
            if not chunk:
                break
            off += len(chunk)
            if discarding:
                nl = chunk.find(b"\n")
                if nl < 0:
                    continue
                discarding, carry = False, b""
                carry_off = off - len(chunk) + nl + 1
                chunk = chunk[nl + 1:]
            data = carry + chunk
            last = data.rfind(b"\n")
            if last < 0:
                if len(data) > MAX_LINE:
                    carry, discarding = b"", True
                else:
                    carry = data
                continue
            complete, carry = data[:last + 1], data[last + 1:]
            for m in _CANDIDATE.finditer(complete):
                yield m.group(1), carry_off + m.start(1), carry_off + m.end()
            carry_off += len(complete)
            self.scanned_to = carry_off
            if len(carry) > MAX_LINE:
                carry, discarding = b"", True


def follow(fd: int, node: str, source: str, tail: Tail | None) -> Tail:
    """Head of the file by following the chain forward from `tail` (the writer's cached head) or, with None, from the start of the file (the first chain record must be a chain_link at
    offset 0). Cost: the bytes after the starting point."""
    size = os.fstat(fd).st_size
    seq, prev, end = (None, None, 0) if tail is None else (tail.seq, tail.hash, tail.end)
    for line, start, nxt in LineScan(fd, end, size):
        rec = parse_record(line, node, source)
        if rec is None:
            continue
        if seq is None:
            if not (start == 0 and rec["type"] == "chain_link"):
                continue
        elif rec["seq"] != seq + 1 or rec["prev_hash"] != prev:
            continue
        seq, prev, end = rec["seq"], rec["hash"], nxt
    return Tail(seq, prev, end, size, size - end)


def tail_state(fd: int, node: str, source: str) -> Tail:
    """Cold start: follow the chain from the beginning of the file."""
    return follow(fd, node, source, None)


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
    foreign_bytes: int = 0                                   # damaged bytes a tail_repair did not describe, or that sit between chain records without one (a hostile writer racing the writer)
    trailing_bytes: int = 0                                  # damage after the last chain record (a torn write not yet repaired, or the damage a successor's chain_link accounts for)
    trailing_sha256: str | None = None


def verify_file(fd: int, node: str, source: str, *, start_seq: int | None, start_prev: str | None, strict: bool) -> FileReport:
    """Reads the whole file. `start_seq`/`start_prev`: what the first record must continue (None/None: the first record must be a genesis chain_link, seq 1, genesis hash).
    A record is accepted into the chain only if it CONTINUES it (seq + prev_hash); a valid-looking record that does not is damage, like junk. Damaged byte ranges inside the file are
    accepted only where the NEXT chain record is a tail_repair whose `bytes`/`sha256` describe the first `bytes` of them; bytes beyond that prefix were appended by someone racing
    the repair: a problem when `strict` (priv log: nobody else writes it), counted in `foreign_bytes` otherwise (agent log: the agent can append to its own log). Damage at the very
    end is reported in trailing_bytes/sha256; whether it is acceptable depends on the file (live: not yet repaired; sealed: the successor's chain_link must account for it)."""
    rep = FileReport()
    size = rep.size = os.fstat(fd).st_size
    expect_seq = 1 if start_seq is None else start_seq
    expect_prev = chain.GENESIS_HASH if start_prev is None else start_prev
    end_of_chain = 0
    for line, line_start, nxt in LineScan(fd, 0, size):
        rec = parse_record(line, node, source)
        if rec is not None and rep.first is None:
            rep.first = rec                                          # the very first record of the file decides where the chain starts
        if rec is None or rec["seq"] != expect_seq or rec["prev_hash"] != expect_prev:
            if rec is not None and rep.records == 0 and line_start == end_of_chain:
                rep.problems.append(f"seq {rec['seq']}: the first record does not continue the chain (expected seq {expect_seq})")
                return rep
            continue                                                 # not part of the chain: damage (accounted for when the next chain record, or the end of the file, is reached)
        dmg_start, dmg_len = end_of_chain, line_start - end_of_chain  # EVERY byte between the last chain record and this one (junk lines, empty lines, forgeries) is damage
        if rec["type"] == "tail_repair" and dmg_len:
            n, ins = rec.get("bytes"), rec.get("inserted_newline")
            ok = isinstance(n, int) and not isinstance(n, bool) and isinstance(ins, bool) and isinstance(rec.get("sha256"), str) and n >= 0
            extra = dmg_len - n - (1 if ins else 0) if ok else -1
            if ok and (extra < 0 or (ins and os.pread(fd, 1, dmg_start + dmg_len - 1) != b"\n") or region_digest(fd, dmg_start, n) != rec["sha256"]):
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
        elif dmg_len:
            if strict:
                rep.problems.append(f"offset {dmg_start}: {dmg_len} damaged bytes not accounted for by a tail_repair record")
                return rep
            rep.foreign_bytes += dmg_len                  # slipped in between the writer's last look at the tail and its write; the chain itself is intact
        rep.records += 1
        rep.head_seq, rep.head_hash = rec["seq"], rec["hash"]
        expect_seq, expect_prev = rec["seq"] + 1, rec["hash"]
        end_of_chain = nxt
    if end_of_chain < size:
        rep.trailing_bytes = size - end_of_chain
        rep.trailing_sha256 = region_digest(fd, end_of_chain, size - end_of_chain)
    if rep.records == 0:
        rep.problems.append("no record in file")
    elif rep.first is None or rep.first["type"] != "chain_link":
        rep.problems.append("first record is not a chain_link")
    return rep
