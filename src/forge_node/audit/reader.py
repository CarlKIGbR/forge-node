"""Read-only access to a rotated audit log for SHIPPING (the agent reads both logs and sends them to the hub). No lock, no flag, no write: only the permission the agent has anyway (read
on the root-owned directories). A Cursor remembers where reading stopped; records are accepted only if they CONTINUE the chain (seq and prev_hash), so bytes a hostile writer put into the
agent's own log are skipped, never shipped."""
import os
import stat
from dataclasses import dataclass

from .scan import parse_record
from .spec import gen_file, gen_re

READ_CHUNK = 1 << 20


@dataclass
class Cursor:
    gen: int
    offset: int
    next_seq: int
    prev_hash: str | None          # None until the first record is accepted (the first record of the log is the genesis chain_link)


def _gens(dfd: int, prefix: str) -> list[int]:
    rx = gen_re(prefix)
    return sorted(int(m.group(1)) for n in os.listdir(dfd) if (m := rx.match(n)))


def _open_file(dfd: int, prefix: str, n: int) -> int:
    gfd = os.open(f"{prefix}.{n:06d}", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
    try:
        fd = os.open(gen_file(prefix, n), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=gfd)
    finally:
        os.close(gfd)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise OSError("not a regular file")
    return fd


def first_record(dfd: int, prefix: str, n: int, node: str, source: str) -> dict | None:
    try:
        fd = _open_file(dfd, prefix, n)
    except OSError:
        return None
    try:
        return parse_record(os.pread(fd, 20000, 0).split(b"\n", 1)[0], node, source)
    finally:
        os.close(fd)


def start_cursor(dir_path: str, prefix: str, node: str, source: str, after_seq: int) -> Cursor | None:
    """Cursor at offset 0 of the newest generation whose first record (its chain_link) has seq <= after_seq + 1 - the file that contains record after_seq + 1 or a predecessor of it.
    None when the log has no such generation (empty log / the needed generation was purged)."""
    dfd = os.open(dir_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for n in reversed(_gens(dfd, prefix)):
            r = first_record(dfd, prefix, n, node, source)
            if r is not None and r["seq"] <= after_seq + 1:
                return Cursor(n, 0, r["seq"], r["prev_hash"])
        return None
    finally:
        os.close(dfd)


def read_batch(dir_path: str, prefix: str, node: str, source: str, cur: Cursor, after_seq: int, limit: int) -> list[dict]:
    """Up to `limit` chain-continuing records with seq > after_seq, starting at the cursor; advances the cursor. Records at or below after_seq are skipped (already acknowledged)."""
    out: list[dict] = []
    dfd = os.open(dir_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        while len(out) < limit:
            gens = _gens(dfd, prefix)
            if cur.gen not in gens:
                break
            fd = _open_file(dfd, prefix, cur.gen)
            try:
                progressed = False
                while len(out) < limit:
                    chunk = os.pread(fd, READ_CHUNK, cur.offset)
                    if not chunk:
                        break
                    consumed = 0
                    for line in chunk.split(b"\n")[:-1]:
                        consumed += len(line) + 1
                        rec = parse_record(line, node, source)
                        if rec is None or rec["seq"] != cur.next_seq or (cur.prev_hash is not None and rec["prev_hash"] != cur.prev_hash):
                            continue                                   # not part of the chain: a torn write, a hostile line, a duplicate - never shipped
                        cur.next_seq, cur.prev_hash = rec["seq"] + 1, rec["hash"]
                        if rec["seq"] > after_seq:
                            out.append(rec)
                        if len(out) >= limit:
                            break
                    if not consumed:
                        break                                          # an unterminated tail: wait for the writer
                    cur.offset += consumed
                    progressed = True
                at_end = os.pread(fd, 1, cur.offset) == b""
            finally:
                os.close(fd)
            nxt = [g for g in gens if g > cur.gen]
            if at_end and nxt and len(out) < limit:
                cur.gen, cur.offset = nxt[0], 0
                continue
            break
    finally:
        os.close(dfd)
    return out
