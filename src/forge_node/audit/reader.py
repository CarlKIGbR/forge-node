"""Read-only access to a rotated audit log for SHIPPING (the agent reads both logs and sends them to the hub). No lock, no flag, no write: only the permission the agent has anyway (read
on the root-owned directories). A Cursor remembers where reading stopped; records are accepted only if they CONTINUE the chain (seq and prev_hash), so bytes a hostile writer put into the
agent's own log are skipped, never shipped."""
import os
import stat
from dataclasses import dataclass

from .scan import MAX_LINE, iter_lines, parse_record
from .spec import gen_file, gen_re


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
        return parse_record(os.pread(fd, MAX_LINE, 0).split(b"\n", 1)[0], node, source)
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
    """Up to `limit` chain-continuing records with seq > after_seq, starting at the cursor; advances the cursor. Records at or below after_seq are skipped (already acknowledged).
    A generation that has a successor is SEALED (the successor is only created after the seal): its end is final, so an unterminated fragment at its end is skipped, not waited for."""
    out: list[dict] = []
    dfd = os.open(dir_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        while len(out) < limit:
            gens = _gens(dfd, prefix)
            if cur.gen not in gens:
                break
            nxt = [g for g in gens if g > cur.gen]
            try:
                fd = _open_file(dfd, prefix, cur.gen)
            except OSError:
                if out:
                    break                                           # a successor that is not reachable yet (rotation between steps 4 and 5) / a hidden one: ship what was read, the cursor is consistent
                raise

            try:
                size = os.fstat(fd).st_size
                finished = True
                for line, _start, after in iter_lines(fd, cur.offset, size):
                    rec = parse_record(line, node, source) if line is not None else None
                    if rec is not None and rec["seq"] == cur.next_seq and (cur.prev_hash is None or rec["prev_hash"] == cur.prev_hash):
                        cur.next_seq, cur.prev_hash = rec["seq"] + 1, rec["hash"]
                        if rec["seq"] > after_seq:
                            out.append(rec)
                    cur.offset = after                                 # anything else - a torn write, a hostile line, a duplicate, an over-long line - is skipped, never shipped
                    if len(out) >= limit:
                        finished = False
                        break
                at_end = finished and (nxt or cur.offset == size)
            finally:
                os.close(fd)
            if at_end and nxt and len(out) < limit:
                cur.gen, cur.offset = nxt[0], 0
                continue
            break
    finally:
        os.close(dfd)
    return out
