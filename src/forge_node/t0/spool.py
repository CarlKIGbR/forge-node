"""T0 sample spool (Design 4.1/5.2: ring <= 50 MiB, kept while the hub is unreachable). JSONL segments in an agent-owned directory; the oldest segment is dropped when the ring
is full. The directory is opened once with O_NOFOLLOW and every file operation is relative to that descriptor; before a segment is deleted its inode is re-observed (regular file, our
uid, one link, expected name). A torn last line (power loss) is skipped on read and healed on the next append. Samples carry a strictly increasing `seq`; readers ask for `after_seq`."""
import os
import re
import stat
import threading

from .. import canon

HARD_MAX_BYTES = 50 * 1024 * 1024
SEG_BYTES = 1024 * 1024
MAX_LINE = 16 * 1024
_SEG = re.compile(r"^seg-([0-9]{12})\.jsonl\Z")


class SpoolError(Exception):
    pass


class Spool:
    def __init__(self, directory: str, owner_uid: int, max_bytes: int = HARD_MAX_BYTES):
        """`owner_uid` is required (the directory must belong to it). `max_bytes` can only lower the ceiling."""
        self.max_bytes = min(int(max_bytes), HARD_MAX_BYTES)
        self.uid = owner_uid
        self.seg_bytes = min(SEG_BYTES, max(self.max_bytes // 8, 2048))
        self._lock = threading.Lock()
        try:
            self.dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as e:
            raise SpoolError(f"spool directory unusable ({type(e).__name__})") from e
        st = os.fstat(self.dfd)
        if st.st_uid != self.uid:
            os.close(self.dfd)
            raise SpoolError("spool directory is not owned by the agent user")
        if st.st_mode & 0o077:
            os.fchmod(self.dfd, 0o700)
        self._active = None            # (fd, name, size)
        self._segs: list[tuple[int, str, int]] = []      # (first_seq, name, size), ascending
        self._next_seq = 1
        self._scan()

    # ------------------------------------------------------------------------------------------------------------------ startup
    def _scan(self):
        segs = []
        for n in os.listdir(self.dfd):
            m = _SEG.match(n)
            if not m:
                continue
            try:
                st = os.stat(n, dir_fd=self.dfd, follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_uid != self.uid or st.st_nlink != 1:
                continue
            segs.append((int(m.group(1)), n, st.st_size))
        segs.sort()
        self._segs = segs
        if segs:
            last = None
            for rec in self._lines(segs[-1][1]):
                last = rec
            self._next_seq = (last["seq"] if last else segs[-1][0] - 1) + 1
            self._next_seq = max(self._next_seq, segs[-1][0])

    def _open(self, name: str, flags: int) -> int:
        return os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.dfd)

    def _lines(self, name: str):
        try:
            fd = self._open(name, os.O_RDONLY)
        except OSError:
            return
        try:
            with os.fdopen(fd, "rb", closefd=False) as f:
                for raw in f:
                    if not raw.endswith(b"\n") or len(raw) > MAX_LINE:
                        continue
                    try:
                        rec = canon.loads(raw[:-1])
                    except canon.CanonError:
                        continue
                    if isinstance(rec, dict) and isinstance(rec.get("seq"), int):
                        yield rec
        finally:
            os.close(fd)

    # ------------------------------------------------------------------------------------------------------------------ writing
    def _line(self, sample: dict) -> bytes:
        line = canon.canonical({**sample, "seq": self._next_seq}) + b"\n"
        if len(line) > MAX_LINE:
            raise SpoolError("sample too large")
        return line

    def append(self, sample: dict) -> int:
        """Assign the next seq, write one line. Returns the seq."""
        with self._lock:
            line = self._line(sample)
            if self._active is None or self._active[2] + len(line) > self.seg_bytes:
                self._roll()
                line = self._line(sample)                 # _roll may have skipped seq numbers
            fd, name, size = self._active
            seq = self._next_seq
            os.write(fd, line)
            self._active = (fd, name, size + len(line))
            self._segs[-1] = (self._segs[-1][0], name, size + len(line))
            self._next_seq += 1
            self._evict()
            return seq

    def _roll(self):
        """Start a new segment, always with O_CREAT|O_EXCL: a segment is never reopened (so a torn tail stays where it is) and a foreign entry with the wanted name (symlink,
        hard link, anything) makes us skip to the next sequence number instead of writing through it."""
        if self._active is not None:
            os.fsync(self._active[0])
            os.close(self._active[0])
            self._active = None
        for _ in range(16):
            name = f"seg-{self._next_seq:012d}.jsonl"
            try:
                fd = self._open(name, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL)
            except FileExistsError:
                self._next_seq += 1
                continue
            except OSError as e:
                raise SpoolError(f"cannot create a spool segment ({type(e).__name__})") from e
            self._active = (fd, name, 0)
            self._segs.append((self._next_seq, name, 0))
            return
        raise SpoolError("no free segment name")

    def _evict(self):
        while len(self._segs) > 1 and sum(s for _, _, s in self._segs) > self.max_bytes:
            _, name, _ = self._segs[0]
            try:
                st = os.stat(name, dir_fd=self.dfd, follow_symlinks=False)           # re-observe before the irreversible step
                if stat.S_ISREG(st.st_mode) and st.st_uid == self.uid and st.st_nlink == 1 and _SEG.match(name):
                    os.unlink(name, dir_fd=self.dfd)
            except OSError:
                pass
            self._segs.pop(0)

    # ------------------------------------------------------------------------------------------------------------------ reading
    def oldest_seq(self) -> int | None:
        with self._lock:
            return self._segs[0][0] if self._segs else None

    def depth(self) -> int:
        with self._lock:
            return self._next_seq - self._segs[0][0] if self._segs else 0

    def bytes_used(self) -> int:
        with self._lock:
            return sum(s for _, _, s in self._segs)

    def read_after(self, after_seq: int, max_samples: int, max_bytes: int = 48 * 1024) -> dict:
        """Samples with seq > after_seq, oldest first, bounded by count and by the serialized size. `gap` = samples between after_seq and the oldest kept one were dropped."""
        with self._lock:
            segs = list(self._segs)
            nxt = self._next_seq
        out, total = [], 0
        start = 0
        for i, (first, _, _) in enumerate(segs):
            if first <= after_seq + 1:
                start = i
        for first, name, _ in segs[start:]:
            for rec in self._lines(name):
                if rec["seq"] <= after_seq:
                    continue
                n = len(canon.canonical(rec)) + 1
                if len(out) >= max_samples or total + n > max_bytes:
                    return self._result(out, after_seq, segs, nxt, more=True)
                out.append(rec)
                total += n
        return self._result(out, after_seq, segs, nxt, more=False)

    @staticmethod
    def _result(out, after_seq, segs, nxt, more):
        oldest = segs[0][0] if segs else nxt
        last = out[-1]["seq"] if out else after_seq
        return {"samples": out, "next_seq": last, "gap": bool(out or segs) and after_seq + 1 < (out[0]["seq"] if out else oldest) and after_seq + 1 < oldest, "more": more, "newest_seq": nxt - 1}

    def iter_window(self, since_ts: str):
        """Kept samples with ts >= since_ts, oldest first, ONE AT A TIME (a full 50 MiB ring must never be materialised: the agent unit has 96-128 MiB). ISO 'Z' strings compare
        chronologically."""
        with self._lock:
            segs = list(self._segs)
        for _, name, _ in segs:
            for rec in self._lines(name):
                if isinstance(rec.get("ts"), str) and rec["ts"] >= since_ts:
                    yield rec

    def window(self, since_ts: str) -> list[dict]:
        return list(self.iter_window(since_ts))

    def close(self):
        with self._lock:
            if self._active is not None:
                try:
                    os.fsync(self._active[0])
                    os.close(self._active[0])
                except OSError:
                    pass
                self._active = None
            try:
                os.close(self.dfd)
            except OSError:
                pass
