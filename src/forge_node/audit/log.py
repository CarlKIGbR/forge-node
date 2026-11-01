"""The audit log writer and its root-side administration (Design 8.2/8.3/8.4, gate D).

PROTOCOL (what makes a sealed file impossible to append to - see fsflags.py for the kernel facts this rests on)

  live file     +a                 root:<gid> <file_mode>, named by CURRENT; appended with O_APPEND under the log's flock
  sealed file   +a +i              immutable: a write through ANY descriptor, however old, fails with EPERM; no chmod/chown/truncate/rename is ever issued on an append-only inode
  new file      created inside a root-only (0700) generation directory, +a set BEFORE the directory is made reachable, so no other uid ever holds a descriptor that predates +a

  rotate (root, holding the log's exclusive flock the whole time):
    1 re-read CURRENT and the live file's tail (fresh evidence, never the cache); a damaged tail is repaired by a tail_repair record BEFORE sealing
    2 SEAL the old file: add +i            -> from here nobody can change it, however many descriptors exist
    3 read the sealed file's final tail and its sha256/size (definitive now)
    4 create <prefix>.<n+1>/ (0700), the file inside it, write its first record: chain_link {prev_file, prev_seq, prev_file_sha256, prev_file_bytes, prev_damaged_*}; fsync
    5 add +a to the new file; make the generation directory reachable (fchmod dir_mode); fsync
    6 replace CURRENT by an atomic rename inside the root-owned directory; fsync the directory
  There is no instant at which an existing log file can be written without a flag, and none at which a non-root uid can open a file that is not yet +a.
  Crash at ANY system call: recover() (below) rolls the interrupted rotation forward idempotently, because every state is self-describing:
    CURRENT -> n live, nothing newer ........ nothing to do (a stale CURRENT.tmp is removed)
    CURRENT -> n sealed, no n+1 ............. resume at step 3
    CURRENT -> n sealed, n+1 incomplete ..... the half-built successor is unreachable (0700) and unflagged: remove it and resume at step 4
    CURRENT -> n sealed, n+1 complete ....... finish step 5/6
  Anything else (a gap, a live file with a successor, CURRENT missing while files exist, a successor whose chain_link does not match the sealed predecessor) is AuditCorrupt: quarantine.

Appenders (privd for priv.jsonl, the agent for audit.jsonl) never rotate and never repair CURRENT: a sealed or non-append-only live file is AuditDown for them (fail closed) until root recovers."""
import errno
import fcntl
import hashlib
import os
import stat
import threading
import time
from datetime import datetime
from typing import Callable

from .. import canon, chain, protocol
from . import fsflags
from .scan import Tail, file_summary, follow, last_record, parse_record, region_digest, tail_state, verify_file
from .spec import (CURRENT_NAME, CURRENT_TMP, LOCK_TIMEOUT_S, MAX_CURRENT_BYTES, MIN_AGE_PURGE_S, AuditCorrupt, AuditDown, AuditNotInitialised, LogSpec, gen_file, gen_name, gen_re)

Clock = Callable[[], datetime]
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def trusted_chain(path: str, owner_uid: int, anchor: str) -> bool:
    """Every directory from `path` up to `anchor` (inclusive) is a real directory (no symlink) owned by `owner_uid` and not writable by group/others. The agent therefore has no write
    permission on any directory in the privileged path (test_no_agent_owned_or_writable_directory_on_privileged_path)."""
    d, anchor = os.path.abspath(path), os.path.abspath(anchor)
    if d != anchor and not d.startswith(anchor.rstrip("/") + "/"):
        return False
    while True:
        try:
            st = os.lstat(d)
        except OSError:
            return False
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != owner_uid or st.st_mode & 0o022:
            return False
        if d == anchor:
            return True
        d = os.path.dirname(d)


def _write_all(fd: int, data: bytes) -> None:
    n = os.write(fd, data)
    if n != len(data):
        raise AuditDown("short write")


class Appender:
    """One writer for one log. `node`, `spec` and `clock` are required."""

    def __init__(self, spec: LogSpec, node: str, clock: Clock):
        if not protocol.is_node_id(node):
            raise ValueError("invalid node id")
        self.spec, self.node, self.clock = spec, node, clock
        self._mutex = threading.RLock()
        self._dfd = -1                  # log directory
        self._lfd = -1                  # lock file
        self._gfd = -1                  # generation directory of the open file
        self._fd = -1                   # live file (O_RDWR|O_APPEND)
        self._gen: int | None = None
        self._key = None                # (st_ino, st_size) the cached tail belongs to
        self._tail: Tail | None = None
        self._recovering = False
        self._heal_depth = 0
        self._open_dirs()

    # ------------------------------------------------------------------------------------------------------------- open
    def _creating(self) -> bool:
        return False

    def _open_dirs(self) -> None:
        s = self.spec
        if not trusted_chain(s.dir, s.owner_uid, s.trust_anchor):
            raise AuditDown("log directory chain is not root-controlled")
        if not trusted_chain(os.path.dirname(s.lock), s.owner_uid, s.trust_anchor):
            raise AuditDown("lock directory chain is not root-controlled")
        try:
            self._dfd = os.open(s.dir, _DIR_FLAGS)
        except OSError as e:
            raise AuditDown(f"log directory unavailable ({errno.errorcode.get(e.errno, e.errno)})") from e
        st = os.fstat(self._dfd)
        if st.st_uid != s.owner_uid or st.st_mode & 0o022:
            raise AuditDown("log directory must be owned by root and not writable by group/others")
        try:
            lfd = self._open_lock_file()
        except BaseException:
            os.close(self._dfd)
            self._dfd = -1
            raise
        self._lfd = lfd

    def _open_lock_file(self) -> int:
        s = self.spec
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | (os.O_CREAT if self._creating() else 0)
        try:
            fd = os.open(s.lock, flags, s.lock_mode)
        except OSError as e:
            raise AuditDown(f"lock file unavailable ({errno.errorcode.get(e.errno, e.errno)})") from e
        try:
            if self._creating():
                os.fchown(fd, s.owner_uid, s.gid)
                os.fchmod(fd, s.lock_mode)
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != s.owner_uid or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != s.lock_mode:
                raise AuditDown("lock file must be a regular root-owned file with one link and the expected mode")
        except BaseException:
            os.close(fd)
            raise
        return fd

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:  # noqa: BLE001 - interpreter shutdown
            pass

    def close(self) -> None:
        with self._mutex:
            self._drop()
            for name in ("_lfd", "_dfd"):
                fd = getattr(self, name)
                if fd >= 0:
                    os.close(fd)
                    setattr(self, name, -1)

    def _drop(self) -> None:
        for name in ("_fd", "_gfd"):
            fd = getattr(self, name)
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, name, -1)
        self._gen = self._key = self._tail = None

    # ------------------------------------------------------------------------------------------------------------- lock
    def _lock(self) -> None:
        deadline = time.monotonic() + LOCK_TIMEOUT_S
        while True:
            try:
                fcntl.flock(self._lfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise AuditDown("log lock busy")
                time.sleep(0.002)

    def _unlock(self) -> None:
        fcntl.flock(self._lfd, fcntl.LOCK_UN)

    # --------------------------------------------------------------------------------------------------------- CURRENT
    def _read_current(self) -> int | None:
        """Generation named by CURRENT, None if CURRENT does not exist. Anything malformed is AuditCorrupt (the file is only ever replaced by an atomic rename)."""
        s = self.spec
        try:
            fd = os.open(CURRENT_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._dfd)
        except FileNotFoundError:
            return None
        except OSError as e:
            raise AuditDown(f"CURRENT unreadable ({errno.errorcode.get(e.errno, e.errno)})") from e
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != s.owner_uid or st.st_nlink != 1 or st.st_mode & 0o022 or st.st_size > MAX_CURRENT_BYTES:
                raise AuditCorrupt("CURRENT is not a root-owned regular file")
            raw = os.read(fd, MAX_CURRENT_BYTES + 1)
        finally:
            os.close(fd)
        try:
            doc = canon.loads(raw.rstrip(b"\n"))
            gen = doc["gen"]
            if (set(doc) != {"dir", "file", "fmt", "gen"} or doc["fmt"] != 1 or isinstance(gen, bool) or not isinstance(gen, int) or not 1 <= gen < 10 ** 6
                    or doc["dir"] != gen_name(s.prefix, gen) or doc["file"] != gen_file(s.prefix, gen) or raw != canon.canonical(doc) + b"\n"):
                raise ValueError("fields")
        except (canon.CanonError, KeyError, ValueError, TypeError) as e:
            raise AuditCorrupt("CURRENT is malformed") from e
        return gen

    def _open_gen_dir(self, n: int) -> int:
        fd = os.open(gen_name(self.spec.prefix, n), _DIR_FLAGS, dir_fd=self._dfd)
        st = os.fstat(fd)
        if st.st_uid != self.spec.owner_uid or st.st_mode & 0o022:
            os.close(fd)
            raise AuditCorrupt("generation directory is not root-controlled")
        return fd

    def _check_file(self, fd: int, what: str) -> os.stat_result:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != self.spec.owner_uid or st.st_gid != self.spec.gid or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != self.spec.file_mode:
            raise AuditCorrupt(f"{what}: not a regular file with the expected owner, link count and mode")
        return st

    def _ensure_open(self, cur: int) -> None:
        """Live file for generation `cur`, flags verified. Appenders cannot fix a sealed or flagless file: AuditDown."""
        s = self.spec
        if self._gen == cur and self._fd >= 0:
            try:
                if fsflags.is_live(fsflags.get_flags(self._fd)):
                    return
            except OSError as e:
                raise AuditDown(f"inode flags unreadable ({errno.errorcode.get(e.errno, e.errno)})") from e
        self._drop()
        gfd = fd = -1
        try:
            gfd = self._open_gen_dir(cur)
            if stat.S_IMODE(os.fstat(gfd).st_mode) != s.dir_mode:
                raise AuditDown("generation directory is not yet reachable (rotation unfinished)")
            fd = os.open(gen_file(s.prefix, cur), os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=gfd)
            self._check_file(fd, "live log file")
            fl = fsflags.get_flags(fd)
            if not fsflags.is_live(fl):
                raise AuditDown("live log file is sealed or lacks the append-only flag (recovery needed)")
        except FileNotFoundError as e:
            self._close_quiet(gfd, fd)
            raise AuditCorrupt("CURRENT names a file that does not exist") from e
        except OSError as e:
            self._close_quiet(gfd, fd)
            raise AuditDown(f"cannot open the live log file ({errno.errorcode.get(e.errno, e.errno)})") from e
        except BaseException:
            self._close_quiet(gfd, fd)
            raise
        self._gfd, self._fd, self._gen = gfd, fd, cur
        self._key = self._tail = None

    @staticmethod
    def _close_quiet(*fds: int) -> None:
        for f in fds:
            if f >= 0:
                try:
                    os.close(f)
                except OSError:
                    pass

    def _refresh_tail(self) -> Tail:
        """Head of the live file. The cached head is trusted only as a STARTING POINT: the chain is followed forward from it over whatever was appended since (our own last write ends exactly
        at the cached end; anything beyond is another writer's - root recovery or a hostile agent-uid append - and is read, never assumed). A different inode starts from the file's beginning."""
        st = os.fstat(self._fd)
        key = (st.st_ino, st.st_size)
        if self._tail is None or self._key != key:
            base = self._tail if (self._tail is not None and self._key is not None and self._key[0] == st.st_ino and st.st_size >= self._tail.end) else None
            self._tail = follow(self._fd, self.node, self.spec.source, base)
            self._key = key
            if self._tail.seq is None:
                self._tail = self._key = None
                raise AuditCorrupt("live log file has no valid record (no chain_link)")
        return self._tail

    def _open_current_locked(self) -> None:
        cur = self._read_current()
        if cur is None:
            self._drop()
            raise AuditNotInitialised("audit log is not initialised (CURRENT missing)")
        self._ensure_open(cur)

    # ---------------------------------------------------------------------------------------------------------- append
    def _ts(self) -> str:
        return protocol.fmt_ts(self.clock())

    def _emit(self, fields: dict) -> dict:
        """Seal, validate, write one record at the tail (lock held, file open, tail clean). Returns the record."""
        t = self._tail
        rec = chain.seal_record({"ts": self._ts(), "node": self.node, **fields}, t.seq + 1, t.hash)
        chain.validate_record(rec, self.node, self.spec.source)
        line = canon.canonical(rec) + b"\n"
        try:
            _write_all(self._fd, line)
            os.fsync(self._fd)
        except (OSError, AuditDown) as e:
            self._tail = self._key = None
            raise AuditDown(f"append failed ({type(e).__name__})") from e
        self._cache_after_write(rec)
        return rec

    def _cache_after_write(self, rec: dict) -> None:
        """The head is cached at the offset where OUR write ended (an O_APPEND write leaves the descriptor's offset there, whatever another writer appends afterwards), not at the current size:
        bytes a hostile writer appended in between stay visible to the next refresh instead of being swallowed into the cache."""
        end = os.lseek(self._fd, 0, os.SEEK_CUR)
        st = os.fstat(self._fd)
        self._tail = Tail(rec["seq"], rec["hash"], end, end, 0)
        self._key = (st.st_ino, end)

    def _repair_tail_locked(self) -> dict | None:
        t = self._refresh_tail()
        if t.clean:
            return None
        # the bytes OBSERVED now (streamed: the damage can be arbitrarily large); a hostile writer may still append before our write lands: the verifier tolerates that
        ins = os.pread(self._fd, 1, t.end + t.damaged - 1) != b"\n"
        rec = chain.seal_record({"ts": self._ts(), "node": self.node, "type": "tail_repair", "bytes": t.damaged, "inserted_newline": ins, "sha256": region_digest(self._fd, t.end, t.damaged)},
                                t.seq + 1, t.hash)
        chain.validate_record(rec, self.node, self.spec.source)
        try:
            _write_all(self._fd, (b"\n" if ins else b"") + canon.canonical(rec) + b"\n")
            os.fsync(self._fd)
        except (OSError, AuditDown) as e:
            self._tail = self._key = None
            raise AuditDown(f"tail repair failed ({type(e).__name__})") from e
        self._cache_after_write(rec)
        return rec

    def _append_locked(self, type_: str, fields: dict) -> dict:
        self._open_current_locked()
        self._refresh_tail()
        self._repair_tail_locked()
        return self._emit({**fields, "type": type_})

    def append(self, type_: str, fields: dict) -> dict:
        """The one critical section of the log (Design 8.2): flock, re-read CURRENT, re-validate the cached head against the file, allocate seq/prev_hash, ONE write on the O_APPEND
        descriptor, fsync, update the cache, unlock. Raises AuditDown (retryable, DENY_AUDIT_DOWN) when nothing was written."""
        if not isinstance(type_, str) or not isinstance(fields, dict) or {"fmt", "seq", "prev_hash", "hash", "ts", "node", "type"} & fields.keys():
            raise ValueError("append: type must be a string; fields must not carry chain-owned keys")
        with self._mutex:
            self._lock()
            try:
                return self._append_locked(type_, fields)
            finally:
                self._unlock()

    def head(self) -> tuple[int, str]:
        with self._mutex:
            self._lock()
            try:
                self._open_current_locked()
                t = self._refresh_tail()
                return t.seq, t.hash
            finally:
                self._unlock()


class AuditAdmin(Appender):
    """Root side: initialise, rotate, recover, purge, verify. Needs CAP_LINUX_IMMUTABLE (privd's root; the agent has no such object)."""

    def _creating(self) -> bool:
        return True

    # ------------------------------------------------------------------------------------------------------ inspection
    def _list_gens(self) -> dict[int, dict]:
        rx = gen_re(self.spec.prefix)
        out = {}
        for name in os.listdir(self._dfd):
            m = rx.match(name)
            if m:
                out[int(m.group(1))] = {"name": name}
        return out

    def _gen_state(self, n: int) -> dict:
        """What is on disk for generation n: directory mode, file presence, flags, size. Nothing is opened for writing."""
        s = self.spec
        st = {"n": n, "dir": False, "file": False, "flags": None, "size": None, "dir_mode": None}
        try:
            gfd = self._open_gen_dir(n)
        except FileNotFoundError:
            return st
        try:
            st["dir"], st["dir_mode"] = True, stat.S_IMODE(os.fstat(gfd).st_mode)
            try:
                fd = os.open(gen_file(s.prefix, n), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=gfd)
            except FileNotFoundError:
                return st
            try:
                fst = os.fstat(fd)
                if not stat.S_ISREG(fst.st_mode):
                    raise AuditCorrupt("generation file is not a regular file")
                st["file"], st["flags"], st["size"] = True, fsflags.get_flags(fd), fst.st_size
            finally:
                os.close(fd)
        finally:
            os.close(gfd)
        return st

    def _open_ro(self, n: int) -> tuple[int, int]:
        """(generation directory fd, read-only file fd). Flags can be read and set through a read-only descriptor."""
        gfd = self._open_gen_dir(n)
        try:
            fd = os.open(gen_file(self.spec.prefix, n), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=gfd)
        except BaseException:
            os.close(gfd)
            raise
        return gfd, fd

    # ------------------------------------------------------------------------------------------------- generation build
    def _chain_link_fields(self, n: int, prev: dict | None) -> tuple[dict, int, str]:
        if prev is None:
            return ({"type": "chain_link", "gen": n, "prev_file": None, "prev_seq": 0, "prev_file_sha256": None, "prev_file_bytes": 0, "prev_damaged_bytes": 0, "prev_damaged_sha256": None},
                    1, chain.GENESIS_HASH)
        return ({"type": "chain_link", "gen": n, "prev_file": f"{gen_name(self.spec.prefix, n - 1)}/{gen_file(self.spec.prefix, n - 1)}", "prev_seq": prev["seq"],
                 "prev_file_sha256": prev["sha256"], "prev_file_bytes": prev["bytes"], "prev_damaged_bytes": prev["damaged"], "prev_damaged_sha256": prev["damaged_sha256"]},
                prev["seq"] + 1, prev["hash"])

    def _build_generation(self, n: int, prev: dict | None) -> None:
        """Steps 4+5 of the rotation. The directory is 0700 and the file unflagged until +a is set; only then is the directory made reachable."""
        s = self.spec
        name = gen_name(s.prefix, n)
        os.mkdir(name, 0o700, dir_fd=self._dfd)
        gfd = self._open_gen_dir(n)
        fd = -1
        try:
            os.fchown(gfd, s.owner_uid, s.gid)
            fd = os.open(gen_file(s.prefix, n), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=gfd)
            os.fchmod(fd, s.file_mode)
            os.fchown(fd, s.owner_uid, s.gid)
            fields, seq, prev_hash = self._chain_link_fields(n, prev)
            rec = chain.seal_record({"ts": self._ts(), "node": self.node, **fields}, seq, prev_hash)
            chain.validate_record(rec, self.node, s.source)
            _write_all(fd, canon.canonical(rec) + b"\n")
            os.fsync(fd)
            os.fsync(gfd)
            self._finish_generation(gfd, fd)
        finally:
            os.close(gfd)
            if fd >= 0:
                os.close(fd)

    def _finish_generation(self, gfd: int, fd: int) -> None:
        """Step 5: +a on the (complete) file, then the directory becomes reachable."""
        fl = fsflags.add_flags(fd, fsflags.APPEND)
        if not fsflags.is_live(fl):
            raise AuditCorrupt("could not set the append-only flag on the new log file")
        os.fchmod(gfd, self.spec.dir_mode)
        os.fsync(gfd)
        os.fsync(self._dfd)

    def _write_current(self, n: int) -> None:
        s = self.spec
        doc = canon.canonical({"fmt": 1, "gen": n, "dir": gen_name(s.prefix, n), "file": gen_file(s.prefix, n)}) + b"\n"
        try:
            os.unlink(CURRENT_TMP, dir_fd=self._dfd)
        except FileNotFoundError:
            pass
        fd = os.open(CURRENT_TMP, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self._dfd)
        try:
            os.fchmod(fd, 0o644)
            os.fchown(fd, s.owner_uid, s.gid)
            _write_all(fd, doc)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(CURRENT_TMP, CURRENT_NAME, src_dir_fd=self._dfd, dst_dir_fd=self._dfd)
        os.fsync(self._dfd)

    # ------------------------------------------------------------------------------------------------------------ init
    def init(self) -> int:
        """`privctl audit-init`: first generation (genesis chain_link) + CURRENT. Idempotent: an existing log is recovered/validated instead."""
        with self._mutex:
            self._lock()
            try:
                gens = self._list_gens()
                if self._read_current() is None and set(gens) == {1}:
                    # an init that died before CURRENT was written: generation 1 is unreachable (0700) or was never used, so it is finished or rebuilt, never quarantined
                    self._complete_successor(1, None)
                    self._write_current(1)
                    return 1
                if self._read_current() is not None or gens:
                    self._recover_locked()
                    return self._read_current()
                self._build_generation(1, None)
                self._write_current(1)
                return 1
            finally:
                self._unlock()

    # ------------------------------------------------------------------------------------------------------- rotation
    def rotate(self) -> int:
        with self._mutex:
            self._lock()
            try:
                if any(a.startswith("rotation to generation") for a in self._recover_locked()):
                    return self._read_current()                                # an interrupted rotation was just completed: that IS the rotation that was asked for
                return self._rotate_locked()
            finally:
                self._unlock()

    def due(self) -> bool:
        """The active file reached the size threshold, or is older than max_age_s AND holds more than its chain_link (an idle node does not produce a new file every day)."""
        with self._mutex:
            self._lock()
            try:
                self._open_current_locked()
                if os.fstat(self._fd).st_size >= self.spec.max_file_bytes:
                    return True
                first = parse_record(os.pread(self._fd, chain.MAX_RECORD_BYTES + 64, 0).split(b"\n", 1)[0], self.node, self.spec.source)
                tail = self._refresh_tail()
                if first is None or tail.seq is None or tail.seq <= first["seq"]:
                    return False
                return (self.clock() - protocol.parse_ts(first["ts"])).total_seconds() >= self.spec.max_age_s
            finally:
                self._unlock()

    def _seal_summary(self, fd: int) -> dict:
        """Seal (+i) the live file open as `fd` and describe its final, immutable content."""
        fl = fsflags.add_flags(fd, fsflags.IMMUTABLE)
        if not fsflags.is_sealed(fl):
            raise AuditCorrupt("could not seal the log file")
        os.fsync(fd)                                                          # what we hash is what survives a power loss
        return self._sealed_description(fd)

    def _sealed_description(self, fd: int) -> dict:
        sha, size = file_summary(fd)
        t = tail_state(fd, self.node, self.spec.source)
        if t.seq is None:
            raise AuditCorrupt("sealed log file has no valid record")
        return {"seq": t.seq, "hash": t.hash, "sha256": sha, "bytes": size, "damaged": t.damaged, "damaged_sha256": region_digest(fd, t.end, t.damaged) if t.damaged else None}

    def _rotate_locked(self) -> int:
        cur = self._read_current()
        self._ensure_open(cur)
        self._refresh_tail()
        self._repair_tail_locked()                                            # 1: a damaged tail is accounted for BEFORE the file becomes immutable
        prev = self._seal_summary(self._fd)                                   # 2+3
        self._drop()
        self._build_generation(cur + 1, prev)                                 # 4+5
        self._write_current(cur + 1)                                          # 6
        return cur + 1

    # ------------------------------------------------------------------------------------------------------- recovery
    def recover(self) -> list[str]:
        """Finish an interrupted rotation, restore missing flags, remove leftovers; append a `recovery` record when something was done. Raises AuditCorrupt for states it must not fix."""
        with self._mutex:
            self._lock()
            try:
                return self._recover_locked()
            finally:
                self._unlock()

    def _ensure_open(self, cur: int) -> None:                                  # root heals instead of failing
        try:
            super()._ensure_open(cur)
        except AuditDown:
            if self._recovering or self._heal_depth:
                raise
            self._heal_depth += 1
            try:
                self._recover_locked()
                super()._ensure_open(self._read_current())
            finally:
                self._heal_depth -= 1

    def _expected_link_ok(self, rec: dict, n: int, prev: dict | None) -> bool:
        fields, seq, prev_hash = self._chain_link_fields(n, prev)
        if rec.get("type") != "chain_link" or rec["seq"] != seq or rec["prev_hash"] != prev_hash:
            return False
        return all(rec.get(k) == v for k, v in fields.items())

    def _recover_locked(self) -> list[str]:
        if self._recovering:
            return []
        self._recovering = True
        try:
            actions = self._recover_steps()
        finally:
            self._recovering = False
        if actions:
            self._drop()
            self._append_locked("recovery", {"actions": actions})
        return actions

    def _recover_steps(self) -> list[str]:
        s = self.spec
        actions: list[str] = []
        try:
            os.unlink(CURRENT_TMP, dir_fd=self._dfd)
            actions.append("removed a stale CURRENT.tmp")
        except FileNotFoundError:
            pass
        cur = self._read_current()
        gens = self._list_gens()
        if cur is None:
            if not gens:
                raise AuditNotInitialised("audit log is not initialised")
            raise AuditCorrupt("CURRENT is missing but log generations exist")
        if cur not in gens:
            raise AuditCorrupt("CURRENT names a generation that does not exist")
        newest = max(gens)
        if newest > cur + 1:
            raise AuditCorrupt("generations newer than CURRENT + 1 exist")
        actions += self._recover_old_generations(cur, gens)
        st = self._gen_state(cur)
        if not st["file"]:
            raise AuditCorrupt("CURRENT names a generation without a log file")
        gfd, fd = self._open_ro(cur)
        try:
            self._check_file(fd, "log file named by CURRENT")
            fl = fsflags.get_flags(fd)
            if newest == cur + 1:
                if not fsflags.is_sealed(fl):
                    raise AuditCorrupt("a successor generation exists but its predecessor is not sealed")
                prev = self._sealed_description(fd)
                actions += self._complete_successor(cur + 1, prev)
                self._write_current(cur + 1)
                actions.append(f"rotation to generation {cur + 1} completed (CURRENT switched)")
            elif fsflags.is_sealed(fl):
                prev = self._sealed_description(fd)
                self._build_generation(cur + 1, prev)
                self._write_current(cur + 1)
                actions.append(f"rotation to generation {cur + 1} resumed after the seal and completed")
            else:
                if not fsflags.is_append_only(fl):
                    fsflags.add_flags(fd, fsflags.APPEND)
                    actions.append("set the missing append-only flag on the active log file")
                first = os.pread(fd, chain.MAX_RECORD_BYTES + 64, 0).split(b"\n", 1)[0]
                rec = parse_record(first, self.node, s.source)
                if rec is None or rec["type"] != "chain_link":
                    raise AuditCorrupt("CURRENT names a file whose first record is not a valid chain_link")
        finally:
            os.close(gfd)
            os.close(fd)
        return actions

    def _recover_old_generations(self, cur: int, gens: dict) -> list[str]:
        """What a purge interrupted: a directory whose file is already gone (rmdir), or a file whose flags were cleared before its unlink (re-sealed and made reachable again - purge hides the
        directory (0700) before it clears a flag, so nobody can have opened the flagless file for writing)."""
        s = self.spec
        actions: list[str] = []
        for n in sorted(g for g in gens if g < cur):
            st = self._gen_state(n)
            if not st["dir"]:
                continue
            if not st["file"]:
                os.rmdir(gen_name(s.prefix, n), dir_fd=self._dfd)
                os.fsync(self._dfd)
                actions.append(f"removed the empty directory of generation {n} (an interrupted purge)")
                continue
            if not fsflags.is_sealed(st["flags"]):
                if st["dir_mode"] != 0o700:
                    raise AuditCorrupt(f"generation {n} lost its seal while reachable")
                gfd, fd = self._open_ro(n)
                try:
                    fsflags.add_flags(fd, fsflags.APPEND | fsflags.IMMUTABLE)
                    os.fchmod(gfd, s.dir_mode)
                    os.fsync(gfd)
                finally:
                    os.close(gfd)
                    os.close(fd)
                actions.append(f"re-sealed generation {n} (an interrupted purge cleared its flags)")
            elif st["dir_mode"] != s.dir_mode:
                gfd = self._open_gen_dir(n)
                try:
                    os.fchmod(gfd, s.dir_mode)
                    os.fsync(gfd)
                finally:
                    os.close(gfd)
                actions.append(f"made generation {n} reachable again (an interrupted purge hid it)")
        return actions

    def _complete_successor(self, n: int, prev: dict | None) -> list[str]:
        """The state after a crash between the seal and the CURRENT switch: validate or rebuild generation n (unreachable until step 5, so nobody else can have touched it)."""
        s = self.spec
        actions: list[str] = []
        st = self._gen_state(n)
        if st["file"] and st["flags"] & (fsflags.APPEND | fsflags.IMMUTABLE) == 0:
            if st["dir_mode"] != 0o700:
                raise AuditCorrupt(f"generation {n} is reachable but its file has no append-only flag")
            gfd = self._open_gen_dir(n)
            try:
                fd = os.open(gen_file(s.prefix, n), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=gfd)
                try:
                    data = os.pread(fd, 2 * chain.MAX_RECORD_BYTES, 0)
                finally:
                    os.close(fd)
                line = data.split(b"\n", 1)[0] if b"\n" in data else b""
                rec = parse_record(line, self.node, s.source) if line else None
                complete = rec is not None and data == line + b"\n" and self._expected_link_ok(rec, n, prev)
                if not complete:
                    os.unlink(gen_file(s.prefix, n), dir_fd=gfd)             # never reachable, never flagged: removing it is the only way back to a known state
                    actions.append(f"removed the incomplete successor file of generation {n}")
                    st["file"] = False
            finally:
                os.close(gfd)
        if st["dir"] and not st["file"]:
            if st["dir_mode"] != 0o700:
                raise AuditCorrupt("a reachable generation directory without a log file")
            os.rmdir(gen_name(s.prefix, n), dir_fd=self._dfd)
            actions.append(f"removed the empty successor directory of generation {n}")
            st["dir"] = False
        if not st["dir"]:
            self._build_generation(n, prev)
            actions.append(f"built generation {n} from the sealed predecessor")
            return actions
        # file present and (complete and unflagged) or (flagged)
        gfd, fd = self._open_ro(n)
        try:
            self._check_file(fd, "successor log file")
            data = os.pread(fd, 2 * chain.MAX_RECORD_BYTES, 0)
            line = data.split(b"\n", 1)[0] if b"\n" in data else b""
            rec = parse_record(line, self.node, s.source) if line else None
            if rec is None or data != line + b"\n" or not self._expected_link_ok(rec, n, prev):
                raise AuditCorrupt("successor generation does not continue the sealed predecessor (chain_link mismatch)")
            if st["flags"] & fsflags.IMMUTABLE:
                raise AuditCorrupt("successor generation is sealed before it was ever live")
            if not st["flags"] & fsflags.APPEND:
                if st["dir_mode"] != 0o700:
                    raise AuditCorrupt(f"generation {n} is reachable but its file has no append-only flag")
                actions.append(f"set the append-only flag on generation {n}")
            self._finish_generation(gfd, fd)
            if st["dir_mode"] != s.dir_mode:
                actions.append(f"made generation {n} reachable")
        finally:
            os.close(gfd)
            os.close(fd)
        return actions

    # ----------------------------------------------------------------------------------------------------------- purge
    def purge(self, acked_seq: int, now: datetime) -> list[str]:
        """Remove sealed generations that are >= 90 days old (by their last record) and whose last seq is acknowledged by the hub, oldest first, never the active file nor its direct
        predecessor. Flags are cleared through the opened descriptor immediately before unlinkat; every condition is re-read from the file at that moment."""
        if isinstance(acked_seq, bool) or not isinstance(acked_seq, int) or acked_seq < 0:
            raise ValueError("acked_seq must be a non-negative integer")
        s = self.spec
        removed: list[str] = []
        with self._mutex:
            self._lock()
            try:
                cur = self._read_current()
                if cur is None:
                    raise AuditNotInitialised("audit log is not initialised")
                self._ensure_open(cur)
                head = self._refresh_tail().seq
                if acked_seq > head:
                    raise ValueError(f"acked_seq {acked_seq} is beyond the head of the log ({head})")      # a typo must not purge what the hub never acknowledged
                for n in sorted(self._list_gens()):
                    if n >= cur - 1:
                        break
                    gfd = self._open_gen_dir(n)
                    try:
                        try:
                            fd = os.open(gen_file(s.prefix, n), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=gfd)
                        except FileNotFoundError:
                            fd = -1                                                    # the remains of an interrupted purge: the directory only
                        if fd >= 0:
                            try:
                                self._check_file(fd, "purge candidate")
                                if not fsflags.is_sealed(fsflags.get_flags(fd)):
                                    break
                                t = tail_state(fd, self.node, s.source)
                                last = last_record(fd, t, self.node, s.source)
                                if last is None or t.seq > acked_seq:
                                    break
                                age = (now - protocol.parse_ts(last["ts"])).total_seconds()
                                if age < MIN_AGE_PURGE_S:
                                    break
                                os.fchmod(gfd, 0o700)                                  # hidden BEFORE a flag is cleared: nobody can open the flagless file in between (recover() undoes this)
                                fsflags.clear_flags(fd, fsflags.APPEND | fsflags.IMMUTABLE)
                                os.unlink(gen_file(s.prefix, n), dir_fd=gfd)
                            finally:
                                os.close(fd)
                    finally:
                        os.close(gfd)
                    os.rmdir(gen_name(s.prefix, n), dir_fd=self._dfd)
                    os.fsync(self._dfd)
                    removed.append(gen_name(s.prefix, n))
            finally:
                self._unlock()
        return removed

    # --------------------------------------------------------------------------------------------------------- verify
    def verify(self) -> list[str]:
        """Complete verification of every generation on disk under the lock: chain, chain_link continuity (sha256/size/seq/hash of the predecessor and the damage it accounts for),
        flags (sealed except the active one), and that no byte of a file is unaccounted for. Hostile bytes in the agent log are counted but tolerated (`foreign`); in the priv log
        they are a problem."""
        problems: list[str] = []
        s = self.spec
        strict = s.source == "priv"
        with self._mutex:
            self._lock()
            try:
                cur = self._read_current()
                if cur is None:
                    return ["CURRENT missing"]
                prev = None
                for n in sorted(self._list_gens()):
                    try:
                        gfd, fd = self._open_ro(n)
                    except FileNotFoundError:
                        problems.append(f"generation {n}: directory without a log file (an interrupted purge; recover() removes it)")
                        prev = None
                        continue
                    try:
                        fl = fsflags.get_flags(fd)
                        if n < cur and not fsflags.is_sealed(fl):
                            problems.append(f"generation {n}: not sealed")
                        if n == cur and not fsflags.is_live(fl):
                            problems.append(f"generation {n}: active file is not live+append-only")
                        if n > cur:
                            problems.append(f"generation {n}: newer than CURRENT")
                        first = os.pread(fd, chain.MAX_RECORD_BYTES + 64, 0).split(b"\n", 1)[0]
                        rec0 = parse_record(first, self.node, s.source)
                        if prev is None:
                            # genesis file: from seq 1; the oldest file left after a purge: from whatever its chain_link continues
                            start_seq, start_prev = (None, None) if rec0 is None or rec0.get("prev_file") is None else (rec0["seq"], rec0["prev_hash"])
                        else:
                            start_seq, start_prev = prev["head_seq"] + 1, prev["head_hash"]
                            if (rec0 is None or rec0.get("prev_file_sha256") != prev["sha256"] or rec0.get("prev_file_bytes") != prev["size"]
                                    or rec0.get("prev_damaged_bytes") != prev["trailing"] or rec0.get("prev_damaged_sha256") != prev["trailing_sha"]):
                                problems.append(f"generation {n}: chain_link does not match the sealed predecessor file")
                        rep = verify_file(fd, self.node, s.source, start_seq=start_seq, start_prev=start_prev, strict=strict)
                        problems += [f"generation {n}: {p}" for p in rep.problems]
                        if n == cur and rep.trailing_bytes:
                            problems.append(f"generation {n}: {rep.trailing_bytes} damaged bytes at the end of the file (torn write not yet repaired)")
                        sha, size = file_summary(fd)
                        prev = {"head_seq": rep.head_seq, "head_hash": rep.head_hash, "sha256": sha, "size": size, "trailing": rep.trailing_bytes, "trailing_sha": rep.trailing_sha256}
                        if rep.head_seq is None:
                            break
                    finally:
                        os.close(gfd)
                        os.close(fd)
            finally:
                self._unlock()
        return problems
