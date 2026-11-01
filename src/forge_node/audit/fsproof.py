"""Proof, on the filesystem the logs will live on, that the seal protocol works there (gate D; `privctl audit-init` and `doctor` run it on install).

It creates a canary file in a root-only scratch directory INSIDE the given directory (so it is the same filesystem), holds descriptors across the flag changes exactly as a live writer
would, and checks what the kernel does. Every check records what was expected and what happened; `ok` needs all of them. The scratch directory and file are removed at the end
(flags cleared through the open descriptor first). Nothing outside the scratch directory is touched. Needs CAP_LINUX_IMMUTABLE."""
import ctypes
import errno
import fcntl
import os
import secrets

from . import fsflags

EXPECTED_REFUSED = errno.EPERM


def _try(fn) -> int | None:
    """errno of the failure, None when the call succeeded."""
    try:
        fn()
        return None
    except OSError as e:
        return e.errno


def _refused(fn) -> str:
    """'refused' when the call raised (whatever the errno: unsupported counts - the bytes did not change), else 'SUCCEEDED'."""
    return "SUCCEEDED" if _try(fn) is None else "refused"


FALLOC = {"punch_hole": 0x01 | 0x02, "zero_range": 0x10, "collapse_range": 0x08, "insert_range": 0x20}      # FALLOC_FL_*: PUNCH_HOLE|KEEP_SIZE, ZERO_RANGE, COLLAPSE_RANGE, INSERT_RANGE


def _fallocate(fd: int, mode: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.fallocate(fd, mode, ctypes.c_longlong(0), ctypes.c_longlong(1)) != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))


def _clear_append_then_overwrite(fd: int) -> None:
    fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) & ~os.O_APPEND)
    os.pwrite(fd, b"Z", 0)


def _noappend_overwrite(fd: int) -> None:
    flag = getattr(os, "RWF_NOAPPEND", None)
    if flag is None:
        raise OSError(errno.ENOSYS, "RWF_NOAPPEND is not available")
    os.pwritev(fd, [b"Z"], 0, flag)


def _pwrite_leaves_first_byte(fd_append: int, fd_read: int) -> bool:
    """pwrite on an O_APPEND descriptor appends on Linux (the offset is ignored): the first byte of the file must still be what was written first."""
    before = os.pread(fd_read, 1, 0)
    _try(lambda: os.pwrite(fd_append, b"Z", 0))
    return os.pread(fd_read, 1, 0) == before


def _sweep_stale(dfd: int) -> None:
    """A proof killed half-way leaves a `.fsproof-<pid>-*` directory with a +a canary; remove those whose process is gone (flags cleared through the opened descriptor first)."""
    for name in os.listdir(dfd):
        if not name.startswith(".fsproof-"):
            continue
        try:
            pid = int(name.split("-")[1])
            os.kill(pid, 0)
            continue                                                                  # its process lives: not stale
        except ProcessLookupError:
            pass
        except (ValueError, IndexError, PermissionError):
            continue
        try:
            sfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
        except OSError:
            continue
        try:
            if os.fstat(sfd).st_uid != 0:
                continue
            for f in os.listdir(sfd):
                try:
                    cfd = os.open(f, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=sfd)
                except OSError:
                    continue
                try:
                    fsflags.clear_flags(cfd, fsflags.APPEND | fsflags.IMMUTABLE)
                    os.unlink(f, dir_fd=sfd)
                finally:
                    os.close(cfd)
            os.rmdir(name, dir_fd=dfd)
        except OSError:
            pass
        finally:
            os.close(sfd)


def fs_type(path: str) -> str:
    best, typ = "", "unknown"
    real = os.path.realpath(path)
    try:
        with open("/proc/self/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    mp = parts[1].replace("\\040", " ")
                    if (real == mp or real.startswith(mp.rstrip("/") + "/")) and len(mp) > len(best):
                        best, typ = mp, parts[2]
    except OSError:
        pass
    return typ


def prove(directory: str) -> dict:
    checks: dict[str, dict] = {}

    def rec(name: str, expected, got) -> None:
        checks[name] = {"expected": expected, "got": got, "ok": expected == got}

    report = {"fstype": fs_type(directory), "checks": checks, "cleanup": False, "ok": False}
    try:
        dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        rec("directory", "openable", errno.errorcode.get(e.errno, e.errno))
        return report
    _sweep_stale(dfd)
    sub = f".fsproof-{os.getpid()}-{secrets.token_hex(4)}"
    sfd = fd = early_nonappend = early_append = late_append = -1
    try:
        os.mkdir(sub, 0o700, dir_fd=dfd)
        sfd = os.open(sub, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
        fd = os.open("canary", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=sfd)
        os.write(fd, b"canary\n")
        early_nonappend = os.open("canary", os.O_WRONLY | os.O_NOFOLLOW, dir_fd=sfd)                     # opened BEFORE +a, no O_APPEND
        early_append = os.open("canary", os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW, dir_fd=sfd)
        try:
            fl = fsflags.add_flags(fd, fsflags.APPEND)
        except OSError as e:
            rec("set_append_flag", "ok", errno.errorcode.get(e.errno, e.errno))
            return report
        rec("set_append_flag", True, fsflags.is_live(fl))
        # Informational: what a descriptor that predates +a may do is kernel business (today it can still append); the protocol does not rely on either answer - a new log file is unreachable until it is flagged.
        checks["append_through_descriptor_opened_before_flag"] = {"expected": "informational", "got": _try(lambda: os.write(early_append, b"x\n")) is None, "ok": True}
        late_append = os.open("canary", os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=sfd)         # what a live writer holds: opened after +a
        rec("append_through_descriptor_opened_after_flag", None, _try(lambda: os.write(late_append, b"x\n")))
        for name, mode in FALLOC.items():
            rec(f"live_{name}_refused", "refused", _refused(lambda m=mode: _fallocate(late_append, m)))
        rec("live_clear_o_append_then_overwrite_refused", "refused", _refused(lambda: _clear_append_then_overwrite(late_append)))
        rec("live_rwf_noappend_overwrite_refused", "refused", _refused(lambda: _noappend_overwrite(late_append)))
        rec("live_overwrite_via_pwrite_on_append_descriptor_leaves_the_bytes", True, _pwrite_leaves_first_byte(late_append, fd))
        rec("fresh_open_for_write_without_append_refused", EXPECTED_REFUSED, _try(lambda: os.close(os.open("canary", os.O_WRONLY | os.O_NOFOLLOW, dir_fd=sfd))))
        rec("chmod_refused", EXPECTED_REFUSED, _try(lambda: os.fchmod(fd, 0o440)))
        rec("chown_refused", EXPECTED_REFUSED, _try(lambda: os.fchown(fd, os.fstat(fd).st_uid + 1, -1)))
        rec("truncate_refused", EXPECTED_REFUSED, _try(lambda: os.ftruncate(early_append, 0)))
        rec("unlink_refused", EXPECTED_REFUSED, _try(lambda: os.unlink("canary", dir_fd=sfd)))
        rec("rename_refused", EXPECTED_REFUSED, _try(lambda: os.rename("canary", "canary2", src_dir_fd=sfd, dst_dir_fd=sfd)))
        rec("hardlink_refused", EXPECTED_REFUSED, _try(lambda: os.link("canary", "canary3", src_dir_fd=sfd, dst_dir_fd=sfd)))
        # Informational and the reason the new file is never reachable before +a: a descriptor that predates +a keeps its write access.
        checks["preexisting_nonappend_descriptor_can_still_overwrite"] = {"expected": "informational", "got": _try(lambda: os.pwrite(early_nonappend, b"Z", 0)) is None, "ok": True}
        try:
            fl = fsflags.add_flags(fd, fsflags.IMMUTABLE)
        except OSError as e:
            rec("set_immutable_flag", "ok", errno.errorcode.get(e.errno, e.errno))
            return report
        rec("set_immutable_flag", True, fsflags.is_sealed(fl))
        rec("sealed_append_via_old_append_descriptor_refused", EXPECTED_REFUSED, _try(lambda: os.write(early_append, b"y\n")))
        rec("sealed_overwrite_via_old_nonappend_descriptor_refused", EXPECTED_REFUSED, _try(lambda: os.pwrite(early_nonappend, b"Q", 0)))
        rec("sealed_fresh_append_open_refused", EXPECTED_REFUSED, _try(lambda: os.close(os.open("canary", os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW, dir_fd=sfd))))
        rec("sealed_fsync_and_read_still_work", None, _try(lambda: (os.fsync(early_append), os.pread(fd, 10, 0))))
        report["ok"] = all(c["ok"] for c in checks.values())
        return report
    except OSError as e:
        rec("unexpected_error", None, errno.errorcode.get(e.errno, e.errno))
        return report
    finally:
        try:
            if fd >= 0:
                fsflags.clear_flags(fd, fsflags.APPEND | fsflags.IMMUTABLE)
            for c in (early_nonappend, early_append, late_append):
                if c >= 0:
                    os.close(c)
            if sfd >= 0:
                for n in ("canary", "canary2", "canary3"):
                    try:
                        os.unlink(n, dir_fd=sfd)
                    except FileNotFoundError:
                        pass
            if fd >= 0:
                os.close(fd)
            if sfd >= 0:
                os.close(sfd)
            os.rmdir(sub, dir_fd=dfd)
            report["cleanup"] = True
        except OSError:
            report["cleanup"] = False
        os.close(dfd)
        report["ok"] = bool(report["ok"] and report["cleanup"])
