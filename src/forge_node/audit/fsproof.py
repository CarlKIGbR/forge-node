"""Proof, on the filesystem the logs will live on, that the seal protocol works there (gate D; `privctl audit-init` and `doctor` run it on install).

It creates a canary file in a root-only scratch directory INSIDE the given directory (so it is the same filesystem), holds descriptors across the flag changes exactly as a live writer
would, and checks what the kernel does. Every check records what was expected and what happened; `ok` needs all of them. The scratch directory and file are removed at the end
(flags cleared through the open descriptor first). Nothing outside the scratch directory is touched. Needs CAP_LINUX_IMMUTABLE."""
import errno
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
    sub = f".fsproof-{os.getpid()}-{secrets.token_hex(4)}"
    sfd = fd = early_nonappend = early_append = -1
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
        rec("append_through_descriptor_opened_before_flag", None, _try(lambda: os.write(early_append, b"x\n")))
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
            for c in (early_nonappend, early_append):
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
