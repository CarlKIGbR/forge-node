"""Guarded filesystem access for T0 (Design 4.1, 10.4, 8.2 path rules). Two kinds of access, both through `Fs`:

  * content reads of an ALLOWLISTED set of kernel/system files (/proc, /sys, os-release, ...). A content read below the protected set is refused outright.
  * metadata (stat, directory names, sizes, mtimes) of policy-named directories - allowed for protected areas (Design 10.4 "frozen = metadata only"), never file contents.

Every walk is component-wise with O_NOFOLLOW from a directory fd; the file is fstat-ed (regular file, size cap) after it is opened. `Fs.root` only relocates the logical tree for tests
(the logical path, not the relocated one, is what the allowlist and the protected set see)."""
import errno
import os
import posixpath
import re
import stat as st_mod
from dataclasses import dataclass

DEFAULT_PROTECTED = ("/opt/kmu-ai", "/srv/models", "/srv/kmu-ai", "/srv/tradebot", "/etc/ssh", "/etc/sudoers", "/etc/sudoers.d", "/etc/forge-node", "/root")
READ_ALLOW = (
    re.compile(r"^/proc/(?:self/)?(?:meminfo|loadavg|uptime|stat|cpuinfo|diskstats|mdstat|swaps|mounts|net/dev|net/route|sys/kernel/(?:osrelease|hostname|random/boot_id))\Z"),
    re.compile(r"^/proc/[0-9]{1,9}/(?:cgroup|net/dev|comm)\Z"),
    re.compile(r"^/sys/fs/cgroup/(?:[A-Za-z0-9_.@:\\-]+/){0,4}(?:cpu\.stat|memory\.current|memory\.max|memory\.peak|io\.stat|pids\.current|cgroup\.procs)\Z"),
    re.compile(r"^/sys/class/(?:nvme|hwmon|thermal|net)/[A-Za-z0-9_.:-]+/(?:[A-Za-z0-9_.:-]+/)?(?:model|state|transport|temp[0-9]*_input|name|type|temp|operstate|speed|statistics/(?:rx|tx)_bytes)\Z"),
    re.compile(r"^/sys/block/[A-Za-z0-9]+/(?:queue/rotational|size|removable)\Z"),
    re.compile(r"^/sys/bus/pci/devices/[0-9a-f:.]+/(?:current_link_speed|current_link_width|max_link_speed|max_link_width)\Z"),
    re.compile(r"^/etc/(?:os-release|passwd|group|ufw/ufw\.conf|timezone)\Z"),
    re.compile(r"^/usr/lib/os-release\Z"),                                   # what /etc/os-release points to on Debian/Ubuntu
    re.compile(r"^/(?:var/)?run/reboot-required(?:\.pkgs)?\Z"),
    re.compile(r"^/var/log/unattended-upgrades/(?:unattended-upgrades|unattended-upgrades-dpkg)\.log\Z"),
)
_MAX_READ = 1024 * 1024


class FsError(Exception):
    """Raised for refused or failed access; `code` is a short machine-readable reason ('protected', 'not_allowed', 'unreadable', 'not_regular', 'too_large', 'escape')."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


def norm_abs(p: str) -> str:
    if not isinstance(p, str) or not p.startswith("/") or "\x00" in p or len(p) > 4096:
        raise FsError("not_allowed", "path must be absolute")
    n = posixpath.normpath(p)
    if n.startswith("//"):
        n = n[1:]
    return n


def under(path: str, base: str) -> bool:
    return path == base or path.startswith(base.rstrip("/") + "/")


@dataclass(frozen=True)
class ProtectedSet:
    paths: tuple[str, ...]

    @classmethod
    def from_policy(cls, policy_paths) -> "ProtectedSet":
        """Built-in minimum (Design 7.4) united with the policy's list: a policy can add to the protected set, never take a built-in away."""
        return cls(tuple(sorted({norm_abs(p) for p in DEFAULT_PROTECTED} | {norm_abs(p) for p in policy_paths})))

    def hit(self, logical_real: str) -> str | None:
        for p in self.paths:
            if under(logical_real, p):
                return p
        return None


class Fs:
    def __init__(self, protected: ProtectedSet, root: str = "/"):
        self.protected, self.root = protected, root.rstrip("/") or "/"

    # ------------------------------------------------------------------------------------------------------------------ walking
    def _actual(self, logical: str) -> str:
        return logical if self.root == "/" else self.root + logical

    def _walk_open(self, logical: str, want_dir: bool) -> int:
        """Open `logical` component by component with O_NOFOLLOW. A symlink anywhere on the way is refused (FsError 'escape'), the kernel's own /proc and /sys layout has none
        of the paths we allow except cgroup mounts, which are real directories."""
        logical = norm_abs(logical)
        fd = os.open(self._actual("/") if self.root == "/" else self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            parts = [p for p in logical.split("/") if p]
            for i, name in enumerate(parts):
                last = i == len(parts) - 1
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
                if not last or want_dir:
                    flags |= os.O_DIRECTORY
                try:
                    nfd = os.open(name, flags, dir_fd=fd)
                except OSError as e:
                    if e.errno in (errno.ELOOP, errno.EMLINK) or (e.errno == errno.ENOTDIR and self._is_symlink(fd, name)):
                        raise FsError("escape", "symlink on path") from e
                    raise FsError("unreadable", errno.errorcode.get(e.errno, "OSError")) from e
                os.close(fd)
                fd = nfd
            return fd
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def _is_symlink(dirfd: int, name: str) -> bool:
        try:
            return st_mod.S_ISLNK(os.stat(name, dir_fd=dirfd, follow_symlinks=False).st_mode)
        except OSError:
            return False

    # ------------------------------------------------------------------------------------------------------------ content reads
    def _resolve_for_read(self, logical: str) -> str:
        """Symlinks are everywhere on real hosts (/etc/os-release -> ../usr/lib/os-release, /proc/net -> self/net, /var/run -> /run, /sys/class/* -> /sys/devices/*): the REQUESTED path
        must be allowlisted, it is resolved, and the RESOLVED path must be allowlisted too (anything pointing elsewhere is 'escape'). The file is then opened without following links."""
        logical = norm_abs(logical)
        if not any(rx.match(logical) for rx in READ_ALLOW):
            raise FsError("not_allowed", logical)
        real = self.resolve_dir(logical)
        if logical.startswith("/sys/"):
            if not real.startswith("/sys/"):
                raise FsError("escape", logical)
        elif not any(rx.match(real) for rx in READ_ALLOW):
            raise FsError("escape", f"{logical} -> {real}")
        if self.protected.hit(logical) or self.protected.hit(real):
            raise FsError("protected", logical)
        return real

    def read_text(self, logical: str, limit: int = _MAX_READ) -> str:
        """Content of an allowlisted file. /proc and /sys files report size 0, so they are read in chunks up to `limit`."""
        real = self._resolve_for_read(logical)
        fd = self._walk_open(real, want_dir=False)
        try:
            st = os.fstat(fd)
            if not st_mod.S_ISREG(st.st_mode):
                raise FsError("not_regular", real)
            if st.st_size > limit and not (real.startswith("/proc/") or real.startswith("/sys/")):
                return self._read_tail(fd, st.st_size, limit)
            chunks, left = [], limit + 1
            while left > 0:
                b = os.read(fd, min(left, 65536))
                if not b:
                    break
                chunks.append(b)
                left -= len(b)
            data = b"".join(chunks)
            if len(data) > limit:
                raise FsError("too_large", real)
            return data.decode("utf-8", "replace")
        finally:
            os.close(fd)

    @staticmethod
    def _read_tail(fd: int, size: int, limit: int) -> str:
        """Large log files: the newest `limit` bytes, cut to a line boundary."""
        os.lseek(fd, size - limit, os.SEEK_SET)
        data = os.read(fd, limit)
        nl = data.find(b"\n")
        return data[nl + 1:].decode("utf-8", "replace") if nl >= 0 else data.decode("utf-8", "replace")

    def exists(self, logical: str) -> bool:
        try:
            fd = self._walk_open(self._resolve_for_read(logical), want_dir=False)
        except FsError:
            return False
        os.close(fd)
        return True

    def exists_unfiltered(self, logical: str) -> bool:
        """lstat existence of a policy-derived path (no allowlist: used for layout checks like .git/commondir). Never opens it."""
        try:
            os.lstat(self._actual(norm_abs(logical)))
            return True
        except (OSError, FsError):
            return False

    # ----------------------------------------------------------------------------------------------------------------- metadata
    def resolve_dir(self, logical: str) -> str:
        """Logical realpath of a policy-named directory/file, computed on the (relocated) tree and checked to stay below the root. Symlinks ARE followed here (policy paths such as
        /etc/letsencrypt/live/x -> ../../archive/x are legitimate) - the result, not the name, is what the protected set and later reads see."""
        logical = norm_abs(logical)
        real = os.path.realpath(self._actual(logical))
        if self.root != "/":
            if not (real == self.root or real.startswith(self.root + "/")):
                raise FsError("escape", logical)
            real = real[len(self.root):] or "/"
        return real

    def stat_meta(self, logical_real: str) -> dict:
        """lstat of one entry: kind, size, mtime, uid/gid, mode. No contents."""
        try:
            s = os.lstat(self._actual(norm_abs(logical_real)))
        except OSError as e:
            raise FsError("unreadable", type(e).__name__) from e
        kind = "dir" if st_mod.S_ISDIR(s.st_mode) else "file" if st_mod.S_ISREG(s.st_mode) else "link" if st_mod.S_ISLNK(s.st_mode) else "other"
        return {"kind": kind, "size": s.st_size, "mtime": int(s.st_mtime), "uid": s.st_uid, "gid": s.st_gid, "mode": st_mod.S_IMODE(s.st_mode), "dev": s.st_dev}

    def list_meta(self, logical_real: str, max_entries: int = 2000) -> tuple[list[dict], bool]:
        """Names + metadata of a directory's entries (depth 1). Returns (entries, truncated). Never opens a file. The directory is reached with an O_NOFOLLOW walk and listed through
        its descriptor: a component swapped for a symlink after resolve_dir() is refused instead of followed (and cannot lead the listing outside the protected set)."""
        base = norm_abs(logical_real)
        out: list[dict] = []
        dfd = self._walk_open(base, want_dir=True)
        try:
            with os.scandir(dfd) as it:
                for e in it:
                    if len(out) >= max_entries:
                        return sorted(out, key=lambda x: x["name"]), True
                    try:
                        s = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    kind = "dir" if st_mod.S_ISDIR(s.st_mode) else "file" if st_mod.S_ISREG(s.st_mode) else "link" if st_mod.S_ISLNK(s.st_mode) else "other"
                    out.append({"name": e.name, "kind": kind, "size": s.st_size, "mtime": int(s.st_mtime), "dev": s.st_dev})
        except OSError as e:
            raise FsError("unreadable", type(e).__name__) from e
        finally:
            os.close(dfd)
        return sorted(out, key=lambda x: x["name"]), False

    def read_exception(self, logical: str, allowed_names: re.Pattern, limit: int = 64 * 1024) -> str:
        """The documented metadata exception of Design 10.4 (git revision of a protected repo): read ONE file whose path matches `allowed_names` below a policy-named directory,
        even inside the protected set. The pattern is supplied by the (reviewed) caller module, never by a request."""
        logical = norm_abs(logical)
        if not allowed_names.match(logical):
            raise FsError("not_allowed", logical)
        fd = self._walk_open(logical, want_dir=False)
        try:
            st = os.fstat(fd)
            if not st_mod.S_ISREG(st.st_mode):
                raise FsError("not_regular", logical)
            if st.st_size > limit:
                raise FsError("too_large", logical)
            return os.read(fd, limit).decode("utf-8", "replace")
        finally:
            os.close(fd)

    def read_user_file(self, logical: str, limit: int = 256 * 1024) -> str:
        """Root-side read of a file in a user-controlled location (authorized_keys): every component O_NOFOLLOW, regular file, size cap. Used by the access probe."""
        logical = norm_abs(logical)
        fd = self._walk_open(logical, want_dir=False)
        try:
            st = os.fstat(fd)
            if not st_mod.S_ISREG(st.st_mode) or st.st_size > limit:
                raise FsError("not_regular", logical)
            return os.read(fd, limit).decode("utf-8", "replace")
        finally:
            os.close(fd)
