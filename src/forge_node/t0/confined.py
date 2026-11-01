"""Confined file creation (G27): every write whose path has a component that does not come from our own constants goes through a directory descriptor. Components are validated one by one
(no '', '.', '..', '/', NUL, backslash, anything outside a conservative charset) and each step is `mkdirat`/`openat` relative to the descriptor with O_NOFOLLOW (and O_EXCL for files), so a
name cannot select a path outside the directory it is written under - not by being absolute (`os.path.join` would discard the prefix), not by `..`, not through a symlink that is there."""
import os
import re

COMPONENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,99}\Z")


class ConfinementError(ValueError):
    pass


def open_dir(path: str) -> int:
    """Directory descriptor for a directory we created or own; a symlink as the last component is refused."""
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def _check(parts) -> list[str]:
    parts = list(parts)
    if not parts:
        raise ConfinementError("empty path")
    for p in parts:
        if not isinstance(p, str) or not COMPONENT.match(p):
            raise ConfinementError(f"path component refused: {p!r}")
    return parts


def mkdirs_at(dirfd: int, parts) -> int:
    """Create (if needed) and open the chain `parts` below `dirfd`; returns a NEW descriptor the caller closes. `dirfd` stays open and is not consumed."""
    fd = os.dup(dirfd)
    try:
        for p in _check(parts):
            try:
                os.mkdir(p, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            nfd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def write_new_at(dirfd: int, parts, data: bytes, mode: int = 0o600) -> None:
    """Create the file `parts` below `dirfd` (parent directories as needed) and write `data`. The file must not exist (O_EXCL) and is never a link (O_NOFOLLOW)."""
    parts = _check(parts)
    parent = mkdirs_at(dirfd, parts[:-1]) if len(parts) > 1 else os.dup(dirfd)
    try:
        fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def replace_at(dirfd: int, src: str, dst: str) -> None:
    _check([src, dst])
    os.replace(src, dst, src_dir_fd=dirfd, dst_dir_fd=dirfd)
