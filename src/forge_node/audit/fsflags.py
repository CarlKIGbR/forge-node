"""Inode flags of ext4-style filesystems (`chattr`/`lsattr`) through FS_IOC_GETFLAGS / FS_IOC_SETFLAGS on an OPEN descriptor.

Why a module of its own: the audit protocol (gate D) is built on exactly two flags and on what the kernel does with them, observed on a real ext4 (see audit/fsproof.py and the tests):

  * APPEND (+a): open() for writing without O_APPEND fails with EPERM; truncate, chmod, chown, rename, unlink and link fail with EPERM. BUT a descriptor that was opened for writing
    BEFORE +a was set keeps working (pwrite() overwrites in place) - permissions, and this flag, are checked at open(). So a file must never be reachable by a writer before +a is set.
  * IMMUTABLE (+i): every write through ANY descriptor, including one opened earlier with or without O_APPEND, fails with EPERM. This is the seal: it needs no chmod/chown (which the kernel
    refuses on an append-only inode) and is added to an inode that is already +a, so the file is never writable without a flag.

Only read-modify-write helpers are offered, so unrelated flags (extents, ...) are never cleared by accident. Setting either flag needs CAP_LINUX_IMMUTABLE; reading needs none."""
import array
import fcntl
import struct

APPEND = 0x00000020
IMMUTABLE = 0x00000010

_LONG = struct.calcsize("l")
if _LONG != 8:                                            # the request numbers below are the 64-bit ones (_IOR('f', 1, long) / _IOW('f', 2, long))
    raise ImportError("fsflags supports 64-bit Linux only")
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602


def get_flags(fd: int) -> int:
    buf = array.array("i", [0])
    fcntl.ioctl(fd, FS_IOC_GETFLAGS, buf, True)
    return buf[0]


def _set(fd: int, value: int) -> None:
    fcntl.ioctl(fd, FS_IOC_SETFLAGS, array.array("i", [value]))


def add_flags(fd: int, bits: int) -> int:
    new = get_flags(fd) | bits
    _set(fd, new)
    return get_flags(fd)


def clear_flags(fd: int, bits: int) -> int:
    new = get_flags(fd) & ~bits
    _set(fd, new)
    return get_flags(fd)


def is_append_only(flags: int) -> bool:
    return bool(flags & APPEND)


def is_sealed(flags: int) -> bool:
    return flags & (APPEND | IMMUTABLE) == (APPEND | IMMUTABLE)


def is_live(flags: int) -> bool:
    return flags & (APPEND | IMMUTABLE) == APPEND
