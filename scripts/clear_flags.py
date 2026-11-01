#!/usr/bin/env python3
"""Test-harness cleanup: clear the append-only / immutable inode flags below a directory and remove it. Used by scripts/run-tests.sh (inside the throw-away test container, which
alone holds CAP_LINUX_IMMUTABLE) so that a failed or killed audit test can never leave files in /tmp that the host user cannot delete. Never run on anything but a test directory.

    clear_flags.py <directory-to-empty> [--remove-self]"""
import array
import fcntl
import os
import shutil
import sys

GET, SET = 0x80086601, 0x40086602
BITS = 0x20 | 0x10


def clear(path: str) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return
    try:
        b = array.array("i", [0])
        fcntl.ioctl(fd, GET, b, True)
        if b[0] & BITS:
            b[0] &= ~BITS
            fcntl.ioctl(fd, SET, b)
    except OSError:
        pass
    finally:
        os.close(fd)


def main(argv) -> int:
    root = argv[1]
    if not os.path.isdir(root) or os.path.islink(root):
        return 0
    for d, dirs, files in os.walk(root, followlinks=False):
        for n in dirs + files:
            p = os.path.join(d, n)
            if not os.path.islink(p):
                clear(p)
        clear(d)
    for n in os.listdir(root):
        p = os.path.join(root, n)
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p, ignore_errors=True)
        else:
            try:
                os.unlink(p)
            except OSError:
                pass
    if "--remove-self" in argv:
        try:
            os.rmdir(root)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
