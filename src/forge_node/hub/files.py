"""Signierte Policy-/Release-Dateien ausliefern (Design 3.2). Der Hub PRUEFT nichts davon und hat keinen Endpunkt, der Policy aendert: er liest Dateien, die der Owner abgelegt hat.
Layout: <policy_dir>/<node>/policy-<serial>.json + .sig ; <release_dir>/forge-node-<ver>-<profile>.tar + .tar.sig. Zugriff nur ueber dirfd + O_NOFOLLOW + fstat (regulaere Datei, Groessenlimit)."""
import os
import re
import stat

from ..protocol import ProtoError

MAX_POLICY_BYTES = 1024 * 1024
MAX_RELEASE_BYTES = 256 * 1024 * 1024
_SERIAL_RE = re.compile(r"^[1-9][0-9]{0,8}\Z")
_POLICY_NAME = re.compile(r"^policy-([1-9][0-9]{0,8})\.json\Z")
_VER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.]{1,32})?\Z")


def _open_dir(path):
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def _read_regular(dirfd: int, name: str, limit: int) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dirfd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > limit:
            raise FileNotFoundError("not a servable file")
        chunks, left = [], st.st_size
        while left > 0:
            b = os.read(fd, min(left, 1 << 20))
            if not b:
                break
            chunks.append(b)
            left -= len(b)
        return b"".join(chunks)
    finally:
        os.close(fd)


def latest_serial(policy_dir, node: str) -> int:
    try:
        d = _open_dir(os.path.join(policy_dir, node))
    except OSError:
        return 0
    try:
        best = 0
        for n in os.listdir(d):
            m = _POLICY_NAME.match(n)
            if m:
                try:
                    os.stat(n + ".sig", dir_fd=d, follow_symlinks=False)
                except OSError:
                    continue
                best = max(best, int(m.group(1)))
        return best
    finally:
        os.close(d)


def read_policy(policy_dir, node: str, serial: str) -> tuple[bytes, bytes]:
    if not _SERIAL_RE.match(serial or ""):
        raise ProtoError("BAD_REQUEST", "serial")
    try:
        d = _open_dir(os.path.join(policy_dir, node))
    except OSError as e:
        raise FileNotFoundError("policy") from e
    try:
        return _read_regular(d, f"policy-{serial}.json", MAX_POLICY_BYTES), _read_regular(d, f"policy-{serial}.json.sig", 16 * 1024)
    except OSError as e:
        raise FileNotFoundError("policy") from e
    finally:
        os.close(d)


def open_release(release_dir, profile: str, ver: str, sig: bool) -> tuple[int, int]:
    """(fd, size) einer regulaeren Release-Datei; der Aufrufer streamt und schliesst den fd."""
    if not _VER_RE.match(ver or "") or profile not in ("full", "t0"):
        raise ProtoError("BAD_REQUEST", "version")
    name = f"forge-node-{ver}-{profile}.tar" + (".sig" if sig else "")
    try:
        d = _open_dir(release_dir)
    except OSError as e:
        raise FileNotFoundError("release") from e
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=d)
    except OSError as e:
        raise FileNotFoundError("release") from e
    finally:
        os.close(d)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > (16 * 1024 if sig else MAX_RELEASE_BYTES):
        os.close(fd)
        raise FileNotFoundError("release")
    return fd, st.st_size
