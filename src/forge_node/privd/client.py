"""Socket client for privd requests (agent and privctl). The peer of the socket must be the expected uid (0), checked with SO_PEERCRED BEFORE anything is sent: a squatter on the
socket path never receives a policy blob, a lease or a job."""
import socket
import struct

from .. import canon

MAX_REPLY = 1024 * 1024


class PrivUnavailable(Exception):
    pass


class PrivClient:
    def __init__(self, path: str, expect_uid: int, timeout_s: float):
        self.path, self.expect_uid, self.timeout_s = path, expect_uid, timeout_s

    def request(self, kind: str, body: dict, timeout_s: float | None = None) -> dict:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout_s if timeout_s is None else timeout_s)
        try:
            try:
                s.connect(self.path)
                pid, uid, gid = struct.unpack("3i", s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            except OSError as e:
                raise PrivUnavailable(f"privd socket unreachable ({type(e).__name__})") from e
            if uid != self.expect_uid:
                raise PrivUnavailable("socket peer is not the expected user")
            try:
                s.sendall(canon.canonical({"req": kind, **body}) + b"\n")
                buf = bytearray()
                while not buf.endswith(b"\n"):
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                    if len(buf) > MAX_REPLY:
                        raise PrivUnavailable("reply too large")
            except OSError as e:
                raise PrivUnavailable(f"privd I/O error ({type(e).__name__})") from e
            try:
                doc = canon.loads(bytes(buf).rstrip(b"\n"))
            except canon.CanonError as e:
                raise PrivUnavailable("malformed reply") from e
            if not isinstance(doc, dict) or not isinstance(doc.get("ok"), bool):
                raise PrivUnavailable("malformed reply")
            return doc
        finally:
            s.close()
