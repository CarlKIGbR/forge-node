"""Agent <-> privd contract for root-only T0 reads (Design 3.3 request `t0`). One JSON line each way over the root-owned Unix socket. The request names a probe and carries a small
parameter object; privd (N3) runs `handle_request` inside its `gate()` for the reduced T0 pipeline and starts the probe in a unit of class `ro-probe`. The probe code decides everything
that matters from the root-installed policy - a request can name a probe but never widen what it may read."""
import socket
import struct

from .. import canon
from . import probes
from .env import Env

MAX_LINE = 512 * 1024
PROBE_TIMEOUT_S = 250          # longest probe (RuntimeMaxSec 240) plus a little; one agent job runs inline, so the heartbeat gap stays below the hub's 5-minute alert


class ProbeUnavailable(Exception):
    """privd not reachable, wrong peer, or protocol violation: the section reports `unavailable`, T0 continues."""


class ProbeDenied(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


def encode_request(probe: str, params: dict) -> bytes:
    return canon.canonical({"req": "t0", "probe": probe, "params": params}) + b"\n"


def _decode_line(line: bytes):
    if not line.endswith(b"\n") or len(line) > MAX_LINE:
        raise ValueError("malformed line")
    return canon.loads(line[:-1])


def handle_request(line: bytes, env: Env) -> bytes:
    """privd side. Never raises for a bad request: answers {ok:false, code}."""
    try:
        req = _decode_line(line)
        if not isinstance(req, dict) or set(req) != {"req", "probe", "params"} or req["req"] != "t0" or not isinstance(req["probe"], str):
            raise ValueError("bad request shape")
    except (ValueError, canon.CanonError):
        return canon.canonical({"ok": False, "code": "BAD_REQUEST", "detail": "malformed request"}) + b"\n"
    try:
        data = probes.run_probe(req["probe"], req["params"], env)
        return canon.canonical({"ok": True, "data": data}) + b"\n"
    except probes.ProbeError as e:
        return canon.canonical({"ok": False, "code": e.code, "detail": e.detail[:200]}) + b"\n"
    except Exception as e:  # noqa: BLE001 - a probe bug must not take privd down; the agent sees a generic failure
        return canon.canonical({"ok": False, "code": "FAIL_EXEC", "detail": type(e).__name__}) + b"\n"


class SocketProbeClient:
    """Agent side. `expect_uid` is required: the peer of the socket must be that uid (0 in production), checked with SO_PEERCRED on every connection before anything is sent."""

    def __init__(self, path: str, expect_uid: int, timeout_s: float = PROBE_TIMEOUT_S):
        self.path, self.expect_uid, self.timeout_s = path, expect_uid, timeout_s

    def call(self, probe: str, params: dict) -> dict:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout_s)
        try:
            try:
                s.connect(self.path)
                pid, uid, gid = struct.unpack("3i", s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            except OSError as e:
                raise ProbeUnavailable(f"privd socket unreachable ({type(e).__name__})") from e
            if uid != self.expect_uid:
                raise ProbeUnavailable("socket peer is not the expected user")
            try:
                s.sendall(encode_request(probe, params))
                buf = bytearray()
                while not buf.endswith(b"\n"):
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf.extend(chunk)
                    if len(buf) > MAX_LINE:
                        raise ProbeUnavailable("response too large")
            except OSError as e:
                raise ProbeUnavailable(f"privd I/O error ({type(e).__name__})") from e
            try:
                resp = _decode_line(bytes(buf))
            except (ValueError, canon.CanonError) as e:
                raise ProbeUnavailable("malformed response") from e
            if not isinstance(resp, dict) or not isinstance(resp.get("ok"), bool):
                raise ProbeUnavailable("malformed response")
            if resp["ok"]:
                if not isinstance(resp.get("data"), dict):
                    raise ProbeUnavailable("malformed response")
                return resp["data"]
            raise ProbeDenied(str(resp.get("code", "FAIL_EXEC"))[:40], str(resp.get("detail", ""))[:200])
        finally:
            s.close()
