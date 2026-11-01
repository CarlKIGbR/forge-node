"""privd's socket front end (Design 3.3): a Unix-domain stream socket, one JSON line per request and per reply. Mode 0660 root:forgenode (set by the .socket unit); the peer's
credentials come from SO_PEERCRED - the kernel's word, not the client's - and go into the Request. The request set is CLOSED: exec, lease.put, t0, status, selfcheck, reconcile,
policy.apply, audit.rotate, lockdown. Each handler does nothing but hand its request to gate(); no handler has an effect of its own."""
import os
import socket
import struct
import threading

from .. import canon
from .core import KINDS, Context, Peer, Request
from .gate import gate

MAX_REQUEST_BYTES = 512 * 1024
READ_TIMEOUT_S = 10.0
MAX_CONNECTIONS = 32
MAINTENANCE_EVERY_S = 3600.0
HANDLERS = {"exec": "handle_exec", "lease.put": "handle_lease_put", "t0": "handle_t0", "status": "handle_status", "selfcheck": "handle_selfcheck", "reconcile": "handle_reconcile",
            "policy.apply": "handle_policy_apply", "audit.rotate": "handle_audit_rotate", "lockdown": "handle_lockdown"}
assert set(HANDLERS) == set(KINDS)


def _err(code: str, detail: str) -> bytes:
    return canon.canonical({"ok": False, "code": code, "detail": detail}) + b"\n"


class Server:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self._sem = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self._stop = threading.Event()

    # ---- the nine handlers: closed set, one gate() call each --------------------------------------------------------------------
    def handle_exec(self, peer: Peer, body: dict) -> dict:
        return gate(self.ctx, Request("exec", peer, body))

    def handle_lease_put(self, peer: Peer, body: dict) -> dict:
        return gate(self.ctx, Request("lease.put", peer, body))

    def handle_t0(self, peer: Peer, body: dict) -> dict:
        return gate(self.ctx, Request("t0", peer, body))

    def handle_status(self, peer: Peer, body: dict) -> dict:
        return gate(self.ctx, Request("status", peer, body))

    def handle_selfcheck(self, peer: Peer, body: dict) -> dict:
        return gate(self.ctx, Request("selfcheck", peer, body))

    def handle_reconcile(self, peer: Peer, body: dict) -> dict:
        return gate(self.ctx, Request("reconcile", peer, body))

    def handle_policy_apply(self, peer: Peer, body: dict) -> dict:
        return gate(self.ctx, Request("policy.apply", peer, body))

    def handle_audit_rotate(self, peer: Peer, body: dict) -> dict:
        return gate(self.ctx, Request("audit.rotate", peer, body))

    def handle_lockdown(self, peer: Peer, body: dict) -> dict:
        return gate(self.ctx, Request("lockdown", peer, body))

    # ---- transport --------------------------------------------------------------------------------------------------------------
    def dispatch(self, line: bytes, peer: Peer) -> bytes:
        """One request line -> one reply line. Never raises."""
        try:
            if not line.endswith(b"\n") or len(line) > MAX_REQUEST_BYTES:
                return _err("BAD_REQUEST", "malformed request line")
            doc = canon.loads(line[:-1])
            kind = doc.get("req") if isinstance(doc, dict) else None
            name = HANDLERS.get(kind) if isinstance(kind, str) else None
            if name is None:
                return _err("DENY_OP_UNKNOWN", "unknown request kind")
            body = {k: v for k, v in doc.items() if k != "req"}
        except (canon.CanonError, ValueError, TypeError):
            return _err("BAD_REQUEST", "request is not strict JSON")
        try:
            return canon.canonical(getattr(self, name)(peer, body)) + b"\n"
        except Exception:  # noqa: BLE001 - gate() does not raise; this is the last line of defence
            return _err("FAIL_EXEC", "internal error")

    @staticmethod
    def peer_of(conn: socket.socket) -> Peer:
        pid, uid, gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        return Peer(pid, uid, gid)

    def serve_connection(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(READ_TIMEOUT_S)
            peer = self.peer_of(conn)
            buf = bytearray()
            while not buf.endswith(b"\n"):
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buf += chunk
                if len(buf) > MAX_REQUEST_BYTES:
                    conn.sendall(_err("BAD_REQUEST", "request too large"))
                    return
            conn.settimeout(None)
            conn.sendall(self.dispatch(bytes(buf), peer))
        except (OSError, struct.error):
            pass
        finally:
            try:
                conn.close()
            finally:
                self._sem.release()

    def serve(self, listener: socket.socket) -> None:
        from . import maintenance
        listener.settimeout(0.5)
        next_prune = self.ctx.monotonic() + MAINTENANCE_EVERY_S
        while not self._stop.is_set():
            if self.ctx.monotonic() >= next_prune:
                next_prune = self.ctx.monotonic() + MAINTENANCE_EVERY_S
                try:
                    maintenance.prune(self.ctx)
                except Exception:  # noqa: BLE001 - housekeeping must never take the socket down
                    pass
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not self._sem.acquire(blocking=False):
                try:
                    conn.sendall(_err("DENY_RATE", "too many connections"))
                finally:
                    conn.close()
                continue
            threading.Thread(target=self.serve_connection, args=(conn,), daemon=True).start()

    def stop(self) -> None:
        self._stop.set()


def listen(path: str, gid: int) -> socket.socket:
    """Standalone listening socket (tests and manual runs; production gets the socket from forge-node-privd.socket). 0660 root:gid, in a root-owned directory."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o117)
    try:
        s.bind(path)
    finally:
        os.umask(old)
    os.chown(path, 0, gid)
    s.listen(64)
    return s
