"""HTTPS-Server des Hubs (Design 3.2, 5): TLS 1.3, HTTP/1.1, JSON, Bodies <= 1 MiB, Client-Zertifikat (mTLS). Nur stdlib.

Identitaet: Zertifikat gueltig unter der privaten CA (TLS-Handshake) UND SAN-URI urn:forge:node:<id> UND SHA-256 des Zertifikats == node.nodes.cert_sha256 des aktiven Knotens
(bei jeder Anfrage gegen die DB, damit ein Widerruf sofort greift). Ohne Zertifikat ist nur /healthz erreichbar (Vorabtest aus 13.D, ohne Informationsgehalt)."""
import hashlib
import json
import os
import re
import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .. import PROTOCOL_VERSION, __version__, canon, protocol
from ..protocol import ProtoError
from . import files
from .core import AuthError

_SAN_RE = re.compile(r"^urn:forge:node:([a-z0-9][a-z0-9-]{0,31})\Z")
_UUID_RE = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
ROUTES = (
    ("GET", re.compile(r"^/healthz\Z"), "healthz"),
    ("POST", re.compile(r"^/v1/poll\Z"), "poll"),
    ("POST", re.compile(rf"^/v1/jobs/({_UUID_RE})/result\Z"), "result"),
    ("POST", re.compile(r"^/v1/audit\Z"), "audit"),
    ("GET", re.compile(r"^/v1/policy/([0-9]{1,9})\Z"), "policy"),
    ("GET", re.compile(r"^/v1/release/([0-9A-Za-z.+-]{1,64}?)(\.sig)?\Z"), "release"),
)
MAX_CONNECTIONS = 64


def make_ssl_context(cert, key, ca) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(str(cert), str(key))
    ctx.load_verify_locations(str(ca))
    ctx.verify_mode = ssl.CERT_OPTIONAL          # /healthz darf ohne Client-Zertifikat antworten; alles andere verlangt es im Handler
    ctx.options |= ssl.OP_NO_TICKET
    return ctx


class TlsServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, addr, handler, ssl_context):
        super().__init__(addr, handler)
        self.ssl_context = ssl_context
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def process_request_thread(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            request.settimeout(10)
            try:
                request = self.ssl_context.wrap_socket(request, server_side=True)
            except (ssl.SSLError, OSError):
                self.shutdown_request(request)
                return
            request.settimeout(60)
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def _json_bytes(obj) -> bytes:
    return canon.canonical(obj)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "forge-nodehub"
    sys_version = ""
    hub = None       # vom Server gesetzt (Unterklasse)
    cfg = None

    # ---- Verbindung / Identitaet
    def setup(self):
        super().setup()
        self.node_id = None
        self.cert_sha256 = None
        try:
            der = self.connection.getpeercert(binary_form=True)
            cert = self.connection.getpeercert()
        except (ValueError, AttributeError, ssl.SSLError):
            der = cert = None
        if der and cert:
            uris = [v for k, v in cert.get("subjectAltName", ()) if k == "URI"]
            m = [_SAN_RE.match(u) for u in uris]
            if len(uris) == 1 and m[0]:
                self.node_id = m[0].group(1)
                self.cert_sha256 = hashlib.sha256(der).hexdigest()

    def log_message(self, fmt, *args):  # keine Bodies, keine Query-Strings
        sys.stderr.write("nodehub %s %s\n" % (self.node_id or "-", (fmt % args)[:200]))

    # ---- Antworten
    def _send(self, status: int, obj=None, raw: bytes | None = None, ctype="application/json", extra=None):
        body = raw if raw is not None else _json_bytes(obj)
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _err(self, status: int, code: str, detail: str = ""):
        self._send(status, {"error": code, "detail": detail[:200]})

    def _read_json(self):
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            raise ProtoError("BAD_REQUEST", "chunked bodies are not accepted")
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            raise _Http(415, "unsupported_media_type")
        try:
            n = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise _Http(411, "length_required") from None
        if n < 0 or n > protocol.MAX_BODY_BYTES:
            raise _Http(413, "body_too_large")
        data = self.rfile.read(n)
        if len(data) != n:
            raise ProtoError("BAD_REQUEST", "short body")
        try:
            return canon.loads(data)
        except canon.CanonError as e:
            raise ProtoError("BAD_REQUEST", str(e)) from e

    # ---- Dispatch
    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._drain()
        self._err(405, "method_not_allowed")

    do_DELETE = do_PATCH = do_PUT

    def send_error(self, code, message=None, explain=None):
        self.close_connection = True       # Parser-Fehler (unbekannte Methode, kaputte Request-Zeile): nie auf demselben Stream weiterlesen
        super().send_error(code, message, explain)

    def _dispatch(self, method: str):
        path = self.path.split("?", 1)[0]
        route = None
        allowed = False
        for m, rx, name in ROUTES:
            mt = rx.match(path)
            if mt:
                allowed = True
                if m == method:
                    route = (name, mt)
                    break
        if route is None:
            self._drain()
            return self._err(405 if allowed else 404, "method_not_allowed" if allowed else "not_found")
        name, mt = route
        try:
            if name == "healthz":
                return self._send(200, {"ok": True, "hub": "forge-nodehub", "protocol": PROTOCOL_VERSION, "version": __version__})
            if self.node_id is None:
                self._drain()
                return self._err(401, "client_certificate_required")
            with self.server.hub.db.tx() as conn:
                node = self.server.hub.authenticate(conn, self.node_id, self.cert_sha256)
            getattr(self, "_h_" + name)(node, *mt.groups())
        except AuthError:
            self._drain()
            self._err(403, "forbidden")
        except _Http as e:
            self._err(e.status, e.code)
            self.close_connection = True
        except ProtoError as e:
            self._err(400, "bad_request", e.detail or e.code)
        except FileNotFoundError:
            self._err(404, "not_found")
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, socket.timeout):
            self.close_connection = True
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"nodehub internal error on {name}: {type(e).__name__}\n")
            self._err(500, "internal")

    def _drain(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        if 0 < n <= protocol.MAX_BODY_BYTES:
            self.rfile.read(n)
        elif n:
            self.close_connection = True

    # ---- Handler
    def _h_poll(self, node):
        self._send(200, self.server.hub.poll(node["node_id"], self._read_json()))

    def _h_result(self, node, job_id):
        self._send(200, self.server.hub.accept_result(node["node_id"], job_id, self._read_json()))

    def _h_audit(self, node):
        self._send(200, self.server.hub.ingest_audit(node["node_id"], self._read_json()))

    def _h_policy(self, node, serial):
        policy, sig = files.read_policy(self.server.hub.cfg.policy_dir, node["node_id"], serial)
        self._send(200, {"serial": int(serial), "policy": policy.decode("utf-8"), "sig": sig.decode("ascii")})

    def _h_release(self, node, ver, is_sig):
        fd, size = files.open_release(self.server.hub.cfg.release_dir, node["profile"], ver, bool(is_sig))
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            left = size
            while left > 0:
                chunk = os.read(fd, min(left, 1 << 20))
                if not chunk:
                    break
                self.wfile.write(chunk)
                left -= len(chunk)
        finally:
            os.close(fd)


class _Http(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status, self.code = status, code


def make_server(hub, host: str, port: int, ssl_context) -> TlsServer:
    srv = TlsServer((host, port), Handler, ssl_context)
    srv.hub = hub
    return srv
