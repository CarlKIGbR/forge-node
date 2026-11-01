"""Hub client (Design 5.2, 5.3): TLS 1.3 only, the hub certificate must chain to the private CA AND its leaf SHA-256 must be one of the signed policy's `hub_tls_pins` - checked right
after the handshake, before a single request byte is sent. A CA-valid certificate that is not pinned (stolen/replaced hub certificate, rotated CA misuse) is refused. The client
presents the node certificate. No redirects, no proxies, responses are size-bounded and strict JSON."""
import hashlib
import hmac
import http.client
import ssl

from .. import canon, protocol

MAX_RESPONSE = protocol.MAX_BODY_BYTES + 4096


class HubError(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(f"hub answered {status} {code}")
        self.status, self.code = status, code


class HubUnreachable(Exception):
    pass


class PinError(HubUnreachable):
    """TLS and CA validation succeeded but the leaf is not pinned in the policy."""


def make_context(node_cert: str, node_key: str, ca_file: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.load_verify_locations(ca_file)
    ctx.load_cert_chain(node_cert, node_key)
    return ctx


def pin_matches(der: bytes | None, pins) -> bool:
    if not der:
        return False
    d = hashlib.sha256(der).hexdigest()
    return any(hmac.compare_digest(d, p) for p in pins)


class _PinnedConnection(http.client.HTTPSConnection):
    def __init__(self, *a, pins, **kw):
        super().__init__(*a, **kw)
        self._pins = tuple(pins)
        self.peer_der: bytes | None = None

    def connect(self):
        super().connect()
        der = self.sock.getpeercert(binary_form=True)
        if not pin_matches(der, self._pins):
            self.close()
            raise PinError("hub certificate is not in the policy's hub_tls_pins")
        self.peer_der = der


class HubClient:
    def __init__(self, host: str, port: int, node_cert: str, node_key: str, ca_file: str, pins, timeout_s: float = 45.0):
        """`pins` is required and must be non-empty: there is no unpinned mode."""
        if not pins:
            raise ValueError("hub_tls_pins must not be empty")
        self.host, self.port, self.pins, self.timeout_s = host, port, tuple(pins), timeout_s
        self._ctx = make_context(node_cert, node_key, ca_file)
        self._conn: _PinnedConnection | None = None

    def close(self):
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def hub_certificate_der(self) -> bytes | None:
        return self._conn.peer_der if self._conn else None

    def _request(self, method: str, path: str, body: dict | None):
        data = canon.canonical(body) if body is not None else None
        if data is not None and len(data) > protocol.MAX_BODY_BYTES:
            raise ValueError("request body too large")
        headers = {"Content-Type": "application/json", "Accept": "application/json"} if data is not None else {"Accept": "application/json"}
        for attempt in (1, 2):
            if self._conn is None:
                self._conn = _PinnedConnection(self.host, self.port, context=self._ctx, timeout=self.timeout_s, pins=self.pins)
            try:
                self._conn.request(method, path, body=data, headers=headers)
                resp = self._conn.getresponse()
                raw = resp.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
                    self.close()
                    raise HubUnreachable("response too large")
                if resp.getheader("Connection", "").lower() == "close":
                    self.close()
                break
            except PinError:
                self.close()
                raise
            except (OSError, http.client.HTTPException, ssl.SSLError) as e:
                self.close()
                if attempt == 2 or isinstance(e, ssl.SSLCertVerificationError):
                    raise HubUnreachable(f"{type(e).__name__}") from e
        try:
            doc = canon.loads(raw)
        except canon.CanonError as e:
            raise HubUnreachable("hub answered non-JSON") from e
        if resp.status != 200:
            raise HubError(resp.status, str(doc.get("error", "error"))[:60] if isinstance(doc, dict) else "error")
        if not isinstance(doc, dict):
            raise HubUnreachable("unexpected response shape")
        return doc

    def healthz(self) -> dict:
        """Connection test (Design 13.D): TLS 1.3, chain, name and the leaf PIN are all checked before the first byte; /healthz needs no registration."""
        return self._request("GET", "/healthz", None)

    def poll(self, body: dict) -> dict:
        return self._request("POST", "/v1/poll", body)

    def post_audit(self, body: dict) -> dict:
        return self._request("POST", "/v1/audit", body)

    def post_result(self, job_id: str, body: dict) -> dict:
        return self._request("POST", f"/v1/jobs/{protocol.check_uuid(job_id)}/result", body)

    def get_policy(self, serial: int) -> dict:
        if isinstance(serial, bool) or not isinstance(serial, int) or not 1 <= serial <= 10**9 - 1:
            raise ValueError("serial")
        return self._request("GET", f"/v1/policy/{serial}", None)
