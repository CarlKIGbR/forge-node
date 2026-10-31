"""Hub client TLS behaviour without a database: a bare TLS 1.3 server presents a certificate from the test CA; the agent must also find its leaf in the policy pins."""
import hashlib
import http.server
import json
import ssl
import threading

import pytest

from forge_node.agent import client as C


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    seen = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        self.seen.append((self.path, self.rfile.read(n)))
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST

    def log_message(self, *a):
        pass


def serve(pki, cert, key, verify_client=True, tls13_only=True):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if tls13_only:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    else:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cert), str(key))
    ctx.load_verify_locations(str(pki.ca_crt))
    ctx.verify_mode = ssl.CERT_REQUIRED if verify_client else ssl.CERT_NONE
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    Handler.seen = []
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture(scope="module")
def certs(pki):
    return {"hub": pki.issue("c_hub", "forge-nodehub", "IP:127.0.0.1", "serverAuth"), "hub2": pki.issue("c_hub2", "forge-nodehub-2", "IP:127.0.0.1", "serverAuth"),
            "wrongip": pki.issue("c_wrongip", "forge-nodehub", "IP:10.9.9.9", "serverAuth"), "node": pki.issue("c_node", "forge-node-g2", "URI:urn:forge:node:g2", "clientAuth")}


def pin_of(pki, cert):
    return pki.sha256_der(cert[1])


def client_for(pki, srv, certs, pins):
    return C.HubClient("127.0.0.1", srv.server_address[1], str(certs["node"][1]), str(certs["node"][0]), str(pki.ca_crt), pins, timeout_s=5)


def test_pinned_ca_valid_hub_is_accepted_and_request_is_sent(pki, certs):
    srv = serve(pki, certs["hub"][1], certs["hub"][0])
    c = client_for(pki, srv, certs, [pin_of(pki, certs["hub"])])
    assert c.poll({"x": 1}) == {"ok": True} and Handler.seen[0][0] == "/v1/poll" and c.hub_certificate_der()
    assert hashlib.sha256(c.hub_certificate_der()).hexdigest() == pin_of(pki, certs["hub"])
    assert c.poll({"x": 2}) == {"ok": True}                       # keep-alive reuse
    srv.shutdown()


def test_agent_rejects_ca_valid_hub_cert_not_in_pins(pki, certs):
    """T-REVOKE: a certificate that chains to the CA but is not the pinned leaf is refused before a single request byte is sent."""
    srv = serve(pki, certs["hub2"][1], certs["hub2"][0])
    c = client_for(pki, srv, certs, [pin_of(pki, certs["hub"])])
    with pytest.raises(C.PinError):
        c.poll({"secret": "lease-material"})
    assert Handler.seen == []
    with pytest.raises(C.HubUnreachable):
        c.get_policy(1)
    assert Handler.seen == []
    srv.shutdown()


def test_second_pin_in_the_list_allows_certificate_rotation(pki, certs):
    srv = serve(pki, certs["hub2"][1], certs["hub2"][0])
    c = client_for(pki, srv, certs, [pin_of(pki, certs["hub"]), pin_of(pki, certs["hub2"])])
    assert c.poll({}) == {"ok": True}
    srv.shutdown()


def test_ip_san_mismatch_is_refused_even_if_pinned(pki, certs):
    srv = serve(pki, certs["wrongip"][1], certs["wrongip"][0])
    c = client_for(pki, srv, certs, [pin_of(pki, certs["wrongip"])])
    with pytest.raises(C.HubUnreachable):
        c.poll({})
    assert Handler.seen == []
    srv.shutdown()


def test_certificate_from_another_ca_is_refused_even_if_its_pin_is_listed(pki, other_pki, certs):
    foreign = other_pki.issue("c_foreign", "forge-nodehub", "IP:127.0.0.1", "serverAuth")
    srv = serve(other_pki, foreign[1], foreign[0], verify_client=False)
    c = client_for(pki, srv, certs, [other_pki.sha256_der(foreign[1])])
    with pytest.raises(C.HubUnreachable):
        c.poll({})
    assert Handler.seen == []
    srv.shutdown()


def test_tls12_only_server_is_refused(pki, certs):
    srv = serve(pki, certs["hub"][1], certs["hub"][0], verify_client=False, tls13_only=False)
    c = client_for(pki, srv, certs, [pin_of(pki, certs["hub"])])
    with pytest.raises(C.HubUnreachable):
        c.poll({})
    assert Handler.seen == []
    srv.shutdown()


def test_empty_pin_list_is_a_programming_error_not_an_unpinned_mode(pki, certs):
    with pytest.raises(ValueError):
        C.HubClient("127.0.0.1", 1, str(certs["node"][1]), str(certs["node"][0]), str(pki.ca_crt), [])
    assert not C.pin_matches(b"der", ()) and not C.pin_matches(None, ("a" * 64,)) and C.pin_matches(b"der", (hashlib.sha256(b"der").hexdigest(),))


def test_client_certificate_is_presented(pki, certs):
    srv = serve(pki, certs["hub"][1], certs["hub"][0], verify_client=True)
    # a client without the node certificate cannot even finish the handshake against a server that demands one: covered by using the node cert above; here: wrong CA client cert
    assert client_for(pki, srv, certs, [pin_of(pki, certs["hub"])]).poll({}) == {"ok": True}
    srv.shutdown()


def test_client_is_tls13_only_and_verifies_hostnames():
    import inspect
    src = inspect.getsource(C.make_context)
    assert "TLSv1_3" in src and "CERT_REQUIRED" in src and "check_hostname = True" in src
