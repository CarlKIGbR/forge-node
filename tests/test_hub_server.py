"""HTTPS-Hub mit echtem mTLS (TLS 1.3, private Test-CA, Loopback): Identitaet, Routen, Limits, Dateiauslieferung, STOP bleibt unberuehrt. Braucht Postgres."""
import hashlib
import http.client
import json
import os
import ssl
import threading
import uuid

import pytest

from conftest import add_node
from forge_node import chain, protocol
from forge_node.hub import config as hubconfig
from forge_node.hub.core import Hub, JobRequest, Signer
from forge_node.hub.server import make_server, make_ssl_context

pytestmark = pytest.mark.db


@pytest.fixture(scope="module")
def certs(pki):
    srv = pki.issue("hubsrv", "forge-nodehub", "IP:127.0.0.1", "serverAuth")
    g2 = pki.issue("n_g2", "forge-node-g2", "URI:urn:forge:node:g2", "clientAuth")
    g1 = pki.issue("n_g1", "forge-node-g1", "URI:urn:forge:node:g1", "clientAuth")
    nosan = pki.issue("n_nosan", "forge-node-x", "DNS:example.org", "clientAuth")
    two = pki.issue("n_two", "forge-node-two", "URI:urn:forge:node:g2,URI:urn:forge:node:g1", "clientAuth")
    return {"srv": srv, "g2": g2, "g1": g1, "nosan": nosan, "two": two}


@pytest.fixture
def server(pki, certs, hub, hubcfg, adm):
    adm.execute("UPDATE node.nodes SET cert_sha256=%s WHERE node_id='g2'", (pki.sha256_der(certs["g2"][1]),))
    adm.execute("UPDATE node.nodes SET cert_sha256=%s WHERE node_id='g1'", (pki.sha256_der(certs["g1"][1]),))
    hub.sleep = lambda s: None
    srv = make_server(hub, "127.0.0.1", 0, make_ssl_context(certs["srv"][1], certs["srv"][0], pki.ca_crt))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def ctx_for(pki, client=None, minimum=ssl.TLSVersion.TLSv1_3, maximum=ssl.TLSVersion.TLSv1_3):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.minimum_version, c.maximum_version = minimum, maximum
    c.load_verify_locations(str(pki.ca_crt))
    if client:
        c.load_cert_chain(str(client[1]), str(client[0]))
    return c


def call(server, ctx, method, path, body=None, headers=None, raw=None):
    conn = http.client.HTTPSConnection("127.0.0.1", server.server_address[1], context=ctx, timeout=15)
    try:
        h = {"Content-Type": "application/json", **(headers or {})}
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        conn.request(method, path, body=data, headers=h)
        r = conn.getresponse()
        payload = r.read()
        try:
            parsed = json.loads(payload)
        except ValueError:
            parsed = payload
        return r.status, dict(r.getheaders()), parsed
    finally:
        conn.close()


def poll_body(**kw):
    b = {"v": 1, "version": "0.1.0", "policy": {"serial": 0, "sha256": ""}, "clock": "2026-10-31T13:40:10Z", "spool_depth": 0, "audit_heads": {}, "open_jobs": []}
    b.update(kw)
    return b


# ----------------------------------------------------------------------------------------------------------------------- identity
def test_healthz_works_without_client_certificate_and_leaks_nothing(server, pki):
    st, h, body = call(server, ctx_for(pki), "GET", "/healthz")
    assert st == 200 and body["ok"] is True and set(body) == {"ok", "hub", "protocol", "version"}
    assert h["Cache-Control"] == "no-store" and "python" not in h.get("Server", "").lower() and "Python" not in h.get("Server", "")


def test_everything_else_needs_a_client_certificate(server, pki):
    for m, p in (("POST", "/v1/poll"), ("POST", "/v1/audit"), ("GET", "/v1/policy/1"), ("GET", "/v1/release/0.1.0"), ("POST", "/v1/jobs/" + str(uuid.uuid4()) + "/result")):
        st, _, body = call(server, ctx_for(pki), m, p, poll_body() if m == "POST" else None)
        assert st == 401 and body["error"] == "client_certificate_required", (m, p)


def test_client_certificate_from_another_ca_fails_the_handshake(server, pki, other_pki):
    foreign = other_pki.issue("evil", "forge-node-g2", "URI:urn:forge:node:g2", "clientAuth")
    ctx = ctx_for(pki, foreign)
    with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
        call(server, ctx, "POST", "/v1/poll", poll_body())


def test_tls12_client_is_refused(server, pki, certs):
    ctx = ctx_for(pki, certs["g2"], minimum=ssl.TLSVersion.TLSv1_2, maximum=ssl.TLSVersion.TLSv1_2)
    with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
        call(server, ctx, "GET", "/healthz")


def test_server_negotiates_tls13(server, pki, certs):
    conn = http.client.HTTPSConnection("127.0.0.1", server.server_address[1], context=ctx_for(pki, certs["g2"]))
    conn.connect()
    assert conn.sock.version() == "TLSv1.3"
    conn.close()


def test_registered_certificate_gets_through_unregistered_or_mismatching_does_not(server, pki, certs, adm):
    ok = call(server, ctx_for(pki, certs["g2"]), "POST", "/v1/poll", poll_body())
    assert ok[0] == 200
    assert call(server, ctx_for(pki, certs["nosan"]), "POST", "/v1/poll", poll_body())[0] == 401         # kein SAN urn:forge:node:*
    assert call(server, ctx_for(pki, certs["two"]), "POST", "/v1/poll", poll_body())[0] == 401           # zwei Identitaeten
    adm.execute("UPDATE node.nodes SET cert_sha256=repeat('d',64) WHERE node_id='g2'")                  # Registry kennt ein anderes Zertifikat
    assert call(server, ctx_for(pki, certs["g2"]), "POST", "/v1/poll", poll_body())[0] == 403
    adm.execute("UPDATE node.nodes SET cert_sha256=%s WHERE node_id='g2'", (pki.sha256_der(certs["g2"][1]),))
    assert call(server, ctx_for(pki, certs["g2"]), "POST", "/v1/poll", poll_body())[0] == 200


def test_cert_of_node_g1_cannot_act_as_g2(server, pki, certs):
    st, _, body = call(server, ctx_for(pki, certs["g1"]), "POST", "/v1/poll", poll_body())
    assert st == 200
    # die Antwort ist an g1 adressiert, nie an g2
    assert json.loads(body["lease"]["payload"])["node"] == "g1"


def test_revocation_takes_effect_immediately_on_the_next_request(server, pki, certs, adm):             # Hub-Deny-List (Design 5.3)
    ctx = ctx_for(pki, certs["g2"])
    assert call(server, ctx, "POST", "/v1/poll", poll_body())[0] == 200
    adm.execute("UPDATE node.nodes SET status='revoked' WHERE node_id='g2'")
    assert call(server, ctx, "POST", "/v1/poll", poll_body())[0] == 403
    adm.execute("UPDATE node.nodes SET status='revoked' WHERE node_id='g1'")
    assert call(server, ctx_for(pki, certs["g1"]), "POST", "/v1/audit", {"source": "priv", "records": []})[0] == 403


def test_pending_node_is_refused(server, pki, certs, adm):
    adm.execute("UPDATE node.nodes SET status='pending' WHERE node_id='g1'")
    assert call(server, ctx_for(pki, certs["g1"]), "POST", "/v1/poll", poll_body())[0] == 403


# ------------------------------------------------------------------------------------------------------------------- protocol e2e
def test_poll_delivers_signed_job_and_lease_end_to_end(server, pki, certs, hub, gate_keys, clock):
    e = hub.enqueue_job(JobRequest("g2", 0, "inv.host"))
    ctx = ctx_for(pki, certs["g2"])
    st, _, body = call(server, ctx, "POST", "/v1/poll", poll_body())
    assert st == 200 and set(body) == {"v", "lease", "jobs", "reconcile", "policy_serial_latest", "server_time"}
    job = protocol.verify_job(body["jobs"][0], gate_keys, "g2", clock(), ssh_keygen="ssh-keygen")
    assert job["job_id"] == e.job_id
    assert protocol.verify_lease(body["lease"], gate_keys, "g2", clock(), 0, ssh_keygen="ssh-keygen")["node"] == "g2"
    st, _, r = call(server, ctx, "POST", f"/v1/jobs/{e.job_id}/result", {"attempt": 1, "status": "committed", "reason_code": None, "output": "ok", "audit_seq_range": None, "plan_hash": None})
    assert st == 200 and r["state"] == "committed"
    assert hub.job_state(e.job_id)["state"] == "committed"


def test_result_for_other_nodes_job_is_rejected(server, pki, certs, hub, gate_keys):
    e = hub.enqueue_job(JobRequest("g1", 0, "inv.host"))
    call(server, ctx_for(pki, certs["g1"]), "POST", "/v1/poll", poll_body())
    st, _, body = call(server, ctx_for(pki, certs["g2"]), "POST", f"/v1/jobs/{e.job_id}/result",
                       {"attempt": 1, "status": "committed", "reason_code": None, "output": "", "audit_seq_range": None, "plan_hash": None})
    assert st == 400 and hub.job_state(e.job_id)["state"] == "issued"


def test_audit_endpoint_chain_and_ack(server, pki, certs, adm):
    ctx = ctx_for(pki, certs["g2"])
    recs, prev = [], chain.GENESIS_HASH
    for i in range(1, 4):
        r = chain.seal_record({"ts": "2026-10-31T13:40:10Z", "node": "g2", "type": "t0"}, i, prev)
        recs.append(r)
        prev = r["hash"]
    st, _, body = call(server, ctx, "POST", "/v1/audit", {"source": "priv", "records": recs})
    assert st == 200 and body == {"ok": True, "acked": {"priv": 3}, "stored": 3}
    st, _, body = call(server, ctx, "POST", "/v1/audit", {"source": "priv", "records": [recs[2] | {"hash": "a" * 64}]})
    assert st == 200 and body["ok"] is False and adm.execute("SELECT quarantine FROM node.nodes WHERE node_id='g2'").fetchone()["quarantine"]


def test_node_id_in_audit_records_must_be_the_certificate_node(server, pki, certs, adm):
    r = chain.seal_record({"ts": "2026-10-31T13:40:10Z", "node": "g1", "type": "t0"}, 1, chain.GENESIS_HASH)
    st, _, body = call(server, ctx_for(pki, certs["g2"]), "POST", "/v1/audit", {"source": "priv", "records": [r]})
    assert st == 200 and body["ok"] is False
    assert adm.execute("SELECT count(*) AS n FROM node.audit WHERE node_id='g1' AND source='priv'").fetchone()["n"] == 0


# ------------------------------------------------------------------------------------------------------------------------ limits
def test_routing_limits_and_error_shapes(server, pki, certs):
    ctx = ctx_for(pki, certs["g2"])
    assert call(server, ctx, "GET", "/nope")[0] == 404
    assert call(server, ctx, "GET", "/v1/poll")[0] == 405
    assert call(server, ctx, "PUT", "/v1/poll", {})[0] == 405
    assert call(server, ctx, "DELETE", "/v1/poll")[0] == 405
    assert call(server, ctx, "POST", "/v1/poll", headers={"Content-Type": "text/plain"}, raw=b"{}")[0] == 415
    assert call(server, ctx, "POST", "/v1/poll", raw=b"{not json")[0] == 400
    assert call(server, ctx, "POST", "/v1/poll", raw=b'{"v":1,"v":1}')[0] == 400                     # doppelte Schluessel
    assert call(server, ctx, "POST", "/v1/poll", raw=b'{"clock":1.5}')[0] == 400                      # Floats
    st, _, body = call(server, ctx, "POST", "/v1/poll", {**poll_body(), "extra": 1})
    assert st == 400 and body["error"] == "bad_request"
    assert call(server, ctx, "GET", "/v1/jobs/" + str(uuid.uuid4()) + "/result")[0] == 405
    assert call(server, ctx, "POST", "/v1/jobs/not-a-uuid/result", {})[0] == 404


def test_body_limit_1mib(server, pki, certs):
    ctx = ctx_for(pki, certs["g2"])
    st, _, body = call(server, ctx, "POST", "/v1/poll", raw=b"x" * (protocol.MAX_BODY_BYTES + 1))
    assert st == 413


def test_chunked_bodies_are_not_accepted(server, pki, certs):
    conn = http.client.HTTPSConnection("127.0.0.1", server.server_address[1], context=ctx_for(pki, certs["g2"]), timeout=10)
    conn.putrequest("POST", "/v1/poll")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Transfer-Encoding", "chunked")
    conn.endheaders()
    conn.send(b"2\r\n{}\r\n0\r\n\r\n")
    r = conn.getresponse()
    assert r.status in (400, 411)
    conn.close()


def test_internal_errors_do_not_leak_details(server, pki, certs, hub, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("SECRET-INTERNALS /srv/x password=hunter2")

    monkeypatch.setattr(hub, "poll", boom)
    st, _, body = call(server, ctx_for(pki, certs["g2"]), "POST", "/v1/poll", poll_body())
    assert st == 500 and body == {"error": "internal", "detail": ""}


def test_keep_alive_serves_several_requests_on_one_connection(server, pki, certs):
    conn = http.client.HTTPSConnection("127.0.0.1", server.server_address[1], context=ctx_for(pki, certs["g2"]), timeout=10)
    for _ in range(3):
        conn.request("POST", "/v1/poll", body=json.dumps(poll_body()), headers={"Content-Type": "application/json"})
        r = conn.getresponse()
        assert r.status == 200
        r.read()
    conn.close()


# ----------------------------------------------------------------------------------------------------------- policy / release files
def test_policy_served_read_only_from_node_directory(server, pki, certs, hubcfg):
    d = hubcfg.policy_dir / "g2"
    d.mkdir()
    (d / "policy-3.json").write_text('{"serial":3}')
    (d / "policy-3.json.sig").write_text("-----BEGIN SSH SIGNATURE-----\nx\n-----END SSH SIGNATURE-----\n")
    other = hubcfg.policy_dir / "g1"
    other.mkdir()
    (other / "policy-9.json").write_text('{"serial":9}')
    (other / "policy-9.json.sig").write_text("sig")
    ctx = ctx_for(pki, certs["g2"])
    st, _, body = call(server, ctx, "GET", "/v1/policy/3")
    assert st == 200 and body["serial"] == 3 and body["policy"] == '{"serial":3}' and body["sig"].startswith("-----BEGIN SSH SIGNATURE")
    assert call(server, ctx, "GET", "/v1/policy/9")[0] == 404                               # g1's Policy ist fuer g2 unsichtbar
    assert call(server, ctx, "GET", "/v1/policy/4")[0] == 404
    assert call(server, ctx, "GET", "/v1/policy/03")[0] == 404 or call(server, ctx, "GET", "/v1/policy/03")[0] == 400
    assert call(server, ctx, "GET", "/v1/policy/..%2f..%2fetc%2fpasswd")[0] == 404
    for m in ("POST", "PUT", "DELETE"):
        assert call(server, ctx, m, "/v1/policy/3", {})[0] == 405


def test_policy_symlink_and_hardlink_are_not_followed(server, pki, certs, hubcfg, tmp_path):
    d = hubcfg.policy_dir / "g2"
    d.mkdir()
    secret = tmp_path / "secret"
    secret.write_text("TOPSECRET")
    os.symlink(secret, d / "policy-5.json")
    (d / "policy-5.json.sig").write_text("sig")
    ctx = ctx_for(pki, certs["g2"])
    assert call(server, ctx, "GET", "/v1/policy/5")[0] == 404
    os.link(secret, d / "policy-6.json")
    (d / "policy-6.json.sig").write_text("sig")
    assert call(server, ctx, "GET", "/v1/policy/6")[0] == 404                               # nlink != 1
    # das Verzeichnis selbst als Symlink
    os.symlink(d, hubcfg.policy_dir / "g1")
    assert call(server, ctx_for(pki, certs["g1"]), "GET", "/v1/policy/5")[0] == 404


def test_hub_has_no_endpoint_that_writes_policy(server, pki, certs, hubcfg):
    d = hubcfg.policy_dir / "g2"
    d.mkdir()
    ctx = ctx_for(pki, certs["g2"])
    for p in ("/v1/policy", "/v1/policy/7", "/v1/policy/7/apply"):
        for m in ("POST", "PUT"):
            call(server, ctx, m, p, {"policy": "{}", "sig": "x"})
    assert os.listdir(d) == [] and os.listdir(hubcfg.policy_dir) == ["g2"]


def test_release_artifact_streamed_for_profile_only(server, pki, certs, hubcfg):
    blob = os.urandom(3 * 1024 * 1024 + 17)
    (hubcfg.release_dir / "forge-node-0.1.0-full.tar").write_bytes(blob)
    (hubcfg.release_dir / "forge-node-0.1.0-full.tar.sig").write_text("-----BEGIN SSH SIGNATURE-----\nz\n-----END SSH SIGNATURE-----\n")
    (hubcfg.release_dir / "forge-node-0.1.0-t0.tar").write_bytes(b"t0-only")
    full, t0 = ctx_for(pki, certs["g2"]), ctx_for(pki, certs["g1"])        # g2 = full, g1 = t0
    st, h, body = call(server, full, "GET", "/v1/release/0.1.0")
    assert st == 200 and h["Content-Type"] == "application/octet-stream" and hashlib.sha256(body).digest() == hashlib.sha256(blob).digest()
    assert call(server, full, "GET", "/v1/release/0.1.0.sig")[0] == 200
    assert call(server, t0, "GET", "/v1/release/0.1.0")[2] == b"t0-only"                  # das t0-Profil bekommt nur das t0-Artefakt
    assert call(server, t0, "GET", "/v1/release/0.1.0.sig")[0] == 404
    for bad in ("/v1/release/..%2f0.1.0", "/v1/release/0.1", "/v1/release/0.1.0%00", "/v1/release/0.1.0.tar"):
        assert call(server, full, "GET", bad)[0] in (400, 404)


def test_release_symlink_not_followed(server, pki, certs, hubcfg, tmp_path):
    s = tmp_path / "x"
    s.write_text("secret")
    os.symlink(s, hubcfg.release_dir / "forge-node-0.2.0-full.tar")
    assert call(server, ctx_for(pki, certs["g2"]), "GET", "/v1/release/0.2.0")[0] == 404


# ------------------------------------------------------------------------------------------------- STOP is untouchable from a node
def test_stop_state_cannot_be_changed_by_any_node_request(server, pki, certs, hubcfg, hub):       # test_stop_release_not_possible_from_node
    ctrl = hubcfg.control_dir
    (ctrl / "STOP").write_text("STOP by owner\n")
    st0 = (ctrl / "STOP").stat()
    before = sorted(os.listdir(ctrl))
    ctx = ctx_for(pki, certs["g2"])
    reqs = [("POST", "/v1/poll", poll_body(wait_s=0)), ("POST", "/v1/audit", {"source": "priv", "records": []}), ("GET", "/v1/policy/1", None), ("GET", "/v1/release/0.1.0", None),
            ("POST", "/v1/jobs/" + str(uuid.uuid4()) + "/result", {}), ("GET", "/control/STOP", None), ("DELETE", "/control/STOP", None), ("POST", "/v1/stop", {}),
            ("POST", "/v1/release", {}), ("POST", "/v1/poll", {"stop": False, "release": True}), ("POST", "/release", {}), ("GET", "/healthz", None)]
    for m, p, b in reqs:
        call(server, ctx, m, p, b)
    after = (ctrl / "STOP").stat()
    assert (ctrl / "STOP").read_text() == "STOP by owner\n" and (st0.st_mtime_ns, st0.st_ino) == (after.st_mtime_ns, after.st_ino)
    assert sorted(os.listdir(ctrl)) == before
    # und umgekehrt: kein Request kann STOP anlegen
    (ctrl / "STOP").unlink()
    for m, p, b in reqs:
        call(server, ctx, m, p, b)
    assert not (ctrl / "STOP").exists()


def test_poll_during_stop_reports_stop_in_lease_and_still_serves_t0(server, pki, certs, hubcfg, hub, gate_keys, clock):
    (hubcfg.control_dir / "STOP").write_text("x")
    hub.enqueue_job(JobRequest("g2", 0, "inv.host"))
    st, _, body = call(server, ctx_for(pki, certs["g2"]), "POST", "/v1/poll", poll_body())
    assert protocol.verify_lease(body["lease"], gate_keys, "g2", clock(), 0, ssh_keygen="ssh-keygen")["stop"] is True and len(body["jobs"]) == 1


# --------------------------------------------------------------------------------------------------------------------------- config
def test_hub_never_binds_a_wildcard_address():
    for bad in ("0.0.0.0", "::", "", "localhost", "carlgpu2", "224.0.0.1", "192.168.10"):
        with pytest.raises(hubconfig.ConfigError):
            hubconfig.check_bind_host(bad)
    for bad in ("", "localhost", "carlgpu2", "224.0.0.1"):
        with pytest.raises(hubconfig.ConfigError):
            hubconfig.check_bind_host(bad, in_container=True)
    assert hubconfig.check_bind_host("0.0.0.0", in_container=True) == "0.0.0.0"       # nur im Container; die Erreichbarkeit regelt das Publish (test_deploy.py)
    assert hubconfig.check_bind_host("192.168.10.4") == "192.168.10.4"
    assert hubconfig.check_bind_host("127.0.0.1") == "127.0.0.1"


def test_from_env_requires_everything_and_refuses_wildcard(tmp_path):
    env = {"FORGE_NODEHUB_DB_DSN": "dbname=x", "FORGE_NODEHUB_LISTEN_HOST": "192.168.10.4", "FORGE_NODEHUB_TLS_CERT": "c", "FORGE_NODEHUB_TLS_KEY": "k", "FORGE_NODEHUB_TLS_CA": "ca",
           "FORGE_NODEHUB_GATE_KEY": "g", "FORGE_NODEHUB_GATE_KEY_ID": "hub-gate-1", "FORGE_NODEHUB_CONTROL_DIR": "/c", "FORGE_NODEHUB_POLICY_DIR": "/p", "FORGE_NODEHUB_RELEASE_DIR": "/r"}
    cfg = hubconfig.HubConfig.from_env(env)
    assert cfg.listen_port == 8094 and cfg.lease_valid_s == 60 and cfg.long_poll_max_s == 30
    for k in list(env):
        with pytest.raises(hubconfig.ConfigError):
            hubconfig.HubConfig.from_env({x: y for x, y in env.items() if x != k})
    with pytest.raises(hubconfig.ConfigError):
        hubconfig.HubConfig.from_env({**env, "FORGE_NODEHUB_LISTEN_HOST": "0.0.0.0"})
    assert hubconfig.HubConfig.from_env({**env, "FORGE_NODEHUB_LISTEN_HOST": "0.0.0.0", "FORGE_NODEHUB_CONTAINER": "1"}).listen_host == "0.0.0.0"
    with pytest.raises(hubconfig.ConfigError):
        hubconfig.HubConfig.from_env({**env, "FORGE_NODEHUB_LEASE_VALID_S": "61"})
    assert hubconfig.HubConfig.from_env({**env, "FORGE_NODEHUB_LONG_POLL_S": "99"}).long_poll_max_s == 30


def test_unread_request_bodies_never_desynchronise_a_keep_alive_connection(server, pki, certs):
    """Fehlerantworten (404/405/401) muessen den Body verbrauchen oder die Verbindung schliessen - sonst wird er als naechste Anfrage gelesen."""
    conn = http.client.HTTPSConnection("127.0.0.1", server.server_address[1], context=ctx_for(pki, certs["g2"]), timeout=10)
    for m, p in (("PUT", "/v1/poll"), ("POST", "/nope"), ("GET", "/v1/poll"), ("DELETE", "/v1/audit")):
        conn.request(m, p, body=b'{"policy": "{}", "sig": "x"}', headers={"Content-Type": "application/json"})
        r = conn.getresponse()
        r.read()
        assert r.status in (404, 405)
    conn.request("POST", "/v1/poll", body=json.dumps(poll_body()), headers={"Content-Type": "application/json"})
    r = conn.getresponse()
    assert r.status == 200
    conn.close()
    anon = http.client.HTTPSConnection("127.0.0.1", server.server_address[1], context=ctx_for(pki), timeout=10)
    anon.request("POST", "/v1/poll", body=b'{"x": 1}', headers={"Content-Type": "application/json"})
    r = anon.getresponse()
    r.read()
    assert r.status == 401
    anon.request("GET", "/healthz")
    assert anon.getresponse().status == 200
    anon.close()
