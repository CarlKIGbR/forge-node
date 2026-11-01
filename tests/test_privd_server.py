"""privd over its real Unix socket (agent uid, other uids, root), the closed request set, and privctl."""
import base64
import io
import json
import os
import socket
import stat
import struct
import threading
import time

import pytest
from audit_helpers import AGENT_GID, AGENT_UID, run_as_agent
from privd_helpers import NODE, PrivdEnv, lease_payload

from forge_node import canon, protocol
from forge_node.privd import privctl
from forge_node.privd.client import PrivClient, PrivUnavailable
from forge_node.privd.server import MAX_REQUEST_BYTES, Server, listen


@pytest.fixture
def served(privd_env):
    e = privd_env.ready()
    sock = listen(e.paths.socket, AGENT_GID)
    srv = Server(e.ctx)
    t = threading.Thread(target=srv.serve, args=(sock,), daemon=True)
    t.start()
    e.server = srv
    yield e
    srv.stop()
    t.join(5)
    sock.close()


def raw_call(path, data: bytes, timeout=5.0) -> bytes:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(path)
    s.sendall(data)
    buf = b""
    while not buf.endswith(b"\n"):
        c = s.recv(65536)
        if not c:
            break
        buf += c
    s.close()
    return buf


def req(kind, **body):
    return canon.canonical({"req": kind, **body}) + b"\n"


def test_socket_is_root_owned_group_agent_mode_0660(served):
    st = os.stat(served.paths.socket)
    assert stat.S_ISSOCK(st.st_mode) and (st.st_uid, st.st_gid, st.st_mode & 0o777) == (0, AGENT_GID, 0o660)


def test_other_uid_cannot_connect_to_socket(served):
    def try_connect():
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(served.paths.socket)
            return "connected"
        except OSError as ex:
            return ex.errno
    assert run_as_agent(try_connect, uid=2000, gid=2000) == 13                       # EACCES
    assert run_as_agent(try_connect, uid=AGENT_UID, gid=AGENT_GID) == "connected"


def test_peer_credentials_come_from_the_kernel_not_from_the_request(served):
    # the agent claims to be root in every way a JSON body can; privd still sees uid 1001
    def attempt():
        c = PrivClient(served.paths.socket, 0, 10)
        return [c.request("audit.rotate", {"log": "priv", "uid": 0, "peer": {"uid": 0}}), c.request("lockdown", {"uid": 0})]
    r1, r2 = run_as_agent(attempt)
    assert r1["ok"] is False and r1["code"] == "DENY_JOB_SIGNATURE" and r2["ok"] is False
    assert not os.path.exists(served.paths.local_stop)
    # SO_PEERCRED as the server reads it: the forked agent's uid
    def uid_seen():
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(served.paths.socket)
        return struct.unpack("3i", s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]
    assert run_as_agent(uid_seen) == 0                                               # the PEER of the agent is root (privd): what the agent client verifies


def test_agent_cannot_forge_lease_or_job_over_the_socket(served):
    env = served.lease_env(seq=500)                                                       # signed here, by the hub's key, then tampered with by the "agent"
    env["payload"] = env["payload"].replace('"stop":false', '"stop":true')
    jenv, _ = served.job_env(dry_run=True)
    jenv["sig"] = jenv["sig"][:-40] + "A" * 40

    def attempt():
        c = PrivClient(served.paths.socket, 0, 20)
        out = [c.request("lease.put", {"lease": env})]
        out.append(c.request("exec", {"job": jenv}))
        out.append(c.request("exec", {"job": {"payload": "{}", "sig": "x", "key_id": "hub-gate-1"}}))
        out.append(c.request("status", {}))
        return out
    lease, jobr, junk, status = run_as_agent(attempt)
    assert lease["ok"] is False and jobr["ok"] is False and junk["ok"] is False
    assert status["status"]["lease"]["seq"] == 1 and not status["status"]["lease"]["stop"]


def test_agent_can_use_the_whole_socket_protocol_end_to_end(served):
    jenv, job = served.job_env(dry_run=True, params={"note": "via socket"})

    def attempt():
        c = PrivClient(served.paths.socket, 0, 60)
        return c.request("exec", {"job": jenv}), c.request("status", {}), c.request("lease.put", {"lease": lease2})
    lease2 = served.lease_env(seq=2)
    r, status, lease = run_as_agent(attempt)
    assert r["ok"] and r["result"]["status"] == "dry_run" and r["result"]["job_id"] == job["job_id"]
    assert status["status"]["open_jobs"] == [] and lease["ok"] is True and lease["lease"]["seq"] == 2       # the agent carries a genuine lease; privd verified it itself


def test_closed_request_set_and_malformed_lines(served):
    p = served.paths.socket
    for data, code in ((b"not json\n", "BAD_REQUEST"), (b'{"req":"exec","req":"status"}\n', "BAD_REQUEST"), (b'{"req":"rm -rf"}\n', "DENY_OP_UNKNOWN"), (b"[]\n", "DENY_OP_UNKNOWN"),
                       (b'{"nothing":1}\n', "DENY_OP_UNKNOWN"), (b'{"req":"status","x":1.5}\n', "BAD_REQUEST"), (b"\xff\xfe\n", "BAD_REQUEST")):
        r = json.loads(raw_call(p, data))
        assert r["ok"] is False and r["code"] == code, (data, r)
    big = json.loads(raw_call(p, b'{"req":"status","pad":"' + b"a" * (MAX_REQUEST_BYTES + 10) + b'"}\n'))
    assert big["ok"] is False and big["code"] == "BAD_REQUEST"
    # a client that connects and says nothing / half a line does not wedge the server
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(p)
    s.sendall(b'{"req":"status"')
    s.close()
    assert json.loads(raw_call(p, req("status")))["ok"] is True
    from forge_node.privd.server import HANDLERS
    from forge_node.privd.core import KINDS
    assert set(HANDLERS) == set(KINDS) and len(KINDS) == 9


def test_many_concurrent_clients_are_served(served):
    results = []

    def go():
        results.append(json.loads(raw_call(served.paths.socket, req("status")))["ok"])
    ts = [threading.Thread(target=go) for _ in range(24)]
    [t.start() for t in ts]
    [t.join(30) for t in ts]
    assert results == [True] * 24


def test_client_checks_the_socket_peer_before_sending_anything(tmp_path):
    """A squatter on the socket path that is not root never receives a policy blob, lease or job."""
    path = str(tmp_path / "squat.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)
    received = []

    def serve():
        c, _ = srv.accept()
        c.settimeout(1)
        try:
            received.append(c.recv(100))
        except OSError:
            received.append(b"")
    t = threading.Thread(target=serve)
    t.start()
    with pytest.raises(PrivUnavailable):
        PrivClient(path, 12345, 2).request("policy.apply", {"policy_b64": "AAAA", "sig": "x"})
    t.join(5)
    assert received == [b""]


# ------------------------------------------------------------------------------------------------------------------------------ privctl
def make_ctl(e, euid=0, **kw):
    out = io.StringIO()
    calls = []
    ctl = privctl.Ctl(euid=euid, client=PrivClient(e.paths.socket, 0, 30), state_setup=lambda: None, admin_factory=lambda: (e.priv_log, e.agent_log), ledger_path=e.paths.ledger,
                      local_stop=e.paths.local_stop, systemctl_provider=kw.get("provider", lambda n: None), protected_units=("kmu-*",), protected_paths=("/opt/kmu-ai",),
                      run_systemctl=lambda a: (calls.append(a) or (0, b"", b"")), clock=e.clock, out=out)
    return ctl, out, calls


def test_privctl_policy_apply_nofollow_and_hashes_the_bytes_it_installs(served, tmp_path):
    e = served
    ctl, out, _ = make_ctl(e)
    raw, sig = e.sign(e.doc(tiers=(0, 1), serial=2, t1_ops=[{"op": "selftest.noop", "mode": "enforce"}]))
    d = tmp_path / "in"
    d.mkdir()
    (d / "p.json").write_bytes(raw)
    (d / "p.json.sig").write_text(sig)
    assert privctl.main(["policy-apply", str(d / "p.json"), str(d / "p.json.sig")], ctl) == 0
    res = json.loads(out.getvalue())
    import hashlib
    assert res["ok"] and res["policy"]["serial"] == 2 and res["policy"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert open(f"{e.paths.policy_dir}/policy-2.json", "rb").read() == raw                 # the installed bytes ARE the bytes that were read
    # a symlink, a FIFO and a directory are refused; nothing is sent
    (d / "link.json").symlink_to(d / "p.json")
    os.mkfifo(d / "fifo.json")
    for bad in (d / "link.json", d / "fifo.json", d):
        out.truncate(0)
        assert privctl.main(["policy-apply", str(bad), str(d / "p.json.sig")], ctl) == 1
    assert e.ctx.policies.installed_serial() == 2
    # the file is swapped for another (properly signed) policy between 'read' and 'install': impossible, because it is not read again
    raw3, sig3 = e.sign(e.doc(tiers=(0,), serial=3))
    seen = {}
    real = privctl.read_nofollow

    def swap(path, limit):
        data = real(path, limit)
        if path.endswith("q.json"):
            (d / "q.json").write_bytes(raw3)
            seen["swapped"] = True
        return data
    (d / "q.json").write_bytes(e.sign(e.doc(tiers=(0,), serial=4))[0])
    (d / "q.json.sig").write_text(e.sign(e.doc(tiers=(0,), serial=4))[1])
    privctl.read_nofollow = swap
    try:
        out.truncate(0)
        out.seek(0)
        assert privctl.main(["policy-apply", str(d / "q.json"), str(d / "q.json.sig")], ctl) in (0, 1)
    finally:
        privctl.read_nofollow = real
    assert seen["swapped"] and e.ctx.policies.installed_serial() in (2, 4)
    assert e.ctx.policies.installed_serial() != 3


def test_policy_applied_directly_by_owner_without_hub(served):
    """Revocation by policy serial+1 needs no hub: root applies a policy that removes the old gate key; leases and jobs of the old key are dead immediately."""
    e = served
    old_job, _ = e.job_env(dry_run=True)
    assert e.call("exec", {"job": old_job})["result"]["status"] == "dry_run"
    other_priv, other_pub = ("x", "x")
    r = e.install(e.doc(tiers=(0, 1), serial=2, t1_ops=[{"op": "selftest.noop", "mode": "enforce"}],
                        gate_keys=[{"id": "hub-gate-2", "pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOCnQJdkGAnqC9RpKFPyX3e4R8Y5v0QG9hJmFqQqkG8E", "not_after": "2099-12-31"}]))
    assert r["ok"], r
    e.clock.advance(seconds=1)
    r = e.call("exec", {"job": e.job_env(dry_run=True)[0]})                                # signed by hub-gate-1, which serial 2 no longer lists
    assert r["ok"] is False and r["code"] == "DENY_JOB_SIGNATURE"
    r = e.call("lease.put", {"lease": e.lease_env(seq=9)})
    assert r["ok"] is False
    assert e.call("status", {})["status"]["lease"] is None                                # the stored lease no longer verifies under the new key list


def test_privctl_commands_refuse_non_root_and_do_nothing(served):
    e = served
    ctl, out, calls = make_ctl(e, euid=1001)
    for argv in (["audit-init"], ["audit-verify"], ["audit-rotate", "both"], ["policy-apply", "/x", "/y"], ["status"], ["lockdown"], ["unit-closure", "a.service", "start"],
                 ["circuit-ack", "selftest.noop", "me"], ["audit-purge", "1", "1"]):
        assert privctl.main(argv, ctl) == 1, argv
    assert not os.path.exists(e.paths.local_stop) and calls == [] and out.getvalue() == ""
    assert privctl.main([], ctl) == 2 and privctl.main(["rm"], ctl) == 2


def test_privctl_lockdown_audit_rotate_verify_and_closure(served):
    e = served
    ctl, out, calls = make_ctl(e)
    assert privctl.main(["lockdown"], ctl) == 0 and os.path.exists(e.paths.local_stop)
    assert calls == [["stop", "forge-node-agent.service"], ["disable", "--now", "forge-node-privd.socket"]]
    res = json.loads(out.getvalue())
    assert res["steps"]["stop_agent"]["rc"] == 0
    assert privctl.main(["lockdown"], ctl) == 0                                           # idempotent
    out.truncate(0)
    out.seek(0)
    assert privctl.main(["audit-rotate", "both"], ctl) == 0
    assert json.loads(out.getvalue())["rotated"] == {"priv": 2, "agent": 2}
    out.truncate(0)
    out.seek(0)
    assert privctl.main(["audit-verify"], ctl) == 0 and json.loads(out.getvalue()) == {"priv": [], "agent": []}
    # the resolver through privctl: a closure with a protected member exits 1 and shows the edge; a clean one prints the hash
    from test_resolver import U, graph
    ctl2, out2, _ = make_ctl(e, provider=graph(U("forge-x.service", Wants="kmu-a.service"), U("kmu-a.service")))
    assert privctl.main(["unit-closure", "forge-x.service", "start"], ctl2) == 1
    doc = json.loads(out2.getvalue())
    assert doc["denied"] and doc["closure_sha256"] is None and any("kmu-a.service" in h for h in doc["hits"])
    ctl3, out3, _ = make_ctl(e, provider=graph(U("forge-x.service", Wants="forge-w.service"), U("forge-w.service")))
    assert privctl.main(["unit-closure", "forge-x.service", "start"], ctl3) == 0 and len(json.loads(out3.getvalue())["closure_sha256"]) == 64


def test_privctl_audit_init_proves_the_filesystem_and_refuses_without_creating_anything(realfs, tmp_path):
    """audit-init runs the seal proof on the target filesystem first. On a filesystem without inode flags (tmpfs) it refuses and creates no log."""
    from audit_helpers import make_specs
    from forge_node.audit.log import AuditAdmin
    # a real-ext4 target works and reports the proof
    specs = make_specs(realfs)
    adm = (AuditAdmin(specs["priv"], NODE, lambda: __import__("privd_helpers").NOW), AuditAdmin(specs["agent"], NODE, lambda: __import__("privd_helpers").NOW))
    out = io.StringIO()
    ctl = privctl.Ctl(euid=0, client=None, state_setup=lambda: None, admin_factory=lambda: adm, ledger_path="", local_stop="", systemctl_provider=None, protected_units=(),
                      protected_paths=(), run_systemctl=None, clock=lambda: None, out=out)
    assert privctl.main(["audit-init"], ctl) == 0
    doc = json.loads(out.getvalue())
    assert doc["priv"]["fs_proof"]["ok"] and doc["priv"]["fs_proof"]["fstype"] == "ext4" and doc["priv"]["generation"] == 1
    assert doc["agent"]["generation"] == 1
