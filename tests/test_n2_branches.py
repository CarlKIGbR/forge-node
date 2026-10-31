"""Error branches and edge cases of the N2 modules (fail-closed paths that normal runs never reach)."""
import errno
import json
import os
import socket
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from forge_node import canon, protocol
from forge_node.agent import __main__ as agent_main
from forge_node.agent import client as C
from forge_node.agent import loop as L
from forge_node.t0 import collect, fsread, metrics, policy as P, probes, runner, sanitize
from forge_node.t0.env import Env
from forge_node.t0.fsread import Fs, FsError, ProtectedSet
from forge_node.t0.runner import Run
from forge_node.t0.spool import Spool, SpoolError

from n2_helpers import FakeRunner, NOW, PROC, make_env, policy_doc, view, write_tree
from test_t0_engine import FakeProbe, make as make_engine
from test_t0_probes import CID, H1, env_with, git_env, inspect_line, repo_files


# ============================================================================================================ runner: every command expands
REPR = {"unit": "a.service", "unit_glob": "a*", "hex64": "a" * 64, "image_id": "sha256:" + "b" * 64, "int": "5", "seconds": "-3600s", "abs_path": "/srv/x y", "pkg_pattern": "docker-ce"}


@pytest.mark.skipif(os.getuid() != 0, reason="needs root-owned fake binaries")
def test_every_table_command_expands_executes_and_keeps_values_as_single_argv_elements(tmp_path, monkeypatch):
    d = tmp_path / "bin"
    d.mkdir()
    monkeypatch.setattr(runner, "FIXED_PATH", (str(d),))
    monkeypatch.setitem(runner._ENV_BASE, "PATH", str(d))
    for b in {c.binary for c in runner.CMDS.values()}:
        p = d / b
        p.write_text('#!/bin/sh\nfor a in "$@"; do echo "[$a]"; done\n')
        os.chmod(p, 0o755)
    for cid, c in runner.CMDS.items():
        slots = {name: ([REPR[kind]] * 2 if f"<{name}...>" in " ".join(c.argv) else REPR[kind]) for name, kind in c.slots}
        r = runner.run(cid, slots, b"der" if c.stdin else None)
        assert r.ok, (cid, r)
        lines = r.text.splitlines()
        assert lines, cid
        if cid == "journal_unit":
            assert "[--since=-3600s]" in lines and "[a.service]" in lines
        if cid == "du_ionice":
            assert "[/srv/x y]" in lines
        if cid == "docker_inspect":
            assert lines.count("[" + "a" * 64 + "]") == 2


def test_option_lookalike_is_rejected_only_when_it_is_a_whole_argv_element():
    with pytest.raises(runner.RunnerError):
        runner.run("systemctl_is_active", {"unit": "-x.service"})
    with pytest.raises(runner.RunnerError):
        runner.run("journal_unit", {"unit": "a.service", "since": "3600", "lines": "5"})          # not the 'seconds' pattern
    c = runner.Cmd("x", ("<a> <b>",), slots=(("a", "int"), ("b", "int")))
    with pytest.raises(runner.RunnerError):
        runner._expand(c, {"a": "1", "b": "2"})


@pytest.mark.skipif(os.getuid() != 0, reason="needs root-owned fake binaries")
def test_exec_format_error_and_wrong_oserror_are_reported_not_raised(tmp_path, monkeypatch):
    d = tmp_path / "bin"
    d.mkdir()
    monkeypatch.setattr(runner, "FIXED_PATH", (str(d),))
    (d / "lsblk").write_bytes(b"\x00\x01garbage-not-a-script")
    os.chmod(d / "lsblk", 0o755)
    r = runner.run("lsblk")
    assert not r.ok and r.reason == "oserror"
    assert runner.ReadOnlyRunner().run("lsblk").reason == "oserror" and runner.ReadOnlyRunner().available("lsblk") is True
    assert runner._trusted("/nonexistent") is False


# ===================================================================================================================== sanitize
def test_sanitize_odd_inputs():
    assert sanitize.clean_text(12345) == "12345"
    deep = cur = []
    for _ in range(30):
        nxt = []
        cur.append(nxt)
        cur = nxt
    assert "[too deep]" in json.dumps(sanitize.clean_tree(deep))
    assert sanitize.clean_tree({1, 2}).startswith("{") and sanitize.clean_tree(2.5) == 2 and sanitize.clean_tree(float("inf")) is None
    out, tr = sanitize.fit({"a": [["x" * 100] * 30] * 5, "b": ["y" * 100] * 10}, 1500)
    assert len(canon.canonical(out)) <= 1500 and tr
    t = sanitize.finalize("g2", "inv.host", "2026-10-31T13:40:10Z", "internal", {"x": "y" * 5000}, full_redaction=False, limit=380)
    assert json.loads(t)["data"] == {"error": "output_too_large"}


# ======================================================================================================================== fsread
def test_fsread_edge_cases(tmp_path):
    write_tree(tmp_path, PROC)
    f = Fs(ProtectedSet.from_policy(["/etc/passwd"]), str(tmp_path))
    with pytest.raises(FsError) as e:
        f.read_text("/etc/passwd")
    assert e.value.code == "protected"
    assert f.exists("/proc/meminfo") and not f.exists("/proc/nothing")
    (tmp_path / "d").mkdir()
    for i in range(5):
        (tmp_path / "d" / f"f{i}").write_text("x")
    entries, trunc = f.list_meta("/d", 3)
    assert len(entries) == 3 and trunc
    with pytest.raises(FsError):
        f.list_meta("/nope")
    with pytest.raises(FsError):
        f.stat_meta("/nope")
    (tmp_path / "d" / "dangling").symlink_to("/nonexistent-target")
    assert any(e["kind"] == "link" for e in f.list_meta("/d")[0])
    os.mkfifo(tmp_path / "d" / "fifo")
    import re
    pat = re.compile(r"^/d/.*\Z")
    with pytest.raises(FsError) as e:
        f.read_exception("/d/fifo", pat)
    assert e.value.code == "not_regular"
    (tmp_path / "d" / "big").write_text("x" * 100)
    with pytest.raises(FsError) as e:
        f.read_exception("/d/big", pat, limit=10)
    assert e.value.code == "too_large"
    with pytest.raises(FsError) as e:
        f.read_user_file("/d/fifo")
    assert e.value.code == "not_regular"
    with pytest.raises(FsError) as e:
        f.read_user_file("/d/big", limit=10)
    assert e.value.code == "not_regular"
    assert f.read_user_file("/d/f1") == "x"


# ======================================================================================================================== metrics
def test_pid_cgroup_key_branches(tmp_path):
    env = make_env(tmp_path, FakeRunner({}), files={"/proc/7/cgroup": "0::/user.slice/user-1000.slice\n", "/proc/8/cgroup": "0::/system.slice/forge-edge.service\n", "/proc/9/cgroup": "1:cpu:/x\n"})
    assert metrics._pid_cgroup_key(env, "x") is None and metrics._pid_cgroup_key(env, 404) is None and metrics._pid_cgroup_key(env, 9) is None and metrics._pid_cgroup_key(env, 7) is None
    assert metrics._pid_cgroup_key(env, 8) == "u:forge-edge.service"


def test_cgroup_scan_skips_unreadable_or_odd_entries(tmp_path):
    files = {"/sys/fs/cgroup/system.slice/a.service/memory.current": "not-a-number\n", "/sys/fs/cgroup/system.slice/b.service/memory.current": "5\n", "/sys/fs/cgroup/system.slice/file.service": "x"}
    cg = metrics.cgroup_counters(make_env(tmp_path, FakeRunner({}), files=files))
    assert cg == {"u:b.service": [0, 5, 0, 0]}


# ======================================================================================================================= collect
def test_local_tls_reads_expiry_from_a_real_listener(tmp_path, pki, monkeypatch):
    srv_cert = pki.issue("t_local", "localhost", "IP:127.0.0.1", "serverAuth")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(srv_cert[1]), str(srv_cert[0]))
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(2)
    port = ls.getsockname()[1]

    def serve():
        for _ in range(2):
            try:
                c, _ = ls.accept()
                with ctx.wrap_socket(c, server_side=True):
                    pass
            except (OSError, ssl.SSLError):
                pass
    threading.Thread(target=serve, daemon=True).start()
    monkeypatch.setattr(collect, "LOCAL_TLS_PORTS", (port,))
    seen = {}
    out = "notAfter=Nov 14 12:00:00 2026 GMT\nsubject=CN=localhost\nsha256 Fingerprint=" + ":".join(["AB"] * 32) + "\n"
    r = FakeRunner({"openssl_x509_der": lambda slots, stdin: (seen.setdefault("der", stdin), Run(True, "ok", 0, out.encode()))[1]})
    t = collect.local_tls(make_env(tmp_path, r))["listeners"][0]
    assert t["port"] == port and t["days_left"] == 13 and t["subject"] == "CN=localhost" and seen["der"][:1] == b"\x30"
    r2 = FakeRunner({"openssl_x509_der": Run(False, "nonzero", 1, b"", "bad")})
    t2 = make_env(tmp_path / "b", r2)
    threading.Thread(target=serve, daemon=True).start()
    assert collect.local_tls(t2)["listeners"][0]["error"] == "nonzero"
    ls.close()


# ======================================================================================================================== engine
def test_engine_defence_in_depth_branches(tmp_path):
    from forge_node.t0 import engine as E
    eng, env, clk = make_engine(tmp_path)
    with pytest.raises(E.OpDenied):
        eng._logs({"unit": "sshd.service"})
    del eng._ops["inv.host"]
    assert eng.execute("inv.host", 0, {}).reason_code == "DENY_OP_UNKNOWN"
    eng2, *_ = make_engine(tmp_path / "v", FakeRunner({"virsh_list": " Id Name State\n---\n", "virsh_pools": " Name State\n---\n"}), FakeProbe({"vms": {"domains": {"status": "ok", "domains": []}, "pools": {"status": "ok", "pools": []}}}))
    assert json.loads(eng2.execute("inv.vms", 0, {}).output)["data"]["domains"]["status"] == "ok"


# ======================================================================================================================== policy
@pytest.mark.parametrize("over,needle", [
    ({"t0": {"cert_paths": "x"}}, "list"), ({"t0": {"cert_paths": [5]}}, "invalid entry"), ({"t0": {"units_for_logs": "x"}}, "list"), ({"t0": {"units_for_logs": [5]}}, "entry"),
    ({"t0": {"units_for_logs": [{"unit": "a.service", "x": 1}]}}, "entry"), ({"not_before": "yesterday"}, "not_before"), ({"t0": {"backup_units": ["a b"]}}, "invalid entry"),
    ({"t0": {"backup_dirs": ["x" * 5000]}}, "invalid entry"),
])
def test_policy_parse_error_branches(over, needle):
    with pytest.raises(P.PolicyError) as e:
        P.parse_policy(json.dumps(policy_doc(**over)).encode(), "g2", 1, NOW)
    assert needle in e.value.detail
    with pytest.raises(P.PolicyError):
        P.parse_policy(b"[1]", "g2", 1, NOW)
    with pytest.raises(P.PolicyError):
        P.parse_policy(b"not json", "g2", 1, NOW)


def test_policy_too_long_list_and_oversized_file(tmp_path, owner):
    with pytest.raises(P.PolicyError):
        P.parse_policy(json.dumps(policy_doc(t0={"repos": [f"/r/{i}" for i in range(65)]})).encode(), "g2", 1, NOW)
    from n2_helpers import install_policy, signers_text
    d = tmp_path / "policy"
    install_policy(d, policy_doc(), owner["priv"], raw=b" " * (P.MAX_POLICY_BYTES + 5))
    s = tmp_path / "as"
    s.write_text(signers_text(owner["pub"]))
    os.chmod(s, 0o644)
    with pytest.raises(P.PolicyError) as e:
        P.load_installed(str(d), str(s), "g2", NOW, owner_uid=os.getuid(), ssh_keygen="ssh-keygen")
    assert "too large" in e.value.detail or "not a regular" in e.value.detail


# ======================================================================================================================== probes
def test_probe_error_branches(tmp_path):
    assert probes._json_field("{not json") is None
    r = FakeRunner({"docker_ps_ids": CID + "\n", "docker_inspect": Run(False, "timeout")})
    c = probes.run_probe("containers", {}, env_with(tmp_path, r))["containers"]
    assert c == {"status": "error", "code": "timeout"}
    # working dir that does not exist -> owner unknown; log path in docker dir that vanished -> age None; with_usage with an unreadable /proc/<pid>/net/dev -> no net key
    line = inspect_line(labels={"com.docker.compose.project.working_dir": "/srv/gone", "com.docker.compose.project": "p"}, pid=777)
    r = FakeRunner({"docker_ps_ids": CID + "\n", "docker_inspect": line + "\n"})
    c = probes.run_probe("containers", {}, env_with(tmp_path, r))["containers"]["containers"][0]
    assert c["attribution"]["working_dir_owner_uid"] is None and c["last_log_age_s"] is None and "net" not in c


def test_certs_probe_error_rows(tmp_path):
    env = env_with(tmp_path, FakeRunner({"openssl_x509_file": Run(False, "nonzero", 1, b"", "x")}), t0={"cert_paths": ["/etc/c/a.crt"]}, files={"/etc/c/a.crt": "c"})
    assert probes.run_probe("certs", {}, env)["certs"]["paths"][0]["certs"] == [{"file": "a.crt", "error": "nonzero"}]
    env = env_with(tmp_path / "b", FakeRunner(), t0={"cert_paths": ["/etc/c"]}, files={"/etc/c/dangling.crt": "x"})
    os.unlink(tmp_path / "b" / "etc/c/dangling.crt")
    os.symlink("/nonexistent/x", tmp_path / "b" / "etc/c/dangling.crt")
    assert probes.run_probe("certs", {}, env)["certs"]["paths"][0]["certs"] == []


def test_git_probe_edge_cases(tmp_path):
    r = FakeRunner({"git_status_tracked": ""})
    env = git_env(tmp_path, r, ref=None)                                           # no loose ref and no packed-refs: rev unknown, branch known
    g = probes.run_probe("git", {}, env)["repos"]["repos"][0]
    assert g["rev"] is None and g["branch"] == "main"
    env = env_with(tmp_path / "x", r, t0={"repos": ["/opt/missing"]})
    assert probes.run_probe("git", {}, env)["repos"]["repos"][0]["error"] == "unreadable"


def test_git_config_changed_while_git_ran_discards_the_result(tmp_path):
    env_holder = {}

    def status(slots, stdin):
        (tmp_path / "opt/kmu-ai/.git/config").write_text("[core]\n\tfsmonitor = /tmp/evil\n")
        return Run(True, "ok", 0, b" M a\n")
    r = FakeRunner({"git_status_tracked": status})
    g = probes.run_probe("git", {}, git_env(tmp_path, r))["repos"]["repos"][0]
    assert g["dirty_status"] == "config_changed_during_read" and g["dirty_tracked"] is None


def test_git_budget_skips_remaining_repos(tmp_path):
    state = {"t": NOW}

    def status(slots, stdin):
        state["t"] += timedelta(seconds=probes.GIT_BUDGET_S + 1)
        return Run(True, "ok", 0, b"")
    files = {**repo_files(), **{k.replace("kmu-ai", "other"): v for k, v in repo_files().items()}}
    env = env_with(tmp_path, FakeRunner({"git_status_tracked": status}), t0={"repos": ["/opt/kmu-ai", "/opt/other"]}, files=files)
    env.now = lambda: state["t"]
    rows = probes.run_probe("git", {}, env)["repos"]["repos"]
    assert [r["dirty_status"] for r in rows] == ["ok", "skipped_budget"]


def test_access_probe_filesystem_failures(tmp_path):
    env = env_with(tmp_path, FakeRunner({"sshd_effective": ""}))
    (tmp_path / "etc/group").unlink()
    a = probes.run_probe("access", {}, env)
    assert a["groups"]["status"] == "error"
    (tmp_path / "etc/passwd").unlink()
    assert probes.run_probe("access", {}, env)["authorized_keys"]["status"] == "error"
    many = "".join(f"u{i}:x:{2000 + i}:{2000 + i}::/home/u{i}:/bin/bash\n" for i in range(150))
    env = env_with(tmp_path / "m", FakeRunner({"sshd_effective": ""}), files={"/etc/passwd": many, "/etc/group": "docker:x:1:\n"})
    body = "AAAAC3NzaC1lZDI1NTE5AAAAIOCnQJdkGAnqC9RpKFPyX3e4R8Y5v0QG9hJmFqQqkG8E"
    for i in range(120):
        write_tree(tmp_path / "m", {f"/home/u{i}/.ssh/authorized_keys": f"ssh-ed25519 {body} u{i}\n"})
    assert len(probes.run_probe("access", {}, env)["authorized_keys"]["users"]) == 100


def test_models_probe_unreadable_children_and_missing_dir(tmp_path):
    env = env_with(tmp_path, FakeRunner({}, available=set()), t0={"model_dirs": ["/srv/models", "/srv/none"]}, files={"/srv/models/a/x": "1"})
    real = env.fs.list_meta

    def flaky(path, n=2000):
        if path.endswith("/a"):
            raise FsError("unreadable")
        return real(path, n)
    env.fs.list_meta = flaky
    dirs = probes.run_probe("models", {}, env)["models"]["dirs"]
    assert dirs[0]["entries"][0]["children"] == [] and dirs[1]["error"] in ("unreadable", "escape")


def test_journal_probe_failure_is_a_status_section(tmp_path):
    r = FakeRunner({"journal_unit": Run(False, "timeout")})
    assert probes.run_probe("journal", {"unit": "forge-postbote.service"}, env_with(tmp_path, r))["log"] == {"status": "error", "code": "timeout"}


# ======================================================================================================================== spool
def test_spool_os_error_branches(tmp_path, monkeypatch):
    d = tmp_path / "s"
    d.mkdir()
    s = Spool(str(d), os.getuid(), 1 << 16)
    s.append({"ts": "2026-10-31T00:00:00Z"})
    s.append({"ts": "2026-10-31T00:00:01Z"})
    s.close()
    (d / "seg-000000000099.jsonl").write_text('{"seq": 99, "ts": "x"}\nnot json\n' + "x" * 20000 + "\n")
    s2 = Spool(str(d), os.getuid(), 1 << 16)
    got = s2.read_after(0, 100, 10**9)["samples"]
    assert [x["seq"] for x in got] == [1, 2, 99]
    monkeypatch.setattr(Spool, "_open", lambda self, name, flags: (_ for _ in ()).throw(PermissionError("denied")))
    s2._active = None
    with pytest.raises(SpoolError):
        s2.append({"ts": "x"})


def test_spool_gives_up_when_every_name_is_taken(tmp_path):
    d = tmp_path / "s"
    d.mkdir()
    s = Spool(str(d), os.getuid(), 1 << 16)
    for i in range(1, 40):
        (d / f"seg-{i:012d}.jsonl").symlink_to("/nonexistent")
    with pytest.raises(SpoolError):
        s.append({"ts": "x"})


def test_spool_missing_files_and_eviction_races(tmp_path):
    d = tmp_path / "s"
    d.mkdir()
    s = Spool(str(d), os.getuid(), 4096)
    for i in range(40):
        s.append({"ts": "2026-10-31T00:00:00Z", "pad": "z" * 80})
    first = sorted(os.listdir(d))[0]
    os.unlink(d / first)                                  # someone removed the oldest segment: eviction and reads must cope
    for i in range(80):
        s.append({"ts": "2026-10-31T00:00:00Z", "pad": "z" * 80})
    assert s.read_after(0, 10**6, 10**9)["samples"]
    s.close()
    s.close()


# ======================================================================================================================== client
class RawServer:
    def __init__(self, pki, cert, handler):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(str(cert[1]), str(cert[0]))
        ctx.load_verify_locations(str(pki.ca_crt))
        ctx.verify_mode = ssl.CERT_REQUIRED
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.handler, self.ctx = handler, ctx
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            try:
                with self.ctx.wrap_socket(c, server_side=True) as t:
                    data = b""
                    while b"\r\n\r\n" not in data:
                        chunk = t.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                    head, _, body = data.partition(b"\r\n\r\n")
                    want = int(next((l.split(b":")[1] for l in head.split(b"\r\n") if l.lower().startswith(b"content-length")), b"0"))
                    while len(body) < want:                      # read the whole request, else the close would RST the response away
                        chunk = t.recv(65536)
                        if not chunk:
                            break
                        body += chunk
                    t.sendall(self.handler(data))
            except (OSError, ssl.SSLError):
                pass


def http(status, body, extra=""):
    return f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n{extra}\r\n".encode() + body


@pytest.fixture(scope="module")
def raw_certs(pki):
    return {"hub": pki.issue("b_hub", "forge-nodehub", "IP:127.0.0.1", "serverAuth"), "node": pki.issue("b_node", "forge-node-g2", "URI:urn:forge:node:g2", "clientAuth")}


@pytest.mark.parametrize("reply,exc", [
    (http("200 OK", b"not json"), C.HubUnreachable), (http("200 OK", b"[1,2]"), C.HubUnreachable), (http("500 Internal", b'{"error":"internal"}'), C.HubError),
    (http("500 Internal", b"[1]"), C.HubError), (http("200 OK", b"x" * (C.MAX_RESPONSE + 100)), C.HubUnreachable),
])
def test_client_response_handling(pki, raw_certs, reply, exc):
    srv = RawServer(pki, raw_certs["hub"], lambda req: reply)
    c = C.HubClient("127.0.0.1", srv.port, str(raw_certs["node"][1]), str(raw_certs["node"][0]), str(pki.ca_crt), [pki.sha256_der(raw_certs["hub"][1])], timeout_s=5)
    with pytest.raises(exc):
        c.poll({})
    srv.sock.close()


def test_client_connection_close_and_argument_checks(pki, raw_certs):
    srv = RawServer(pki, raw_certs["hub"], lambda req: http("200 OK", b'{"ok":true}', "Connection: close\r\n"))
    c = C.HubClient("127.0.0.1", srv.port, str(raw_certs["node"][1]), str(raw_certs["node"][0]), str(pki.ca_crt), [pki.sha256_der(raw_certs["hub"][1])], timeout_s=5)
    assert c.poll({}) == {"ok": True} and c._conn is None and c.hub_certificate_der() is None
    for bad in (0, -1, True, "1", 10**9):
        with pytest.raises(ValueError):
            c.get_policy(bad)
    with pytest.raises(ValueError):
        c.poll({"x": "y" * (protocol.MAX_BODY_BYTES + 1)})
    with pytest.raises(protocol.ProtoError):
        c.post_result("not-a-uuid", {})
    srv.sock.close()


# ===================================================================================================================== agent loop
def test_main_wiring_and_helpers(monkeypatch, tmp_path, capsys):
    agent_main._log("token=CANARYsecret12345 hello")
    assert "CANARY" not in capsys.readouterr().err
    assert agent_main._now().tzinfo is timezone.utc
    calls = {}

    class FakeAgent:
        def run(self):
            calls["ran"] = True

        def stop(self):
            calls["stopped"] = True
    monkeypatch.setenv("FORGE_NODE_NODE_ID", "g2")
    monkeypatch.setattr(agent_main, "trusted_binary", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(agent_main, "build", lambda cfg, **kw: (calls.setdefault("probe_uid", kw["probe"].expect_uid), calls.setdefault("runner", type(kw["runner"]).__name__), calls.setdefault("keygen", kw["ssh_keygen"]), FakeAgent())[3])
    import signal
    old = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
    try:
        assert agent_main.main([]) == 0
        signal.getsignal(signal.SIGTERM)()
    finally:
        for s, h in old.items():
            signal.signal(s, h)
    assert calls == {"probe_uid": 0, "runner": "ReadOnlyRunner", "keygen": "/usr/bin/ssh-keygen", "ran": True, "stopped": True}
    monkeypatch.setattr(agent_main, "trusted_binary", lambda name: (_ for _ in ()).throw(runner.RunnerError("no trusted ssh-keygen")))
    assert agent_main.main([]) == 2 and "no trusted ssh-keygen" in capsys.readouterr().err


class StubClient:
    def __init__(self, poll=None):
        self.poll_resp, self.posted, self.closed = poll, [], False

    def poll(self, body):
        if isinstance(self.poll_resp, Exception):
            raise self.poll_resp
        return self.poll_resp

    def post_result(self, job_id, body):
        self.posted.append((job_id, body))

    def close(self):
        self.closed = True

    def get_policy(self, serial):
        return {"serial": serial + 1, "policy": "", "sig": ""}


def stub_agent(tmp_path, client, owner_pub=None, engine=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    from forge_node.agent.config import AgentConfig
    cfg = AgentConfig("g2", "127.0.0.1", 1, "/c", "/k", "/ca", str(tmp_path / "policy"), str(tmp_path / "signers"), str(tmp_path), "/s", os.getuid(), os.getuid(), "/")
    v = view()
    logs = []
    (tmp_path / "state").mkdir(exist_ok=True)
    spool = Spool(str(tmp_path / "state"), os.getuid(), 1 << 16)
    holder = type("H", (), {"refresh": lambda self: (v, False), "cfg": cfg})()
    rt = L.Runtime(v, client, engine or type("E", (), {"execute": lambda *a: None, "env": None})())
    ag = L.Agent(cfg, holder, lambda view_: rt, spool, lambda r: None, lambda: NOW, "ssh-keygen", log=logs.append)
    ag.logs = logs
    return ag


def test_poll_error_and_shape_branches(tmp_path):
    ag = stub_agent(tmp_path, StubClient(C.HubError(403, "forbidden")))
    assert ag.poll_once(0) == "unreachable" and any("hub:" in m for m in ag.logs)
    ag = stub_agent(tmp_path / "b", StubClient({"unexpected": 1}))
    assert ag.poll_once(0) == "bad_response"


def test_agent_survives_engine_exceptions(tmp_path, monkeypatch):
    class Boom:
        env = None

        def execute(self, *a):
            raise RuntimeError("bug")
    client = StubClient()
    ag = stub_agent(tmp_path, client, engine=Boom())
    from conftest import job_payload
    monkeypatch.setattr(L.protocol, "verify_job", lambda env, keys, node, now, kg: job_payload(node="g2"))
    rt = ag._runtime()
    ag._run_job(rt, {})
    assert client.posted[0][1]["reason_code"] == "FAIL_EXEC" and client.posted[0][1]["status"] == "failed" and any("unexpected" in m for m in ag.logs)


def test_poll_loop_catches_cycle_exceptions_and_run_starts_both_threads(tmp_path):
    ag = stub_agent(tmp_path, StubClient())
    ag.poll_once = lambda wait_s=25: (_ for _ in ()).throw(RuntimeError("x"))
    ag._stop.wait = lambda d: ag.stop()
    ag._poll_loop()
    assert any("poll cycle failed" in m for m in ag.logs) and ag._fail == 1
    ag2 = stub_agent(tmp_path / "r", StubClient())
    ticks = []
    ag2.sampler = type("S", (), {"tick": lambda self: ticks.append(1)})()
    ag2.poll_once = lambda wait_s=25: (time.sleep(0.05), "idle")[1]
    t = threading.Thread(target=ag2.run)
    t.start()
    time.sleep(0.3)
    ag2.stop()
    t.join(10)
    assert not t.is_alive() and ticks


def test_sample_loop_survives_a_crashing_sampler(tmp_path):
    ag = stub_agent(tmp_path, StubClient())
    ag.sampler = type("S", (), {"tick": lambda self: 1 / 0})()
    ag._stop.wait = lambda d: ag.stop()
    ag._sample_loop()
    assert any("sampler: ZeroDivisionError" in m for m in ag.logs)


def test_flush_drops_expired_pending_and_reconcile_is_logged(tmp_path, monkeypatch):
    ag = stub_agent(tmp_path, StubClient())
    ag._pending = [("j", {}, time.monotonic() - 1)]
    ag._flush_pending(ag._runtime())
    assert ag._pending == []


def test_policy_holder_dedupes_log_lines_and_handles_missing_dir(tmp_path):
    from forge_node.agent.config import AgentConfig
    cfg = AgentConfig("g2", "127.0.0.1", 1, "/c", "/k", "/ca", str(tmp_path / "nopolicy"), str(tmp_path / "signers"), str(tmp_path), "/s", os.getuid(), os.getuid(), "/")
    logs = []
    h = L.PolicyHolder(cfg, lambda: NOW, logs.append, "ssh-keygen")
    assert h.refresh() == (None, False) and h.refresh() == (None, False)
    assert logs == []                                                         # nothing was ever installed: silent
    (tmp_path / "nopolicy").mkdir()
    os.chmod(tmp_path / "nopolicy", 0o755)
    (tmp_path / "nopolicy" / "policy-1.json").write_text("{}")
    h.refresh()
    h.refresh()
    h.refresh()
    assert len(logs) == 1
    assert h._signature() is not None
    assert L.PolicyHolder(AgentConfig("g2", "127.0.0.1", 1, "/c", "/k", "/ca", "/definitely/not/here", "/s", "/st", "/p", 0, 0, "/"), lambda: NOW, logs.append, "ssh-keygen")._signature() is None


def test_selfcheck_ok_when_everything_required_is_present(tmp_path):
    from forge_node.t0 import selfcheck as sc
    avail = set(sc.REQUIRED_COMMANDS)
    env = make_env(tmp_path, FakeRunner({c: "x" for c in avail}), files={"/sys/fs/cgroup/system.slice/a.service/memory.current": "1\n"})
    r = sc.selfcheck(env)
    assert r["missing_required_commands"] == [] and r["cgroup_v2_system_slice"] is True and r["ok"] is True


def test_reconcile_requests_are_logged_not_acted_on_and_invalid_results_become_failures(tmp_path, monkeypatch):
    resp_holder = {}
    client = StubClient()
    ag = stub_agent(tmp_path, client)
    rt = ag._runtime()
    from conftest import lease_payload, job_payload
    monkeypatch.setattr(L.protocol, "verify_lease", lambda env, keys, node, now, last, kg: lease_payload(node="g2", seq=last + 1))
    resp = {"v": 1, "lease": {}, "jobs": [], "reconcile": ["x"], "policy_serial_latest": 0, "server_time": "2026-10-31T13:40:10Z"}
    assert ag._handle(rt, resp) == "idle" and any("no ledger" in m for m in ag.logs)

    class Weird:
        env = None

        def execute(self, *a):
            return L.Outcome("committed", "DENY_STOP", "x")          # committed with a reason code is not a valid result
    ag2 = stub_agent(tmp_path / "w", StubClient(), engine=Weird())
    monkeypatch.setattr(L.protocol, "verify_job", lambda env, keys, node, now, kg: job_payload(node="g2"))
    ag2._run_job(ag2._runtime(), {})
    posted = ag2.rt.client.posted[0][1]
    assert posted["status"] == "failed" and posted["reason_code"] == "FAIL_EXEC" and any("invalid" in m for m in ag2.logs)


def test_fsread_exists_survives_odd_paths_and_sanitize_walks_nested_strings(tmp_path):
    write_tree(tmp_path, PROC)
    f = Fs(ProtectedSet.from_policy([]), str(tmp_path))
    assert f.exists("/proc/meminfo/not-a-dir") is False
    body = {"l": [["a" * 400, ["b" * 400]], {"k": "c" * 400}]}
    out, tr = sanitize.fit(body, 300)
    assert len(canon.canonical(out)) <= 300 and tr


# ===================================================================================================== review round (independent reviewer, 15 findings)
def test_directory_listing_never_follows_a_symlink_swapped_in_after_resolution(tmp_path):
    write_tree(tmp_path, {"/srv/models/a/w.bin": "x", "/etc/secret-dir/shadow": "root-only"})
    f = Fs(ProtectedSet.from_policy([]), str(tmp_path))
    os.rename(tmp_path / "srv/models/a", tmp_path / "srv/models/a.real")
    os.symlink(str(tmp_path / "etc/secret-dir"), tmp_path / "srv/models/a")            # the swap
    with pytest.raises(FsError) as e:
        f.list_meta("/srv/models/a")
    assert e.value.code in ("escape", "unreadable")
    env = env_with(tmp_path, FakeRunner({}, available=set()), t0={"model_dirs": ["/srv/models"]})
    ents = {x["name"]: x for x in probes.run_probe("models", {}, env)["models"]["dirs"][0]["entries"]}
    assert "a" in ents and ents["a"].get("children", []) == [] and "shadow" not in json.dumps(ents)


def test_certificate_links_are_followed_only_to_certificate_looking_unprotected_targets(tmp_path):
    out = "notAfter=Nov 14 12:00:00 2026 GMT\nsubject=CN=x\nsha256 Fingerprint=" + ":".join(["AB"] * 32) + "\n"
    files = {"/etc/letsencrypt/archive/d/fullchain1.pem": "c", "/etc/letsencrypt/archive/d/privkey1.pem": "KEY", "/root/.ssh/innocent.pem": "KEY?", "/etc/ssh/ssh_host.crt": "c"}
    env = env_with(tmp_path, FakeRunner({"openssl_x509_file": out}), t0={"cert_paths": ["/etc/letsencrypt/live/d"]}, files=files)
    live = tmp_path / "etc/letsencrypt/live/d"
    live.mkdir(parents=True)
    os.symlink("../../archive/d/fullchain1.pem", live / "fullchain.pem")                # the legitimate letsencrypt layout
    os.symlink("../../archive/d/privkey1.pem", live / "privkey.pem")                    # name filter already drops it
    os.symlink("../../archive/d/privkey1.pem", live / "cert.pem")                       # innocent link name, key-looking target
    os.symlink(str(tmp_path / "root/.ssh/innocent.pem"), live / "root-link.pem")        # target in the protected set (/root)
    os.symlink("../../../ssh/ssh_host.crt", live / "ssh-link.crt")                      # target in /etc/ssh (protected)
    rows = {c["file"]: c for c in probes.run_probe("certs", {}, env)["certs"]["paths"][0]["certs"]}
    assert rows["fullchain.pem"]["days_left"] == 13
    assert set(rows) == {"fullchain.pem", "cert.pem", "root-link.pem", "ssh-link.crt"} and all(rows[k].get("error") == "target_not_a_certificate_name" for k in rows if k != "fullchain.pem")


def test_odd_directory_names_are_per_item_results_not_probe_failures(tmp_path):
    """Review finding: '(', ')', '&', non-ASCII names made the table refuse the path and killed the whole inv.models/certs/git. Printable names work; control characters degrade ONE item."""
    seen = []
    r = FakeRunner({"du_ionice": lambda slots, _: (seen.append(slots["path"]), Run(True, "ok", 0, b"7\t-\n"))[1]})
    files = {"/srv/models/Qwen3 (Q4)/w": "1", "/srv/models/M\u00fcnchen/w": "1", "/srv/models/a&b;c/w": "1", "/srv/models/bad\nname/w": "1", "/srv/models/ok/w": "1"}
    env = env_with(tmp_path, r, t0={"model_dirs": ["/srv/models"]}, files=files)
    ents = {e["name"]: e for e in probes.run_probe("models", {}, env)["models"]["dirs"][0]["entries"]}
    assert ents["Qwen3 (Q4)"]["size"] == 7 and ents["M\u00fcnchen"]["size"] == 7 and ents["a&b;c"]["size"] == 7 and ents["ok"]["size"] == 7
    assert ents["bad\nname"]["size"] is None and ents["bad\nname"]["size_status"] == "unsupported_name"
    # certs: a file whose real path the table refuses is an item error
    env = env_with(tmp_path / "c", FakeRunner({"openssl_x509_file": "x"}), t0={"cert_paths": ["/etc/c"]}, files={"/etc/c/a\nb.crt": "c"})
    assert probes._CERT_FILE.match("a\nb.crt") is None


def test_du_gets_the_remaining_budget_as_its_deadline(tmp_path):
    waits = []
    state = {"t": NOW}

    def du(slots, _):
        return Run(True, "ok", 0, b"1\t-\n")
    r = FakeRunner({"du_ionice": du})
    orig = r.run

    def run(cid, slots=None, stdin=None, max_wait_s=None):
        waits.append(max_wait_s)
        state["t"] += timedelta(seconds=60)
        return orig(cid, slots, stdin, max_wait_s)
    r.run = run
    env = env_with(tmp_path, r, t0={"model_dirs": ["/srv/models"]}, files={f"/srv/models/m{i}/x": "1" for i in range(4)})
    env.now = lambda: state["t"]
    ents = probes.run_probe("models", {}, env)["models"]["dirs"][0]["entries"]
    assert waits[0] == 120.0 and waits[1] == 90.0 and all(w <= 120 for w in waits)                    # min(120, what is left of the 150 s budget)
    assert [e["size"] for e in ents][:2] == [1, 1] and ents[3]["size_status"] == "skipped_budget"


def test_policy_holder_never_keeps_serving_the_old_policy_after_an_unexpected_error(tmp_path, owner, monkeypatch):
    from forge_node.agent.config import AgentConfig
    from n2_helpers import install_policy, signers_text
    pol = tmp_path / "policy"
    install_policy(pol, policy_doc(), owner["priv"])
    signers = tmp_path / "as"
    signers.write_text(signers_text(owner["pub"]))
    os.chmod(signers, 0o644)
    cfg = AgentConfig("g2", "127.0.0.1", 1, "/c", "/k", "/ca", str(pol), str(signers), str(tmp_path), "/s", os.getuid(), os.getuid(), "/")
    logs = []
    h = L.PolicyHolder(cfg, lambda: NOW, logs.append, "ssh-keygen")
    assert h.refresh()[0].serial == 1
    install_policy(pol, policy_doc(serial=2), owner["priv"])
    monkeypatch.setattr(L, "load_installed", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert h.refresh() == (None, True) and h.view is None and any("unexpected RuntimeError" in m for m in logs)
    # a changed owner key file alone (no policy change) forces a re-verification
    monkeypatch.undo()
    h2 = L.PolicyHolder(cfg, lambda: NOW, logs.append, "ssh-keygen")
    assert h2.refresh()[0].serial == 2
    signers.write_text("# rotated: no owner key any more\n")
    os.chmod(signers, 0o644)
    assert h2.refresh() == (None, True)


def test_staging_survives_garbage_answers_and_untrusted_signer_files(tmp_path, monkeypatch):
    class Client(StubClient):
        def __init__(self, answer):
            super().__init__()
            self.answer = answer

        def get_policy(self, serial):
            return self.answer
    for answer in ({"serial": 2, "policy": 5, "sig": "x"}, {"serial": 3, "policy": "{}", "sig": "x"}, {"serial": 2, "policy": "{}", "sig": ["x"]}, {"unexpected": 1}):
        ag = stub_agent(tmp_path / str(abs(hash(str(answer)))), Client(answer))
        rt = ag._runtime()
        ag._maybe_stage_policy(rt, 2)
        assert any("not staged" in m for m in ag.logs), answer
        assert not (tmp_path / "staging").exists()


def test_clamping_and_key_redaction(tmp_path):
    body = {"disk": {"size": 10**30, "neg": -10**30, "ok": 5}, "label sk-CANARYabcdef123456": "v", "token=CANARYsecret123456": 1}
    t = sanitize.finalize("g2", "inv.disks", "2026-10-31T13:40:10Z", "internal", body, full_redaction=False)
    e = json.loads(t)["data"]
    assert e["disk"] == {"size": 2**53 - 1, "neg": -(2**53 - 1), "ok": 5} and "CANARY" not in t


def test_statvfs_remembers_hung_mounts_and_df_has_a_time_budget(monkeypatch, tmp_path):
    import time
    collect._HUNG.clear()
    calls = []

    def slow(path):
        calls.append(path)
        time.sleep(2)
        raise OSError("late")
    monkeypatch.setattr(os, "statvfs", slow)
    assert collect._statvfs("/mnt/dead", timeout=0.1) == {"unresponsive": True}
    assert collect._statvfs("/mnt/dead", timeout=0.1) == {"unresponsive": True, "remembered": True} and calls == ["/mnt/dead"]
    collect._HUNG.clear()
    mounts = json.dumps({"filesystems": [{"target": f"/mnt/n{i}", "source": "x:/e", "fstype": "nfs4", "options": "rw"} for i in range(5)]})
    env = make_env(tmp_path, FakeRunner({"lsblk": "{}", "findmnt": mounts}))
    monkeypatch.setattr(collect, "DF_BUDGET_S", 0.25)
    t = {"n": 0}

    def fake(path, timeout=3.0):
        t["n"] += 1
        time.sleep(0.2)
        return {"size": 1, "avail": 1, "used": 0}
    dfs = [m["df"] for m in collect.disks(env, statvfs=fake)["mounts"]["mounts"]]
    assert dfs.count({"skipped": "budget"}) >= 2 and t["n"] < 5
    collect._HUNG.clear()


def test_keys_that_filter_to_the_same_text_do_not_overwrite_each_other():
    out = sanitize.clean_tree({"hf_aaaaaaaa1.service": 1, "hf_bbbbbbbb2.service": 2, "a\nb": 3, "a\x00b": 4})
    assert len(out) == 4 and sorted(out.values()) == [1, 2, 3, 4]


def test_the_policy_serials_remembered_for_staging_are_bounded(tmp_path):
    ag = stub_agent(tmp_path, StubClient())
    rt = ag._runtime()
    for serial in range(2, 120):
        ag._maybe_stage_policy(rt, serial)
    assert len(ag._fetched) <= 32 and max(ag._fetched) == 119
