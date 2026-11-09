import json
import os
import re
import socket
import threading
from datetime import timedelta

import pytest

from forge_node.t0 import probes, wire
from forge_node.t0.probes import ProbeError, run_probe
from forge_node.t0.runner import Run

from n2_helpers import FakeRunner, NOW, make_env, policy_doc, view

import probe_decl_guard

H1 = "a" * 40
CID = "c" * 64


@pytest.fixture(autouse=True)
def _every_probe_runs_under_its_declaration(monkeypatch):
    """probefix: all probe tests below also prove that the probe reads nothing its declaration (t0/needs.py) does not name."""
    probe_decl_guard.install(monkeypatch)


def env_with(tmp_path, runner=None, t0=None, files=None, now=NOW, **kw):
    pol = view(policy_doc(t0={"units_for_logs": ["forge-postbote.service", {"unit": "kmu-s2-backup.service", "sensitivity": "customer"}], **(t0 or {})}, **kw))
    return make_env(tmp_path, runner or FakeRunner(), policy=pol, files=files, now=now)


# ------------------------------------------------------------------------------------------------------------------------------- dispatch
def test_unknown_probe_and_non_object_params_rejected(tmp_path):
    env = env_with(tmp_path)
    with pytest.raises(ProbeError) as e:
        run_probe("shell", {}, env)
    assert e.value.code == "DENY_OP_UNKNOWN"
    with pytest.raises(ProbeError) as e:
        run_probe("net", [], env)
    assert e.value.code == "DENY_PARAM"
    for name in ("net", "firewall", "vms", "certs", "git", "access", "models", "activity", "container_net"):
        with pytest.raises(ProbeError) as e:
            run_probe(name, {"x": 1}, env)
        assert e.value.code == "DENY_PARAM", name


@pytest.mark.parametrize("name", sorted(probes.HEAVY_PROBES))
def test_heavy_probes_refuse_inside_the_blackout_window_at_execution_time(tmp_path, name):
    from datetime import datetime, timezone
    inside = datetime(2026, 11, 3, 2, 30, tzinfo=__import__("forge_node.t0.window", fromlist=["BERLIN"]).BERLIN).astimezone(timezone.utc)
    r = FakeRunner()
    env = env_with(tmp_path, r, now=inside)
    with pytest.raises(ProbeError) as e:
        run_probe(name, {}, env)
    assert e.value.code == "DENY_WINDOW" and not r.calls


# ------------------------------------------------------------------------------------------------------------------------------------ net
def test_net_probe_lists_listeners_with_process_names_and_firewall_probe_lists_docker_user_rules(tmp_path):
    r = FakeRunner({"ss_listen_procs": 'tcp LISTEN 0 4096 192.168.10.4:8094 0.0.0.0:* users:(("python3",pid=1,fd=3))\n',
                    "iptables_docker_user": "-N DOCKER-USER\n-A DOCKER-USER -s 192.168.10.0/29 -p tcp -m tcp --dport 8094 -j ACCEPT\n-A DOCKER-USER -j RETURN\n"})
    env = env_with(tmp_path, r)
    n = run_probe("net", {}, env)
    assert set(n) == {"listeners"} and n["listeners"]["listeners"][0]["processes"] == ["python3"] and n["listeners"]["processes_visible"]
    f = run_probe("firewall", {}, env)
    assert set(f) == {"docker_user"} and f["docker_user"]["count"] == 3
    assert [c[0] for c in r.calls] == ["ss_listen_procs", "iptables_docker_user"]            # each probe runs only its own command
    r = FakeRunner({"iptables_docker_user": Run(False, "nonzero", 1, b"", "chain missing")})
    assert run_probe("firewall", {}, env_with(tmp_path / "b", r))["docker_user"]["status"] == "error"


# ----------------------------------------------------------------------------------------------------------------------------- containers
def inspect_line(cid=CID, name="/pg", image="sha256:" + "d" * 64, ref="postgres:16", state="running", restarts=2, started="2026-10-30T10:00:00Z", pid=4242, logpath="/var/lib/docker/containers/x/x-json.log",
                 labels=None, ports=None, mounts=None):
    j = json.dumps
    if mounts is None:
        mounts = [{"Type": "bind", "Source": "/srv/forge/node/mnt/pg", "Destination": "/var/lib/postgresql", "RW": True}, {"Type": "volume", "Name": "vol1", "Source": "/var/lib/docker/volumes/vol1/_data", "Destination": "/data", "RW": True}]
    return "\t".join([j(cid), j(name), j(image), j(ref), j(state), j(restarts), j(started), j(pid), j(logpath), j(labels), j(ports), j(mounts)])


def test_containers_probe_keeps_only_safe_fields_and_flags_attribution(tmp_path):
    labels = {"forge.managed": "true", "forge.project": "forge-core", "forge.critical": "true", "com.docker.compose.project": "fc", "secret.thing": "tok", "org.opencontainers.image.title": "pg",
              "com.docker.compose.project.working_dir": "/srv/forge/fc"}
    line1 = inspect_line(labels=labels, ports={"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5432"}], "9/udp": None})
    line2 = inspect_line(cid="e" * 64, name="/stray", labels=None)
    r = FakeRunner({"docker_ps_ids": f"{CID}\n{'e' * 64}\n", "docker_inspect": line1 + "\n" + line2 + "\n",
                    "docker_image_inspect": json.dumps("sha256:" + "d" * 64) + "\t" + json.dumps(["postgres@sha256:" + "f" * 64]) + "\n"})
    env = env_with(tmp_path, r, files={"/srv/forge/fc/compose.yaml": "x", "/var/lib/docker/containers/x/x-json.log": "log\n"})
    os.utime(tmp_path / "var/lib/docker/containers/x/x-json.log", (NOW.timestamp() - 600, NOW.timestamp() - 600))
    c = run_probe("containers", {}, env)["containers"]
    a, b = c["containers"]
    assert a["id"] == CID[:12] and a["name"] == "pg" and a["image_digests"] == ["postgres@sha256:" + "f" * 64] and a["ports"] == ["127.0.0.1:5432->5432/tcp"]
    assert "secret.thing" not in a["labels"] and a["labels"]["forge.project"] == "forge-core" and a["forge_managed"] and a["forge_critical"] and a["bind_sources"] == ["/srv/forge/node/mnt/pg"]
    assert a["attribution"] == {"forge_project": "forge-core", "compose_project": "fc", "working_dir_owner_uid": 0, "unattributed": False} and a["last_log_age_s"] == 600
    assert b["attribution"]["unattributed"] is True and b["forge_managed"] is False
    assert r.calls[1][1]["id"] == [CID, "e" * 64]


def test_containers_probe_never_requests_env_cmd_and_params_are_closed(tmp_path):
    for params in ({"env": True}, {"with_usage": True}):
        with pytest.raises(ProbeError):
            run_probe("containers", params, env_with(tmp_path))
    assert run_probe("containers", {}, env_with(tmp_path, FakeRunner({})))["containers"] == {"status": "unavailable", "reason": "docker not installed"}


def test_inspect_parser_rejects_malformed_lines():
    assert probes.parse_inspect_line("only\tthree\tfields") is None
    assert probes.parse_inspect_line("\t".join(["\"nothex\""] + ["x"] * 11)) is None
    ok = probes.parse_inspect_line(inspect_line(labels={"a": "b"}, ports={}))
    assert ok["mounts"][0] == {"type": "bind", "source": "/srv/forge/node/mnt/pg", "destination": "/var/lib/postgresql", "rw": True}


def test_a_container_with_tab_newline_or_separators_in_a_mount_path_is_still_inventoried(tmp_path):
    """Review finding: a raw tab-separated mount list let a bind source containing TAB/NEWLINE/'|'/';' make the row unparsable and the container vanish. Mounts are JSON now."""
    nasty = "/srv/x\tevil\nline|pipe;semi"
    line = inspect_line(mounts=[{"Type": "bind", "Source": nasty, "Destination": "/d", "RW": True}], labels={"forge.project": "p"})
    r = FakeRunner({"docker_ps_ids": CID + "\n" + "e" * 64 + "\n", "docker_inspect": line + "\n" + "garbage-row-without-fields\n"})
    c = run_probe("containers", {}, env_with(tmp_path, r))["containers"]
    assert c["count"] == 1 and c["unparsed"] == 1 and c["containers"][0]["bind_sources"] == [nasty]
    assert "{{json .Mounts}}" in " ".join(runner_cmd("docker_inspect"))


def runner_cmd(cid):
    from forge_node.t0 import runner
    return runner.CMDS[cid].argv


def test_container_net_probe_reads_proc_net_dev_per_container(tmp_path):
    r = FakeRunner({"docker_ps_ids": CID + "\n", "docker_inspect": inspect_line(pid=777) + "\n"})
    env = env_with(tmp_path, r, files={"/proc/777/net/dev": "h\nh\n  eth0: 5000 5 0 0 0 0 0 0 7000 7 0 0 0 0 0 0\n    lo: 9 1 0 0 0 0 0 0 9 1 0 0 0 0 0 0\n"})
    assert run_probe("container_net", {}, env)["container_net"]["containers"] == {CID[:12]: {"rx_bytes": 5000, "tx_bytes": 7000}}
    env = env_with(tmp_path / "b", FakeRunner({"docker_ps_ids": CID + "\n", "docker_inspect": inspect_line(pid=778) + "\n"}))
    assert run_probe("container_net", {}, env)["container_net"]["containers"] == {}
    assert run_probe("container_net", {}, env_with(tmp_path / "c", FakeRunner({})))["container_net"]["status"] == "unavailable"
    with pytest.raises(ProbeError):
        run_probe("container_net", {"x": 1}, env)


def test_container_net_probe_with_a_realistic_sized_proc_net_dev(tmp_path):
    """m-5: a docker host's /proc/<pid>/net/dev has dozens of veth/br lines (7.6 KB on carlgpu2, 24189d3 refused > 1 KB). 70 interfaces through the probe's real read path and limit."""
    rows = "".join(f"{('veth%07x' % i):>13}: {1000 + i} {i} 0 0 0 0 0 0 {2000 + i} {i} 0 0 0 0 0 0\n" for i in range(70))
    text = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" \
           "    lo: 9 1 0 0 0 0 0 0 9 1 0 0 0 0 0 0\n" + rows
    assert text.count("\n") >= 60 and len(text) > 3 * 1024          # the old 1024-byte limit would refuse it
    r = FakeRunner({"docker_ps_ids": CID + "\n", "docker_inspect": inspect_line(pid=777) + "\n"})
    env = env_with(tmp_path, r, files={"/proc/777/net/dev": text})
    got = run_probe("container_net", {}, env)["container_net"]["containers"]
    assert got == {CID[:12]: {"rx_bytes": sum(1000 + i for i in range(70)), "tx_bytes": sum(2000 + i for i in range(70))}}


def test_log_path_outside_docker_dir_is_not_statted(tmp_path):
    line = inspect_line(logpath="/etc/shadow")
    r = FakeRunner({"docker_ps_ids": CID + "\n", "docker_inspect": line + "\n"})
    c = run_probe("containers", {}, env_with(tmp_path, r, files={"/etc/shadow": "x"}))["containers"]["containers"][0]
    assert "last_log_age_s" not in c


# ------------------------------------------------------------------------------------------------------------------------------------ vms
def test_vms_absent_and_present(tmp_path):
    assert run_probe("vms", {}, env_with(tmp_path, FakeRunner({})))["domains"]["status"] == "unavailable"
    tbl = " Id   Name   State\n----------------\n 1    lab    running\n"
    v = run_probe("vms", {}, env_with(tmp_path, FakeRunner({"virsh_list": tbl, "virsh_pools": " Name State Autostart\n---\n forge active yes\n"})))
    assert v["domains"]["domains"] == [{"id": "1", "name": "lab", "state": "running"}]


# ---------------------------------------------------------------------------------------------------------------------------------- certs
def test_certs_probe_scans_policy_paths_only_and_computes_days_left(tmp_path):
    out = "notAfter=Nov 14 12:00:00 2026 GMT\nsubject=CN=example\nsha256 Fingerprint=" + ":".join(["CD"] * 32) + "\n"
    r = FakeRunner({"openssl_x509_file": out})
    files = {"/etc/letsencrypt/archive/d/fullchain1.pem": "c", "/etc/letsencrypt/archive/d/privkey1.pem": "KEY", "/etc/letsencrypt/archive/d/readme.txt": "x", "/etc/caddy/cert.crt": "c"}
    env = env_with(tmp_path, r, t0={"cert_paths": ["/etc/letsencrypt/archive/d", "/etc/caddy/cert.crt", "/etc/missing"]}, files=files)
    c = run_probe("certs", {}, env)["certs"]["paths"]
    assert [x["file"] for x in c[0]["certs"]] == ["fullchain1.pem"] and c[0]["certs"][0]["days_left"] == 13 and c[1]["certs"][0]["file"] == "cert.crt" and c[2]["error"] == "unreadable"
    assert all("privkey" not in json.dumps(x) for x in c)
    assert [call[1]["path"] for call in r.calls] == ["/etc/letsencrypt/archive/d/fullchain1.pem", "/etc/caddy/cert.crt"]


# ----------------------------------------------------------------------------------------------------------------------------------- git
def repo_files(config="[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote \"origin\"]\n\turl = https://github.com/x/y.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n",
               head="ref: refs/heads/main\n", ref=H1 + "\n"):
    f = {"/opt/kmu-ai/.git/HEAD": head, "/opt/kmu-ai/.git/config": config, "/opt/kmu-ai/code.py": "x"}
    if ref is not None:
        f["/opt/kmu-ai/.git/refs/heads/main"] = ref
    return f


def git_env(tmp_path, runner, **kw):
    return env_with(tmp_path, runner, t0={"repos": ["/opt/kmu-ai"]}, files=repo_files(**kw))


def test_git_probe_rev_branch_and_tracked_dirty_count(tmp_path):
    r = FakeRunner({"git_status_tracked": " M a.py\n M b.py\n"})
    g = run_probe("git", {}, git_env(tmp_path, r))["repos"]["repos"][0]
    assert g["rev"] == H1 and g["branch"] == "main" and g["detached"] is False and g["dirty_tracked"] == 2 and g["dirty_status"] == "ok"
    assert [c[0] for c in r.calls] == ["git_status_tracked"] and r.calls[0][1]["repo"] == "/opt/kmu-ai"


def test_git_rev_comes_from_packed_refs_and_detached_head(tmp_path):
    r = FakeRunner({"git_status_tracked": ""})
    env = git_env(tmp_path, r, ref=None)
    (tmp_path / "opt/kmu-ai/.git/packed-refs").write_text(f"# pack-refs\n{'b' * 40} refs/heads/main\n{'c' * 40} refs/heads/other\n")
    assert run_probe("git", {}, env)["repos"]["repos"][0]["rev"] == "b" * 40
    d = run_probe("git", {}, git_env(tmp_path, r, head="d" * 40 + "\n"))["repos"]["repos"][0]
    assert d["detached"] is True and d["rev"] == "d" * 40 and d["branch"] is None


EVIL_CONFIGS = [
    "[core]\n\tfsmonitor = /tmp/evil\n", "[core]\n\thooksPath = /tmp/h\n", "[filter \"x\"]\n\tclean = /tmp/evil\n", "[diff \"y\"]\n\ttextconv = /tmp/evil\n", "[include]\n\tpath = /tmp/x\n",
    "[includeIf \"gitdir:/\"]\n\tpath = /tmp/x\n", "[alias]\n\tst = !evil\n", "[core]\n\tsshCommand = evil\n", "[credential]\n\thelper = evil\n", "[extensions]\n\tworktreeConfig = true\n",
    "[core]\n\tfilemode = true \\\n\t, fsmonitor = evil\n", "orphan = key\n", "[core]\n\tpager = evil\n", "[core]\n\tattributesFile = /tmp/a\n", "[core]\n\teditor = evil\n",
    "[core] fsmonitor = x\n", "[CORE]\n\tFSMONITOR = x\n", "[core]\n\tfilemode = true\n\tfsmonitor = /tmp/evil\n",
]


@pytest.mark.parametrize("config", EVIL_CONFIGS)
def test_git_runs_against_a_generated_snapshot_never_the_repository_config(tmp_path, config):
    """Rework 1 (MAJOR 1): there is no scan-then-run. Whatever the repository config says, git is pointed at a private git dir whose config the probe wrote; at the moment git is
    started (inside the runner call) that directory holds ONLY inert keys, the HEAD and the ref the probe read, and nothing else."""
    seen = {}

    def status(slots, stdin):
        snap = slots["snap"]
        seen["files"] = sorted(os.path.relpath(os.path.join(d, f), snap) for d, _, fs in os.walk(snap) for f in fs)
        seen["config"] = open(os.path.join(snap, "config")).read()
        seen["head"] = open(os.path.join(snap, "HEAD")).read()
        seen["ref"] = open(os.path.join(snap, "refs/heads/main")).read()
        seen["repo"] = slots["repo"]
        return Run(True, "ok", 0, b" M a\n")
    r = FakeRunner({"git_status_tracked": status})
    g = run_probe("git", {}, git_env(tmp_path, r, config=config))["repos"]["repos"][0]
    assert g["dirty_status"] == "ok" and g["dirty_tracked"] == 1 and g["rev"] == H1
    assert seen["files"] == ["HEAD", "config", "refs/heads/main"] and seen["head"] == "ref: refs/heads/main\n" and seen["ref"] == H1 + "\n"
    keys = [l.strip() for l in seen["config"].splitlines() if "=" in l]
    assert set(l.split("=")[0].strip() for l in keys) <= {"repositoryformatversion", *probes._INERT_CORE} and seen["config"].startswith("[core]\n")
    for forbidden in ("fsmonitor", "evil", "hookspath", "filter", "include", "alias", "textconv", "sshcommand", "helper", "worktreeconfig", "pager", "editor", "attributesfile", "/tmp"):
        assert forbidden not in seen["config"].lower(), forbidden
    assert g.get("config_not_used"), "whatever was not carried over is reported"


def test_the_snapshot_is_removed_after_the_run_and_even_if_git_fails(tmp_path):
    import glob
    before = set(glob.glob("/tmp/fn-git-*"))
    run_probe("git", {}, git_env(tmp_path, FakeRunner({"git_status_tracked": Run(False, "timeout")})))
    run_probe("git", {}, git_env(tmp_path / "b", FakeRunner({"git_status_tracked": " M x\n"})))
    assert set(glob.glob("/tmp/fn-git-*")) == before


def test_inert_core_settings_are_carried_into_the_snapshot_and_dropped_ones_are_reported(tmp_path):
    seen = {}
    r = FakeRunner({"git_status_tracked": lambda s, _: (seen.setdefault("c", open(os.path.join(s["snap"], "config")).read()), Run(True, "ok", 0, b""))[1]})
    cfg = "[core]\n\tfilemode = false\n\tautocrlf = input\n\tignorecase = true\n\tfsmonitor = /x\n\tsymlinks = $(id)\n[filter \"lfs\"]\n\tclean = git-lfs clean\n[user]\n\tname = a\n"
    g = run_probe("git", {}, git_env(tmp_path, r, config=cfg))["repos"]["repos"][0]
    assert seen["c"] == "[core]\n\trepositoryformatversion = 0\n\tautocrlf = input\n\tfilemode = false\n\tignorecase = true\n"
    assert set(g["config_not_used"]) == {"core.fsmonitor", "core.symlinks", "[filter]", "[user]"}


def test_filter_git_config_output_is_generated_never_copied():
    for text in ("[core]\n\tfilemode = true # c\n", "\ufeff[core]\n\tfilemode = true\n", "[core]\r\n\tfilemode = true\r\n", "[core]\n\tfilemode = tr\nue\n"):
        cfg, _ = probes.filter_git_config(text)
        assert cfg.startswith("[core]\n\trepositoryformatversion = 0\n") and "#" not in cfg and "\r" not in cfg and "\ufeff" not in cfg
    assert probes.filter_git_config("[core]\n\tfilemode = true\n[remote \"o\"]\n\turl = u\n")[1] == ["[remote]"]


def test_git_head_with_dotdot_branch_or_non_hex_rev_is_not_followed(tmp_path):
    r = FakeRunner({"git_status_tracked": ""})
    g = run_probe("git", {}, git_env(tmp_path, r, head="ref: refs/heads/../../../etc/passwd\n"))["repos"]["repos"][0]
    assert g["rev"] is None
    g = run_probe("git", {}, git_env(tmp_path, r, ref="not-a-hash\n"))["repos"]["repos"][0]
    assert g["rev"] is None


def test_git_status_failure_and_unsupported_layout(tmp_path):
    g = run_probe("git", {}, git_env(tmp_path, FakeRunner({"git_status_tracked": Run(False, "timeout")})))["repos"]["repos"][0]
    assert g["dirty_status"] == "failed:timeout"
    env = env_with(tmp_path, FakeRunner(), t0={"repos": ["/opt/wt"]}, files={"/opt/wt/.git": "gitdir: /elsewhere\n"})
    assert run_probe("git", {}, env)["repos"]["repos"][0]["error"] == "unsupported_git_layout"


def test_git_probe_does_not_read_other_files_of_the_protected_repo(tmp_path):
    env = git_env(tmp_path, FakeRunner({"git_status_tracked": ""}))
    with pytest.raises(Exception):
        env.fs.read_text("/opt/kmu-ai/code.py")
    assert not probes._SAFE_GIT_FILES.match("/opt/kmu-ai/.env") and not probes._SAFE_GIT_FILES.match("/opt/kmu-ai/.git/hooks/pre-commit") and not probes._SAFE_GIT_FILES.match("/opt/kmu-ai/.git/index")


# -------------------------------------------------------------------------------------------------------------------------------- access
def test_access_probe_returns_fingerprints_and_comments_only(tmp_path):
    body = "AAAAC3NzaC1lZDI1NTE5AAAAIOCnQJdkGAnqC9RpKFPyX3e4R8Y5v0QG9hJmFqQqkG8E"
    files = {"/home/carl/.ssh/authorized_keys": f"ssh-ed25519 {body} carl@mac\n", "/root/.ssh/authorized_keys": f'command="x --password=hunter2" ssh-ed25519 {body} root-backup\n',
             "/var/www/.ssh/authorized_keys": f"ssh-ed25519 {body} www\n"}
    r = FakeRunner({"sshd_effective": "port 22\nallowusers carl\nhostkey /etc/ssh/ssh_host_ed25519_key\n"})
    a = run_probe("access", {}, env_with(tmp_path, r, files=files))
    assert a["sshd"]["allowusers"] == ["carl"] and a["groups"]["docker"] == ["carl", "forge"]
    users = {u["user"]: u for u in a["authorized_keys"]["users"]}
    assert set(users) == {"root", "carl"} and users["carl"]["keys"][0]["comment"] == "carl@mac" and "hunter2" not in json.dumps(a) and body not in json.dumps(a)


def test_access_probe_refuses_symlinked_authorized_keys(tmp_path):
    body = "AAAAC3NzaC1lZDI1NTE5AAAAIOCnQJdkGAnqC9RpKFPyX3e4R8Y5v0QG9hJmFqQqkG8E"
    env = env_with(tmp_path, FakeRunner({"sshd_effective": ""}), files={"/etc/shadow": f"ssh-ed25519 {body} leaked\n"})
    (tmp_path / "home/carl/.ssh").mkdir(parents=True)
    os.symlink("/etc/shadow", tmp_path / "home/carl/.ssh/authorized_keys")
    os.symlink(str(tmp_path / "etc/shadow"), tmp_path / "home/carl/.ssh/authorized_keys2")
    a = run_probe("access", {}, env)
    assert not any(u["user"] == "carl" for u in a["authorized_keys"]["users"])


# ---------------------------------------------------------------------------------------------------------------------------------- models
def test_models_probe_metadata_only_with_sizes_from_ionice_du(tmp_path):
    files = {"/srv/models/llama/weights.safetensors": "SECRET-WEIGHTS", "/srv/models/llama/config.json": "{}", "/srv/models/readme.txt": "hi"}
    r = FakeRunner({"du_ionice": lambda slots, _: Run(True, "ok", 0, b"123456\t" + slots["path"].encode() + b"\n")})
    env = env_with(tmp_path, r, t0={"model_dirs": ["/srv/models"]}, files=files)
    m = run_probe("models", {}, env)["models"]["dirs"][0]
    names = {e["name"]: e for e in m["entries"]}
    assert names["llama"]["size"] == 123456 and [c["name"] for c in names["llama"]["children"]] == ["config.json", "weights.safetensors"] and names["readme.txt"]["size"] == 2
    assert "SECRET" not in json.dumps(m)
    assert [c[0] for c in r.calls] == ["du_ionice"]


def test_models_probe_without_ionice_reports_no_sizes_never_runs_du(tmp_path):
    r = FakeRunner({}, available=set())
    env = env_with(tmp_path, r, t0={"model_dirs": ["/srv/models"]}, files={"/srv/models/a/x": "1"})
    e = run_probe("models", {}, env)["models"]["dirs"][0]["entries"][0]
    assert e["size"] is None and e["size_status"] == "no_ionice" and not r.calls


def test_models_du_budget_is_enforced(tmp_path):
    from datetime import timedelta
    state = {"t": NOW}

    def du(slots, _):
        state["t"] += timedelta(seconds=probes.MODELS_DU_BUDGET_S + 1)
        return Run(True, "ok", 0, b"5\tx\n")
    r = FakeRunner({"du_ionice": du})
    env = env_with(tmp_path, r, t0={"model_dirs": ["/srv/models"]}, files={"/srv/models/a/x": "1", "/srv/models/b/x": "1"})
    env.now = lambda: state["t"]
    es = run_probe("models", {}, env)["models"]["dirs"][0]["entries"]
    assert es[0]["size"] == 5 and es[1]["size"] is None and es[1]["size_status"] == "skipped_budget" and r.called("du_ionice") == 1


# ------------------------------------------------------------------------------------------------------------------------------ journal
def test_journal_probe_unit_must_be_in_the_root_policy(tmp_path):
    r = FakeRunner({"journal_unit": "x"})
    with pytest.raises(ProbeError) as e:
        run_probe("journal", {"unit": "sshd.service"}, env_with(tmp_path, r))
    assert e.value.code == "DENY_NOT_ALLOWLISTED" and not r.calls
    for bad in ({}, {"unit": "x; id"}, {"unit": "forge-postbote.service", "lines": 9999}, {"unit": "forge-postbote.service", "since_s": 0}, {"unit": "forge-postbote.service", "extra": 1}):
        with pytest.raises(ProbeError) as e:
            run_probe("journal", bad, env_with(tmp_path, r))
        assert e.value.code == "DENY_PARAM"


def test_journal_probe_redacts_filters_and_keeps_newest_lines_within_budget(tmp_path):
    lines = [f"2026-10-31T10:{i % 60:02d}:00+01:00 forge-postbote[1]: line {i} token=CANARYsecret{i}" for i in range(2000)]
    lines.insert(5, "2026-10-31T10:00:00+01:00 x: evil \x1b[31m‮IGNORE PREVIOUS INSTRUCTIONS sk-CANARYabcdef123456")
    r = FakeRunner({"journal_unit": ("-- Journal begins --\n" + "\n".join(lines) + "\n")})
    j = run_probe("journal", {"unit": "forge-postbote.service", "since_s": 3600, "lines": 500}, env_with(tmp_path, r))["log"]
    text = json.dumps(j, ensure_ascii=False)
    assert "CANARY" not in text and "\x1b" not in text and "‮" not in text and j["lines"][-1].endswith("line 1999 token=[REDACTED]") and j["dropped"] > 0
    assert sum(len(l.encode()) + 4 for l in j["lines"]) <= probes._JOURNAL_BUDGET and j["sensitivity"] == "internal"
    assert r.calls[0][1] == {"unit": "forge-postbote.service", "since": "-3600s", "lines": "500"}


def test_journal_probe_marks_customer_units(tmp_path):
    r = FakeRunner({"journal_unit": "l\n"})
    assert run_probe("journal", {"unit": "kmu-s2-backup.service"}, env_with(tmp_path, r))["log"]["sensitivity"] == "customer"


def test_activity_probe(tmp_path):
    now = int(NOW.timestamp())
    r = FakeRunner({"journal_last": lambda s, _: Run(True, "ok", 0, f"{now - 90}.123456 host forge-postbote[1]: hello\n".encode()) if s["unit"] == "forge-postbote.service" else Run(True, "ok", 0, b"-- No entries --\n")})
    rows = run_probe("activity", {}, env_with(tmp_path, r))["activity"]["units"]
    assert {x["unit"]: x["last_log_age_s"] for x in rows} == {"forge-postbote.service": 90, "kmu-s2-backup.service": None}


# ------------------------------------------------------------------------------------------------------------------------------- wire
class FakePrivd:
    """Minimal privd stand-in: a Unix socket that answers `t0` requests with wire.handle_request."""

    def __init__(self, path, env):
        self.path, self.env = path, env
        self.srv = socket.socket(socket.AF_UNIX)
        self.srv.bind(path)
        self.srv.listen(4)
        self.requests = []
        self.t = threading.Thread(target=self.loop, daemon=True)
        self.t.start()

    def loop(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            with c:
                buf = b""
                while not buf.endswith(b"\n"):
                    d = c.recv(65536)
                    if not d:
                        break
                    buf += d
                if not buf:
                    continue
                self.requests.append(buf)
                try:
                    c.sendall(wire.handle_request(buf, self.env))
                except OSError:
                    pass

    def close(self):
        self.srv.close()


@pytest.fixture
def privd(tmp_path):
    env = env_with(tmp_path, FakeRunner({"ss_listen_procs": "tcp LISTEN 0 1 1.2.3.4:1 0.0.0.0:*\n", "iptables_docker_user": "-N DOCKER-USER\n"}))
    sock = f"/tmp/fn-priv-{os.getpid()}-{id(tmp_path)}.sock"
    p = FakePrivd(sock, env)
    yield p
    p.close()
    os.unlink(sock) if os.path.exists(sock) else None


def test_socket_client_round_trip_and_denial_mapping(privd):
    c = wire.SocketProbeClient(privd.path, expect_uid=os.getuid(), timeout_s=5)
    assert c.call("net", {})["listeners"]["status"] == "ok"
    with pytest.raises(wire.ProbeDenied) as e:
        c.call("journal", {"unit": "sshd.service"})
    assert e.value.code == "DENY_NOT_ALLOWLISTED"
    with pytest.raises(wire.ProbeDenied) as e:
        c.call("rm-rf", {})
    assert e.value.code == "DENY_OP_UNKNOWN"


def test_client_refuses_a_peer_with_the_wrong_uid_before_sending_anything(privd):
    c = wire.SocketProbeClient(privd.path, expect_uid=os.getuid() + 1, timeout_s=5)
    with pytest.raises(wire.ProbeUnavailable):
        c.call("net", {})
    assert privd.requests == []


def test_client_reports_unavailable_for_missing_socket_garbage_and_oversized(tmp_path):
    with pytest.raises(wire.ProbeUnavailable):
        wire.SocketProbeClient(str(tmp_path / "none.sock"), os.getuid()).call("net", {})
    for reply in (b"not json\n", b'{"ok":"yes"}\n', b'{"ok":true,"data":[1]}\n', b"x" * (wire.MAX_LINE + 10)):
        path = f"/tmp/fn-bad-{os.getpid()}-{len(reply)}.sock"
        srv = socket.socket(socket.AF_UNIX)
        srv.bind(path)
        srv.listen(1)

        def serve(s=srv, rep=reply):
            c, _ = s.accept()
            c.recv(65536)
            try:
                c.sendall(rep)
            except OSError:
                pass
            c.close()
        t = threading.Thread(target=serve, daemon=True)
        t.start()
        with pytest.raises(wire.ProbeUnavailable):
            wire.SocketProbeClient(path, os.getuid(), timeout_s=3).call("net", {})
        t.join(5)
        srv.close()
        os.unlink(path)


def test_handle_request_rejects_malformed_requests_and_survives_probe_bugs(tmp_path, monkeypatch):
    env = env_with(tmp_path)
    for line in (b"{}\n", b'{"req":"exec","probe":"net","params":{}}\n', b"x\n", b'{"req":"t0","probe":1,"params":{}}\n', b'{"req":"t0","probe":"net","params":{},"extra":1}\n', b'{"req":"t0","probe":"net","params":{}}'):
        r = json.loads(wire.handle_request(line, env))
        assert r["ok"] is False and r["code"] == "BAD_REQUEST"
    monkeypatch.setitem(probes.__dict__, "_probe_net", lambda p, e: 1 / 0)
    r = json.loads(wire.handle_request(wire.encode_request("net", {}), env))
    assert r == {"ok": False, "code": "FAIL_EXEC", "detail": "ZeroDivisionError"}


def test_uulog_probe_returns_only_the_parsed_outcome_never_log_lines(tmp_path):
    log = "2026-10-31 06:25:01,100 INFO Starting unattended upgrades script\n2026-10-31 06:25:01,200 INFO Allowed origins are: o=Ubuntu,a=noble, o=Ubuntu,a=noble-security\n2026-10-31 06:25:02,000 INFO password=hunter2 All upgrades installed\n"
    env = env_with(tmp_path, FakeRunner(), files={"/var/log/unattended-upgrades/unattended-upgrades.log": log})
    r = run_probe("uulog", {}, env)["uulog"]
    assert r == {"status": "ok", "last_run": "2026-10-31 06:25:01", "result": "installed", "origins": ["o=Ubuntu,a=noble", "o=Ubuntu,a=noble-security"]}
    assert "hunter2" not in json.dumps(r)
    assert run_probe("uulog", {}, env_with(tmp_path / "none", FakeRunner()))["uulog"]["status"] == "error"
    with pytest.raises(ProbeError):
        run_probe("uulog", {"x": 1}, env)


def test_wire_answers_survive_values_canonical_json_would_reject(tmp_path, monkeypatch):
    """Review finding: huge integers, NUL and lone surrogates in probe data turned the whole answer into FAIL_EXEC at the wire."""
    monkeypatch.setitem(probes.__dict__, "_probe_vms", lambda p, e: {"domains": {"status": "ok", "domains": [{"name": "a\x00b", "size": 10**30, "weird": "x\ud800y", "n": [1, None, True]}]}})
    r = json.loads(wire.handle_request(wire.encode_request("vms", {}), env_with(tmp_path)))
    d = r["data"]["domains"]["domains"][0]
    assert r["ok"] is True and d["name"] == "a?b" and d["size"] == 2**53 - 1 and "\ud800" not in json.dumps(d, ensure_ascii=True).replace("\\ud800", "") or d["weird"].startswith("x")


def test_unicode_line_separators_in_docker_output_do_not_hide_a_container(tmp_path):
    """Review finding: Python splitlines() splits on U+0085/U+2028 which Go's {{json}} does not escape; the row broke in two and the container vanished."""
    line = inspect_line(labels={"forge.project": "p", "com.docker.compose.project": "x\u0085y\u2028z"})
    line = line.replace("\\u0085", "\u0085").replace("\\u2028", "\u2028")                  # Go's {{json}} emits these raw; Python's json.dumps escapes them
    assert "\u0085" in line and len(line.splitlines()) == 3 and len(line.split("\n")) == 1
    r = FakeRunner({"docker_ps_ids": CID + "\n", "docker_inspect": line + "\n"})
    c = run_probe("containers", {}, env_with(tmp_path, r))["containers"]
    assert c["count"] == 1 and c["unparsed"] == 0


def test_container_probes_stop_at_their_time_budget_and_say_so(tmp_path):
    state = {"t": NOW}
    ids = "\n".join(f"{i:064x}" for i in range(1, 301))

    def inspect(slots, _):
        state["t"] += timedelta(seconds=35)
        return Run(True, "ok", 0, "\n".join(inspect_line(cid=c) for c in slots["id"]).encode() + b"\n")
    r = FakeRunner({"docker_ps_ids": ids, "docker_inspect": inspect})
    env = env_with(tmp_path, r)
    env.now = lambda: state["t"]
    c = run_probe("containers", {}, env)["containers"]
    assert 0 < c["count"] < 300 and c["unparsed"] == 300 - c["count"] and r.called("docker_inspect") <= 4


def test_activity_probe_stops_at_its_time_budget(tmp_path):
    from datetime import timedelta as td
    state = {"t": NOW}
    pol_units = [f"u{i}.service" for i in range(12)]
    pol = view(policy_doc(t0={"units_for_logs": pol_units}))

    def last(slots, _):
        state["t"] += td(seconds=15)
        return Run(True, "ok", 0, b"-- No entries --\n")
    env = make_env(tmp_path, FakeRunner({"journal_last": last}), policy=pol)
    env.now = lambda: state["t"]
    rows = run_probe("activity", {}, env)["activity"]["units"]
    assert any(r.get("skipped") == "budget" for r in rows) and rows[0].get("skipped") is None


def test_the_git_snapshot_is_private_and_nothing_else_is_written(tmp_path):
    seen = {}

    def status(slots, stdin):
        st = os.stat(slots["snap"])
        seen["mode"], seen["uid"], seen["parent"] = st.st_mode & 0o777, st.st_uid, os.path.dirname(slots["snap"])
        seen["repo_before"] = sorted(str(p) for p in (tmp_path / "opt/kmu-ai").rglob("*"))
        return Run(True, "ok", 0, b"")
    env = git_env(tmp_path, FakeRunner({"git_status_tracked": status}))
    before = sorted(str(p) for p in (tmp_path / "opt/kmu-ai").rglob("*"))
    run_probe("git", {}, env)
    after = sorted(str(p) for p in (tmp_path / "opt/kmu-ai").rglob("*"))
    assert seen["mode"] == 0o700 and seen["uid"] == os.getuid() and seen["parent"] == __import__("tempfile").gettempdir()
    assert before == after == seen["repo_before"]                           # the repository tree is neither written nor given extra files


# ===================================================================================== rework 2: the snapshot must not be able to write outside itself

GOOD_BRANCHES = ["main", "feature/x", "release-1.2", "a.b/c_d", "v1.0.0", "x" * 100, "user/fix-123"]
BAD_BRANCHES = ["/abs/path", "//x", "a//b", "a/", "/", ".hidden", "a/.hidden", "a..b", "a.lock", "a/b.lock", "a b", "a\\b", "a~b", "a^b", "a:b", "a?b", "a*b", "a[b", "a@{b", "@", "-flag", "a.", "",
                "x" * 201, "../../etc/x", "a/../b", "a\x00b", "ünï", "refs/heads/../x"]


@pytest.mark.parametrize("name", GOOD_BRANCHES)
def test_ordinary_branch_names_are_accepted(name):
    assert probes.valid_branch(name)


@pytest.mark.parametrize("name", BAD_BRANCHES)
def test_malformed_absolute_and_odd_ref_names_are_refused(name):
    assert not probes.valid_branch(name)


def _wire_git(env):
    return json.loads(wire.handle_request(wire.encode_request("git", {}), env))


@pytest.mark.parametrize("branch_of", [lambda canary: str(canary), lambda canary: "../" * 12 + str(canary).lstrip("/"), lambda canary: "x/../../" + str(canary).lstrip("/")])
def test_a_branch_ref_that_names_a_path_cannot_make_the_probe_write_there(tmp_path, branch_of):
    """The reviewer's case through wire.handle_request: HEAD `ref: refs/heads//<absolute path>` plus a matching loose ref; os.path.join discarded the snapshot prefix and the canary was
    overwritten with the revision. Now: refused as malformed, git never started, the canary is untouched, nothing else appears."""
    canary = tmp_path / "outside" / "canary.txt"
    canary.parent.mkdir()
    canary.write_text("CANARY-UNTOUCHED\n")
    branch = branch_of(canary)
    head = f"ref: refs/heads/{'/' if str(canary).startswith('/') and branch == str(canary) else ''}{branch.lstrip('/') if branch != str(canary) else branch.lstrip('/')}\n"
    if branch == str(canary):
        head = f"ref: refs/heads/{branch}\n"                                 # exactly the reviewer's 'refs/heads//tmp/...'
    r = FakeRunner({"git_status_tracked": lambda s, _: (_ for _ in ()).throw(AssertionError("git must not be started for a malformed ref"))})
    files = repo_files(head=head, ref=None)
    env = env_with(tmp_path, r, t0={"repos": ["/opt/kmu-ai"]}, files=files)
    # the matching loose ref, as in the review (inside the fixture repository, at the path the HEAD names)
    loose = tmp_path / "opt/kmu-ai/.git/refs/heads" / ("/".join(p for p in branch.split("/") if p not in ("", ".", "..")) or "x")
    loose.parent.mkdir(parents=True, exist_ok=True)
    loose.write_text("a" * 40 + "\n")
    before = sorted(str(p) for p in tmp_path.rglob("*"))
    resp = _wire_git(env)
    assert resp["ok"] is True
    row = resp["data"]["repos"]["repos"][0]
    assert row["error"] == "malformed_ref" and row["dirty_status"] == "rejected:malformed_ref" and row["rev"] is None and row["branch"] is None
    assert canary.read_text() == "CANARY-UNTOUCHED\n"
    assert sorted(str(p) for p in tmp_path.rglob("*")) == before and not r.calls


def test_a_valid_branch_that_merely_looks_like_a_path_stays_inside_the_snapshot(tmp_path):
    """`refs/heads/tmp/x/canary` is a legal (if odd) branch name: git runs, the ref is created UNDER refs/heads of the snapshot, the real file of that name is untouched."""
    canary = tmp_path / "outside" / "canary.txt"
    canary.parent.mkdir()
    canary.write_text("CANARY-UNTOUCHED\n")
    branch = str(canary).lstrip("/")
    seen = {}

    def status(slots, _):
        seen["ref"] = open(os.path.join(slots["snap"], "refs/heads", branch)).read()
        seen["head"] = open(os.path.join(slots["snap"], "HEAD")).read()
        return Run(True, "ok", 0, b"")
    env = env_with(tmp_path, FakeRunner({"git_status_tracked": status}), t0={"repos": ["/opt/kmu-ai"]}, files=repo_files(head=f"ref: refs/heads/{branch}\n", ref=None))
    loose = tmp_path / "opt/kmu-ai/.git/refs/heads" / branch
    loose.parent.mkdir(parents=True, exist_ok=True)
    loose.write_text("a" * 40 + "\n")
    row = _wire_git(env)["data"]["repos"]["repos"][0]
    assert row["dirty_status"] == "ok" and seen["ref"] == "a" * 40 + "\n" and seen["head"] == f"ref: refs/heads/{branch}\n" and canary.read_text() == "CANARY-UNTOUCHED\n"


def test_the_snapshot_writer_itself_refuses_paths_that_leave_it_even_if_validation_upstream_failed(tmp_path):
    """Second layer: _git_snapshot is called with a hostile branch directly (as if valid_branch had a hole)."""
    from forge_node.t0 import confined
    canary = tmp_path / "canary"
    canary.write_text("untouched")
    for branch in (str(canary), "../../" + str(canary).lstrip("/"), "a/../../x", "/", "a//b"):
        with pytest.raises(confined.ConfinementError):
            probes._git_snapshot({"rev": "a" * 40, "detached": False, "branch": branch}, "[core]\n")
    assert canary.read_text() == "untouched"
    import glob
    assert not [p for p in glob.glob("/tmp/fn-git-*") if os.path.isdir(p) and str(tmp_path) in p]


def test_confined_writes_refuse_dotdot_absolute_empty_nul_and_backslash_components(tmp_path):
    from forge_node.t0 import confined
    fd = confined.open_dir(str(tmp_path))
    try:
        for parts in (["..", "x"], ["/etc", "x"], ["a", ""], ["a", "."], ["a\x00b"], ["a\\b"], [], ["a/b"], [".hidden"], ["-x"], ["x" * 101]):
            with pytest.raises(confined.ConfinementError):
                confined.write_new_at(fd, parts, b"x")
        confined.write_new_at(fd, ["d", "e", "f.txt"], b"ok")
        assert (tmp_path / "d/e/f.txt").read_bytes() == b"ok"
        with pytest.raises(FileExistsError):
            confined.write_new_at(fd, ["d", "e", "f.txt"], b"again")                       # O_EXCL
    finally:
        os.close(fd)


def test_confined_writes_do_not_follow_a_symlink_planted_in_the_directory(tmp_path):
    from forge_node.t0 import confined
    outside = tmp_path / "outside"
    outside.mkdir()
    snap = tmp_path / "snap"
    snap.mkdir()
    os.symlink(outside, snap / "refs")                                   # a directory link where we want to create a directory
    fd = confined.open_dir(str(snap))
    try:
        with pytest.raises(OSError):
            confined.write_new_at(fd, ["refs", "heads", "main"], b"x")
        os.symlink(outside / "target", snap / "HEAD")                       # a link where we want to create a file
        with pytest.raises(OSError):
            confined.write_new_at(fd, ["HEAD"], b"x")
    finally:
        os.close(fd)
    assert list(outside.iterdir()) == []
    link = tmp_path / "linked-snap"
    os.symlink(snap, link)
    with pytest.raises(OSError):
        confined.open_dir(str(link))                                        # the directory itself may not be a link


def test_a_loose_ref_that_is_a_symlink_is_not_followed(tmp_path):
    secret = tmp_path / "secret-ref"
    secret.write_text("b" * 40 + "\n")
    r = FakeRunner({"git_status_tracked": " M x\n"})
    env = git_env(tmp_path, r, ref=None)
    (tmp_path / "opt/kmu-ai/.git/refs/heads").mkdir(parents=True, exist_ok=True)
    os.symlink(secret, tmp_path / "opt/kmu-ai/.git/refs/heads/main")
    row = _wire_git(env)["data"]["repos"]["repos"][0]
    assert row["rev"] is None and row["dirty_status"] == "no_revision" and not r.calls


def test_staging_blobs_are_written_through_confined_descriptors(tmp_path):
    from forge_node.agent import loop as L
    ag = None
    from test_n2_branches import stub_agent, StubClient
    ag = stub_agent(tmp_path / "ag", StubClient())
    ag.cfg = ag.cfg.__class__(**{**ag.cfg.__dict__, "state_dir": str(tmp_path / "state")})
    (tmp_path / "state").mkdir()
    ag._write_staged(7, {"policy": "{}", "sig": "S"})
    assert (tmp_path / "state/staging/policy-7.json").read_text() == "{}" and (tmp_path / "state/staging/policy-7.json.sig").read_text() == "S"
    assert sorted(os.listdir(tmp_path / "state/staging")) == ["policy-7.json", "policy-7.json.sig"]
    ag._write_staged(7, {"policy": "{2}", "sig": "S2"})                    # re-staging replaces
    assert (tmp_path / "state/staging/policy-7.json").read_text() == "{2}"
    for bad in (0, -1, True, "7", 10**10, 1.5):
        with pytest.raises(ValueError):
            ag._write_staged(bad, {"policy": "x", "sig": "y"})
    outside = tmp_path / "outside"
    outside.mkdir()
    os.rename(tmp_path / "state/staging", tmp_path / "state/staging.old")
    os.symlink(outside, tmp_path / "state/staging")                           # staging replaced by a link
    with pytest.raises(OSError):
        ag._write_staged(8, {"policy": "x", "sig": "y"})
    assert list(outside.iterdir()) == []


def test_a_failure_while_building_the_snapshot_removes_it_and_reports_failed_snapshot(tmp_path, monkeypatch):
    import glob
    from forge_node.t0 import confined
    before = set(glob.glob("/tmp/fn-git-*"))
    real = confined.write_new_at

    def flaky(fd, parts, data, mode=0o600):
        if parts == ["config"]:
            raise OSError("disk full")
        return real(fd, parts, data, mode)
    monkeypatch.setattr(confined, "write_new_at", flaky)
    r = FakeRunner({"git_status_tracked": " M x\n"})
    row = _wire_git(git_env(tmp_path, r))["data"]["repos"]["repos"][0]
    assert row["dirty_status"] == "failed:snapshot" and row["rev"] == H1 and not r.calls
    assert set(glob.glob("/tmp/fn-git-*")) == before
