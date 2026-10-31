"""Live-proof style tests against the REAL binaries in the test image (read-only commands on throw-away data): the argv of the command table and the parsers must work on real output,
not only on scripted fixtures. Skipped tools are named in the skip reason - the gate jobs count them."""
import os
import shutil
import subprocess
from datetime import datetime, timedelta, timezone

import pytest

from forge_node.t0 import collect, parse, probes, runner
from forge_node.t0.env import Env
from forge_node.t0.fsread import Fs, ProtectedSet
from forge_node.t0.runner import ReadOnlyRunner

from n2_helpers import NOW, policy_doc, view

need = lambda *b: pytest.mark.skipif(not all(shutil.which(x) for x in b), reason=f"needs {b} in the test image")


def real_env(policy=None):
    pol = policy or view()
    return Env(Fs(ProtectedSet.from_policy([])), ReadOnlyRunner(), lambda: datetime.now(timezone.utc), pol)


@need("lsblk", "findmnt")
def test_lsblk_and_findmnt_real_output_parses():
    r = runner.run("lsblk")
    assert r.ok or r.reason == "nonzero"                                  # a container may have no block devices; the command line itself must be accepted
    assert r.reason != "bad_slot"
    f = runner.run("findmnt")
    assert f.ok, f
    m = parse.findmnt(f.text)
    assert m and all(set(x) == {"target", "source", "fstype", "options"} for x in m) and any(x["target"] == "/" for x in m)
    d = collect.disks(real_env())
    assert d["mounts"]["status"] == "ok" and d["mounts"]["mounts"] and any(x["df"] and x["df"].get("size", 0) > 0 for x in d["mounts"]["mounts"])      # in a container '/' is an overlay (filtered)


@need("openssl")
def test_openssl_x509_real_output_for_file_and_der(tmp_path, pki):
    key, crt = pki.issue("rt_leaf", "forge-node-g2", "URI:urn:forge:node:g2", "clientAuth")
    r = runner.run("openssl_x509_file", {"path": str(crt)})
    assert r.ok, r
    d = parse.x509(r.text)
    assert d["sha256"] == pki.sha256_der(crt) and d["subject"] == "CN=forge-node-g2" and d["not_after_epoch"] > datetime.now(timezone.utc).timestamp() + 20 * 86400
    der = subprocess.run(["openssl", "x509", "-in", str(crt), "-outform", "der"], capture_output=True, check=True).stdout
    r2 = runner.run("openssl_x509_der", stdin=der)
    assert r2.ok and parse.x509(r2.text)["sha256"] == d["sha256"]
    c = collect.own_certs(real_env(), str(crt), datetime.now(timezone.utc))
    assert c["status"] == "ok" and 28 <= c["days_left"] <= 30


@need("du", "ionice", "nice")
def test_du_under_ionice_idle_class_on_real_tree(tmp_path):
    (tmp_path / "m" / "a").mkdir(parents=True)
    (tmp_path / "m" / "a" / "w.bin").write_bytes(b"x" * 12345)
    (tmp_path / "m" / "readme").write_text("hi")
    r = runner.run("du_ionice", {"path": str(tmp_path / "m")})
    assert r.ok, r
    assert parse.du_bytes(r.text) >= 12345
    pol = view(policy_doc(t0={"model_dirs": [str(tmp_path / "m")]}))
    out = probes.run_probe("models", {}, real_env(pol))["models"]["dirs"][0]
    ents = {e["name"]: e for e in out["entries"]}
    assert ents["a"]["size"] >= 12345 and ents["a"]["children"][0]["name"] == "w.bin" and ents["readme"]["size"] == 2


def make_repo(path, config_extra=""):
    env = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "PATH": os.environ["PATH"], "HOME": "/nonexistent", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@x"}
    run = lambda *a: subprocess.run(["git", "-C", str(path), *a], env=env, capture_output=True, check=True)
    path.mkdir(parents=True)
    run("init", "-q", "-b", "main")
    (path / "tracked.txt").write_text("one\n")
    (path / "other.txt").write_text("one\n")
    run("add", ".")
    run("commit", "-q", "-m", "init")
    head = run("rev-parse", "HEAD").stdout.decode().strip()
    (path / "tracked.txt").write_text("two\n")                   # tracked change
    (path / "untracked.txt").write_text("u\n")                   # untracked: must not count
    if config_extra:
        with open(path / ".git" / "config", "a") as f:
            f.write(config_extra)
    return head


@need("git")
def test_git_probe_with_real_git_counts_tracked_changes_only(tmp_path):
    head = make_repo(tmp_path / "repo")
    before = (tmp_path / "repo" / ".git" / "index").stat().st_mtime_ns
    pol = view(policy_doc(t0={"repos": [str(tmp_path / "repo")]}))
    g = probes.run_probe("git", {}, real_env(pol))["repos"]["repos"][0]
    assert g["rev"] == head and g["branch"] == "main" and g["dirty_tracked"] == 1 and g["dirty_status"] == "ok"
    assert (tmp_path / "repo" / ".git" / "index").stat().st_mtime_ns == before                  # --no-optional-locks: the index was not rewritten


@need("git")
def test_a_repository_config_that_runs_a_program_is_never_given_to_git(tmp_path):
    marker = tmp_path / "ran-as-root"
    hook = tmp_path / "evil.sh"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
    os.chmod(hook, 0o755)
    make_repo(tmp_path / "repo", config_extra=f"[core]\n\tfsmonitor = {hook}\n")
    # control: plain `git status` really executes the program named in the repository config (this is the risk the scanner exists for)
    subprocess.run(["git", "-c", f"safe.directory={tmp_path / 'repo'}", "-C", str(tmp_path / "repo"), "status", "--porcelain"], env={"PATH": os.environ["PATH"], "HOME": "/nonexistent", "GIT_CONFIG_GLOBAL": "/dev/null"}, capture_output=True)
    assert marker.exists(), "control failed: git did not run the configured fsmonitor program in this image"
    marker.unlink()
    pol = view(policy_doc(t0={"repos": [str(tmp_path / "repo")]}))
    g = probes.run_probe("git", {}, real_env(pol))["repos"]["repos"][0]
    assert g["dirty_status"] == "skipped_unsafe_config" and g["rev"] and not marker.exists()


@need("git")
def test_even_if_the_scanner_were_wrong_the_command_line_disables_fsmonitor_and_hooks(tmp_path):
    """Second layer: the argv itself overrides core.fsmonitor/hooksPath, so a config the scanner mis-parsed still cannot start the program through these two settings."""
    marker = tmp_path / "ran"
    hook = tmp_path / "evil.sh"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
    os.chmod(hook, 0o755)
    make_repo(tmp_path / "repo", config_extra=f"[core]\n\tfsmonitor = {hook}\n")
    r = runner.run("git_status_tracked", {"repo": str(tmp_path / "repo")})
    assert r.ok and not marker.exists() and r.text.count("tracked.txt") == 1
