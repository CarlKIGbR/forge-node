"""Live-proof style tests against the REAL binaries in the test image (read-only commands on throw-away data): the argv of the command table and the parsers must work on real output,
not only on scripted fixtures. Skipped tools are named in the skip reason - the gate jobs count them."""
import os
from pathlib import Path
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


PLAIN_ENV = {"PATH": os.environ["PATH"], "HOME": "/nonexistent", "GIT_CONFIG_GLOBAL": "/dev/null"}


def plain_git_status(repo):
    """What the probe used to be / what a naive implementation does: git run directly on the repository."""
    subprocess.run(["git", "-c", f"safe.directory={repo}", "-C", str(repo), "status", "--porcelain"], env=PLAIN_ENV, capture_output=True)


def program(tmp_path, name, marker):
    p = tmp_path / name
    p.write_text(f"#!/bin/sh\ntouch {marker}\ncat\n")
    os.chmod(p, 0o755)
    return p


@need("git")
def test_a_repository_config_that_runs_a_program_does_not_run_it_in_the_probe(tmp_path):
    marker = tmp_path / "ran-as-root"
    hook = program(tmp_path, "evil.sh", marker)
    make_repo(tmp_path / "repo", config_extra=f"[core]\n\tfsmonitor = {hook}\n")
    plain_git_status(tmp_path / "repo")
    assert marker.exists(), "control failed: git did not run the configured fsmonitor program in this image"
    marker.unlink()
    pol = view(policy_doc(t0={"repos": [str(tmp_path / "repo")]}))
    g = probes.run_probe("git", {}, real_env(pol))["repos"]["repos"][0]
    assert g["dirty_status"] == "ok" and g["dirty_tracked"] == 1 and g["rev"] and not marker.exists() and "core.fsmonitor" in g["config_not_used"]


class RacingRunner:
    """The reviewer's case: at the runner boundary - after the probe has read the config, before git starts - the repository owner swaps in a config that names programs, and (after
    git finished) puts the old one back. Wraps the real runner."""

    def __init__(self, real, swap, restore=None):
        self.real, self.swap, self.restore = real, swap, restore
        self.ran = 0

    def run(self, cmd_id, slots=None, stdin=None, max_wait_s=None):
        if cmd_id == "git_status_tracked":
            self.swap()
            self.ran += 1
        r = self.real.run(cmd_id, slots, stdin, max_wait_s)
        if cmd_id == "git_status_tracked" and self.restore:
            self.restore()
        return r

    def available(self, cmd_id):
        return self.real.available(cmd_id)


@need("git")
def test_replacing_the_repository_config_at_the_runner_boundary_executes_no_external_program(tmp_path):
    marker = tmp_path / "filter-ran"
    other = tmp_path / "fsmonitor-ran"
    third = tmp_path / "include-ran"
    clean, fsmon, inc = program(tmp_path, "clean.sh", marker), program(tmp_path, "fsmon.sh", other), program(tmp_path, "inc.sh", third)
    repo = tmp_path / "repo"
    make_repo(repo)
    cfg = repo / ".git" / "config"
    benign = cfg.read_text()
    included = tmp_path / "included.cfg"
    included.write_text(f"[core]\n\tfsmonitor = {inc}\n")
    evil = benign + f'[filter "review"]\n\tclean = {clean}\n[core]\n\tfsmonitor = {fsmon}\n[include]\n\tpath = {included}\n'
    (repo / ".gitattributes").write_text("* filter=review\n")
    for n in ("tracked.txt", "other.txt", ".gitattributes"):
        os.utime(repo / n, (1, 1))                                          # stat data differs from the index: status must hash content, i.e. run the clean filter

    def swap():
        cfg.write_text(evil)
    # control 1: with the evil config in place, plain git runs the programs
    swap()
    plain_git_status(repo)
    assert marker.exists() or other.exists(), "control failed: plain git did not run any repository-controlled program"
    for m in (marker, other, third):
        m.unlink(missing_ok=True)
    for n in ("tracked.txt", "other.txt", ".gitattributes"):
        os.utime(repo / n, (1, 1))
    cfg.write_text(benign)
    pol = view(policy_doc(t0={"repos": [str(repo)]}))
    env = real_env(pol)
    racing = RacingRunner(env.runner, swap, restore=lambda: cfg.write_text(benign))
    env.runner = racing
    g = probes.run_probe("git", {}, env)["repos"]["repos"][0]
    assert racing.ran == 1 and g["dirty_status"] == "ok", g
    assert not marker.exists() and not other.exists() and not third.exists(), "a repository-controlled program was executed by the probe"
    assert cfg.read_text() == benign


@need("git")
def test_a_commondir_that_points_at_an_unscanned_config_cannot_run_a_filter_as_the_probe_user(tmp_path):
    marker = tmp_path / "filter-ran"
    evil = program(tmp_path, "evil.sh", marker)
    repo = make_commondir_repo(tmp_path, evil)
    plain_git_status(repo)
    assert marker.exists(), "control failed: this git version did not run the commondir filter"
    marker.unlink()
    pol = view(policy_doc(t0={"repos": [str(repo)]}))
    g = probes.run_probe("git", {}, real_env(pol))["repos"]["repos"][0]
    assert not marker.exists()
    assert g["dirty_status"] in ("ok", "no_revision") or g["dirty_status"].startswith("failed:")


@need("git")
def test_a_repository_hook_and_info_attributes_filter_cannot_run_either(tmp_path):
    marker = tmp_path / "ran"
    prog = program(tmp_path, "evil.sh", marker)
    repo = tmp_path / "repo"
    make_repo(repo)
    hooks = repo / ".git" / "hooks"
    for h in ("pre-commit", "post-checkout", "fsmonitor-watchman", "post-index-change"):
        (hooks / h).write_text(f"#!/bin/sh\ntouch {marker}\n")
        os.chmod(hooks / h, 0o755)
    (repo / ".git" / "info").mkdir(exist_ok=True)
    (repo / ".git" / "info" / "attributes").write_text("* filter=x diff=y\n")
    with open(repo / ".git" / "config", "a") as f:
        f.write(f'[filter "x"]\n\tclean = {prog}\n[diff "y"]\n\ttextconv = {prog}\n[core]\n\thooksPath = {hooks}\n\tpager = {prog}\n')
    pol = view(policy_doc(t0={"repos": [str(repo)]}))
    g = probes.run_probe("git", {}, real_env(pol))["repos"]["repos"][0]
    assert g["dirty_status"] == "ok" and not marker.exists()


def _git(path, *a, env_extra=None):
    env = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "PATH": os.environ["PATH"], "HOME": "/nonexistent", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@x", **(env_extra or {})}
    return subprocess.run(["git", "-C", str(path), *a], env=env, capture_output=True, check=True)


def make_commondir_repo(tmp_path, evil_script):
    """The attack from the review: <repo>/.git has a benign config, but its `commondir` file points at a git dir whose config defines a clean filter; .gitattributes applies it."""
    make_repo(tmp_path / "real", "")
    common = tmp_path / "evil-common"
    shutil_copy = __import__("shutil").copytree
    shutil_copy(tmp_path / "real" / ".git", common)
    with open(common / "config", "a") as f:
        f.write(f'[filter "x"]\n\tclean = {evil_script}\n')
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    for n in ("HEAD", "index"):
        shutil_copy_file = __import__("shutil").copy
        shutil_copy_file(tmp_path / "real" / ".git" / n, repo / ".git" / n)
    (repo / ".git" / "commondir").write_text(str(common) + "\n")
    (repo / ".git" / "config").write_text("[core]\n\trepositoryformatversion = 0\n")          # benign: this is the only file the scanner reads
    for n in ("tracked.txt", "other.txt"):
        (repo / n).write_text("two\n")
    (repo / ".gitattributes").write_text("* filter=x\n")
    for n in ("tracked.txt", "other.txt", ".gitattributes"):
        os.utime(repo / n, (1, 1))                                      # stat data differs from the index: status must hash the content, i.e. run the clean filter
    return repo


@need("git")
def test_submodule_config_is_never_consulted(tmp_path):
    marker = tmp_path / "sub-filter-ran"
    evil = tmp_path / "evil.sh"
    evil.write_text(f"#!/bin/sh\ntouch {marker}\ncat\n")
    os.chmod(evil, 0o755)
    make_repo(tmp_path / "sub", "")
    make_repo(tmp_path / "super", "")
    _git(tmp_path / "super", "-c", "protocol.file.allow=always", "submodule", "add", str(tmp_path / "sub"), "m")
    _git(tmp_path / "super", "commit", "-q", "-m", "sub")
    modcfg = tmp_path / "super" / ".git" / "modules" / "m" / "config"
    modcfg.write_text(modcfg.read_text() + f'[filter "x"]\n\tclean = {evil}\n')
    (tmp_path / "super" / "m" / ".gitattributes").write_text("* filter=x\n")
    for p in (tmp_path / "super" / "m").iterdir():
        if p.is_file():
            os.utime(p, (1, 1))
    # control: a plain `git status` of the super project does consult the submodule and runs its filter
    subprocess.run(["git", "-c", f"safe.directory={tmp_path / 'super'}", "-C", str(tmp_path / "super"), "status", "--porcelain"], env={"PATH": os.environ["PATH"], "HOME": "/nonexistent", "GIT_CONFIG_GLOBAL": "/dev/null"}, capture_output=True)
    assert marker.exists(), "control failed: plain git status did not run the submodule filter in this image"
    marker.unlink()
    for p in (tmp_path / "super" / "m").iterdir():
        if p.is_file():
            os.utime(p, (1, 1))
    pol = view(policy_doc(t0={"repos": [str(tmp_path / "super")]}))
    g = probes.run_probe("git", {}, real_env(pol))["repos"]["repos"][0]
    assert g["dirty_status"] == "ok" and not marker.exists()


@need("git")
def test_reviewers_absolute_ref_case_with_real_git_and_real_filesystem_via_the_wire(tmp_path):
    """Rework 2 (MAJOR): HEAD `ref: refs/heads//<abs path>` + a matching loose ref in a real repository; through wire.handle_request with the real reader and the real runner. Before:
    the canary outside repository and snapshot was overwritten with 40 'a' and the response said ok:true."""
    import json
    from forge_node.t0 import wire
    repo = tmp_path / "repo"
    make_repo(repo)
    canary = tmp_path / "outside-snapshot" / "marker"
    canary.parent.mkdir()
    canary.write_text("CANARY-UNTOUCHED\n")
    assert os.path.join("/snapshot", "refs", "heads", str(canary)) == str(canary)                      # the mechanism of the bug: join discards the prefix of an absolute component
    (repo / ".git" / "HEAD").write_text(f"ref: refs/heads/{canary}\n")                                  # 'refs/heads//tmp/...'
    loose = Path(str(repo / ".git" / "refs" / "heads") + str(canary))
    loose.parent.mkdir(parents=True, exist_ok=True)
    loose.write_text("a" * 40 + "\n")
    pol = view(policy_doc(t0={"repos": [str(repo)]}))
    resp = json.loads(wire.handle_request(wire.encode_request("git", {}), real_env(pol)))
    row = resp["data"]["repos"]["repos"][0]
    assert resp["ok"] is True and row["error"] == "malformed_ref" and row["dirty_status"] == "rejected:malformed_ref" and row["rev"] is None
    assert canary.read_text() == "CANARY-UNTOUCHED\n"
    assert sorted(p.name for p in canary.parent.iterdir()) == ["marker"]
