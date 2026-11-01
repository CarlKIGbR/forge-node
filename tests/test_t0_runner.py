import os
import re
import stat
import sys
import time

import pytest

from forge_node.t0 import runner

pytestmark = pytest.mark.skipif(os.getuid() != 0, reason="runner trust checks need a root-owned fake binary directory (the test container runs as root)")


@pytest.fixture
def fakebin(tmp_path, monkeypatch):
    d = tmp_path / "bin"
    d.mkdir()
    monkeypatch.setattr(runner, "FIXED_PATH", (str(d),))
    monkeypatch.setitem(runner._ENV_BASE, "PATH", str(d))

    def make(name, body, mode=0o755):
        p = d / name
        p.write_text("#!/bin/sh\n" + body + "\n")
        os.chmod(p, mode)
        return p
    return make


def test_table_is_a_closed_snapshot_of_read_only_commands():
    """Any new command shows up here in review. Binaries and first verbs are fixed."""
    shape = sorted((c.binary, c.argv[0] if c.argv else "") for c in runner.CMDS.values())
    assert shape == sorted([
        ("lsblk", "-J"), ("findmnt", "-J"), ("timedatectl", "show"), ("nvidia-smi", "--query-gpu=index,uuid,name,memory.used,memory.total,utilization.gpu,temperature.gpu,power.draw,power.limit,clocks.sm,clocks.max.sm,"
                                                                              "pcie.link.gen.current,pcie.link.width.current,clocks_throttle_reasons.active"),
        ("nvidia-smi", "--query-compute-apps=gpu_uuid,pid,process_name,used_gpu_memory"), ("systemctl", "show"), ("systemctl", "show"), ("systemctl", "show"), ("systemctl", "list-units"), ("systemctl", "list-timers"),
        ("systemctl", "is-active"), ("apt-get", "-s"), ("apt-mark", "showhold"), ("apt-config", "dump"), ("dpkg-query", "-W"), ("ip", "-j"), ("ss", "-tulnH"), ("ss", "-tulnpH"),
        ("iptables", "-S"), ("docker", "ps"), ("docker", "inspect"), ("docker", "image"), ("virsh", "-r"), ("virsh", "-r"), ("openssl", "x509"), ("openssl", "x509"),
        ("git", "--no-optional-locks"), ("sshd", "-T"), ("journalctl", "-u"), ("journalctl", "-u"), ("ionice", "-c3"),
    ])


MUTATING = re.compile(r"^(?:run|exec|cp|rm|rmi|stop|start|restart|kill|prune|build|pull|push|load|save|commit|create|update|tag|enable|disable|mask|unmask|daemon-reload|reload|isolate|"
                      r"-A|-I|-D|-F|-X|-N|-P|-R|-Z|install|remove|purge|upgrade|dist-upgrade|autoremove|clean|checkout|reset|add|commit|merge|fetch|pull|gc)\Z")


def test_no_command_in_the_table_carries_a_mutating_verb():
    for cid, c in runner.CMDS.items():
        for tok in c.argv:
            assert not MUTATING.match(tok) or (cid, tok) in {("apt_simulate", "upgrade")}, (cid, tok)
        if c.binary == "docker":
            assert c.argv[0] in ("ps", "inspect", "image") and (c.argv[0] != "image" or c.argv[1] == "inspect")
        if c.binary == "systemctl":
            assert c.argv[0] in ("show", "list-units", "list-timers", "is-active")
        if c.binary == "iptables":
            assert c.argv[0] == "-S"
        if c.binary == "apt-get":
            assert c.argv[0] == "-s", "apt-get only as a simulation"
        if c.binary == "git":
            assert "status" in c.argv and "--porcelain=v1" in c.argv and "--untracked-files=no" in c.argv and "core.fsmonitor=false" in c.argv


def test_docker_inspect_template_never_reads_env_cmd_or_secrets():
    t = " ".join(runner.CMDS["docker_inspect"].argv)
    for forbidden in (".Env", ".Cmd", ".Args", ".Entrypoint", ".HostConfig", ".Config.User", "Secrets", ".Config.Healthcheck", ".ExecIDs"):
        assert forbidden not in t
    assert ".Config.Labels" in t and ".Config.Image" in t
    assert "docker inspect" not in " ".join(runner.CMDS["docker_ps_ids"].argv)


def test_slot_values_are_validated_and_flags_cannot_be_smuggled():
    for bad in ("../etc", "-rf.service", "a b.service", "x;y.service", "x.service\n", "x$(id).service", "x.exe"):
        with pytest.raises(runner.RunnerError):
            runner.run("systemctl_is_active", {"unit": bad})
    with pytest.raises(runner.RunnerError):
        runner.run("docker_inspect", {"id": ["--format"]})
    with pytest.raises(runner.RunnerError):
        runner.run("docker_inspect", {"id": ["a" * 64] * 41})
    for bad in ("relative", "/a/../etc", "/a\x00b", "-/x"):
        with pytest.raises(runner.RunnerError):
            runner.run("du_ionice", {"path": bad})
    with pytest.raises(runner.RunnerError):
        runner.run("lsblk", {"extra": "x"})                       # slots must match the definition exactly
    with pytest.raises(runner.RunnerError):
        runner.run("nope")
    with pytest.raises(runner.RunnerError):
        runner.run("openssl_x509_der")                            # declares stdin
    with pytest.raises(runner.RunnerError):
        runner.run("lsblk", stdin=b"x")


def test_runs_with_fixed_environment_no_shell_no_stdin(fakebin):
    fakebin("lsblk", '/usr/bin/env | /usr/bin/sort; echo "ARGS:$*"; /usr/bin/cat 2>&1; echo "stdin-closed:$?"')
    r = runner.run("lsblk")
    t = r.text
    assert r.ok and "ARGS:-J -b -o NAME,KNAME" in t
    env_lines = {l.split("=", 1)[0] for l in t.splitlines() if re.match(r"^[A-Z_]+=", l)}
    assert env_lines <= {"PATH", "LC_ALL", "LANG", "HOME", "TERM", "PWD", "SHLVL", "_", "OLDPWD"}, env_lines
    assert "stdin-closed:0" in t


def test_argument_with_shell_metacharacters_is_one_argv_element(fakebin):
    fakebin("ionice", 'for a in "$@"; do echo "[$a]"; done')
    for weird in ("/tmp/a b,c=d", "/srv/models/Qwen3 (Q4)", "/srv/models/M\u00fcnchen", "/srv/models/a&b;c", "/srv/models/$(id)", "/srv/models/'q'"):
        r = runner.run("du_ionice", {"path": weird})
        assert r.ok and f"[{weird}]" in r.text.splitlines(), weird
    for bad in ("/srv/models/a\nb", "/srv/models/a\x01b", "/srv/models/../etc", "relative"):
        with pytest.raises(runner.RunnerError):
            runner.run("du_ionice", {"path": bad})


def test_programs_the_command_itself_starts_are_part_of_the_trust_check(fakebin):
    fakebin("ionice", "echo ok")
    assert runner.run("du_ionice", {"path": "/tmp"}).ok
    cmd = runner.CMDS["du_ionice"]
    object.__setattr__(cmd, "extra_binaries", ("/usr/bin/nice", "/nonexistent/du"))
    try:
        assert runner.run("du_ionice", {"path": "/tmp"}).reason == "untrusted_binary" and not runner.ReadOnlyRunner().available("du_ionice")
    finally:
        object.__setattr__(cmd, "extra_binaries", ("/usr/bin/nice", "/usr/bin/du"))


def test_binary_in_a_group_writable_directory_is_untrusted_but_sticky_root_dirs_are_fine(fakebin, tmp_path):
    p = fakebin("lsblk", "echo hi")
    assert runner.run("lsblk").ok                                  # fake dir under root-owned, sticky /tmp
    os.chmod(p.parent, 0o775)
    assert runner.run("lsblk").reason == "untrusted_binary"
    os.chmod(p.parent, 0o755)
    sub = p.parent / "sub"
    sub.mkdir()
    os.chmod(sub, 0o777)
    assert runner.run("lsblk").ok                                  # a writable directory NEXT to the binary does not matter, only the ones above it


def test_max_wait_can_only_shorten_the_timeout(fakebin):
    fakebin("lsblk", "/usr/bin/sleep 5")
    t0 = time.monotonic()
    assert runner.run("lsblk", max_wait_s=0.5).reason == "timeout" and time.monotonic() - t0 < 4
    t0 = time.monotonic()
    fakebin("findmnt", "/usr/bin/sleep 2; echo done")
    assert runner.run("findmnt", max_wait_s=3600).ok and time.monotonic() - t0 < 10        # a huge value does not extend the table's own timeout


def test_git_is_pointed_at_the_probes_snapshot_and_uses_the_repository_only_as_data(fakebin):
    fakebin("git", '/usr/bin/env | /usr/bin/sort | /usr/bin/grep -E "^GIT_(DIR|COMMON_DIR|WORK_TREE|INDEX_FILE|OBJECT_DIRECTORY|CONFIG_[A-Z]+)="; echo "$*"')
    r = runner.run("git_status_tracked", {"repo": "/srv/my repo", "snap": "/tmp/fn-git-abc"})
    t = r.text
    for needle in ("GIT_DIR=/tmp/fn-git-abc\n", "GIT_COMMON_DIR=/tmp/fn-git-abc\n", "GIT_WORK_TREE=/srv/my repo\n", "GIT_INDEX_FILE=/srv/my repo/.git/index", "GIT_OBJECT_DIRECTORY=/srv/my repo/.git/objects",
                   "--git-dir=/tmp/fn-git-abc", "--work-tree=/srv/my repo", "--ignore-submodules=all", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1"):
        assert needle in t, needle
    assert "GIT_DIR=/srv/my repo" not in t and "GIT_COMMON_DIR=/srv/my repo" not in t               # never the repository's own git dir


def test_every_declared_slot_must_be_used_in_the_argv():
    with pytest.raises(runner.RunnerError):
        runner._expand(runner.Cmd("x", ("a",), slots=(("p", "int"),)), {"p": "1"})


def test_missing_binary_is_reported_not_raised(fakebin):
    r = runner.run("lsblk")
    assert not r.ok and r.reason == "missing"


def test_untrusted_binary_is_refused(fakebin):
    fakebin("lsblk", "echo hi", mode=0o777)
    assert runner.run("lsblk").reason == "untrusted_binary"
    p = fakebin("lsblk", "echo hi", mode=0o755)
    os.chown(p, 1000, 1000)
    assert runner.run("lsblk").reason == "untrusted_binary"


def test_nonzero_exit_and_ok_rc_table(fakebin):
    fakebin("lsblk", "echo oops >&2; exit 3")
    r = runner.run("lsblk")
    assert not r.ok and r.reason == "nonzero" and r.rc == 3 and "oops" in r.err
    fakebin("systemctl", "exit 3")
    assert runner.run("systemctl_is_active", {"unit": "a.service"}).ok                          # is-active: 3 = inactive is a valid answer


def _state_of(pid: int) -> str | None:
    try:
        return open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0]
    except OSError:
        return None


def test_timeout_kills_the_whole_process_group(fakebin, tmp_path):
    pidfile = tmp_path / "grandchild.pid"
    fakebin("lsblk", f"/usr/bin/sleep 60 &\necho $! > {pidfile}\n/usr/bin/sleep 60")
    cmd = runner.CMDS["lsblk"]
    object.__setattr__(cmd, "timeout_s", 1)
    try:
        t0 = time.monotonic()
        r = runner.run("lsblk")
    finally:
        object.__setattr__(cmd, "timeout_s", 20)
    assert r.reason == "timeout" and time.monotonic() - t0 < 10
    pid = int(pidfile.read_text())
    for _ in range(50):
        if _state_of(pid) in (None, "Z"):              # gone, or killed and not yet reaped by the container's init
            break
        time.sleep(0.1)
    assert _state_of(pid) in (None, "Z"), "the background child of the command survived the timeout"


def test_output_is_capped_and_producer_killed(fakebin):
    fakebin("lsblk", "/usr/bin/yes AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    cmd = runner.CMDS["lsblk"]
    object.__setattr__(cmd, "max_out", 100000)
    try:
        t0 = time.monotonic()
        r = runner.run("lsblk")
    finally:
        object.__setattr__(cmd, "max_out", 1024 * 1024)
    assert r.truncated and len(r.out) == 100000 and time.monotonic() - t0 < 10


def test_stdin_command_receives_bytes(fakebin):
    fakebin("openssl", "/usr/bin/cat | /usr/bin/wc -c")
    r = runner.run("openssl_x509_der", stdin=b"x" * 1234)
    assert r.ok and r.text.strip() == "1234"


def test_git_environment_is_hardened(fakebin):
    fakebin("git", "/usr/bin/env | /usr/bin/sort | /usr/bin/grep -E '^(GIT_|HOME)'; echo \"$*\"")
    r = runner.run("git_status_tracked", {"repo": "/srv/x", "snap": "/tmp/s"})
    for needle in ("GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0", "GIT_EXTERNAL_DIFF=/bin/false", "--no-optional-locks",
                   "core.fsmonitor=false", "core.hooksPath=/dev/null", "-C /srv/x status --porcelain=v1 --untracked-files=no"):
        assert needle in r.text, needle


def test_subprocess_is_imported_only_by_runner_and_sshsig():
    import ast
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "src" / "forge_node"
    importers = sorted(str(p.relative_to(root)) for p in root.rglob("*.py") if any(
        (isinstance(n, ast.Import) and any(a.name.split(".")[0] == "subprocess" for a in n.names)) or (isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] == "subprocess")
        for n in ast.walk(ast.parse(p.read_text()))))
    # N2: the closed read-only command table and ssh-keygen. N3 adds exactly the places that start transient units or build the release: the systemd backend and the local-process test
    # double (privd/units.py), privd's trusted command wrapper (privd/main.py) and the switcher (release/switcher.py). The release BUILDER starts nothing (it only writes files).
    assert importers == ["privd/main.py", "privd/units.py", "release/switcher.py", "sshsig.py", "t0/runner.py"]
    for p in root.rglob("*.py"):
        t = p.read_text()
        assert not re.search(r"\bos\.(system|popen|exec[lv]p?e?|spawn\w*)\(", t), p
        assert "shell=True" not in t, p


def test_a_symlinked_command_is_trusted_only_if_every_link_and_its_directory_are(fakebin, tmp_path):
    """Review finding: only the link TARGET's directory chain was checked. /usr/sbin/iptables -> /etc/alternatives/iptables -> xtables-nft-multi must pass; a link in a
    group-writable directory (shadowing a command found later in PATH) must not."""
    real = tmp_path / "real"
    real.mkdir()
    prog = real / "multi"
    prog.write_text("#!/bin/sh\necho multi:$0\n")
    os.chmod(prog, 0o755)
    bindir = tmp_path / "bin"
    alt = tmp_path / "alternatives"
    alt.mkdir()
    os.symlink(prog, alt / "lsblk")
    os.symlink(alt / "lsblk", bindir / "lsblk")                        # bin/lsblk -> alternatives/lsblk -> real/multi
    r = runner.run("lsblk")
    assert r.ok and "multi:" in r.text and r.argv[0] == str(bindir / "lsblk")           # exec'd through the unresolved path: multi-call programs use argv[0]
    os.chmod(alt, 0o775)                                              # the directory holding the intermediate link is group-writable
    assert runner.run("lsblk").reason == "untrusted_binary"
    os.chmod(alt, 0o755)
    os.chmod(bindir, 0o775)                                           # the directory holding the PATH hit is group-writable
    assert runner.run("lsblk").reason == "untrusted_binary"
    os.chmod(bindir, 0o755)
    assert runner.run("lsblk").ok
    os.unlink(alt / "lsblk")
    os.symlink(alt / "lsblk", alt / "lsblk")                          # a loop is refused, not an exception
    assert runner.run("lsblk").reason in ("missing", "untrusted_binary")


def test_a_child_that_closes_its_pipes_and_keeps_running_is_waited_for_and_keeps_its_exit_code(fakebin):
    """Final verification (MAJOR): the group was killed on EOF of both pipes, so a wrapper that closes its fds, sleeps 200 ms and exits 0 came back as rc=-9 after ~5 ms."""
    fakebin("lsblk", "echo out; exec >&- 2>&-; /usr/bin/sleep 0.2; exit 0")
    t0 = time.monotonic()
    r = runner.run("lsblk")
    dt = time.monotonic() - t0
    assert r.ok and r.rc == 0 and r.text == "out\n" and 0.19 <= dt < 5
    fakebin("lsblk", "exec >&- 2>&-; /usr/bin/sleep 0.2; exit 3")
    r = runner.run("lsblk")
    assert not r.ok and r.rc == 3 and r.reason == "nonzero"


def test_a_child_that_closes_its_pipes_and_overruns_the_deadline_is_killed(fakebin):
    fakebin("lsblk", "exec >&- 2>&-; /usr/bin/sleep 60")
    cmd = runner.CMDS["lsblk"]
    object.__setattr__(cmd, "timeout_s", 1)
    try:
        t0 = time.monotonic()
        r = runner.run("lsblk")
    finally:
        object.__setattr__(cmd, "timeout_s", 20)
    assert r.reason == "timeout" and time.monotonic() - t0 < 5


def test_background_children_left_behind_by_a_finished_command_are_still_stopped(fakebin, tmp_path):
    pidfile = tmp_path / "bg.pid"
    fakebin("lsblk", f"/usr/bin/sleep 60 >&- 2>&- &\necho $! > {pidfile}\nexit 0")
    r = runner.run("lsblk")
    assert r.ok and r.rc == 0
    pid = int(pidfile.read_text())
    for _ in range(50):
        if _state_of(pid) in (None, "Z"):
            break
        time.sleep(0.1)
    assert _state_of(pid) in (None, "Z")
