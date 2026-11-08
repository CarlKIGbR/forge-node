"""probefix (0.5.1): the declaration of what a probe reads (t0/needs.py) is the ONE place the sandbox of a probe is generated from, and it is proven against the real kernel.
Regression for the carlgpu2 install: `doctor` failed probe:net and probe:container_net with 'denied inside the real unit' although no unit denied anything - forge-node's own selfcheck
read /proc/net/dev with a 1024-byte limit (7644 bytes on a docker host) and asked for /proc/self/net/dev, which its own allowlist never contained."""
import ast
import os
import re
from pathlib import Path

import pytest

from forge_node.t0 import hardening, needs, probes, runner, selfcheck
from forge_node.t0.env import Env
from forge_node.t0.fsread import DeclaredFs, Fs, FsError, ProtectedSet

SRC = Path(probes.__file__)
OWN_RULES = {"not_allowed", "not_declared", "escape", "protected", "too_large", "not_regular"}          # codes that mean forge-node itself refused (never environment)


def real_env(name, root="/"):
    return Env(needs.declared_fs(name, ProtectedSet.from_policy([]), root), runner.ReadOnlyRunner(), None, None)


def test_the_declaration_covers_exactly_the_probes_and_only_known_commands():
    assert set(needs.PROBE_NEEDS) == set(probes.PROBE_NAMES) == set(hardening.RO_PROBES)
    for name, n in needs.PROBE_NEEDS.items():
        assert set(n.commands) | set(n.optional) <= set(runner.CMDS), name
        assert n.meta <= needs.FS_METHODS, name
        assert not set(n.commands) & set(n.optional), name


@pytest.mark.parametrize("name", sorted(needs.PROBE_NEEDS))
def test_every_declared_read_opens_on_the_real_kernel_exactly_as_the_probe_opens_it(name):
    """Real /proc and /etc of the machine running the tests, the Fs the unit entry builds, the limit the probe uses. Only the host may say no (EACCES/ENOENT on a root-only log):
    a refusal by forge-node's own rules, by the size limit or by the allowlist is a bug."""
    env = real_env(name)
    for rd in needs.PROBE_NEEDS[name].reads:
        p = rd.sample()
        try:
            env.fs.read_text(p, rd.limit)
        except FsError as e:
            assert e.code not in OWN_RULES, f"{name}: {p} refused by forge-node itself: {e}"
            assert not p.startswith(("/proc/", "/etc/")), f"{name}: {p} must be readable everywhere: {e}"
    r = selfcheck.probe_selfcheck(name, env)
    assert not [m for m in r["missing"] if re.search(r"(?:not_allowed|not_declared|escape|protected|too_large|not_regular)$", m)], r


def test_selfcheck_uses_the_probe_limit_not_a_small_one(tmp_path):
    """A docker host's /proc/net/dev is 7.6 KB (many veth): the check must not fail on size. Relocated tree with a 40 KB file for this very process."""
    d = tmp_path / "proc" / str(os.getpid()) / "net"
    d.mkdir(parents=True)
    (d / "dev").write_text("Inter-|   Receive\n face |bytes\n" + "".join(f"veth{i:04x}: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16\n" for i in range(900)))
    assert (d / "dev").stat().st_size > 30000
    env = Env(needs.declared_fs("container_net", ProtectedSet.from_policy([]), str(tmp_path)), runner.ReadOnlyRunner(), None, None)
    r = selfcheck.probe_selfcheck("container_net", env)
    assert r["paths"] == {f"/proc/{os.getpid()}/net/dev": True}, r
    assert all(rd.limit >= 64 * 1024 for n in needs.PROBE_NEEDS.values() for rd in n.reads if rd.path.startswith("/proc/"))


def test_selfcheck_names_the_reason_for_a_refusal(tmp_path):
    env = Env(needs.declared_fs("container_net", ProtectedSet.from_policy([]), str(tmp_path)), runner.ReadOnlyRunner(), None, None)
    r = selfcheck.probe_selfcheck("container_net", env)                                              # no /proc in this tree: the host says no
    assert not r["ok"] and r["missing"][-1].endswith(": unreadable"), r


@pytest.mark.parametrize("name", sorted(needs.PROBE_NEEDS))
def test_a_probe_cannot_read_or_stat_what_it_did_not_declare(name):
    fs = needs.declared_fs(name, ProtectedSet.from_policy([]), "/")
    n = needs.PROBE_NEEDS[name]
    declared = [r.regex for r in n.reads]
    for p in ("/proc/meminfo", "/proc/stat", "/proc/net/dev", "/proc/self/net/dev", f"/proc/{os.getpid()}/net/dev", "/etc/passwd", "/etc/group", "/etc/os-release",
              "/var/log/unattended-upgrades/unattended-upgrades.log", "/proc/mounts"):
        if not any(rx.match(p) for rx in declared):
            with pytest.raises(FsError) as e:
                fs.read_text(p)
            assert e.value.code == "not_declared", (name, p)
            assert fs.exists(p) is False                                                            # exists() reports a refusal as 'no', never as 'yes'
    calls = {"resolve_dir": ("/etc",), "stat_meta": ("/etc",), "list_meta": ("/etc",), "read_exception": ("/etc/hostname", re.compile(".*")), "read_user_file": ("/etc/hostname",)}
    assert set(calls) == needs.FS_METHODS
    for m, args in calls.items():
        if m not in n.meta:
            with pytest.raises(FsError) as e:
                getattr(fs, m)(*args)
            assert e.value.code == "not_declared", (name, m)


def test_the_net_and_container_net_declarations_are_the_least_that_works():
    """net runs `ss -p` and reads no file; container_net reads /proc/<digits>/net/dev (read-only, no capability: caps stay empty) and nothing under /proc/self or other /proc files."""
    assert needs.PROBE_NEEDS["net"].reads == () and needs.PROBE_NEEDS["net"].meta == frozenset()
    cn = needs.PROBE_NEEDS["container_net"]
    assert [r.path for r in cn.reads] == ["/proc/{pid}/net/dev"] and cn.meta == frozenset()
    rx = cn.reads[0].regex
    assert rx.match("/proc/4242/net/dev") and not rx.match("/proc/self/net/dev") and not rx.match("/proc/4242/net/dev2") and not rx.match("/proc/4242/environ") and not rx.match("/proc/4242/net/../environ")
    assert hardening.RO_PROBES["container_net"]["caps"] == ()


# ----------------------------------------------------------------------------------------------------- static: every fs call in probes.py is declared
def _calls_by_function(tree):
    funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    return funcs


def _reachable(funcs, start):
    seen, todo = set(), [start]
    while todo:
        f = todo.pop()
        if f in seen or f not in funcs:
            continue
        seen.add(f)
        todo += [c.func.id for c in ast.walk(funcs[f]) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)]
    return seen


def _template(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "{pid}" for v in node.values)
    return None


@pytest.mark.parametrize("name", sorted(needs.PROBE_NEEDS))
def test_probes_py_reads_nothing_its_probe_does_not_declare(name):
    tree = ast.parse(SRC.read_text())
    funcs = _calls_by_function(tree)
    n = needs.PROBE_NEEDS[name]
    for fn in _reachable(funcs, "_probe_" + name):
        for c in ast.walk(funcs[fn]):
            if not (isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and isinstance(c.func.value, ast.Attribute) and c.func.value.attr == "fs"):
                continue
            m = c.func.attr
            if m in ("read_text", "exists"):
                t = _template(c.args[0])
                assert t is not None, f"{name}/{fn}: dynamic path in fs.{m} at line {c.lineno}"
                # `{r['pid']}` in an f-string becomes "{pid}", the only placeholder a declaration may use
                assert any(r.regex.match(t.replace("{pid}", "1234")) for r in n.reads), f"{name}/{fn} line {c.lineno}: fs.{m}({t!r}) is not declared"
            else:
                assert m in n.meta, f"{name}/{fn} line {c.lineno}: fs.{m} is not declared"
