"""Static and structural checks of what slice N2 delivers - and what it must not: T0 only, no listener, no writes outside the agent's own state, no audit writer (gate D stays unmet),
nothing installed or generated."""
import ast
import io
import json
import os
import re
from pathlib import Path

import pytest

from forge_node import gates
from forge_node.agent import __main__ as agent_main
from forge_node.agent.config import AgentConfig, ConfigError
from forge_node.t0 import hardening, params as T0P, probe_main, selfcheck as sc

from n2_helpers import FakeRunner, install_policy, make_env, policy_doc, signers_text, view, NOW

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "forge_node"
MODULES = [p for d in ("t0", "agent") for p in (SRC / d).glob("*.py")]


def code_only(path) -> str:
    """Source without comments and docstrings (prose may legitimately say 'sudo' or name a capability)."""
    import tokenize
    src = path.read_text()
    tree = ast.parse(src)
    doc_lines = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)) and n.body and isinstance(n.body[0], ast.Expr) and isinstance(getattr(n.body[0], "value", None), ast.Constant) \
                and isinstance(n.body[0].value.value, str):
            doc_lines |= set(range(n.body[0].lineno, n.body[0].end_lineno + 1))
    out = []
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type == tokenize.COMMENT or tok.start[0] in doc_lines:
            continue
        out.append(tok.string)
    return " ".join(out).replace('( "docker" , "sudo" , "adm" )', "")        # inv.access reports the MEMBERS of the sudo group; that is a group name, not a command


def calls(tree):
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Attribute):
                yield (f.value.id if isinstance(f.value, ast.Name) else None), f.attr, n
            elif isinstance(f, ast.Name):
                yield None, f.id, n


# -------------------------------------------------------------------------------------------------------------------------- hardening
def test_agent_unit_has_nonewprivileges_and_no_sudoers():
    p = hardening.agent_properties("g2")
    assert p["NoNewPrivileges"] == "yes" and p["User"] == "forgenode" and p["CapabilityBoundingSet"] == "" and p["ProtectSystem"] == "strict"
    assert p["IPAddressDeny"] == "any" and p["IPAddressAllow"] == "192.168.10.4/32 127.0.0.0/8" and p["MemoryMax"] == "128M" and p["CPUQuota"] == "15%" and p["Nice"] == "19"
    assert hardening.agent_properties("g4")["MemoryMax"] == "96M" and hardening.agent_properties("g1")["MemoryMax"] == "128M"
    assert "AF_NETLINK" in p["RestrictAddressFamilies"] and "AF_INET" in p["RestrictAddressFamilies"] and p["SystemCallFilter"] == "@system-service"
    assert p["ReadWritePaths"] == "/var/lib/forge-node /var/log/forge-node-agent"
    for k in ("LockPersonality", "RestrictRealtime", "RestrictSUIDSGID", "RestrictNamespaces", "ProtectClock", "ProtectHostname", "ProtectKernelLogs", "ProtectKernelModules", "ProtectControlGroups"):
        assert p[k] == "yes", k
    assert "PrivateDevices" not in p and "MemoryDenyWriteExecute" not in p          # nvidia-smi needs the device nodes and writable+executable mappings
    for m in MODULES:
        assert not re.search(r"\bsudo\b", code_only(m)), m
    assert not [f for f in ROOT.rglob("*") if f.is_file() and "sudoers" in f.name and ".git" not in f.parts]


def test_ro_probe_class_properties_come_from_a_fixed_table_not_from_parameters():
    import inspect
    assert list(inspect.signature(hardening.ro_probe_properties).parameters) == ["probe"] and list(inspect.signature(hardening.agent_properties).parameters) == ["node_id"]
    for name in hardening.RO_PROBES:
        p = hardening.ro_probe_properties(name)
        assert p["NoNewPrivileges"] == "yes" and p["ProtectSystem"] == "strict" and p["IPAddressDeny"] == "any" and "ReadWritePaths" not in p and p["PrivateTmp"] == "yes"
        assert p["KillMode"] == "control-group" and p["SendSIGKILL"] == "yes" and p["MemoryMax"] and p["TasksMax"] and p["RuntimeMaxSec"].isdigit()
        assert p["PrivateDevices"] == "yes" and p["MemoryDenyWriteExecute"] == "yes" and p["RestrictNamespaces"] == "yes" and p["LockPersonality"] == "yes" and p["UMask"] == "0077"
        assert "CAP_SYS_ADMIN" not in p["CapabilityBoundingSet"] and "CAP_SYS_RAWIO" not in p["CapabilityBoundingSet"] and "CAP_DAC_OVERRIDE" not in p["CapabilityBoundingSet"]
        hidden = [h.lstrip("-") for h in p["InaccessiblePaths"].split()]
        for sock in ("/run/forge-node", "/run/containerd", "/run/dbus", "/run/systemd/private"):
            assert sock in hidden, (name, sock)                                                # no probe reaches privd, containerd, D-Bus or systemd's private socket
        assert ("/run/docker.sock" in hidden) == (not hardening.RO_PROBES[name]["docker"])
        assert ("/run/libvirt" in hidden) == (name != "vms")
    caps = {n: set(hardening.ro_probe_properties(n)["CapabilityBoundingSet"].split()) for n in hardening.RO_PROBES}
    assert "CAP_SYS_PTRACE" in caps["net"] and "CAP_NET_ADMIN" not in caps["net"] and caps["firewall"] == {"CAP_NET_ADMIN"}          # ss -p and iptables never share a unit
    assert caps["containers"] == {"CAP_DAC_READ_SEARCH"} and caps["container_net"] == set()           # /proc/<pid>/net/dev is world-readable (hidepid=0)
    assert [n for n, c in caps.items() if "CAP_NET_ADMIN" in c] == ["firewall"] and [n for n, c in caps.items() if "CAP_SYS_PTRACE" in c] == ["net"]
    assert hardening.ro_probe_properties("models")["IOSchedulingClass"] == "idle" and "IOSchedulingClass" not in hardening.ro_probe_properties("net")
    assert hardening.ro_probe_properties("access")["ProtectHome"] == "read-only"
    assert "AF_INET" in hardening.ro_probe_properties("firewall")["RestrictAddressFamilies"] and "AF_INET" not in hardening.ro_probe_properties("net")["RestrictAddressFamilies"]


def test_every_probe_has_a_hardening_entry_and_vice_versa():
    from forge_node.t0 import probes
    assert set(hardening.RO_PROBES) == set(probes.PROBE_NAMES)
    assert set(probes.HEAVY_PROBES) <= set(probes.PROBE_NAMES)
    for n in probes.HEAVY_PROBES:
        assert hardening.RO_PROBES[n]["idle_io"] is True


# ---------------------------------------------------------------------------------------------------------------------------------- scope
def test_agent_opens_no_listener_and_runs_no_server():
    for m in MODULES:
        tree = ast.parse(m.read_text())
        for obj, attr, _ in calls(tree):
            assert attr not in ("listen", "bind", "serve_forever", "accept", "start_server"), (m.name, attr)
        names = {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names} | {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        assert not (names & {"http.server", "socketserver", "ThreadingHTTPServer", "HTTPServer", "TlsServer"}), m.name


def test_writes_are_confined_to_the_agent_state_modules():
    """Which modules may create/modify/delete anything at all."""
    writers = {}
    for m in MODULES:
        tree = ast.parse(m.read_text())
        hits = set()
        for obj, attr, node in calls(tree):
            if (obj == "os" and attr in ("unlink", "rename", "replace", "write", "makedirs", "mkdir", "chmod", "fchmod", "chown", "ftruncate", "symlink", "link", "remove", "rmdir", "mkstemp")) \
                    or (attr in ("write_text", "write_bytes", "unlink", "mkdir", "touch")):
                hits.add(attr)
            if attr == "open" and obj in (None, "os"):
                flags = ast.unparse(node)
                if re.search(r"O_(WRONLY|RDWR|CREAT|APPEND|TRUNC)|[\"'][wax+]b?[\"']", flags):
                    hits.add("open-for-write")
        if obj := hits:
            writers[m.name] = sorted(hits)
    # probes.py: the git probe's private snapshot directory (mkdtemp in the unit's PrivateTmp, 0700, removed after the run) is the only thing a probe creates
    assert set(writers) == {"spool.py", "limits.py", "loop.py", "__main__.py", "probes.py", "confined.py"}, writers
    # rework 2: the only code that creates files from NAMES THAT ARE NOT OUR CONSTANTS is confined.py (descriptor-relative, validated components). loop.py (staging) and probes.py
    # (git snapshot) keep only the mkdirat/unlinkat/chmod calls on directories/files they created themselves.
    assert set(writers["loop.py"]) <= {"unlink"} and set(writers["probes.py"]) <= {"chmod", "mkdir"}, writers
    # the agent never changes permissions or ownership of anything except its own spool directory
    for name, hits in writers.items():
        if name not in ("spool.py", "probes.py", "loop.py"):
            assert not ({"chmod", "fchmod", "chown", "symlink", "link", "unlink", "remove", "rmdir"} & set(hits)), (name, hits)


def test_no_audit_file_writer_in_n2_so_gate_d_has_nothing_to_seal():
    """Audit files (agent audit.jsonl, priv.jsonl), rotation and sealing arrive with N3. N2 must not contain the pieces: chain sealing, chattr, +a handling, CURRENT pointer."""
    for m in MODULES + [SRC / "hub" / "core.py"]:
        t = m.read_text()
        if m.name == "core.py":
            continue
        assert "seal_record" not in t and "chattr" not in t and "FS_APPEND_FL" not in t and "FS_IOC_SETFLAGS" not in t and "audit.jsonl" not in t and "priv.jsonl" not in t and "CURRENT" not in t, m.name
    assert gates.GATES["D"].met is False and all(not g.met for g in gates.GATES.values())


def test_n2_executes_no_mutating_op_and_has_no_privileged_execution_path():
    for m in MODULES:
        t = code_only(m)
        assert not re.search(r"systemctl\s+(start|stop|restart|enable|disable|mask)|docker\s+(run|exec|rm|stop|start)|\bsudo\b|setuid|setgid|CAP_SYS_ADMIN", t), m.name
    from forge_node.t0 import engine
    assert all(gates.OPS[o].tier == 0 and not gates.OPS[o].mutating for o in engine.T0_OPS)


def test_t0_ops_registry_matches_the_design_table():
    design = (ROOT / "docs" / "design" / "FORGE_NODE.md").read_text()
    from forge_node.t0 import engine
    for op in engine.T0_OPS:
        assert f"`{op}`" in design
    assert set(engine.T0_OPS) == {"inv.host", "inv.disks", "inv.gpu", "inv.net", "inv.units", "inv.containers", "inv.vms", "inv.pkgs", "inv.certs", "inv.backups", "inv.git", "inv.access",
                                  "inv.usage", "inv.models", "metrics.sample", "logs.unit"}


def test_agent_package_has_stdlib_only_imports():
    import sys
    std = set(sys.stdlib_module_names) | {"forge_node"}
    for m in MODULES:
        for n in ast.walk(ast.parse(m.read_text())):
            mods = [a.name.split(".")[0] for a in n.names] if isinstance(n, ast.Import) else [n.module.split(".")[0]] if isinstance(n, ast.ImportFrom) and n.module and n.level == 0 else []
            assert set(mods) <= std, (m.name, mods)
    for m in MODULES:
        for n in ast.walk(ast.parse(m.read_text())):
            if isinstance(n, ast.ImportFrom) and n.level and n.module:
                assert not n.module.startswith("hub"), (m.name, n.module)         # the agent/t0 layer never imports the hub package (psycopg)


def test_main_exit_codes_and_no_network_at_import(monkeypatch, capsys):
    assert agent_main.main(["--version"]) == 0 and "0.1.0" in capsys.readouterr().out
    assert agent_main.main(["bogus"]) == 2
    monkeypatch.delenv("FORGE_NODE_NODE_ID", raising=False)
    assert agent_main.main([]) == 2 and "NODE_ID" in capsys.readouterr().err


def test_config_validation():
    base = {"FORGE_NODE_NODE_ID": "g2"}
    c = AgentConfig.from_environ(base)
    assert c.hub_host == "192.168.10.4" and c.hub_port == 8094 and c.owner_uid == 0 and c.fs_root == "/" and c.policy_dir == "/etc/forge-node/policy"
    for bad in ({"FORGE_NODE_NODE_ID": "G2!"}, {**base, "FORGE_NODE_HUB_HOST": "hub.example.org"}, {**base, "FORGE_NODE_HUB_PORT": "x"}, {**base, "FORGE_NODE_HUB_PORT": "0"},
                {**base, "FORGE_NODE_STATE_DIR": "relative"}, {}):
        with pytest.raises(ConfigError):
            AgentConfig.from_environ(bad)


def test_selfcheck_reports_availability_without_side_effects(tmp_path):
    env = make_env(tmp_path, FakeRunner({"lsblk": "{}", "findmnt": "{}"}))
    r = sc.selfcheck(env)
    assert r["commands"]["lsblk"] is True and r["commands"]["ip_route"] is False and "ip_route" in r["missing_required_commands"] and r["ok"] is False
    assert r["paths"]["/proc/meminfo"] is True and r["cgroup_v2_system_slice"] is False


def test_probe_main_loads_the_policy_itself_and_answers_one_json_line(tmp_path, owner):
    pol = tmp_path / "policy"
    install_policy(pol, policy_doc(), owner["priv"])
    signers = tmp_path / "allowed_signers"
    signers.write_text(signers_text(owner["pub"]))
    os.chmod(signers, 0o644)
    out = io.StringIO()
    rc = probe_main.main(["vms"], io.StringIO("{}\n"), out, node_id="g2", policy_dir=str(pol), allowed_signers=str(signers), fs_root=str(tmp_path), owner_uid=os.getuid(), now=lambda: NOW, ssh_keygen="ssh-keygen")
    r = json.loads(out.getvalue())
    assert rc == 0 and r["ok"] is True and r["data"]["domains"] == {"status": "unavailable", "reason": "virsh not installed"}
    out = io.StringIO()
    assert probe_main.main(["journal"], io.StringIO('{"unit":"sshd.service"}\n'), out, node_id="g2", policy_dir=str(pol), allowed_signers=str(signers), fs_root=str(tmp_path), owner_uid=os.getuid(), now=lambda: NOW, ssh_keygen="ssh-keygen") == 0
    assert json.loads(out.getvalue())["code"] == "DENY_NOT_ALLOWLISTED"
    out = io.StringIO()
    assert probe_main.main(["vms"], io.StringIO("{}\n"), out, node_id="g3", policy_dir=str(pol), allowed_signers=str(signers), fs_root=str(tmp_path), owner_uid=os.getuid(), now=lambda: NOW, ssh_keygen="ssh-keygen") == 1
    assert json.loads(out.getvalue())["code"] == "DENY_POLICY_INVALID"
    out = io.StringIO()
    assert probe_main.main(["vms", "extra"], io.StringIO(""), out, node_id="g2", policy_dir=str(pol), allowed_signers=str(signers), fs_root=str(tmp_path), owner_uid=os.getuid(), now=lambda: NOW, ssh_keygen="ssh-keygen") == 2
    out = io.StringIO()
    assert probe_main.main(["vms"], io.StringIO("not json\n"), out, node_id="g2", policy_dir=str(pol), allowed_signers=str(signers), fs_root=str(tmp_path), owner_uid=os.getuid(), now=lambda: NOW, ssh_keygen="ssh-keygen") == 2


@pytest.mark.parametrize("op,params,ok", [
    ("inv.host", {}, True), ("inv.host", {"x": 1}, False), ("logs.unit", {"unit": "a.service", "since_s": 604800, "lines": 500}, True), ("logs.unit", {"unit": "a.service", "since_s": 604801}, False),
    ("logs.unit", {"unit": "a.service", "lines": 501}, False), ("logs.unit", {"unit": "A B.service"}, False), ("logs.unit", {"unit": "a.exe"}, False), ("inv.usage", {"window_h": 72}, True),
    ("inv.usage", {"window_h": 0}, False), ("metrics.sample", {}, True), ("metrics.sample", {"after_seq": 5, "max_samples": 400}, True), ("metrics.sample", {"max_samples": 401}, False),
    ("metrics.sample", {"after_seq": True}, False), ("metrics.sample", {"after_seq": "1"}, False),
])
def test_t0_param_schema_is_shared_by_hub_and_node(op, params, ok):
    from forge_node.hub import params as hub_params
    from forge_node.protocol import ProtoError
    for fn in (lambda: T0P.validate_t0(op, params), lambda: hub_params.validate(op, 0, params)):
        if ok:
            fn()
        else:
            with pytest.raises(ProtoError) as e:
                fn()
            assert e.value.code == "DENY_PARAM"


def test_design_n2_list_names_existing_tests():
    design = (ROOT / "docs" / "design" / "FORGE_NODE.md").read_text()
    sec = design[design.index("### 16.2 Slice N2 acceptance list"):design.index("## 17. Open questions")]
    named = set(re.findall(r"`(test_[a-z0-9_]+)`", sec.split("**Not in N2")[0]))
    defined = set()
    for f in (ROOT / "tests").glob("test_*.py"):
        defined |= set(re.findall(r"^def (test_[a-z0-9_]+)\(", f.read_text(), re.M))
    assert not sorted(named - defined), sorted(named - defined)
    assert len(named) >= 100


def test_inventory_of_path_construction_in_the_t0_layer_and_the_agent():
    """Rework 2 (G27): `os.path.join(snap, 'refs', 'heads', <attacker string>)` discarded the snapshot prefix for an absolute component. Every os.path.join / open-for-write /
    makedirs in t0/ and agent/ is listed here with the reason its components are not attacker-controlled. A new one fails this test until it has been reviewed."""
    reviewed = {
        ("collect.py", "_which_smartctl", "os.path.join"): "constant directories x constant names",
        ("runner.py", "_resolve", "os.path.join"): "FIXED_PATH directories x binary name from the command table",
        ("runner.py", "_trusted", "os.path.join"): "readlink() target of a link found in a root-trusted directory chain; only used to follow the chain, never to write",
        ("loop.py", "_signature", "os.path.join"): "names from listdir() of the policy directory, filtered by the prefix 'policy-'; only stat()-ed",
        ("__main__.py", "build", "os.path.join"): "state directory from the config x constants",
    }
    found = {}
    root = ROOT / "src" / "forge_node"
    for m in MODULES:
        tree = ast.parse(m.read_text())
        for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            for n in ast.walk(fn):
                if isinstance(n, ast.Call) and ast.unparse(n.func) == "os.path.join":
                    found[(m.name, fn.name, "os.path.join")] = True
    inner = {k for k in found}
    # a join inside a nested function is attributed to the outer one as well; compare on the set of (file, innermost-or-outer function)
    missing = sorted(k for k in inner if k not in reviewed and not any(k[0] == r[0] and k[2] == r[2] and k[1] in (r[1], "build") for r in reviewed))
    assert not missing, f"unreviewed os.path.join: {missing}"
    # nothing in probes.py or loop.py joins paths any more
    assert not [k for k in inner if k[0] in ("probes.py",)]
    # no builtin open() for writing anywhere except the reviewed spots
    writers = []
    for m in MODULES:
        for n in ast.walk(ast.parse(m.read_text())):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "open" and len(n.args) > 1 and isinstance(n.args[1], ast.Constant) and any(c in str(n.args[1].value) for c in "wax+"):
                writers.append(m.name)
    assert writers == [], writers
