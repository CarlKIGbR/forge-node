"""Statische Pruefung der mitgelieferten Deployment-Dateien und des Slice-Umfangs: N1 installiert, baut und startet nichts."""
import re
import stat
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
ROOT = Path(__file__).resolve().parents[1]
COMPOSE = yaml.safe_load((ROOT / "deploy" / "compose.nodehub.yaml").read_text())
HUB = COMPOSE["services"]["forge-nodehub"]


def test_hub_is_published_on_the_lan_ip_only_and_exactly_one_port():
    assert len(HUB["ports"]) == 1
    p = HUB["ports"][0]
    assert p["host_ip"] == "192.168.10.4" and p["published"] == 8094 and p["target"] == 8094 and p["protocol"] == "tcp"
    raw = (ROOT / "deploy" / "compose.nodehub.yaml").read_text()
    assert not re.search(r"0\.0\.0\.0:\d+|host_ip:\s*(0\.0\.0\.0|::|\"\")", raw)
    assert "network_mode" not in raw and "privileged" not in raw


def test_hub_container_is_hardened():
    assert HUB["read_only"] is True and HUB["cap_drop"] == ["ALL"] and "no-new-privileges:true" in HUB["security_opt"]
    assert HUB["user"] == "${FORGE_UID}:${FORGE_GID}" and HUB["pids_limit"] and HUB["mem_limit"]
    assert HUB["logging"]["options"] == {"max-size": "10m", "max-file": "3"}                  # Design 4.2.1: Log-Rotation Pflicht
    assert HUB["restart"] == "unless-stopped"
    assert re.search(r"^\$\{IMG_FORGE_NODEHUB\}$", HUB["image"])
    assert HUB["labels"]["forge.critical"] == "true" and HUB["labels"]["forge.managed"] == "true"


def test_hub_mounts_are_minimal_and_readonly_except_control_dir():
    rw = [v for v in HUB["volumes"] if not v.endswith(":ro")]
    assert rw == ["/srv/forge/post/control:/post/control:rw"]
    text = " ".join(HUB["volumes"])
    for forbidden in ("docker.sock", "/etc", "/root", "/srv/models", "/opt/kmu-ai", "/srv/kmu-ai", ":/post:"):
        assert forbidden not in text.replace("/post/control", "")
    assert not any(v.startswith("/srv/forge/post/control") and v.endswith(":ro") for v in HUB["volumes"])


def test_hub_env_points_to_files_for_every_secret():
    env = HUB["environment"]
    assert env["FORGE_NODEHUB_DB_PASSWORD_FILE"].startswith("/run/secrets/")
    assert not any(k.endswith(("PASSWORD", "TOKEN", "SECRET", "KEY_PEM")) for k in env)
    assert not re.search(r"password=\S+", env["FORGE_NODEHUB_DB_DSN"])
    assert env["FORGE_NODEHUB_CONTAINER"] == "1" and env["FORGE_NODEHUB_CONTROL_DIR"] == "/post/control"


def test_migrate_service_runs_as_schema_owner_not_as_hub_role_and_is_profile_gated():
    m = COMPOSE["services"]["nodehub-migrate"]
    assert "user=forge_nodehub" not in m["environment"]["FORGE_NODEHUB_MIGRATE_DSN"] and m["profiles"] == ["nodehub-migrate"] and m["restart"] == "no"


def test_images_are_never_floating_in_n1_files():
    df = (ROOT / "Dockerfile").read_text()
    assert "ARG BASE_IMAGE" in df and not re.search(r"^FROM\s+\S+:latest", df, re.M)
    assert "USER ${FORGE_UID}:${FORGE_GID}" in df.splitlines()[-2] or "USER ${FORGE_UID}:${FORGE_GID}" in df


# ----------------------------------------------------------------------------------------------------------- slice scope (nothing installed)
FILES = [p for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts and "__pycache__" not in p.parts and "tests" not in p.relative_to(ROOT).parts[:1]]


def test_no_unit_files_sudoers_or_keys_are_shipped():
    names = [p.name for p in FILES]
    assert not [n for n in names if n.endswith((".service", ".socket", ".timer", ".mount", ".target"))]
    assert not [n for n in names if "sudoers" in n]
    assert not [n for n in names if n.endswith((".key", ".pem", ".crt", ".sig")) or n.startswith(("id_", "gate_", "owner_"))]
    for p in FILES:
        if p.suffix in (".md", ".sql", ".py", ".sh", ".yaml", ".toml") or p.name == "Dockerfile":
            t = p.read_text(errors="replace")
            assert "-----BEGIN OPENSSH PRIVATE KEY-----" not in t and "-----BEGIN EC PRIVATE KEY-----" not in t and "-----BEGIN PRIVATE KEY-----" not in t, p


def _strings_in_calls(tree, attrs):
    import ast

    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in attrs:
            for c in ast.walk(n):
                if isinstance(c, ast.Constant) and isinstance(c.value, str):
                    out.append(c.value)
    return out


def test_source_never_generates_keys_or_touches_the_system():
    import ast

    importers = []
    for p in (ROOT / "src").rglob("*.py"):
        tree = ast.parse(p.read_text())
        mods = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} | {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        if "subprocess" in mods:
            importers.append(p.name)
        calls = _strings_in_calls(tree, {"run", "Popen", "call", "check_call", "check_output", "system", "popen", "execv", "execvp", "chmod", "chown"})
        for bad in ("systemctl", "systemd-run", "sudo", "useradd", "chattr", "iptables", "docker", "openssl", "-genkey", "genpkey", "ecparam", "-t"):
            assert bad not in calls, (p.name, bad)
    # ssh-keygen -Y sign/verify (sshsig) and the T0 read-only command table (N2: t0/runner.py, a closed argv table - see test_t0_runner.py)
    assert sorted(importers) == ["runner.py", "sshsig.py"]
    sshsig = (ROOT / "src" / "forge_node" / "sshsig.py").read_text()
    assert sorted(set(re.findall(r'"(-Y|-lf|-q)"', sshsig))) == ["-Y", "-lf", "-q"] and '"sign"' in sshsig and '"verify"' in sshsig
    assert "-N" not in sshsig and "-t\"" not in sshsig and "keygen\", \"-" not in sshsig
    for p in (ROOT / "scripts").iterdir():
        if p.suffix == ".sh":
            t = p.read_text()
            assert "sudo " not in t and "systemctl" not in t and "ssh-keygen -t" not in t and "useradd" not in t


def test_sql_scripts_contain_no_passwords():
    for p in (ROOT / "scripts" / "sql").glob("*.sql"):
        assert not re.search(r"PASSWORD\s+'", p.read_text(), re.I), p
    assert not re.search(r"PASSWORD\s+'", (ROOT / "migrations" / "0001_node_schema.sql").read_text(), re.I)


def test_migration_touches_only_schema_node():
    sql = "\n".join(l for l in (ROOT / "migrations" / "0001_node_schema.sql").read_text().splitlines() if not l.lstrip().startswith("--"))
    assert not re.search(r"\b(core|mem|lg)\.", sql)
    assert not re.search(r"ALTER\s+(TABLE|SYSTEM)\s+(?!node\.)", sql)
    assert not re.search(r"\bDROP\s+(SCHEMA|ROLE)\b", sql)
    assert re.findall(r"\bDROP\s+TABLE\b[^;]*", sql) == ["DROP TABLE node.%I', nm)"]          # nur die 400-Tage-geschuetzte Retention-Funktion (audit_drop_partition)


def test_hub_package_has_no_policy_or_install_or_approval_surface():
    """Neither N1 nor N2 delivers privd, privctl, a ledger, the unit resolver, policy application or T3 proposals (N2 adds the agent and the T0 layer)."""
    pkg = ROOT / "src" / "forge_node"
    assert sorted(p.name for p in pkg.iterdir() if p.is_dir() and p.name != "__pycache__") == ["agent", "hub", "t0"]
    assert not any((pkg / n).exists() for n in ("privd.py", "agent.py", "privctl.py", "ledger.py", "resolver.py", "privd", "privctl"))
    assert not [f for d in ("agent", "t0") for n in ("privd*.py", "ledger*.py", "resolver*.py", "approval*.py", "apply*.py") for f in (pkg / d).glob(n)]
    server = (pkg / "hub" / "server.py").read_text()
    for route in ("/v1/stop", "/v1/release/apply", "/v1/policy/apply", "/v1/t3", "/v1/exec"):
        assert route not in server


def test_run_tests_script_is_not_world_writable_and_executable():
    m = (ROOT / "scripts" / "run-tests.sh").stat().st_mode
    assert m & stat.S_IXUSR and not m & stat.S_IWOTH


def test_design_n1_list_names_existing_tests():
    design = (ROOT / "docs" / "design" / "FORGE_NODE.md").read_text()
    sec = design[design.index("### 16.1 Slice N1 acceptance list"):design.index("## 17. Open questions")]
    named = set(re.findall(r"`(test_[a-z0-9_]+)`", sec))
    defined = set()
    for f in (ROOT / "tests").glob("test_*.py"):
        defined |= set(re.findall(r"^def (test_[a-z0-9_]+)\(", f.read_text(), re.M))
    # nur der "Nicht in N1"-Absatz nennt Tests anderer Slices
    in_n1 = set(re.findall(r"`(test_[a-z0-9_]+)`", sec.split("**Not in N1")[0]))
    missing = sorted(in_n1 - defined)
    assert not missing, missing
    assert len(in_n1) >= 70 and named >= in_n1
