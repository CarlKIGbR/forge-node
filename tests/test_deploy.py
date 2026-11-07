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


def test_hub_image_contains_exactly_the_hub_import_closure():
    """The Dockerfile copies the hub's import closure and nothing of the node side (agent, privd, audit, release, doctor ...)."""
    import ast
    base = ROOT / "src" / "forge_node"
    copied = set()
    for line in (ROOT / "Dockerfile").read_text().splitlines():
        if line.startswith("COPY src/forge_node"):
            *srcs, dst = line.split()[1:]
            for src in srcs:
                path = ROOT / src
                copied |= {p.relative_to(base).as_posix() for p in (path.rglob("*.py") if path.is_dir() else [path])}

    def deps(rel):
        tree = ast.parse((base / rel).read_text())
        pkg = rel.split("/")[:-1]
        out = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.ImportFrom) and n.level:
                up = pkg[:len(pkg) - (n.level - 1)]
                mod = up + (n.module.split(".") if n.module else [])
                names = [a.name for a in n.names]
                cands = ["/".join(mod) + ".py", "/".join(mod) + "/__init__.py"] + ["/".join(mod + [x]) + ".py" for x in names]
                out |= {c for c in cands if (base / c).exists()}
        return out
    todo, seen = [p for p in copied if p.startswith("hub/")], set()
    while todo:
        f = todo.pop()
        if f in seen:
            continue
        seen.add(f)
        todo += [d for d in deps(f) if d not in seen]
    # the closure also needs the package markers of every directory it touches
    seen |= {(Path(f).parent / "__init__.py").as_posix() for f in seen if (base / Path(f).parent / "__init__.py").exists() and Path(f).parent.as_posix() != "."} | {"__init__.py"}
    assert seen <= copied, sorted(seen - copied)
    assert not [c for c in copied if c.split("/")[0] in ("agent", "privd", "audit", "release") or c in ("doctor.py", "cli.py", "profile.py")], sorted(copied)


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
    """N1/N2 never touched the system. N3's privd drives systemd (transient units) and maintains its own root-owned state; the scope of that is pinned PER MODULE: only these modules
    may contain these commands, nothing may contain sudo/useradd/iptables/docker/openssl or any key generation."""
    import ast

    ever_banned = ("sudo", "useradd", "iptables", "docker", "openssl", "-genkey", "genpkey", "ecparam", "-t")
    allowed = {                                                       # module -> the otherwise banned words (as literal arguments of process-starting calls) it may carry
        "privd/units.py": {"systemctl", "systemd-run"},                # the systemd backend
        "privd/main.py": {"systemctl", "systemd-run"},                 # trusted binary lookup for the backend / privctl
        "privd/privctl.py": {"systemctl"},                             # lockdown: stop the agent, disable the socket
        "release/switcher.py": {"systemctl"},                          # link/daemon-reload/start/stop around a release switch
    }
    importers = []
    for p in (ROOT / "src").rglob("*.py"):
        rel = str(p.relative_to(ROOT / "src" / "forge_node"))
        tree = ast.parse(p.read_text())
        mods = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} | {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        if "subprocess" in mods:
            importers.append(rel)
        calls = _strings_in_calls(tree, {"run", "Popen", "call", "check_call", "check_output", "system", "popen", "execv", "execvp", "chmod", "fchmod", "chown", "fchown"})
        for bad in ("systemctl", "systemd-run", "chattr", *ever_banned):
            if bad in calls:
                assert bad in allowed.get(rel, set()) and bad not in ever_banned, (rel, bad)
    assert sorted(importers) == ["privd/main.py", "privd/units.py", "release/cli.py", "release/switcher.py", "sshsig.py", "t0/runner.py"]      # N5-prep: release/cli.py = the owner's interactive `ssh-keygen -Y sign` (never a key generation)
    cli_src = (ROOT / "src" / "forge_node" / "release" / "cli.py").read_text()
    assert "capture_output" not in cli_src.replace("NO capture_output", "") and '"-N"' not in cli_src and "genkey" not in cli_src and "keygen\", \"-t" not in cli_src
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
    """The HUB has no endpoint that applies policy, releases, T3 proposals or runs anything, and no privileged code is reachable from the agent package: privd, the audit admin and the
    release tooling are separate packages that the agent never imports beyond the append-only writer and the socket client (N3 delivers them; N2 had none)."""
    pkg = ROOT / "src" / "forge_node"
    assert sorted(p.name for p in pkg.iterdir() if p.is_dir() and p.name != "__pycache__") == ["agent", "audit", "hub", "privd", "release", "t0"]
    assert not [f for d in ("agent", "t0", "hub") for n in ("privd*.py", "ledger*.py", "resolver*.py", "approval*.py", "apply*.py") for f in (pkg / d).glob(n)]
    server = (pkg / "hub" / "server.py").read_text()
    for route in ("/v1/stop", "/v1/release/apply", "/v1/policy/apply", "/v1/t3", "/v1/exec"):
        assert route not in server
    import ast
    for d in ("agent", "hub", "t0"):
        for p in (pkg / d).rglob("*.py"):
            for n in ast.walk(ast.parse(p.read_text())):
                if isinstance(n, ast.ImportFrom) and n.module and n.module.split(".")[0] in ("privd", "release"):
                    assert d == "agent" and n.module == "privd.client", (p.name, n.module)            # the agent's only way to privd is the socket client


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


def test_overlay_external_network_name_equals_the_one_forge_core_declares():
    core = Path("/srv/forge/work/forge-core/compose.yaml")
    if not core.is_file():
        pytest.skip("forge-core is not mounted in this environment")
    declared = yaml.safe_load(core.read_text())["networks"]["forge_core"]
    assert declared.get("external") is True
    overlay = COMPOSE["networks"]["forge_core"]
    assert overlay["external"] is True
    assert overlay.get("name", "forge_core") == declared.get("name", "forge_core")
