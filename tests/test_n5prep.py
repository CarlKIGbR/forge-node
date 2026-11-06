"""N5-prep: install readiness. (1) `release build|sign` with a passphrase-protected key, interactively (a pty plays the owner's terminal); (2) every host installs the t0 profile: templates, artifacts and
privd's refusal of anything above T0 for a t0 release; (3) the order of the install (design 13.D)."""
import base64
import json
import os
import pty
import select
import shutil
import subprocess
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import pytest
from privd_helpers import NODE, NOW, gates_with, policy_doc

from forge_node import cli as fn_cli
from forge_node import sshsig
from forge_node.privd import optable as optable_mod
from forge_node.privd.policy_full import parse_full
from forge_node.privd.policy_store import PolicyStore, release_table_ops
from forge_node.release import build, policies
from forge_node.release import cli as rel_cli
from forge_node.t0.policy import OWNER_PRINCIPAL, PolicyError

SRC = Path(__file__).resolve().parents[1] / "src"
PASSPHRASE = "correct horse battery staple"
ALL_GATES = gates_with("A", "B", "C", "D")
PIN = "ab" * 32
GATE_PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOCnQJdkGAnqC9RpKFPyX3e4R8Y5v0QG9hJmFqQqkG8E"


def keygen(d: Path, name: str, passphrase: str = "") -> Path:
    priv = d / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-a", "16", "-N", passphrase, "-C", "forge-node-owner", "-f", str(priv)], check=True, capture_output=True)
    return priv


@pytest.fixture(scope="module")
def n5keys(tmp_path_factory):
    d = tmp_path_factory.mktemp("n5keys")
    os.chmod(d, 0o700)
    return {"pw": keygen(d, "owner_pw", PASSPHRASE), "plain": keygen(d, "owner_plain"), "other": keygen(d, "other_plain"), "dir": d}


def signers_for(key: Path, ns: str = sshsig.NS_RELEASE) -> str:
    return sshsig.allowed_signers_text([(OWNER_PRINCIPAL, " ".join(Path(str(key) + ".pub").read_text().split()[:2]), ns)])


def run_in_pty(argv: list[str], answers: list[str], timeout: float = 90.0, env: dict | None = None) -> tuple[int, str, int]:
    """Run argv with a controlling terminal (like the owner's shell): whenever the output ends in a prompt that mentions 'passphrase', type the next answer. Returns (exit status, transcript, prompts)."""
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(argv[0], argv, env if env is not None else os.environ)
    out, prompts, deadline = b"", 0, time.time() + timeout
    answers = list(answers)
    seen_upto = 0
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
            tail = out[seen_upto:].lower()
            if b"passphrase" in tail and tail.rstrip().endswith(b":") and answers:
                os.write(fd, (answers.pop(0) + "\n").encode())
                prompts += 1
                seen_upto = len(out)
        else:
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                return os.waitstatus_to_exitcode(status), out.decode("utf-8", "replace"), prompts
    try:
        os.kill(pid, 9)
    except OSError:
        pass
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), out.decode("utf-8", "replace"), prompts


def cli_argv(*args: str) -> list[str]:
    return [sys.executable, "-m", "forge_node.cli", "release", *args]


def cli_env() -> dict:
    return {**os.environ, "PYTHONPATH": str(SRC), "PYTHONDONTWRITEBYTECODE": "1"}


# ======================================================================================================================== 1. release build / sign
def test_release_build_asks_for_the_passphrase_on_the_terminal_twice_and_the_signatures_verify(n5keys, tmp_path):
    out = tmp_path / "rel"
    rc, transcript, prompts = run_in_pty(cli_argv("build", "0.5.0", "t0", "--out", str(out), "--key", str(n5keys["pw"])), [PASSPHRASE, PASSPHRASE], env=cli_env())
    assert rc == 0, transcript
    assert prompts == 2, transcript                                                     # manifest + tarball: two signatures, two prompts - on the terminal, not captured
    assert PASSPHRASE not in transcript                                                 # the terminal does not echo a passphrase
    tar, sig = out / "forge-node-0.5.0-t0.tar", out / "forge-node-0.5.0-t0.tar.sig"
    signers = signers_for(n5keys["pw"])
    assert sshsig.verify(tar.read_bytes(), sig.read_text(), sshsig.NS_RELEASE, OWNER_PRINCIPAL, signers)                         # the tarball signature, as 13.C C2
    with tarfile.open(tar) as tf:
        raw = tf.extractfile("forge-node-0.5.0/RELEASE.json").read()
        inner = tf.extractfile("forge-node-0.5.0/RELEASE.json.sig").read().decode()
    assert sshsig.verify(raw, inner, sshsig.NS_RELEASE, OWNER_PRINCIPAL, signers)                                               # the manifest signature the switcher checks
    assert json.loads(raw)["profile"] == "t0" and "signer:" in transcript and "SHA256:" in transcript


def test_release_build_with_a_wrong_passphrase_fails_and_leaves_no_artifact(n5keys, tmp_path):
    out = tmp_path / "rel"
    rc, transcript, _ = run_in_pty(cli_argv("build", "0.5.0", "t0", "--out", str(out), "--key", str(n5keys["pw"])), ["wrong"] * 6, env=cli_env())
    assert rc == 1, transcript
    assert not out.exists() or not list(out.glob("*"))


def test_release_build_failure_of_the_second_signature_removes_the_half_built_tarball(n5keys, tmp_path, monkeypatch):
    calls = []

    def flaky(data, key, ns, ssh_keygen, what="data"):
        calls.append(what)
        if len(calls) == 2:
            raise rel_cli.CliError("boom")
        return sshsig.sign(data, n5keys["plain"], ns)
    monkeypatch.setattr(rel_cli, "interactive_sign", flaky)
    out = tmp_path / "rel"
    rc = rel_cli.main(["build", "0.5.0", "t0", "--out", str(out), "--key", str(n5keys["plain"])])
    assert rc == 1 and len(calls) == 2 and not list(out.glob("*"))


def test_signing_runs_ssh_keygen_attached_to_the_terminal_not_captured(n5keys, tmp_path, monkeypatch):
    seen = []
    real = subprocess.run

    def spy(argv, *a, **kw):
        if "-Y" in argv and "sign" in argv:
            seen.append((list(argv), dict(kw)))
        return real(argv, *a, **kw)
    monkeypatch.setattr(rel_cli.subprocess, "run", spy)
    f = tmp_path / "x.txt"
    f.write_bytes(b"data")
    assert rel_cli.main(["sign", str(f), "--key", str(n5keys["plain"])]) == 0
    (argv, kw), = seen
    assert argv[1:4] == ["-Y", "sign", "-f"] and argv[4] == str(n5keys["plain"]) and argv[5:7] == ["-n", "forge-node-release"] and "-q" not in argv
    assert not (set(kw) - {"check"}), kw                                                 # no capture_output, stdin, stdout, stderr, input, env, timeout: the child inherits the owner's terminal and environment
    assert kw.get("check") is False


def test_sign_writes_a_detached_signature_only_valid_in_its_namespace(n5keys, tmp_path):
    f = tmp_path / "policy-g2.json"
    f.write_bytes(b'{"a": 1}\n')
    assert rel_cli.main(["sign", str(f), "--key", str(n5keys["plain"]), "--namespace", "forge-node-policy"]) == 0
    sig = (tmp_path / "policy-g2.json.sig").read_text()
    assert sshsig.verify(f.read_bytes(), sig, sshsig.NS_POLICY, OWNER_PRINCIPAL, signers_for(n5keys["plain"], sshsig.NS_POLICY))
    with pytest.raises(sshsig.SigError):
        sshsig.verify(f.read_bytes(), sig, sshsig.NS_RELEASE, OWNER_PRINCIPAL, signers_for(n5keys["plain"], sshsig.NS_RELEASE))      # a policy signature is not a release signature
    assert rel_cli.main(["sign", str(f), "--key", str(n5keys["plain"]), "--namespace", "forge-node-policy"]) == 1                   # no silent overwrite
    assert rel_cli.main(["sign", str(f), "--key", str(n5keys["plain"]), "--namespace", "forge-node-policy", "--force"]) == 0
    with pytest.raises(SystemExit):
        rel_cli.main(["sign", str(f), "--key", str(n5keys["plain"]), "--namespace", "forge-node-hub", "--force"])                  # the hub's namespace is not the owner's to sign in


def test_sign_through_a_passphrase_prompt_on_the_terminal(n5keys, tmp_path):
    f = tmp_path / "approval.json"
    f.write_bytes(b"{}\n")
    rc, transcript, prompts = run_in_pty(cli_argv("sign", str(f), "--key", str(n5keys["pw"]), "--namespace", "forge-node-policy"), [PASSPHRASE], env=cli_env())
    assert rc == 0 and prompts == 1, transcript
    assert sshsig.verify(f.read_bytes(), (tmp_path / "approval.json.sig").read_text(), sshsig.NS_POLICY, OWNER_PRINCIPAL, signers_for(n5keys["pw"], sshsig.NS_POLICY))


def test_a_signature_by_a_key_that_is_not_the_expected_owner_key_is_caught_on_the_mac(n5keys, tmp_path):
    out = tmp_path / "rel"
    rc = rel_cli.main(["build", "0.5.0", "t0", "--out", str(out), "--key", str(n5keys["plain"]), "--pub", str(n5keys["other"]) + ".pub"])
    assert rc == 1 and not list(out.glob("*"))


def test_key_and_output_guards(n5keys, tmp_path):
    loose = tmp_path / "loose"
    shutil.copy(n5keys["plain"], loose)
    os.chmod(loose, 0o644)
    shutil.copy(str(n5keys["plain"]) + ".pub", str(loose) + ".pub")
    assert rel_cli.main(["build", "0.5.0", "t0", "--out", str(tmp_path / "o"), "--key", str(loose)]) == 1               # a private key others can read is refused
    assert rel_cli.main(["build", "0.5.0", "t0", "--out", str(tmp_path / "o"), "--key", str(tmp_path / "missing")]) == 1
    assert rel_cli.main(["build", "../x", "t0", "--out", str(tmp_path / "o"), "--key", str(n5keys["plain"])]) == 1          # bad version: BuildError becomes a clean refusal
    assert rel_cli.main(["build", "0.5.0", "t0", "--out", str(tmp_path / "o"), "--key", str(n5keys["plain"])]) == 0
    assert rel_cli.main(["build", "0.5.0", "t0", "--out", str(tmp_path / "o"), "--key", str(n5keys["plain"])]) == 1          # a version is built once
    assert rel_cli.main(["build", "0.5.0", "t0", "--out", str(tmp_path / "o"), "--key", str(n5keys["plain"]), "--force"]) == 0


def test_the_cli_build_is_reproducible_and_equals_build_release(n5keys, tmp_path):
    assert rel_cli.main(["build", "0.5.0", "t0", "--out", str(tmp_path / "a"), "--key", str(n5keys["plain"])]) == 0
    assert rel_cli.main(["build", "0.5.0", "t0", "--out", str(tmp_path / "b"), "--key", str(n5keys["plain"])]) == 0
    a, b = (tmp_path / "a" / "forge-node-0.5.0-t0.tar").read_bytes(), (tmp_path / "b" / "forge-node-0.5.0-t0.tar").read_bytes()
    assert a == b
    ref = build.build_release("0.5.0", "t0", tmp_path / "c", src_root=SRC, sign=lambda raw: sshsig.sign(raw, n5keys["plain"], sshsig.NS_RELEASE))
    assert ref["tar"].read_bytes() == a


def test_release_commands_are_dispatched_by_the_cli_and_are_not_part_of_any_artifact(n5keys, tmp_path, capsys):
    f = tmp_path / "f.txt"
    f.write_bytes(b"x")
    assert fn_cli.main(["release", "sign", str(f), "--key", str(n5keys["plain"])]) == 0 and (tmp_path / "f.txt.sig").exists()      # forge_node.cli dispatches `release`
    res = build.build_release("0.5.0", "t0", tmp_path / "o", src_root=SRC, sign=lambda raw: sshsig.sign(raw, n5keys["plain"], sshsig.NS_RELEASE))
    with tarfile.open(res["tar"]) as tf:
        tf.extract("forge-node-0.5.0/forge-node.pyz", tmp_path, filter="data")
    pyz = tmp_path / "forge-node-0.5.0" / "forge-node.pyz"
    names = zipfile.ZipFile(pyz).namelist()
    assert not [n for n in names if n.startswith("forge_node/release/") or n.startswith("forge_node/hub/")]
    r = subprocess.run([sys.executable, "-I", str(pyz), "release", "build", "1", "t0", "--out", "x", "--key", "y"], capture_output=True, text=True)
    assert r.returncode == 2 and "source checkout" in r.stderr


def test_release_cli_needs_only_the_standard_library_and_python_312():
    code = ("import sys; sys.path.insert(0, %r); import forge_node.release.cli, forge_node.release.build; "
            "print(sorted({m.split('.')[0] for m in sys.modules} - set(sys.stdlib_module_names) - {'forge_node', '__main__', '_sysconfigdata__linux_x86_64-linux-gnu', '_frozen_importlib', '_frozen_importlib_external'}))" % str(SRC))
    r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True)
    assert r.stdout.strip() == "[]", r.stdout
    assert rel_cli.MIN_PYTHON == (3, 12)
    assert sys.version_info >= rel_cli.MIN_PYTHON


# ======================================================================================================================== 2. T0 profile on every host
def fill(doc: dict) -> bytes:
    return json.dumps(doc).replace("__HUB_TLS_PIN__", PIN).replace("__HUB_GATE_PUB__", GATE_PUB).encode()


def parse_t0(raw: bytes, *, build_profile="t0", gates_map=None, **kw):
    table = optable_mod.build_optable(build_profile)
    node = json.loads(raw)["node"]
    return parse_full(raw, expect_node=node, file_serial=1, now=NOW, gates_map=gates_map or __import__("forge_node").gates.GATES, table_ops=release_table_ops(table, build_profile),
                      devof=kw.get("devof", lambda p: 1), protected_devs=lambda: set())


@pytest.mark.parametrize("nid", ["g1", "g2", "g3", "g4"])
def test_every_host_template_is_t0_only(nid):
    doc = policies.template(nid)
    assert doc["profile"] == "t0" and doc["global_mode"] == "observe" and doc["tiers_enabled"] == [0]
    assert "forge_roots" not in doc and doc["t1"] == {"workloads_enabled": False} and doc["t2"] == {"ops": []} and doc["t3"] == {"manifests_enabled": [], "opaque_enabled": False}
    assert "selftest" not in json.dumps(doc) and "loop" not in json.dumps(doc) and "forge-root" not in json.dumps(doc)
    pol = parse_t0(fill(doc))                                                         # the template validates, with the REAL t0 op table and release rules
    assert pol.profile == "t0" and pol.tiers == (0,) and not pol.ops and not pol.forge_roots and pol.workloads_enabled is False and not pol.opaque_enabled and not pol.t3_manifests
    with pytest.raises(PolicyError):
        parse_t0(json.dumps(doc).encode())                                            # the placeholders are still unfilled: never applicable


def test_all_four_hosts_ship_in_the_t0_artifact_and_full_is_still_available_for_g2_g3(n5keys, tmp_path):
    sign = lambda raw: sshsig.sign(raw, n5keys["plain"], sshsig.NS_RELEASE)               # noqa: E731
    t0 = build.build_release("0.5.0", "t0", tmp_path / "t0", src_root=SRC, sign=sign)
    assert {k for k in t0["manifest"]["files"] if k.startswith("policy/")} == {f"policy/policy-{n}.json" for n in ("g1", "g2", "g3", "g4")}
    with tarfile.open(t0["tar"]) as tf:
        for n in ("g1", "g2", "g3", "g4"):
            doc = json.loads(tf.extractfile(f"forge-node-0.5.0/policy/policy-{n}.json").read())
            assert doc["node"] == n and doc["profile"] == "t0" and doc["tiers_enabled"] == [0] and "forge_roots" not in doc
        names = tf.getnames()
    assert not [n for n in names if "ops.py" in n or "opworker" in n]
    with tarfile.open(t0["tar"]) as tf:
        tf.extract("forge-node-0.5.0/forge-node.pyz", tmp_path, filter="data")
    z = zipfile.ZipFile(tmp_path / "forge-node-0.5.0" / "forge-node.pyz")
    assert not [n for n in z.namelist() if n.endswith(("privd/ops.py", "privd/opworker.py"))]
    assert all(b"def noop_effect" not in z.read(n) for n in z.namelist() if n.endswith(".py"))                                   # no selftest.noop code in the artifact
    full = build.build_release("0.5.0", "full", tmp_path / "full", src_root=SRC, sign=sign)
    assert {k for k in full["manifest"]["files"] if k.startswith("policy/")} == {"policy/policy-g2.json", "policy/policy-g3.json"}
    with tarfile.open(full["tar"]) as tf:
        for n in ("g2", "g3"):
            doc = json.loads(tf.extractfile(f"forge-node-0.5.0/policy/policy-{n}.json").read())
            assert doc["profile"] == "full" and doc["tiers_enabled"] == [0] and doc["forge_roots"] and doc["global_mode"] == "observe"
    with pytest.raises(KeyError):
        policies.template("g1", "full")                                              # g1/g4 never get a full template


def test_the_install_order_is_the_design_order():
    assert policies.INSTALL_ORDER == ("g2", "g3", "g1", "g4") and set(policies.INSTALL_ORDER) == set(policies.NODES)           # 13.D: g4, the live-trading host, last


def _violations():
    base = policy_doc(profile="t0", mode="observe", tiers=(0,), gate_keys=[{"id": "hub-gate-1", "pub": GATE_PUB, "not_after": "2099-12-31"}])
    root = {"path": "/srv/forge/node", "quota_backend": "loop_fs", "backing_image": "/var/lib/forge-node-img/forge-root.img", "size_bytes": 107374182400, "log_budget_bytes": 2147483648,
            "min_free_bytes": 214748364800}
    return {
        "tier 1": dict(tiers_enabled=[0, 1]), "tier 2": dict(tiers_enabled=[0, 2]), "tier 3": dict(tiers_enabled=[0, 3]), "tier 1 only": dict(tiers_enabled=[1]),
        "t1 op": dict(tiers_enabled=[0, 1], t1={"workloads_enabled": False, "ops": [{"op": "selftest.noop", "mode": "enforce"}]}),
        "t1 op without tier": dict(t1={"workloads_enabled": False, "ops": [{"op": "selftest.noop", "mode": "dry_run_only"}]}),
        "t2 op": dict(tiers_enabled=[0, 2], t2={"ops": [{"op": "unit.restart", "mode": "dry_run_only"}]}),
        "workloads": dict(t1={"workloads_enabled": True}, forge_roots=[root]),
        "forge root": dict(forge_roots=[root]),
        "vm pool": dict(t1={"workloads_enabled": False, "vm_pool": {"x": 1}}),
        "t3 manifests": dict(t3={"manifests_enabled": ["unit_action"], "opaque_enabled": False}),
        "t3 opaque": dict(t3={"manifests_enabled": [], "opaque_enabled": True}),
        "profile full with tier 0 only": dict(profile="full"),
        "profile full with a forge root": dict(profile="full", forge_roots=[root]),
        "profile full with tier 1": dict(profile="full", tiers_enabled=[0, 1]),
    }, base


@pytest.mark.parametrize("gates_label", ["production gates", "every gate open"])
def test_privd_of_a_t0_release_rejects_every_policy_above_t0(gates_label):
    """With the production gate table AND with every gate hypothetically met (a later release): the t0 release itself refuses, by profile - not only because a gate is unmet."""
    viol, base = _violations()
    gm = ALL_GATES if gates_label == "every gate open" else None
    ok = parse_t0(json.dumps(base).encode(), gates_map=gm)
    assert ok.tiers == (0,) and ok.profile == "t0"
    for name, over in viol.items():
        doc = {**base, **over}
        try:
            parse_t0(json.dumps(doc).encode(), gates_map=gm)
        except PolicyError as e:
            assert e.code == "DENY_POLICY_INVALID", name
        else:
            pytest.fail(f"accepted: {name}")


def test_a_t0_release_refuses_a_full_policy_even_if_it_asks_for_nothing_above_t0():
    viol, base = _violations()
    with pytest.raises(PolicyError) as e:
        parse_t0(json.dumps({**base, "profile": "full"}).encode(), gates_map=ALL_GATES)
    assert "release is profile t0" in e.value.detail
    parse_t0(json.dumps({**base, "profile": "full"}).encode(), build_profile="full", gates_map=ALL_GATES)       # a full release does accept it (the later T1 step) ...
    parse_t0(json.dumps(base).encode(), build_profile="full", gates_map=ALL_GATES)                                  # ... and a t0 policy too (downgrade)


def test_policy_apply_on_a_t0_privd_refuses_above_t0_end_to_end(privd_env):
    """The real request path (policy.apply -> PolicyStore.apply -> parse_full) of a privd built from the t0 release rules."""
    env = privd_env
    table = optable_mod.build_optable("t0")
    store = PolicyStore(policy_dir=env.paths.policy_dir, allowed_signers=env.paths.allowed_signers, serial_file=env.paths.serial_file, node=NODE, owner_uid=0, ssh_keygen=env.ssh_keygen,
                        clock=env.clock, gates_map=ALL_GATES, table_ops=release_table_ops(table, "t0"), devof=env.devof, protected_devs=lambda: set())
    env.ctx = env.make_context(policies=store, optable=table, gates=ALL_GATES)
    for i, over in enumerate(({"tiers": (0, 1)}, {"tiers": (0, 2)}, {"profile": "full", "tiers": (0,)}, {"profile": "full", "tiers": (0, 1), "t1_ops": [{"op": "selftest.noop", "mode": "enforce"}]}), start=1):
        r = env.install(serial=i, **{"mode": "observe", **over})
        assert r["ok"] is False and r["code"] == "DENY_POLICY_INVALID", (over, r)
    assert store.installed_serial() == 0
    r = env.install(serial=9, profile="t0", mode="observe", tiers=(0,))
    assert r["ok"] is True, r
    assert store.installed_serial() == 9


# ======================================================================================================================== 3. hub deploy readiness: the migration role of production
@pytest.fixture
def prod_like_db():
    """A database whose migration role is what production's forge_core is: it may CONNECT and nothing else on the database (no CREATE, so no CREATE SCHEMA, not even IF NOT EXISTS)."""
    import uuid

    import psycopg

    from conftest import TEST_DSN, _conninfo
    if not TEST_DSN:
        pytest.skip("no database")
    tag = uuid.uuid4().hex[:8]
    db, role = f"fn_prod_{tag}", f"fn_mig_{tag}"
    admin = _conninfo("postgres")
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='forge_nodehub') THEN CREATE ROLE forge_nodehub LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; END IF; END $$")
        c.execute(f'CREATE ROLE "{role}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE')
        c.execute(f'CREATE DATABASE "{db}"')
        c.execute(f'REVOKE ALL ON DATABASE "{db}" FROM PUBLIC')
        c.execute(f'GRANT CONNECT ON DATABASE "{db}" TO "{role}"')
    su = _conninfo(db)
    yield {"su": su, "mig": su.replace("user=postgres", f"user={role}"), "role": role}
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)')
        c.execute(f'DROP ROLE IF EXISTS "{role}"')


def test_node_migration_with_the_production_migration_role_needs_the_schema_created_once_by_the_superuser(prod_like_db, monkeypatch, capsys):
    import psycopg

    from forge_node.hub import migrate as m
    assert "user=" + prod_like_db["role"] in prod_like_db["mig"]
    with pytest.raises(m.MigrateError) as e:                                            # the schema is missing and this role cannot create schemas: a clear instruction, not a stack trace
        m.migrate(prod_like_db["mig"])
    assert "CREATE SCHEMA node AUTHORIZATION forge_core" in str(e.value)
    monkeypatch.setenv("FORGE_NODEHUB_MIGRATE_DSN", prod_like_db["mig"])
    assert m.main() == 3 and "node migration:" in capsys.readouterr().err
    with psycopg.connect(prod_like_db["su"], autocommit=True) as c:                    # create_db_role.sh does this for core/mem/lg; the hub GO does it for node
        c.execute(f'CREATE SCHEMA node AUTHORIZATION "{prod_like_db["role"]}"')
    assert m.migrate(prod_like_db["mig"]) == ["0001_node_schema"]                       # base: `CREATE SCHEMA IF NOT EXISTS node` fails here with 'permission denied for database'
    assert m.migrate(prod_like_db["mig"]) == []
    with psycopg.connect(prod_like_db["su"]) as c:
        assert c.execute("SELECT count(DISTINCT tableowner) FROM pg_tables WHERE schemaname='node'").fetchone()[0] == 1
        assert c.execute("SELECT tableowner = %s FROM pg_tables WHERE schemaname='node' AND tablename='nodes'", (prod_like_db["role"],)).fetchone()[0]


def test_migration_0001_does_not_create_the_schema_itself():
    sql = "\n".join(l for l in (SRC.parent / "migrations" / "0001_node_schema.sql").read_text().splitlines() if not l.lstrip().startswith("--"))
    assert "CREATE SCHEMA" not in sql.upper()


def test_hub_image_keeps_the_node_migrations_apart_from_the_base_images_own():
    """Rehearsal finding: `COPY migrations ./migrations` on top of forge-core/app put forge-core's 0001_init.sql ... 0020 and 0001_node_schema.sql in one /app/migrations, and the node migrator would have
    run them all (as forge_core, against the production database)."""
    df = (SRC.parent / "Dockerfile").read_text()
    assert "COPY migrations ./node-migrations" in df and "FORGE_NODE_MIGRATIONS_DIR=/app/node-migrations" in df
    assert not [l for l in df.splitlines() if l.startswith("COPY") and l.rstrip().endswith("./migrations")] and "/app/migrations" not in df.replace("forge-core's /app/migrations", "")


def test_the_node_migrator_ignores_files_that_are_not_the_nodes(tmp_path, dsn):
    import psycopg

    from forge_node.hub import migrate as m
    for name in ("0001_init.sql", "0002_exec_identity.sql", "0020_guard_required.sql", "notes.sql"):
        (tmp_path / name).write_text("DROP SCHEMA core CASCADE; SELECT 1/0;")
    (tmp_path / "0001_node_x.sql").write_text("CREATE TABLE node.n5_probe(i int);")
    assert m.migrate(dsn, tmp_path) == ["0001_node_x"]
    with psycopg.connect(dsn) as c:
        assert c.execute("SELECT to_regclass('node.n5_probe')").fetchone()[0] is not None


def test_build_hub_script_checks_the_pinned_base_before_building():
    sh = (SRC.parent / "scripts" / "build-hub.sh").read_text()
    assert subprocess.run(["bash", "-n", str(SRC.parent / "scripts" / "build-hub.sh")]).returncode == 0
    assert "forge-core/app:build" in sh and 'IMG_FORGE_CORE_APP=' in sh and '[ "$ID" = "$PIN" ]' in sh and "docker run" not in sh and "compose" not in sh          # builds a local image, starts nothing
    assert sh.index('[ "$ID" = "$PIN" ]') < sh.index("docker build")


def test_create_nodehub_role_script_follows_the_forge_core_pattern():
    p = SRC.parent / "scripts" / "create_nodehub_role.sh"
    sh = p.read_text()
    assert subprocess.run(["bash", "-n", str(p)]).returncode == 0 and os.access(p, os.X_OK)
    assert "secrets/nodehub_db_password" in sh and "chmod 600" in sh and "umask 077" in sh
    assert "CREATE SCHEMA IF NOT EXISTS node AUTHORIZATION forge_core" in sh and "gen_secret_file" in sh
    assert not [l for l in sh.splitlines() if "PASSWORD '" in l or "PGPASSWORD" in l]                    # the password reaches psql through stdin (\set), never through argv or env
    assert "docker compose" not in sh.replace("docker compose --profile", "")                           # creates a role and a schema; starts nothing


# ======================================================================================================================== 4. the owner's guide
GUIDE = SRC.parent / "docs" / "reports" / "N5PREP_OWNER_GUIDE.md"


def _guide_blocks() -> list[str]:
    import re
    return re.findall(r"^```bash\n(.*?)^```$", GUIDE.read_text(), re.S | re.M)


def test_every_command_block_of_the_guide_is_valid_shell(tmp_path):
    blocks = _guide_blocks()
    assert len(blocks) >= 12
    for i, b in enumerate(blocks):
        f = tmp_path / f"b{i}.sh"
        f.write_text(b)
        r = subprocess.run(["bash", "-n", str(f)], capture_output=True, text=True)
        assert r.returncode == 0, (i, r.stderr, b[:200])


def test_guide_installs_t0_everywhere_in_the_design_order_without_a_volume():
    import re
    g = GUIDE.read_text()
    assert "PROFILE=t0" in g and "FORGE_ROOT=none" in g and "PROFILE=full" not in g
    for banned in ("fallocate", "mkfs.ext4", "losetup", "forge-root.img", "systemd-escape", "FORGE_ROOT_BYTES=1", "selftest.noop"):
        assert banned not in "\n".join(_guide_blocks()), banned                                               # no command of the guide creates a volume or touches op code
    head = [l for l in g.splitlines() if l.startswith("| | g2")][0]
    assert [m for m in re.findall(r"\b(g[1-4]) \(", head)] == list(policies.INSTALL_ORDER)                       # table columns = g2, g3, g1, g4
    row = [l for l in g.splitlines() if l.startswith("| `NID` / `IP`")][0]
    for nid, ip in (("g2", "192.168.10.4"), ("g3", "192.168.30.3"), ("g1", "192.168.10.3"), ("g4", "192.168.30.4")):
        assert f"`{nid}` / `{ip}`" in row
    assert g.index("Teil 3") < g.index("Teil 4") < g.index("Teil 5") < g.index("Teil 7")                       # hub, firewall, hosts, rollback
    assert "Zustimmung" in g and "g4" in g.split("Teil 8")[1]


def test_guide_uses_only_commands_that_exist():
    import re
    g = GUIDE.read_text()
    blocks = "\n".join(_guide_blocks())
    ctl = set(re.findall(r'"([a-z-]+)": lambda a', (SRC / "forge_node" / "privd" / "privctl.py").read_text()))
    used = set(re.findall(r"privctl (audit-[a-z]+|status|lockdown|policy-apply|selftest-bypass)\b", blocks))
    assert used and used <= ctl, used - ctl
    sw = (SRC / "forge_node" / "release" / "switcher.py").read_text()
    for sub in set(re.findall(r"forge-node-release (status|check|switch|install-first)\b", g)):
        assert f'"{sub}"' in sw, sub
    fw = [l for l in blocks.splitlines() if "forge-docker-user.sh" in l or l.lstrip().startswith("sudo $FW")]
    assert fw and all("--hub" in l for l in fw if "forge-docker-user.sh" in l or "$FW" in l if not l.startswith("FW=")), fw       # every firewall call is the 8094 set
    p = rel_cli.parser()
    ns = p.parse_args(["build", "0.5.0", "t0", "--out", "o", "--key", "k"])
    assert ns.profile == "t0"
    line = [l for l in blocks.splitlines() if "forge_node.cli release build" in l][0]
    assert "$VER t0 --out" in line and "--key" in line
    sign = [l for l in blocks.splitlines() if "forge_node.cli release sign" in l][0]
    assert "--namespace forge-node-policy" in sign
    assert "'t0'" in blocks and "INSERT INTO node.nodes" in blocks and "SET ROLE forge_core" in blocks                      # registration by SQL while Cockpit /nodes does not exist
