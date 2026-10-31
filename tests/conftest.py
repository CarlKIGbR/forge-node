import os
import shutil
import stat
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from forge_node import protocol  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TEST_DSN = os.environ.get("FORGE_NODE_TEST_DSN")
HAVE_KEYGEN = shutil.which("ssh-keygen") is not None
HAVE_OPENSSL = shutil.which("openssl") is not None


def pytest_collection_modifyitems(config, items):
    for item in items:
        if "db" in item.keywords and not TEST_DSN:
            item.add_marker(pytest.mark.skip(reason="FORGE_NODE_TEST_DSN not set (scripts/run-tests.sh starts a throwaway Postgres)"))


# ------------------------------------------------------------------------------------------------------------------ keys (ephemeral, test only)
class Keys:
    def __init__(self, base: Path):
        self.base = base

    def make(self, name: str) -> tuple[Path, str]:
        priv = self.base / name
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"test-{name}", "-f", str(priv)], check=True, capture_output=True)
        os.chmod(priv, 0o600)
        pub = (self.base / f"{name}.pub").read_text().strip()
        return priv, " ".join(pub.split()[:2])


@pytest.fixture(scope="session")
def keys(tmp_path_factory):
    if not HAVE_KEYGEN:
        pytest.skip("ssh-keygen not available")
    d = tmp_path_factory.mktemp("keys")
    os.chmod(d, 0o700)
    return Keys(d)


@pytest.fixture(scope="session")
def gate(keys):
    """Hub-Gate-Schluessel (nur Test, fluechtig in tmp)."""
    priv, pub = keys.make("gate1")
    return {"priv": priv, "pub": pub, "id": "hub-gate-1", "keys": [{"id": "hub-gate-1", "pub": pub, "not_after": "2099-12-31"}]}


@pytest.fixture(scope="session")
def gate2(keys):
    priv, pub = keys.make("gate2")
    return {"priv": priv, "pub": pub, "id": "hub-gate-2", "keys": [{"id": "hub-gate-2", "pub": pub, "not_after": "2099-12-31"}]}


@pytest.fixture(scope="session")
def owner(keys):
    priv, pub = keys.make("owner")
    return {"priv": priv, "pub": pub}


@pytest.fixture
def gate_keys(gate):
    return protocol.parse_gate_keys(gate["keys"])


NOW = datetime(2026, 10, 31, 13, 40, 10, tzinfo=timezone.utc)


def lease_payload(node="g2", seq=1, now=NOW, valid=60, stop=False, projects=(), quarantine=False):
    return {"typ": "lease", "v": 1, "node": node, "seq": seq, "issued_at": protocol.fmt_ts(now), "valid_until": protocol.fmt_ts(now + timedelta(seconds=valid)),
            "stop": stop, "stopped_projects": sorted(projects), "quarantine": quarantine}


def job_payload(node="g2", op="inv.host", tier=0, now=NOW, ttl=120, job_id=None, delivery_seq=1, **kw):
    p = {"typ": "job", "v": 1, "job_id": job_id or str(uuid.uuid4()), "delivery_seq": delivery_seq, "node": node, "tier": tier, "op": op, "params": {}, "dry_run": False,
         "plan_hash": None, "requester": {"identity": "meta", "planner_call_id": None, "run_id": None, "project": None},
         "issued_at": protocol.fmt_ts(now), "expires_at": protocol.fmt_ts(now + timedelta(seconds=ttl)), "owner_sig": None}
    p.update(kw)
    return p


# ------------------------------------------------------------------------------------------------------------------------- database
def _conninfo(dbname: str) -> str:
    parts = [p for p in TEST_DSN.split() if not p.startswith("dbname=")]
    return " ".join(parts + [f"dbname={dbname}"])


@pytest.fixture(scope="session")
def template_db():
    if not TEST_DSN:
        pytest.skip("no database")
    import psycopg

    from forge_node.hub.migrate import migrate

    name = "fn_tpl_" + uuid.uuid4().hex[:8]
    admin = _conninfo("postgres")
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='forge_nodehub') THEN CREATE ROLE forge_nodehub LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; END IF; END $$")
        c.execute(f'CREATE DATABASE "{name}"')
    applied = migrate(_conninfo(name))
    assert applied == ["0001_node_schema"]
    yield name
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


@pytest.fixture
def dsn(template_db):
    """Frische, migrierte Datenbank je Test (Template-Kopie)."""
    import psycopg

    name = "fn_t_" + uuid.uuid4().hex[:8]
    admin = _conninfo("postgres")
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{name}" TEMPLATE "{template_db}"')
    yield _conninfo(name)
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


@pytest.fixture
def adm(dsn):
    """Admin-/Eigentuemer-Verbindung (autocommit) auf die Test-DB."""
    import psycopg
    from psycopg.rows import dict_row

    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as c:
        yield c


@pytest.fixture
def hubdb(dsn):
    """Hub-Zugang: SET ROLE forge_nodehub (so wie die Produktion mit eingeschraenkten Rechten laeuft)."""
    from forge_node.hub.db import DirectDb

    return DirectDb(dsn, role="forge_nodehub")


@pytest.fixture
def ownerdb(dsn):
    from forge_node.hub.db import DirectDb

    return DirectDb(dsn)


def add_node(adm, node="g2", profile="full", status="active", cert="a" * 64):
    adm.execute("INSERT INTO node.nodes (node_id, profile, status, cert_sha256) VALUES (%s, %s, %s, %s)", (node, profile, status, cert))


# -------------------------------------------------------------------------------------------------------------------------- test PKI
class Pki:
    def __init__(self, base: Path):
        self.base = base
        self.ca_key, self.ca_crt = base / "ca.key", base / "ca.crt"
        self._run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(self.ca_key))
        cnf = base / "ca.cnf"
        cnf.write_text("[req]\ndistinguished_name=dn\nx509_extensions=v3_ca\nprompt=no\n[dn]\nCN=forge-node-test-ca\n[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n")
        self._run("openssl", "req", "-new", "-x509", "-key", str(self.ca_key), "-sha256", "-days", "30", "-config", str(cnf), "-out", str(self.ca_crt))

    def _run(self, *a, **kw):
        return subprocess.run(a, check=True, capture_output=True, **kw)

    def issue(self, name: str, cn: str, san: str, eku: str, ca=None):
        ca_key, ca_crt = (ca.ca_key, ca.ca_crt) if ca else (self.ca_key, self.ca_crt)
        key, csr, crt, ext = (self.base / f"{name}.{x}" for x in ("key", "csr", "crt", "ext"))
        self._run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key))
        self._run("openssl", "req", "-new", "-key", str(key), "-subj", f"/CN={cn}", "-out", str(csr))
        ext.write_text(f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={eku}\nsubjectAltName={san}\n")
        self._run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial", "-days", "30", "-sha256", "-extfile", str(ext), "-out", str(crt))
        os.chmod(key, 0o600)
        return key, crt

    def sha256_der(self, crt: Path) -> str:
        der = subprocess.run(["openssl", "x509", "-in", str(crt), "-outform", "der"], check=True, capture_output=True).stdout
        import hashlib

        return hashlib.sha256(der).hexdigest()


@pytest.fixture(scope="session")
def pki(tmp_path_factory):
    if not HAVE_OPENSSL:
        pytest.skip("openssl not available")
    return Pki(tmp_path_factory.mktemp("pki"))


@pytest.fixture(scope="session")
def other_pki(tmp_path_factory):
    if not HAVE_OPENSSL:
        pytest.skip("openssl not available")
    return Pki(tmp_path_factory.mktemp("pki2"))


# ------------------------------------------------------------------------------------------------------------------------------- hub
class FakeClock:
    def __init__(self, now=NOW):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now = self.now + timedelta(seconds=seconds)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def hubcfg(tmp_path, gate):
    from forge_node.hub.config import HubConfig

    control = tmp_path / "control"
    control.mkdir()
    (tmp_path / "policy").mkdir()
    (tmp_path / "release").mkdir()
    return HubConfig(db_dsn="unused", db_password_file=None, listen_host="127.0.0.1", listen_port=0, tls_cert=tmp_path / "c", tls_key=tmp_path / "k", tls_ca=tmp_path / "ca",
                     gate_key=gate["priv"], gate_key_id=gate["id"], control_dir=control, policy_dir=tmp_path / "policy", release_dir=tmp_path / "release", lock_timeout_s=2.0)


@pytest.fixture
def hub(hubcfg, hubdb, gate, clock, adm):
    from forge_node.hub.core import Hub, Signer

    add_node(adm, "g2", "full", cert="a" * 64)
    add_node(adm, "g1", "t0", cert="b" * 64)
    return Hub(hubcfg, hubdb, Signer(gate["priv"], gate["id"]), clock=clock, sleep=lambda s: clock.advance(s))


@pytest.fixture
def open_gates():
    """NUR fuer Tests: alle Gates erfuellt - so laufen spaeter (N3+) die Pipeline-Pfade oberhalb T0; die Produktion benutzt gates.GATES (test_gates.py)."""
    from dataclasses import replace

    from forge_node import gates

    return {k: replace(v, met=True) for k, v in gates.GATES.items()}


# ---------------------------------------------------------------------------------------------------------------------------- hypothesis
try:
    from hypothesis import settings as _hs

    _hs.register_profile("forge-node", database=None, print_blob=True)
    _hs.load_profile("forge-node")
except ImportError:      # property tests are skipped by importorskip in their modules if hypothesis is missing
    pass
