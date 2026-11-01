"""A complete privd on a real directory tree for the tests: root-owned layout as the install creates it, real audit logs (ext4, chattr +a), real ledger, LocalProcessBackend (real
worker processes), signed policy/lease/job envelopes. (Not a test module.)"""
import base64
import json
import os
import shutil
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from audit_helpers import AGENT_GID, AGENT_UID, make_specs

from forge_node import canon, gates, protocol, sshsig
from forge_node.audit.log import AuditAdmin
from forge_node.gates import GATES, Gate
from forge_node.privd import optable as optable_mod
from forge_node.privd.core import Context, Paths, Peer, Request
from forge_node.privd.gate import gate
from forge_node.privd.lease import LeaseStore
from forge_node.privd.ledger import Ledger
from forge_node.privd.policy_store import PolicyStore
from forge_node.privd.units import LocalProcessBackend
from forge_node.t0.policy import OWNER_PRINCIPAL

NODE = "g2"
SRC = str(Path(__file__).resolve().parents[1] / "src")
NOW = datetime(2026, 10, 31, 13, 40, 10, tzinfo=timezone.utc)       # Saturday 14:40 Berlin


def gates_with(*met) -> dict:
    """The production gate table with the given gates switched on. TEST ONLY: production code builds Context with gates.GATES."""
    return {k: (Gate(g.id, g.title, g.slice, True, g.acceptance, g.required_tests) if k in met else g) for k, g in GATES.items()}


class Clock:
    def __init__(self, t=NOW):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += timedelta(**kw)


def policy_doc(serial=1, node=NODE, profile="full", mode="enforce", tiers=(0, 1), t1_ops=None, t2_ops=None, gate_keys=None, **over):
    d = {"schema": 1, "serial": serial, "not_before": "2026-10-31T00:00:00Z", "node": node, "profile": profile, "global_mode": mode, "tiers_enabled": list(tiers),
         "hub_tls_pins": ["ab" * 32], "hub_gate_keys": gate_keys,
         "protected": {"paths": ["/opt/kmu-ai"], "units": ["kmu-*"]},
         "t0": {"units_for_logs": ["forge-postbote.service"]}, "t1": {"workloads_enabled": False, "ops": t1_ops if t1_ops is not None else []},
         "t2": {"ops": t2_ops or []}, "t3": {"manifests_enabled": [], "opaque_enabled": False}, "windows": {"blackout": "02:00-05:45", "sunday_open": "06:00"}}
    d.update(over)
    return d


class PrivdEnv:
    def __init__(self, base: str, keys, *, gate_set=None, backend_cls=LocalProcessBackend, worker_script: str | None = None, clock=None, attach: bool = False):
        """attach=True: open an EXISTING installation (a second privd process / a restarted privd) - nothing is created or initialised."""
        self.base = base
        self.keys = keys
        self.owner, self.gate_key = (keys["owner"], keys["gate"]) if keys else (None, None)
        self.clock = clock or Clock()
        self.gates = gate_set if gate_set is not None else gates_with("D")
        etc, state, run = f"{base}/etc/forge-node", f"{base}/var/lib/forge-node-priv", f"{base}/run/forge-node"
        for d, mode in (() if attach else ((f"{base}/etc", 0o755), (etc, 0o755), (f"{etc}/policy", 0o755), (f"{base}/var", 0o755), (f"{base}/var/lib", 0o755), (state, 0o700), (f"{state}/locks", 0o700),
                        (f"{state}/work", 0o700), (f"{base}/run", 0o755), (run, 0o755))):
            os.makedirs(d, exist_ok=True)
            os.chown(d, 0, 0)
            os.chmod(d, mode)
        self.paths = Paths(state, run, f"{etc}/policy", f"{etc}/allowed_signers", f"{etc}/LOCAL_STOP")
        if not attach:
            signers = sshsig.allowed_signers_text([(OWNER_PRINCIPAL, self.owner["pub"], sshsig.NS_POLICY), (OWNER_PRINCIPAL, self.owner["pub"], sshsig.NS_APPROVAL)])
            Path(self.paths.allowed_signers).write_text(signers)
            os.chmod(self.paths.allowed_signers, 0o644)
        specs = make_specs(f"{base}/logs") if not attach else make_specs(f"{base}/logs")
        self.specs = specs
        self.priv_log = AuditAdmin(specs["priv"], NODE, self.clock)
        self.agent_log = AuditAdmin(specs["agent"], NODE, self.clock)
        if not attach:
            self.priv_log.init()
            self.agent_log.init()
        self.ledger = Ledger(self.paths.ledger)
        self.backend = backend_cls(f"{base}/units")
        os.environ["PYTHONPATH"] = SRC + (os.pathsep + os.environ["PYTHONPATH"] if os.environ.get("PYTHONPATH") else "")
        os.environ.update({"FN_TEST_SRC": SRC, "FN_TEST_POLICY_DIR": self.paths.policy_dir, "FN_TEST_SIGNERS": self.paths.allowed_signers, "FN_TEST_SSH_KEYGEN": shutil.which("ssh-keygen"),
                           "FORGE_NODE_NODE_ID": NODE})
        self.worker_script = worker_script
        self.table = optable_mod.build_optable()
        self.ssh_keygen = shutil.which("ssh-keygen")
        self.ctx = self.make_context()

    def restart(self, **kw) -> "PrivdEnv":
        """A new privd instance on the same installation (own connections, own clock starting where this one is)."""
        return attach(self.base, keys=self.keys, clock=kw.pop("clock", None) or Clock(self.clock()), gate_set=self.gates, **kw)

    # ------------------------------------------------------------------------------------------------------------------------------ context
    def argv_for(self, role: str, name: str, wd: str | None) -> list:
        py = sys.executable
        if role == "op":
            return [py, self.worker_script, "run", wd] if self.worker_script else [py, "-m", "forge_node.privd.opworker", "run", wd]
        if role == "op-selfcheck":
            return [py, "-m", "forge_node.privd.opworker", "selfcheck", wd]
        shim = str(Path(__file__).with_name("privd_probe_shim.py"))
        return [py, shim, name] if role == "probe" else [py, shim, "--selfcheck", name]

    def make_context(self, **over) -> Context:
        policies = PolicyStore(policy_dir=self.paths.policy_dir, allowed_signers=self.paths.allowed_signers, serial_file=self.paths.serial_file, node=NODE, owner_uid=0,
                               ssh_keygen=self.ssh_keygen, clock=self.clock, gates_map=self.gates, table_ops=lambda prof: self.table.names(prof), devof=self.devof, protected_devs=lambda: set())
        leases = LeaseStore(path=self.paths.lease_file, ledger=self.ledger, node=NODE, ssh_keygen=self.ssh_keygen, clock=self.clock, owner_uid=0)
        kw = dict(node=NODE, paths=self.paths, clock=self.clock, ledger=self.ledger, priv_log=self.priv_log, agent_log=self.agent_log, backend=self.backend, optable=self.table, gates=self.gates,
                  ssh_keygen=self.ssh_keygen, owner_uid=0, agent_uid=AGENT_UID, policies=policies, leases=leases, argv_for=self.argv_for, version="0.0-test", sleep=lambda s: __import__("time").sleep(s),
                  monotonic=__import__("time").monotonic)
        kw.update(over)
        return Context(**kw)

    @staticmethod
    def devof(path: str):
        try:
            return os.stat(path).st_dev
        except OSError:
            return None

    # ----------------------------------------------------------------------------------------------------------------------------- policy
    def gate_keys(self):
        return [{"id": "hub-gate-1", "pub": self.gate_key["pub"], "not_after": "2099-12-31"}]

    def doc(self, **kw):
        kw.setdefault("gate_keys", self.gate_keys())
        return policy_doc(**kw)

    def sign(self, doc_or_raw, ns=sshsig.NS_POLICY):
        raw = doc_or_raw if isinstance(doc_or_raw, bytes) else json.dumps(doc_or_raw, sort_keys=True, separators=(",", ":")).encode()
        return raw, sshsig.sign(raw, self.owner["priv"], ns)

    def install(self, doc=None, **kw):
        """Install a policy the way `privctl policy-apply` does: through the policy.apply request."""
        raw, sig = self.sign(doc or self.doc(**kw))
        return self.call("policy.apply", {"policy_b64": base64.b64encode(raw).decode(), "sig": sig})

    # ------------------------------------------------------------------------------------------------------------------------ lease / job
    def lease_env(self, seq=1, **kw):
        return protocol.seal(lease_payload(self.clock(), seq, **kw), self.gate_key["priv"], "hub-gate-1")

    def put_lease(self, seq=1, **kw):
        return self.call("lease.put", {"lease": self.lease_env(seq, **kw)})

    def job_env(self, op="selftest.noop", tier=1, params=None, dry_run=False, plan_hash=None, job_id=None, owner_sig=None, delivery_seq=1, ttl=120, node=NODE, project=None, key=None):
        p = {"typ": "job", "v": 1, "job_id": job_id or str(uuid.uuid4()), "delivery_seq": delivery_seq, "node": node, "tier": tier, "op": op, "params": params or {}, "dry_run": dry_run,
             "plan_hash": plan_hash, "requester": {"identity": "meta", "planner_call_id": None, "run_id": None, "project": project}, "issued_at": protocol.fmt_ts(self.clock()),
             "expires_at": protocol.fmt_ts(self.clock() + timedelta(seconds=ttl)), "owner_sig": owner_sig}
        return protocol.seal(p, (key or self.gate_key)["priv"], "hub-gate-1"), p

    def ready(self, **policy_kw):
        """A policy that enables tier 1 / selftest.noop, plus a fresh lease."""
        kw = {"t1_ops": [{"op": "selftest.noop", "mode": "enforce"}], **policy_kw}
        r = self.install(**kw)
        assert r["ok"], r
        r = self.put_lease()
        assert r["ok"], r
        return self

    def exec(self, **kw):
        env, payload = self.job_env(**kw)
        return self.call("exec", {"job": env}), payload

    def call(self, kind, body, uid=0, gid=0, pid=1) -> dict:
        return gate(self.ctx, Request(kind, Peer(pid, uid, gid), body))

    # ------------------------------------------------------------------------------------------------------------------------------ audit
    def priv_records(self):
        out = []
        spec = self.specs["priv"]
        for g in sorted(os.listdir(spec.dir)):
            p = os.path.join(spec.dir, g)
            if os.path.isdir(p):
                for f in sorted(os.listdir(p)):
                    for line in open(os.path.join(p, f), "rb").read().split(b"\n"):
                        if line:
                            try:
                                out.append(json.loads(line))
                            except ValueError:
                                pass
        return out

    def types(self, job_id=None):
        return [r["type"] for r in self.priv_records() if job_id is None or r.get("job_id") == job_id]


def lease_payload(now, seq=1, valid=60, stop=False, projects=(), quarantine=False, node=NODE):
    return {"typ": "lease", "v": 1, "node": node, "seq": seq, "issued_at": protocol.fmt_ts(now), "valid_until": protocol.fmt_ts(now + timedelta(seconds=valid)), "stop": stop,
            "stopped_projects": sorted(projects), "quarantine": quarantine}


def attach(base: str, *, keys=None, clock=None, worker_script=None, gate_set=None) -> PrivdEnv:
    return PrivdEnv(base, keys, attach=True, clock=clock, worker_script=worker_script, gate_set=gate_set if gate_set is not None else gates_with("D"))
