"""Agent runtime (Design 3.2, 3.4): poll the hub, verify what comes back, run T0 jobs through the engine, post results.

What the agent trusts: only the policy installed on the node (signature re-verified here) and, through its gate keys, hub-signed leases and jobs. A response whose lease does not verify is
discarded whole. A job is verified (signature, node, expiry) before anything runs; anything above tier 0 is answered `DENY_TIER_DISABLED` - slice N2 has no privileged execution path
(the agent never executes a mutating op; that is privd's gate() from N3 on, behind gate D). Nothing in this module can open a gate, loosen a limit or skip the engine."""
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime

from .. import PROTOCOL_VERSION, __version__, protocol
from ..protocol import ProtoError
from ..redact import redact_light
from ..t0.engine import Outcome, T0Engine
from ..t0.policy import PolicyError, PolicyView, load_installed, read_signers, verify_blob
from .client import HubClient, HubError, HubUnreachable, PinError

WAIT_S = 25
POLICY_FETCH_RETRY_S = 600
MAX_PENDING_RESULTS = 8
PENDING_TTL_S = 300


@dataclass
class Runtime:
    """Everything derived from one policy serial. Replaced as a whole when the installed policy changes."""
    policy: PolicyView
    client: HubClient
    engine: T0Engine


class PolicyHolder:
    """Re-reads the installed policy when its directory listing or the file's identity changes; any failure to verify means NO policy (fail closed, never an older file)."""

    def __init__(self, cfg, clock, log, ssh_keygen):
        self.cfg, self.clock, self.log, self.ssh_keygen = cfg, clock, log, ssh_keygen
        self._sig = None
        self._last_err = None
        self.view: PolicyView | None = None

    def _signature(self):
        """Identity of everything the decision rests on: the policy files AND the owner key file (a rotated or revoked owner key must be noticed without a policy change)."""
        try:
            names = sorted(n for n in os.listdir(self.cfg.policy_dir) if n.startswith("policy-"))
            st = [os.stat(os.path.join(self.cfg.policy_dir, n), follow_symlinks=False) for n in names]
            files = tuple((n, s.st_ino, s.st_mtime_ns, s.st_size) for n, s in zip(names, st))
        except OSError:
            return None
        try:
            a = os.stat(self.cfg.allowed_signers, follow_symlinks=False)
            return files + (("allowed_signers", a.st_ino, a.st_mtime_ns, a.st_size),)
        except OSError:
            return files + (("allowed_signers", None),)

    def refresh(self) -> tuple[PolicyView | None, bool]:
        """(view, changed)"""
        sig = self._signature()
        if sig == self._sig and (self.view is not None or sig is None):
            return self.view, False
        self._sig = sig
        try:
            view = load_installed(self.cfg.policy_dir, self.cfg.allowed_signers, self.cfg.node_id, self.clock(), owner_uid=self.cfg.owner_uid, ssh_keygen=self.ssh_keygen)
        except Exception as e:  # noqa: BLE001 - ANY failure to establish the policy means no policy: never keep serving the previous one
            detail = e.detail if isinstance(e, PolicyError) else f"unexpected {type(e).__name__}"
            if detail != self._last_err and (self.view is not None or sig is not None):
                self.log(f"policy: no usable policy ({detail})")
            self._last_err = detail
            self.view = None
            return None, True
        self._last_err = None
        changed = self.view is None or view.sha256 != self.view.sha256
        self.view = view
        if changed:
            self.log(f"policy: serial {view.serial} installed and verified")
        return view, changed


class Agent:
    def __init__(self, cfg, holder: PolicyHolder, build_runtime, spool, sampler_factory, clock, ssh_keygen, sleep=time.sleep, log=None, rng=None):
        self.cfg, self.holder, self.build_runtime, self.spool, self.sampler_factory = cfg, holder, build_runtime, spool, sampler_factory
        self.clock, self.sleep, self.ssh_keygen = clock, sleep, ssh_keygen
        self.log = log or (lambda m: None)
        self.rng = rng or (lambda: 0.5)
        self.rt: Runtime | None = None
        self.sampler = None
        self._last_lease_seq = 0
        self._pending: list[tuple[str, dict, float]] = []
        self._fetched: dict[int, float] = {}
        self._fail = 0
        self._stop = threading.Event()

    # ------------------------------------------------------------------------------------------------------------------ runtime
    def _runtime(self) -> Runtime | None:
        view, changed = self.holder.refresh()
        if view is None:
            if self.rt is not None:
                self.rt.client.close()
            self.rt = self.sampler = None
            return None
        if changed or self.rt is None:
            if self.rt is not None:
                self.rt.client.close()
            self.rt = self.build_runtime(view)
            self.sampler = self.sampler_factory(self.rt)
            self._last_lease_seq = 0
        return self.rt

    def sample_tick(self):
        if self.sampler is not None:
            self.sampler.tick()

    # ---------------------------------------------------------------------------------------------------------------- one cycle
    def poll_once(self, wait_s: int = WAIT_S) -> str:
        """Returns a short status word (for tests/logs): 'idle', 'no_policy', 'unreachable', 'bad_response', 'job'."""
        rt = self._runtime()
        if rt is None:
            return "no_policy"
        now = self.clock()
        body = {"v": PROTOCOL_VERSION, "version": __version__, "policy": {"serial": rt.policy.serial, "sha256": rt.policy.sha256}, "clock": protocol.fmt_ts(now),
                "spool_depth": self.spool.depth(), "audit_heads": {}, "open_jobs": [], "wait_s": wait_s}
        try:
            resp = rt.client.poll(body)
            self._fail = 0
        except PinError:
            self.log("hub: certificate is not pinned in the policy - refusing")
            self._fail += 1
            return "unreachable"
        except (HubUnreachable, HubError) as e:
            self.log(f"hub: {e}")
            self._fail += 1
            return "unreachable"
        status = self._handle(rt, resp)
        self._flush_pending(rt)
        return status

    def _handle(self, rt: Runtime, resp: dict) -> str:
        now = self.clock()
        try:
            if set(resp) != {"v", "lease", "jobs", "reconcile", "policy_serial_latest", "server_time"} or resp["v"] != PROTOCOL_VERSION or not isinstance(resp["jobs"], list) or len(resp["jobs"]) > 1:
                raise ProtoError("BAD_REQUEST", "poll response shape")
            lease = protocol.verify_lease(resp["lease"], rt.policy.hub_gate_keys, self.cfg.node_id, now, self._last_lease_seq, self.ssh_keygen)
            self._last_lease_seq = lease["seq"]
        except ProtoError as e:
            self.log(f"hub response discarded: {e.code} {e.detail[:80]}")
            return "bad_response"
        if resp["reconcile"]:
            self.log(f"hub asked to reconcile {len(resp['reconcile'])} job(s): this release has no ledger (N3)")
        latest = resp["policy_serial_latest"]
        if isinstance(latest, int) and not isinstance(latest, bool) and latest > rt.policy.serial:
            self._maybe_stage_policy(rt, latest)
        status = "idle"
        for env in resp["jobs"]:
            status = "job"
            self._run_job(rt, env)
        return status

    # ------------------------------------------------------------------------------------------------------------------- jobs
    def _run_job(self, rt: Runtime, env: dict):
        now = self.clock()
        try:
            job = protocol.verify_job(env, rt.policy.hub_gate_keys, self.cfg.node_id, now, self.ssh_keygen)
        except ProtoError as e:
            self.log(f"job rejected: {e.code} {e.detail[:80]}")           # unverifiable: nothing is posted for an id we cannot trust
            return
        if job["tier"] != 0:
            outcome = Outcome("denied", "DENY_TIER_DISABLED", "this release executes tier 0 only")
        else:
            try:
                outcome = rt.engine.execute(job["op"], job["tier"], job["params"])
            except Exception as e:  # noqa: BLE001 - the engine reports its own failures as outcomes; this is the last line of defence for the loop
                self.log(f"engine: unexpected {type(e).__name__}")
                outcome = Outcome("failed", "FAIL_EXEC", type(e).__name__)
        status = outcome.status if outcome.status != "committed" or not job["dry_run"] else "dry_run"
        text = outcome.output if outcome.status == "committed" else redact_light(outcome.output)[:512]
        result = {"attempt": min(job["delivery_seq"], 1000), "status": status, "reason_code": outcome.reason_code, "output": text, "audit_seq_range": None, "plan_hash": None}
        try:
            protocol.validate_result(result)
        except ProtoError as e:
            self.log(f"internal: result for {job['job_id']} invalid ({e.detail})")
            result = {**result, "status": "failed", "reason_code": "FAIL_EXEC", "output": "result could not be encoded"}
        self._post(rt, job["job_id"], result)

    def _post(self, rt: Runtime, job_id: str, result: dict):
        try:
            rt.client.post_result(job_id, result)
        except (HubUnreachable, HubError) as e:
            self.log(f"result for {job_id} not delivered: {e}")
            if len(self._pending) < MAX_PENDING_RESULTS:
                self._pending.append((job_id, result, time.monotonic() + PENDING_TTL_S))

    def _flush_pending(self, rt: Runtime):
        keep = []
        for job_id, result, until in self._pending:
            if time.monotonic() > until:
                continue
            try:
                rt.client.post_result(job_id, result)
            except HubError:
                continue                       # the hub refused it (unknown/terminal job): retrying cannot help
            except HubUnreachable:
                keep.append((job_id, result, until))
        self._pending = keep

    # ----------------------------------------------------------------------------------------------------------------- policy
    def _maybe_stage_policy(self, rt: Runtime, serial: int):
        """Fetch a newer signed policy and keep it, verified, in the agent's staging directory. Installing it is privd's job (N3, `policy.apply`); until then the installed policy stays in force."""
        t = time.monotonic()
        if t - self._fetched.get(serial, -POLICY_FETCH_RETRY_S) < POLICY_FETCH_RETRY_S:
            return
        self._fetched[serial] = t
        while len(self._fetched) > 32:                          # the serial comes from an unsigned field of the hub's answer: do not let it grow state without bound
            self._fetched.pop(next(iter(self._fetched)))
        try:
            doc = rt.client.get_policy(serial)
            if set(doc) != {"serial", "policy", "sig"} or doc["serial"] != serial:
                raise ProtoError("BAD_REQUEST", "policy answer shape")
            if not isinstance(doc["policy"], str) or not isinstance(doc["sig"], str):
                raise ProtoError("BAD_REQUEST", "policy answer types")
            signers = read_signers(self.cfg.allowed_signers, self.cfg.owner_uid)
            verify_blob(doc["policy"].encode("utf-8"), doc["sig"], signers, self.cfg.node_id, serial, self.clock(), self.ssh_keygen)
            self._write_staged(serial, doc)
        except Exception as e:  # noqa: BLE001 - staging is best effort; whatever goes wrong must not abort the handling of this response (its jobs)
            self.log(f"policy {serial} not staged: {type(e).__name__}")
            return
        self.log(f"policy {serial}: signature verified, staged for privd/privctl (not active)")

    def _write_staged(self, serial: int, doc: dict):
        d = os.path.join(self.cfg.state_dir, "staging")
        os.makedirs(d, mode=0o700, exist_ok=True)
        for name, content in ((f"policy-{serial}.json", doc["policy"]), (f"policy-{serial}.json.sig", doc["sig"])):
            tmp = os.path.join(d, "." + name + ".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(content)
            os.replace(tmp, os.path.join(d, name))

    # ------------------------------------------------------------------------------------------------------------------- loop
    def stop(self):
        self._stop.set()

    def run(self):
        sampler_thread = threading.Thread(target=self._sample_loop, name="sampler", daemon=True)
        sampler_thread.start()
        self._poll_loop()
        sampler_thread.join(timeout=5)

    def _poll_loop(self):
        while not self._stop.is_set():
            try:
                st = self.poll_once()
            except Exception as e:  # noqa: BLE001 - one bad cycle must not end the agent; back off like for an unreachable hub
                self.log(f"poll cycle failed: {type(e).__name__}")
                self._fail += 1
                st = "unreachable"
            if st in ("unreachable", "no_policy", "bad_response"):
                delay = min(60.0, 2.0 ** min(self._fail, 6)) if st != "no_policy" else 30.0
                self._stop.wait(delay * (0.5 + self.rng()))

    def _sample_loop(self):
        while not self._stop.is_set():
            try:
                self.sample_tick()
            except Exception as e:  # noqa: BLE001 - sampling must never kill the agent
                self.log(f"sampler: {type(e).__name__}")
            self._stop.wait(5)
