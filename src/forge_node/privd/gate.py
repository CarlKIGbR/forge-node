"""gate(): THE guarded path of privd (Design 3.3, G27). Every request that reaches privd - from the agent, from root, from a test - is answered by this one function, which runs the
pipeline of its kind in a fixed order. The first failing step ends it; each denial is audited (and recorded in the ledger once the job is claimed); nothing later runs. The agent's own
pre-checks are advisory, everything here is re-done from root-protected state.

EXEC pipeline (the design's 20 steps; deviations are marked):
   1 caller uid (root or the agent user)           11 allowlist (policy targets)
   2 job signature, node, expiry (hub gate keys    12 window (Berlin blackout; mutating ops)
     of the policy)                                13 rate buckets + circuit (ledger tables)
   2b ledger claim (atomic; replay/in_progress)    14 owner signature when the policy says so
   3 lease: valid, stop=false, project, quarantine 15 plan: stored plan must exist (the worker re-computes it under the effect lock)
   4 LOCAL_STOP file                               16 target lock + one mutating op per node / per effect key
   5 clock skew vs lease.issued_at <= 60 s         17 ledger `started` (worker unit, dir, fence) BEFORE the unit starts
   5b op in the op table and gates.decide()  [moved ahead of 6: it needs no state]
   6 audit writable + intent fsynced (mutating)    18 effect in the op's transient unit      19 post-check      20 ledger + result audit
   7 policy valid, tier enabled, op enabled        T0 / selfcheck / status / lease.put / reconcile / policy.apply / audit.rotate / lockdown have reduced pipelines (below).
   8 global_mode / op mode / circuit (-> dry run)
   9 parameter schema   10 protected set

No request kind has a code path that skips a step of its pipeline: the pipelines are tuples of step functions, `gate` has no flag, no optional argument, no environment switch."""
import base64
import binascii
import hashlib
import os
import shutil
from dataclasses import dataclass, field

from .. import canon, gates, protocol, redact, sshsig
from ..audit.spec import AuditCorrupt, AuditDown
from ..protocol import ProtoError
from ..t0 import hardening
from ..t0.policy import OWNER_PRINCIPAL, PolicyError
from . import classes, reconcile as rec
from .core import KINDS, Context, Deny, FileLock, Request, job_lock_path, result_doc, work_dir_path
from .ledger import STATE_SCHEMA, Row
from .units import UnitError, op_unit_name

CLOCK_SANITY_S = 60
LIGHT_PROBE_RATE = ((3, 60),)
HEAVY_PROBE_RATE = ((1, 600),)
HEAVY_PROBES = frozenset({"git", "models"})
NODE_MUTATING_RATE = ((6, 60), (60, 3600))
SELFCHECK_RATE = ((12, 60),)
DENIAL_RECORDS_PER_MIN = 60
LEASE_RECORD_EVERY_S = 600


class Done(Exception):
    """A step produced the final reply without a denial (duplicate delivery -> in_progress, replay of a stored result)."""

    def __init__(self, reply: dict):
        super().__init__("done")
        self.reply = reply


@dataclass
class State:
    ctx: Context
    req: Request
    policy: object = None
    job: dict | None = None
    entry: object = None
    params: dict | None = None
    row: Row | None = None
    lease: dict | None = None
    lock: FileLock | None = None
    intent_seq: int | None = None
    first_seq: int | None = None
    dry_run: bool = False
    forced_dry_run: bool = False
    op_policy: object = None
    work_dir: str | None = None
    reply: dict | None = None
    extra: dict = field(default_factory=dict)

    @property
    def claimed_id(self):
        j = self.job
        return j["job_id"] if j else None


# ============================================================================================================================ helpers
def _policy(st: State):
    if st.policy is None:
        try:
            st.policy = st.ctx.policies.current()
        except PolicyError as e:
            raise Deny("DENY_POLICY_INVALID", e.detail) from e
    return st.policy


def _gate_keys(st: State) -> dict:
    return _policy(st).view.hub_gate_keys


def _sha(o) -> str:
    return canon.digest(o)


def _rate(st: State, bucket: str, limits, code: str = "DENY_RATE") -> None:
    if not st.ctx.ledger.rate_take(bucket, list(limits), st.ctx.now().timestamp(), st.claimed_id):
        raise Deny(code, f"rate limit {bucket}")


def _local_stop_active(ctx: Context) -> bool:
    try:
        os.lstat(ctx.paths.local_stop)
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return True                                                           # unreadable => active (fail closed)


# =============================================================================================================================== steps
def s_caller(st: State) -> None:
    if st.req.peer.uid not in (st.ctx.owner_uid, st.ctx.agent_uid):
        raise Deny("DENY_JOB_SIGNATURE", "caller is neither root nor the agent user")


def s_caller_root(st: State) -> None:
    if st.req.peer.uid != st.ctx.owner_uid:
        raise Deny("DENY_JOB_SIGNATURE", "this request is for root only")


def s_job_signature(st: State) -> None:
    env = st.req.body.get("job")
    try:
        st.job = protocol.verify_job(env, _gate_keys(st), st.ctx.node, st.ctx.now(), st.ctx.ssh_keygen)
    except ProtoError as e:
        raise Deny(e.code if e.code in protocol.REASON_CODES else "DENY_JOB_SIGNATURE", e.detail) from e


def s_claim(st: State) -> None:
    """Pipeline 2b. The per-job lock serializes duplicate deliveries, reconcile and retry claims; the ledger claim is atomic."""
    ctx, j = st.ctx, st.job
    if j["tier"] == 0:
        raise Deny("DENY_PARAM", "tier 0 jobs are executed by the agent, not through exec")
    entry = ctx.optable.get(j["op"])
    try:
        eff = entry.effect_key(entry.params(j["params"])) if entry is not None else f"unclaimed:{j['op']}"
    except ProtoError:
        eff = f"invalid:{j['op']}"
    try:
        st.lock = FileLock(job_lock_path(ctx.paths, j["job_id"]), blocking=False)
        st.lock.__enter__()
    except BlockingIOError:
        raise Done({"ok": True, "in_progress": True, "job_id": j["job_id"]})
    c = ctx.ledger.claim(j["job_id"], j["delivery_seq"], j["op"], eff, _sha(j["params"]), j["dry_run"], j["requester"]["identity"], ctx.now())
    st.row = c.row
    if c.kind == "in_progress" and c.row.state == "received":
        st.row = c.row                                                       # a handler that died before `started`: we hold the job lock, so nobody is working on it
    elif c.kind == "in_progress":
        raise Done({"ok": True, "in_progress": True, "job_id": j["job_id"]})
    elif c.kind == "replay":
        raise Done({"ok": True, "result": {"job_id": j["job_id"], **c.row.result}} if c.row.result else {"ok": True, "in_progress": True, "job_id": j["job_id"]})
    elif c.kind == "conflict":
        st.row = None
        raise Deny("DENY_PARAM", "this job_id was already used for a different request")
    st.entry = entry
    st.first_seq = None


def s_lease(st: State) -> None:
    ctx = st.ctx
    p = ctx.leases.current(_gate_keys(st))
    if p is None:
        raise Deny("DENY_STALE_LEASE", "no verifiable lease")
    st.lease = p
    now = ctx.now()
    if now > protocol.parse_ts(p["valid_until"]):
        raise Deny("DENY_STALE_LEASE", "lease expired")
    if p["stop"]:
        raise Deny("DENY_STOP", "global stop")
    project = (st.job or {}).get("requester", {}).get("project")
    if project is not None and project in p["stopped_projects"]:
        raise Deny("DENY_STOP", f"project {project} is stopped")
    if p["quarantine"]:
        raise Deny("DENY_QUARANTINE", "node is in quarantine")


def s_lease_authentic(st: State) -> None:
    """T0 reduced pipeline: a hub-signed lease must exist and verify under the policy's keys; its stop flag is deliberately ignored (T0 continues during STOP) and so is its age -
    but a clock that is far BEHIND the lease is not trusted."""
    p = st.ctx.leases.current(_gate_keys(st))
    if p is None:
        raise Deny("DENY_STALE_LEASE", "no verifiable lease")
    if (st.ctx.now() - protocol.parse_ts(p["issued_at"])).total_seconds() < -CLOCK_SANITY_S:
        raise Deny("DENY_CLOCK", "clock is behind the lease")
    st.lease = p


def s_local_stop(st: State) -> None:
    if _local_stop_active(st.ctx):
        raise Deny("DENY_LOCAL_STOP", "LOCAL_STOP present")


def s_clock(st: State) -> None:
    if abs((st.ctx.now() - protocol.parse_ts(st.lease["issued_at"])).total_seconds()) > protocol.CLOCK_SKEW_MAX_S:
        raise Deny("DENY_CLOCK", "clock skew against the lease")


def s_op_static(st: State) -> None:
    j, ctx = st.job, st.ctx
    profile = _policy(st).profile
    d = gates.decide(j["op"], j["tier"], profile, j["params"], ctx.gates)
    if not d.allowed:
        raise Deny(d.code, d.detail)
    entry = ctx.optable.get(j["op"])
    if entry is None or profile not in entry.profiles:
        raise Deny("DENY_OP_UNKNOWN", f"{j['op']} is not in this release's op table for profile {profile}")
    st.entry = entry


def s_audit_intent(st: State) -> None:
    """Pipeline 6: for a mutating op the intent record is written and fsynced BEFORE anything else happens; if that cannot be done the op is refused (retryable)."""
    ctx, j, row = st.ctx, st.job, st.row
    pol = _policy(st)
    try:
        ctx.priv_log.head()
    except (AuditDown, AuditCorrupt) as e:
        raise Deny("DENY_AUDIT_DOWN", f"audit not writable ({type(e).__name__})") from e
    if st.entry.mutating:
        r = ctx.audit("intent", {"job_id": j["job_id"], "attempt": row.attempt, "fence": row.fence, "requester": j["requester"], "tier": j["tier"], "op": j["op"],
                                 "params": redact.redact_obj(j["params"]), "dry_run": j["dry_run"], "policy_serial": pol.serial, "policy_sha256": pol.raw_sha256,
                                 "lease_seq": st.lease["seq"], "version": ctx.version})
        st.intent_seq = st.first_seq = r["seq"]


def s_policy(st: State) -> None:
    pol, j = _policy(st), st.job
    if j["tier"] not in pol.tiers:
        raise Deny("DENY_TIER_DISABLED", f"policy does not enable tier {j['tier']}")
    st.op_policy = pol.ops.get(j["op"])
    if st.op_policy is None:
        raise Deny("DENY_TIER_DISABLED", f"op {j['op']} is not enabled by the policy")


def s_mode(st: State) -> None:
    """Pipeline 8: observe / dry_run_only force a dry run (not a denial); an open circuit denies apply and still allows dry runs."""
    pol, j = _policy(st), st.job
    st.dry_run = j["dry_run"]
    if pol.global_mode == "observe" or st.op_policy.mode == "dry_run_only":
        st.forced_dry_run = not j["dry_run"]
        st.dry_run = True
    if not st.dry_run and st.ctx.ledger.circuit(j["op"])["state"] == "open":
        raise Deny("DENY_CIRCUIT_OPEN", f"circuit of {j['op']} is open (3 consecutive failures): dry runs only until acknowledged")


def s_params(st: State) -> None:
    try:
        st.params = st.entry.params(st.job["params"])
    except ProtoError as e:
        raise Deny("DENY_PARAM", e.detail) from e


def s_protected(st: State) -> None:
    if st.entry.protected is not None:
        try:
            st.entry.protected(_policy(st), st.params)
        except ProtoError as e:
            raise Deny("DENY_PROTECTED", e.detail) from e


def s_allowlist(st: State) -> None:
    if st.entry.allowlist is not None:
        try:
            st.entry.allowlist(st.op_policy, st.params)
        except ProtoError as e:
            raise Deny("DENY_NOT_ALLOWLISTED", e.detail) from e


def s_window(st: State) -> None:
    if st.entry.mutating and _policy(st).view.window.in_blackout(st.ctx.now()):
        raise Deny("DENY_WINDOW", "mutating op inside the blackout window")


def s_rate(st: State) -> None:
    pol = _policy(st)
    if st.entry.mutating:
        _rate(st, "node.mutating", NODE_MUTATING_RATE)
    limits = st.op_policy.rate or st.entry.default_rate
    if limits:
        _rate(st, f"op.{st.job['op']}", limits)


def owner_binding(job: dict) -> bytes:
    """What the owner signs for `requires: owner_signature`: the identity of THIS job and its request (the job payload itself contains the signature field)."""
    return canon.canonical({"typ": "owner-approval", "v": 1, "job_id": job["job_id"], "node": job["node"], "tier": job["tier"], "op": job["op"], "params": job["params"],
                            "dry_run": job["dry_run"], "plan_hash": job["plan_hash"]})


def s_owner_signature(st: State) -> None:
    if st.op_policy.requires != "owner_signature":
        return
    sig = st.job["owner_sig"]
    if not sig:
        raise Deny("DENY_NEEDS_OWNER_SIG", "the policy requires an owner signature for this op")
    try:
        from ..t0.policy import read_signers
        sshsig.verify(owner_binding(st.job), sig, sshsig.NS_APPROVAL, OWNER_PRINCIPAL, read_signers(st.ctx.paths.allowed_signers, st.ctx.owner_uid), st.ctx.ssh_keygen)
    except (sshsig.SigError, OSError) as e:
        raise Deny("DENY_NEEDS_OWNER_SIG", "owner signature does not verify") from e


def s_plan(st: State) -> None:
    """Pipeline 15. Apply of a plan-requiring op needs the approved plan on file; the plan is RE-COMPUTED by the worker under the effect lock (fresher than here) and compared there."""
    if st.dry_run or not st.entry.requires_plan:
        return
    ph = st.job["plan_hash"]
    if ph is None or st.ctx.ledger.plan_get(ph, st.ctx.now().timestamp()) is None:
        raise Deny("DENY_STALE_PLAN", "no stored, unexpired plan for this plan_hash")
    st.extra["plan_hash"] = ph


def s_target_lock(st: State) -> None:
    ctx, row = st.ctx, st.row
    if ctx.ledger.target_lock(row.effect_key) is not None:
        raise Deny("DENY_TARGET_LOCKED", "the target is locked by an indeterminate job")
    if st.entry.mutating and (ctx.ledger.busy_with_other(row.job_id) is not None or ctx.ledger.effect_busy(row.effect_key, row.job_id) is not None):
        raise Deny("DENY_TARGET_LOCKED", "another mutating op is in flight on this node/target")


def s_started(st: State) -> None:
    """Pipeline 17: unit name, work directory and fence are persisted in the ledger BEFORE the worker exists."""
    ctx, row, entry = st.ctx, st.row, st.entry
    st.work_dir = work_dir_path(ctx.paths, row.job_id, row.attempt)
    unit = op_unit_name(row.job_id, row.attempt)
    dfd = os.open(ctx.paths.work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        name = os.path.basename(st.work_dir)
        try:
            os.mkdir(name, 0o700, dir_fd=dfd)
        except FileExistsError:
            raise Deny("FAIL_PRECHECK", "work directory of this attempt already exists")
        wfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd)
        try:
            req = {"job_id": row.job_id, "attempt": row.attempt, "fence": row.fence, "op": row.op, "params": st.params, "dry_run": st.dry_run, "plan_hash": st.extra.get("plan_hash"),
                   "effect_key": row.effect_key, "ledger_path": ctx.paths.ledger, "lock_dir": ctx.paths.locks, "priv_state": ctx.paths.priv_state}
            fd = os.open("request.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=wfd)
            try:
                os.write(fd, canon.canonical(req) + b"\n")
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(wfd)
        finally:
            os.close(wfd)
        os.fsync(dfd)
    finally:
        os.close(dfd)
    st.row = ctx.ledger.mark_started(row.job_id, row.attempt, unit, st.work_dir, None, st.extra.get("plan_hash"), st.dry_run, ctx.now())


def _fresh_stop_check(st: State) -> None:
    """G28: starting the unit is irreversible, so STOP is re-observed NOW (LOCAL_STOP file, the stored lease re-read and re-verified), not carried over from steps 3/4 which ran
    before the audit intent, the policy, the rate buckets and the work directory. Same codes as the early steps."""
    ctx = st.ctx
    if _local_stop_active(ctx):
        raise Deny("DENY_LOCAL_STOP", "LOCAL_STOP appeared before the unit started")
    p = ctx.leases.current(_gate_keys(st))
    if p is None or ctx.now() > protocol.parse_ts(p["valid_until"]):
        raise Deny("DENY_STALE_LEASE", "lease no longer valid before the unit started")
    if p["stop"] or (st.job["requester"]["project"] is not None and st.job["requester"]["project"] in p["stopped_projects"]):
        raise Deny("DENY_STOP", "stop arrived before the unit started")
    if p["quarantine"]:
        raise Deny("DENY_QUARANTINE", "quarantine arrived before the unit started")


def s_effect(st: State) -> None:
    """Pipeline 18: the effect, in the op's own transient unit with a property set from the fixed table."""
    ctx, row, entry = st.ctx, st.row, st.entry
    _fresh_stop_check(st)
    props = classes.op_unit_properties(entry.unit_class, work_dir=st.work_dir, priv_state=ctx.paths.priv_state, forge_roots=tuple(r.path for r in _policy(st).forge_roots), timeout_s=entry.timeout_s)
    try:
        inv = ctx.backend.start(row.worker_unit, props, ctx.argv_for("op", entry.name, st.work_dir))
    except UnitError as e:
        raise Deny("FAIL_EXEC", f"unit did not start: {e}") from e
    ctx.ledger.set_invocation(row.job_id, row.attempt, inv, ctx.now())
    st.row = ctx.ledger.get(row.job_id)
    outcome = rec.wait_unit(ctx, st.row, entry.timeout_s + 5)
    if outcome == "timeout":
        st.reply = {"ok": True, "in_progress": True, "job_id": row.job_id}
        raise Done(st.reply)


def s_postcheck(st: State) -> None:
    """Pipeline 19: the unit has ended; its complete status.json is the evidence. Missing/torn => the interrupted path (reconciliation, still under the job lock)."""
    ctx, row = st.ctx, st.row
    ex = rec.examine(ctx, ctx.ledger.get(row.job_id))
    if ex.kind == "finished" and ex.status["outcome"] != "fenced":
        st.extra["status"] = ex.status
        return
    kind, res = rec.reconcile_locked(ctx, row.job_id)
    raise Done({"ok": True, "result": {"job_id": row.job_id, **res}} if res else {"ok": True, "in_progress": True, "job_id": row.job_id})


def s_commit(st: State) -> None:
    """Pipeline 20."""
    ctx, row = st.ctx, ctx_row(st)
    res = rec.finalize_from_status(ctx, row, st.extra["status"], seq_first=st.intent_seq)
    if st.forced_dry_run:
        res["output"] = ("forced dry run (observe / dry_run_only): " + res["output"])[:4096]
    st.reply = {"ok": True, "result": {"job_id": row.job_id, **res}}


def ctx_row(st: State) -> Row:
    return st.ctx.ledger.get(st.row.job_id)


# ----------------------------------------------------------------------------------------------------------------- T0 root probes
def s_t0_probe_known(st: State) -> None:
    b = st.req.body
    if set(b) != {"probe", "params"} or not isinstance(b["probe"], str) or not isinstance(b["params"], dict):
        raise Deny("DENY_PARAM", "t0 request needs exactly {probe, params}")
    if b["probe"] not in hardening.RO_PROBES:
        raise Deny("DENY_OP_UNKNOWN", "unknown probe")
    pol = _policy(st)
    if 0 not in pol.tiers:
        raise Deny("DENY_TIER_DISABLED", "policy does not enable tier 0")
    st.extra["probe"] = b["probe"]


def s_t0_rate(st: State) -> None:
    p = st.extra["probe"]
    _rate(st, f"t0.{p}", HEAVY_PROBE_RATE if p in HEAVY_PROBES else LIGHT_PROBE_RATE)


def s_t0_audit(st: State) -> None:
    try:
        st.ctx.priv_log.head()
    except (AuditDown, AuditCorrupt) as e:
        raise Deny("DENY_AUDIT_DOWN", "audit not writable") from e


def s_t0_run(st: State) -> None:
    """Reduced pipeline effect: the probe runs in a unit of class `ro-probe` (properties from hardening.py), its single JSON line is the answer."""
    ctx, probe = st.ctx, st.extra["probe"]
    params = st.req.body["params"]
    name = f"forge-node-probe-{os.urandom(16).hex()}.service"
    spec = hardening.RO_PROBES[probe]
    try:
        rc, out, err = ctx.backend.run_pipe(name, classes.probe_unit_properties(probe, ctx.node), ctx.argv_for("probe", probe, None), canon.canonical(params) + b"\n", spec["runtime_s"] + 15)
    except UnitError as e:
        raise Deny("FAIL_EXEC", f"probe unit failed: {e}") from e
    line = out.split(b"\n", 1)[0]
    try:
        doc = canon.loads(line)
        ok_ = isinstance(doc, dict) and isinstance(doc.get("ok"), bool)
    except canon.CanonError:
        ok_ = False
    if rc != 0 and not ok_ or not ok_:
        raise Deny("FAIL_EXEC", f"probe produced no valid answer (rc {rc})")
    ctx.audit("t0", {"probe": probe, "ok": doc["ok"], "code": doc.get("code"), "bytes": len(line), "sha256": hashlib.sha256(line).hexdigest()})
    st.reply = {"ok": True, "probe": doc}


# ------------------------------------------------------------------------------------------------------------------------ selfcheck
def s_selfcheck_target(st: State) -> None:
    b = st.req.body
    if set(b) != {"target"} or not isinstance(b["target"], str):
        raise Deny("DENY_PARAM", "selfcheck needs exactly {target}")
    kind, _, name = b["target"].partition(":")
    pol = _policy(st)
    if kind == "probe":
        if name not in hardening.RO_PROBES:
            raise Deny("DENY_OP_UNKNOWN", "unknown probe")
    elif kind == "op":
        e = st.ctx.optable.get(name)
        if e is None or pol.profile not in e.profiles:
            raise Deny("DENY_OP_UNKNOWN", "op is not in the table for this profile")
    elif b["target"] != "audit":
        raise Deny("DENY_PARAM", "selfcheck target must be probe:<name>, op:<name> or audit")
    st.extra["kind"], st.extra["name"] = (kind, name) if b["target"] != "audit" else ("audit", "")
    _rate(st, "selfcheck", SELFCHECK_RATE)


def s_selfcheck_run(st: State) -> None:
    ctx, kind, name = st.ctx, st.extra["kind"], st.extra["name"]
    if kind == "audit":
        from ..audit import fsproof
        res = {"priv": fsproof.prove(ctx.priv_log.spec.dir), "agent": fsproof.prove(ctx.agent_log.spec.dir) if ctx.agent_log else None}
        ok_ = res["priv"]["ok"] and (res["agent"] is None or res["agent"]["ok"])
        st.reply = {"ok": True, "selfcheck": {"target": "audit", "ok": ok_, "detail": res}}
        return
    unit = f"forge-node-probe-{os.urandom(16).hex()}.service"
    if kind == "probe":
        props, argv = classes.probe_unit_properties(name, ctx.node), ctx.argv_for("probe-selfcheck", name, None)
    else:
        e = ctx.optable.get(name)
        wd = os.path.join(ctx.paths.work, f"selfcheck-{os.urandom(8).hex()}")
        os.mkdir(wd, 0o700)
        props = classes.op_unit_properties(e.unit_class, work_dir=wd, priv_state=ctx.paths.priv_state, forge_roots=tuple(r.path for r in _policy(st).forge_roots), timeout_s=60)
        with open(os.path.join(wd, "selfcheck.json"), "wb") as f:
            f.write(canon.canonical({"ledger_path": ctx.paths.ledger, "lock_dir": ctx.paths.locks}) + b"\n")
        argv = ctx.argv_for("op-selfcheck", name, wd)
        st.extra["selfcheck_dir"] = wd
    try:
        rc, out, err = ctx.backend.run_pipe(unit, props, argv, b"{}\n", 90)
    except UnitError as ex:
        raise Deny("FAIL_EXEC", f"selfcheck unit failed: {ex}") from ex
    finally:
        if st.extra.get("selfcheck_dir"):
            shutil.rmtree(st.extra["selfcheck_dir"], ignore_errors=True)
    try:
        doc = canon.loads(out.split(b"\n", 1)[0])
    except canon.CanonError:
        doc = None
    st.reply = {"ok": True, "selfcheck": {"target": f"{kind}:{name}", "ok": bool(doc and doc.get("ok") and doc.get("data", {}).get("ok", True)) and rc == 0, "detail": doc, "rc": rc}}


# --------------------------------------------------------------------------------------------------------------------------- status
def s_status(st: State) -> None:
    ctx = st.ctx
    out = {"node": ctx.node, "version": ctx.version, "now": protocol.fmt_ts(ctx.now()), "local_stop": _local_stop_active(ctx), "gates": {g: ctx.gates[g].met for g in sorted(ctx.gates)}}
    try:
        pol = ctx.policies.current()
        out["policy"] = {"serial": pol.serial, "sha256": pol.raw_sha256, "profile": pol.profile, "global_mode": pol.global_mode, "tiers": list(pol.tiers)}
        lease = ctx.leases.current(pol.view.hub_gate_keys)
        out["lease"] = None if lease is None else {k: lease[k] for k in ("seq", "issued_at", "valid_until", "stop", "quarantine", "stopped_projects")}
    except PolicyError as e:
        out["policy"], out["lease"], out["policy_error"] = None, None, e.detail[:200]
    heads = {}
    for name, log in (("priv", ctx.priv_log), ("agent", ctx.agent_log)):
        if log is None:
            continue
        try:
            seq, h = log.head()
            heads[name] = {"seq": seq, "hash": h}
        except (AuditDown, AuditCorrupt) as e:
            heads[name] = {"error": type(e).__name__}
    out["audit_heads"] = heads
    out["open_jobs"] = [{"job_id": r.job_id, "state": r.state, "attempt": r.attempt} for r in ctx.ledger.open_rows()][:64]
    out["ledger_schema"] = STATE_SCHEMA
    st.reply = {"ok": True, "status": out}


# ----------------------------------------------------------------------------------------------------------------------------- lease
def s_lease_put(st: State) -> None:
    ctx = st.ctx
    keys = _gate_keys(st)
    try:
        p = ctx.leases.put(st.req.body.get("lease"), keys)
    except ProtoError as e:
        raise Deny(e.code if e.code in protocol.REASON_CODES else "DENY_STALE_LEASE", e.detail) from e
    last = ctx.ledger.meta_get("lease_audit", "")
    state = canon.canonical_text({"stop": p["stop"], "quarantine": p["quarantine"], "projects": p["stopped_projects"]})
    last_ts = float(ctx.ledger.meta_get("lease_audit_ts", "0"))
    if last != state or ctx.now().timestamp() - last_ts >= LEASE_RECORD_EVERY_S:
        ctx.audit("lease", {"lease_seq": p["seq"], "stop": p["stop"], "quarantine": p["quarantine"], "stopped_projects": p["stopped_projects"], "issued_at": p["issued_at"]})
        ctx.ledger.meta_set("lease_audit", state)
        ctx.ledger.meta_set("lease_audit_ts", str(ctx.now().timestamp()))
    st.reply = {"ok": True, "lease": {"seq": p["seq"], "valid_until": p["valid_until"], "stop": p["stop"]}}


# ------------------------------------------------------------------------------------------------------------------------ reconcile
def s_reconcile(st: State) -> None:
    ctx, b = st.ctx, st.req.body
    if not set(b) <= {"job_id", "resolve"} or "job_id" not in b:
        raise Deny("DENY_PARAM", "reconcile needs {job_id[, resolve]}")
    try:
        protocol.check_uuid(b["job_id"])
    except ProtoError as e:
        raise Deny("DENY_PARAM", e.detail) from e
    _rate(st, "reconcile", ((30, 60),))
    if "resolve" in b:                                                          # ledger.resolve: root only, an indeterminate row only, never the failing caller's decision alone
        if st.req.peer.uid != ctx.owner_uid:
            raise Deny("DENY_NEEDS_OWNER_SIG", "only root may resolve an indeterminate job")
        r = b["resolve"]
        if not isinstance(r, dict) or set(r) != {"verdict", "inspection"} or r["verdict"] not in ("aborted_safe", "committed") or not isinstance(r["inspection"], str) or not 8 <= len(r["inspection"]) <= 4096:
            raise Deny("DENY_PARAM", "resolve needs {verdict: aborted_safe|committed, inspection: 8..4096 chars}")
        row = ctx.ledger.get(b["job_id"])
        if row is None or row.state != "indeterminate":
            raise Deny("DENY_PARAM", "job is not indeterminate")
        status = "committed" if r["verdict"] == "committed" else "aborted_safe"
        ctx_audit = ctx.audit("recovery", {"job_id": row.job_id, "attempt": row.attempt, "op": row.op, "verdict": f"resolved_{r['verdict']}", "inspection_sha256": hashlib.sha256(r["inspection"].encode()).hexdigest(),
                                           "inspection": redact.redact_full(r["inspection"])[:1024]})
        res = result_doc(attempt=row.attempt, status=status, reason_code=None if status == "committed" else "FAIL_EXEC", output="resolved by the Betriebsleiter after inspection",
                         seq_range=[ctx_audit["seq"], ctx_audit["seq"]], plan_hash=row.plan_hash)
        ctx.ledger.finish(row.job_id, row.attempt, "committed" if status == "committed" else "aborted_safe", res, ctx.now(), frm=("indeterminate",))
        ctx.ledger.unlock_target(row.effect_key, row.job_id)
        st.reply = {"ok": True, "result": {"job_id": row.job_id, **res}}
        return
    kind, res = rec.reconcile_job(ctx, b["job_id"])
    st.reply = {"ok": True, "reconcile": kind, "result": None if res is None else {"job_id": b["job_id"], **res}}


# --------------------------------------------------------------------------------------------------------------------- policy.apply
def s_policy_apply(st: State) -> None:
    ctx, b = st.ctx, st.req.body
    if set(b) != {"policy_b64", "sig"} or not isinstance(b["policy_b64"], str) or not isinstance(b["sig"], str):
        raise Deny("DENY_PARAM", "policy.apply needs {policy_b64, sig}")
    try:
        raw = base64.b64decode(b["policy_b64"], validate=True)
    except (binascii.Error, ValueError) as e:
        raise Deny("DENY_PARAM", "policy_b64 is not base64") from e
    _rate(st, "policy.apply", ((10, 60),))
    try:
        ctx.priv_log.head()
    except (AuditDown, AuditCorrupt) as e:
        raise Deny("DENY_AUDIT_DOWN", "audit not writable: refusing to change the policy") from e
    prev = ctx.policies.installed_serial()
    try:
        pol = ctx.policies.apply(raw, b["sig"])
    except PolicyError as e:
        raise Deny("DENY_POLICY_INVALID", e.detail) from e
    try:
        r = ctx.audit("policy", {"action": "apply", "serial": pol.serial, "sha256": pol.raw_sha256, "previous_serial": prev, "profile": pol.profile, "global_mode": pol.global_mode,
                                 "tiers": list(pol.tiers), "caller_uid": st.req.peer.uid})
    except Deny:
        ctx.ledger.meta_set("policy_audit_pending", f"{pol.serial}:{pol.raw_sha256}")
        r = None
    st.reply = {"ok": True, "policy": {"serial": pol.serial, "sha256": pol.raw_sha256}, "audit_seq": None if r is None else r["seq"]}


# ----------------------------------------------------------------------------------------------------------------------- audit.rotate
def s_audit_rotate(st: State) -> None:
    ctx, b = st.ctx, st.req.body
    if set(b) - {"log", "when"} or "log" not in b or b["log"] not in ("priv", "agent", "both") or b.get("when", "now") not in ("now", "due"):
        raise Deny("DENY_PARAM", "audit.rotate needs {log: priv|agent|both[, when: now|due]}")
    out = {}
    due_only = b.get("when", "now") == "due"
    try:
        for name, log in (("priv", ctx.priv_log), ("agent", ctx.agent_log)):
            if b["log"] not in (name, "both"):
                continue
            if log is None:
                raise Deny("DENY_PARAM", "this node has no such log")
            if due_only and not log.due():
                out[name] = None                                                   # not due: nothing rotated
            else:
                out[name] = log.rotate()
    except (AuditDown, AuditCorrupt) as e:
        raise Deny("DENY_AUDIT_DOWN", f"rotation failed ({type(e).__name__}: {e})") from e
    st.reply = {"ok": True, "rotated": out}


# ---------------------------------------------------------------------------------------------------------------------------- lockdown
def s_lockdown(st: State) -> None:
    ctx = st.ctx
    d = os.path.dirname(ctx.paths.local_stop)
    dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        try:
            fd = os.open(os.path.basename(ctx.paths.local_stop), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=dfd)
            os.close(fd)
            created = True
        except FileExistsError:
            created = False
        os.fsync(dfd)
    finally:
        os.close(dfd)
    try:
        ctx.audit("policy", {"action": "lockdown", "local_stop_created": created, "caller_uid": st.req.peer.uid})
    except Deny:
        pass                                                                    # the lock itself must not depend on the audit log
    st.reply = {"ok": True, "lockdown": {"local_stop": True, "created": created}}


# ============================================================================================================================ pipelines
PIPELINES = {
    "exec": (s_caller, s_job_signature, s_claim, s_lease, s_local_stop, s_clock, s_op_static, s_audit_intent, s_policy, s_mode, s_params, s_protected, s_allowlist, s_window, s_rate,
             s_owner_signature, s_plan, s_target_lock, s_started, s_effect, s_postcheck, s_commit),
    "t0": (s_caller, s_t0_probe_known, s_lease_authentic, s_t0_rate, s_t0_audit, s_t0_run),
    "selfcheck": (s_caller, s_selfcheck_target, s_t0_audit, s_selfcheck_run),
    "status": (s_caller, s_status),
    "lease.put": (s_caller, s_lease_put),
    "reconcile": (s_caller, s_reconcile),
    "policy.apply": (s_caller, s_policy_apply),
    "audit.rotate": (s_caller_root, s_audit_rotate),
    "lockdown": (s_caller_root, s_lockdown),
}
assert set(PIPELINES) == set(KINDS)


def _denial_audit_allowed(ctx: Context) -> bool:
    """A flood of garbage requests must not become a flood of audit records: at most DENIAL_RECORDS_PER_MIN per minute, the rest is counted and summarised."""
    now = ctx.monotonic()
    with ctx._lock:
        w = ctx.denial_window
        if now - w[0] >= 60:
            suppressed, w[0], w[1], w[2] = w[2], now, 0, 0
            if suppressed:
                try:
                    ctx.priv_log.append("denial", {"suppressed": suppressed, "reason": "denial records suppressed in the previous minute"})
                except (AuditDown, AuditCorrupt):
                    pass
        if w[1] < DENIAL_RECORDS_PER_MIN:
            w[1] += 1
            return True
        w[2] += 1
        return False


def _record_denial(st: State, d: Deny) -> dict:
    ctx = st.ctx
    retry = d.code in protocol.RETRYABLE_DENIALS
    row = st.row
    reply_err = {"ok": False, "code": d.code, "detail": d.detail[:300]}
    if row is not None:
        cur = ctx.ledger.get(row.job_id)
        if cur is not None and (cur.state in ("effect_done", "reconciling") or (cur.state == "started" and cur.worker_invocation_id is not None)):
            # A worker exists or the effect may have happened: this is not a denial and must never be reported as one. The row stays open; reconcile/attach finishes it.
            return {"ok": True, "in_progress": True, "job_id": row.job_id}
    try:
        if row is not None:
            res = result_doc(attempt=row.attempt, status="denied" if d.code.startswith("DENY_") else "failed", reason_code=d.code, output=d.detail, seq_range=None, plan_hash=None)
            common = {"job_id": row.job_id, "attempt": row.attempt, "fence": row.fence, "op": row.op, "reason_code": d.code, "detail": d.detail[:300]}
            r = ctx.audit("result", {**common, "status": res["status"]}) if st.intent_seq is not None else ctx.audit("denial", common)
            res["audit_seq_range"] = [st.first_seq or r["seq"], r["seq"]]
            ctx.ledger.finish(row.job_id, row.attempt, "denied_retryable" if retry else ("denied" if res["status"] == "denied" else "failed"), res, ctx.now(),
                              frm=("received", "started"))
            return {"ok": True, "result": {"job_id": row.job_id, **res}}
        if _denial_audit_allowed(ctx):
            ctx.audit("denial", {"kind": st.req.kind, "reason_code": d.code, "detail": d.detail[:300], "caller_uid": st.req.peer.uid, "claimed_job_id": st.claimed_id})
    except Deny:
        if row is not None:                                                     # the audit log is down: the job is retryable, nothing was recorded
            res = result_doc(attempt=row.attempt, status="denied", reason_code="DENY_AUDIT_DOWN", output="audit down", seq_range=None, plan_hash=None)
            ctx.ledger.finish(row.job_id, row.attempt, "denied_retryable", res, ctx.now(), frm=("received", "started"))
            return {"ok": True, "result": {"job_id": row.job_id, **res}}
        return {"ok": False, "code": "DENY_AUDIT_DOWN", "detail": "audit down"}
    return reply_err


def gate(ctx: Context, req: Request) -> dict:
    """The single guarded function. Returns the wire reply; never raises for a bad request. See the module docstring for the pipelines."""
    if not isinstance(ctx, Context) or not isinstance(req, Request):
        return {"ok": False, "code": "DENY_OP_UNKNOWN", "detail": "no context or no request: nothing is done"}      # missing guard state rejects (G27 fail closed)
    plan = PIPELINES.get(req.kind)
    if plan is None:
        return {"ok": False, "code": "DENY_OP_UNKNOWN", "detail": "unknown request kind"}
    st = State(ctx, req)
    try:
        for step in plan:
            step(st)
        return st.reply if st.reply is not None else {"ok": False, "code": "FAIL_EXEC", "detail": "pipeline produced no reply"}
    except Done as d:
        return d.reply
    except Deny as d:
        return _record_denial(st, d)
    except ProtoError as e:
        return _record_denial(st, Deny(e.code if e.code in protocol.REASON_CODES else "DENY_PARAM", e.detail))
    except Exception as e:  # noqa: BLE001 - a bug is a refusal, never an effect without the pipeline
        return _record_denial(st, Deny("FAIL_PRECHECK" if st.row is None or st.row.state == "received" else "FAIL_EXEC", f"internal error: {type(e).__name__}"))
    finally:
        if st.lock is not None:
            st.lock.__exit__()
