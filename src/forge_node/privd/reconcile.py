"""Worker-aware reconciliation (Design 9.4) and startup recovery. The ONLY way a ledger row leaves started/effect_done/reconciling without the worker's own result.

  examine:   active (the persisted unit runs with the same InvocationID) -> no reconciliation, no probe, no new attempt; finished (unit ended, status.json complete) -> commit from it;
             interrupted (unit gone/ended and no complete status.json, or timeout) -> reconcile.
  reconcile: (1) per-job lock, concurrent callers get in_progress (2) fence bumped and `reconciling` set in ONE transaction BEFORE anything is looked at (3) the worker is stopped and
             confirmed dead (unit inactive/failed AND cgroup empty), else indeterminate (4) the effect lock is taken (free now; held by an outsider -> indeterminate) (5) delegated effects
             settle, else indeterminate (6) the op's probe classifies: applied -> committed, not_applied -> aborted_safe (retryable with attempt+1), partial/unknown -> indeterminate,
             and a `recovery` audit record is appended. A new attempt can only start from aborted_safe through the serialized claim."""
import threading
from dataclasses import dataclass

from .. import protocol
from ..audit.spec import AuditCorrupt, AuditDown
from . import worker
from .core import Context, FileLock, job_lock_path, result_doc
from .ledger import Row

STOP_WAIT_S = 40.0


@dataclass
class Examined:
    kind: str                   # active | finished | interrupted
    status: dict | None
    info: object | None


def examine(ctx: Context, row: Row) -> Examined:
    info = ctx.backend.show(row.worker_unit) if row.worker_unit else None
    status = worker.read_status(row.worker_dir) if row.worker_dir else None
    if status is not None and (status.get("job_id") != row.job_id or status.get("attempt") != row.attempt):
        status = None
    if info is not None and info.is_active and row.worker_invocation_id in (None, info.invocation_id):
        if row.worker_invocation_id is None:                              # privd died between systemd-run and storing the id: adopt the live unit's
            ctx.ledger.set_invocation(row.job_id, row.attempt, info.invocation_id, ctx.now())
        return Examined("active", status, info)
    if status is not None:
        return Examined("finished", status, info)
    return Examined("interrupted", None, info)


def _output(status: dict) -> str:
    from ..redact import redact_full
    return redact_full(str(status.get("output", status.get("detail", ""))))[:4096]


def finalize_from_status(ctx: Context, row: Row, status: dict, *, seq_first: int | None = None) -> dict:
    """Commit (or fail) a row from the worker's complete status.json. Returns the result doc."""
    entry = ctx.optable.get(row.op)
    outcome = status["outcome"]
    first = seq_first
    if outcome == "done":
        ctx.ledger.mark_effect_done(row.job_id, row.attempt, status.get("post_digest"), ctx.now())
        plan_hash = status.get("plan_hash")
        if row.eff_dry_run and status.get("plan") is not None:
            ctx.ledger.plan_put(plan_hash, row.job_id, row.op, row.params_sha256, status["plan"], ctx.now().timestamp())
        res = result_doc(attempt=row.attempt, status="dry_run" if row.eff_dry_run else "committed", reason_code=None, output=_output(status), seq_range=None, plan_hash=plan_hash)
        rec = ctx.audit("result", {"job_id": row.job_id, "attempt": row.attempt, "fence": row.fence, "op": row.op, "status": res["status"], "reason_code": None, "dry_run": row.eff_dry_run,
                                   "plan_hash": plan_hash, "post_digest": status.get("post_digest"), "output": res["output"][:1024]})
        res["audit_seq_range"] = [first or rec["seq"], rec["seq"]]
        ctx.ledger.finish(row.job_id, row.attempt, "committed", res, ctx.now())
        if entry is not None and not row.eff_dry_run:                        # a dry run says nothing about the apply path: only a real success resets the failure count
            thr = ctx.policies.current().circuit_threshold if _policy_ok(ctx) else 3
            ctx.ledger.circuit_record(row.op, True, thr, ctx.now())
        return res
    code = status.get("code") or "FAIL_EXEC"
    denied = code.startswith("DENY_")
    res = result_doc(attempt=row.attempt, status="denied" if denied else "failed", reason_code=code, output=_output(status), seq_range=None, plan_hash=row.plan_hash)
    rec = ctx.audit("result", {"job_id": row.job_id, "attempt": row.attempt, "fence": row.fence, "op": row.op, "status": res["status"], "reason_code": code, "dry_run": row.eff_dry_run,
                               "output": res["output"][:1024]})
    res["audit_seq_range"] = [first or rec["seq"], rec["seq"]]
    ctx.ledger.finish(row.job_id, row.attempt, "denied" if denied else "failed", res, ctx.now())
    if not denied and entry is not None:
        thr = ctx.policies.current().circuit_threshold if _policy_ok(ctx) else 3
        ctx.ledger.circuit_record(row.op, False, thr, ctx.now())
    return res


def _policy_ok(ctx: Context) -> bool:
    try:
        ctx.policies.current()
        return True
    except Exception:  # noqa: BLE001
        return False


def wait_unit(ctx: Context, row: Row, deadline_s: float) -> str:
    """Poll the persisted unit until it ends. 'ended' | 'timeout'."""
    t_end = ctx.monotonic() + deadline_s
    while True:
        info = ctx.backend.show(row.worker_unit)
        if info is None or not info.is_active:
            return "ended"
        if ctx.monotonic() >= t_end:
            return "timeout"
        ctx.sleep(0.02)


def ensure_dead(ctx: Context, row: Row) -> bool:
    """Stop the unit and wait until it is inactive/failed AND its cgroup is empty. Never infer death from absence of output."""
    try:
        info = ctx.backend.show(row.worker_unit)
        if info is None:
            return True
        if info.is_active or not info.cgroup_empty:
            ctx.backend.stop(row.worker_unit)
        t_end = ctx.monotonic() + STOP_WAIT_S
        while ctx.monotonic() < t_end:
            info = ctx.backend.show(row.worker_unit)
            if info is None or (not info.is_active and info.cgroup_empty):
                return True
            ctx.sleep(0.02)
    except Exception:  # noqa: BLE001 - cannot establish death: not dead
        return False
    return False


def _conclude(ctx: Context, row: Row, verdict: str, evidence: dict) -> dict:
    """Ledger + `recovery` audit record for a reconciliation verdict."""
    label = {"applied": "reconciled_applied", "not_applied": "aborted_safe"}.get(verdict, "indeterminate")
    rec = ctx.audit("recovery", {"job_id": row.job_id, "attempt": row.attempt, "fence": row.fence + 0, "op": row.op, "verdict": label, "evidence": evidence})
    if verdict == "applied":
        res = result_doc(attempt=row.attempt, status="committed", reason_code=None, output="reconciled: the effect had been applied", seq_range=[rec["seq"], rec["seq"]], plan_hash=row.plan_hash)
        ctx.ledger.finish(row.job_id, row.attempt, "committed", res, ctx.now())
    elif verdict == "not_applied":
        res = result_doc(attempt=row.attempt, status="aborted_safe", reason_code="FAIL_EXEC", output="worker interrupted before the effect; safe to retry", seq_range=[rec["seq"], rec["seq"]], plan_hash=row.plan_hash)
        ctx.ledger.finish(row.job_id, row.attempt, "aborted_safe", res, ctx.now())
    else:
        res = result_doc(attempt=row.attempt, status="indeterminate", reason_code="INDETERMINATE", output=str(evidence.get("why", "unknown"))[:200], seq_range=[rec["seq"], rec["seq"]], plan_hash=row.plan_hash)
        ctx.ledger.finish(row.job_id, row.attempt, "indeterminate", res, ctx.now())
        ctx.ledger.lock_target(row.effect_key, row.job_id, "indeterminate", ctx.now())
    return res


def reconcile_job(ctx: Context, job_id: str) -> tuple[str, dict | None]:
    """('in_progress'|'noop'|'committed'|'aborted_safe'|'indeterminate'|'failed', result). Takes the per-job lock without waiting."""
    try:
        lock = FileLock(job_lock_path(ctx.paths, job_id), blocking=False)
        lock.__enter__()
    except BlockingIOError:
        return "in_progress", None
    try:
        return reconcile_locked(ctx, job_id)
    finally:
        lock.__exit__()


def reconcile_locked(ctx: Context, job_id: str) -> tuple[str, dict | None]:
    row = ctx.ledger.get(job_id)
    if row is None or row.state not in ("started", "effect_done", "reconciling"):
        return "noop", None if row is None else row.result
    entry = ctx.optable.get(row.op)
    ex = examine(ctx, row)
    if ex.kind == "active":
        started = protocol.parse_ts(row.worker_started_at) if row.worker_started_at else None
        limit = entry.timeout_s if entry else 30
        if started is None or (ctx.now() - started).total_seconds() < limit:
            return "in_progress", None                                    # NEVER reconcile a worker that is still within its time budget
    if ex.kind == "finished" and ex.status["outcome"] != "fenced" and row.state in ("started", "effect_done"):
        res = finalize_from_status(ctx, row, ex.status)
        return res["status"] if res["status"] != "dry_run" else "committed", res
    row = ctx.ledger.begin_reconcile(job_id, ctx.now()) or row            # fence first
    if not ensure_dead(ctx, row):
        return "indeterminate", _conclude(ctx, row, "unknown", {"why": "worker could not be confirmed dead"})
    fx = FileLock(worker.lock_path(ctx.paths.locks, row.effect_key), blocking=False)
    try:
        fx.__enter__()
    except BlockingIOError:
        return "indeterminate", _conclude(ctx, row, "unknown", {"why": "the effect lock is held by a process outside the worker's cgroup"})
    try:
        if entry is not None and entry.settle is not None and not entry.settle(row.worker_dir):
            return "indeterminate", _conclude(ctx, row, "unknown", {"why": "delegated effects did not settle"})
        status = worker.read_status(row.worker_dir) if row.worker_dir else None
        if status is not None and (status.get("job_id") != row.job_id or status.get("attempt") != row.attempt):
            status = None
        if status is not None and status["outcome"] in ("done", "failed") and entry is not None and entry.idempotency != "opaque":
            res = finalize_from_status(ctx, row, status)                    # the worker did finish (it was past its fence check when the fence moved): its own word stands
            return res["status"] if res["status"] != "dry_run" else "committed", res
        if entry is None or entry.idempotency == "opaque":
            verdict = "unknown"
        elif status is not None and status["outcome"] == "fenced":
            verdict = "not_applied"
        elif entry.probe is not None:
            verdict = entry.probe(row.worker_dir)
        else:
            verdict = "unknown"
    finally:
        fx.__exit__()
    res = _conclude(ctx, row, verdict, {"probe": verdict, "status_outcome": None if status is None else status["outcome"]})
    return res["status"], res


def attach_monitor(ctx: Context, row: Row) -> threading.Thread:
    """Re-attach to a surviving worker after a privd restart: wait for the unit to end (or the op's timeout), then commit from status.json or reconcile."""
    def run():
        try:
            lock = FileLock(job_lock_path(ctx.paths, row.job_id), blocking=True)
            with lock:
                cur = ctx.ledger.get(row.job_id)
                if cur is None or cur.state not in ("started", "effect_done"):
                    return
                entry = ctx.optable.get(cur.op)
                wait_unit(ctx, cur, entry.timeout_s if entry else 30)
                ex = examine(ctx, cur)
                if ex.kind == "finished" and ex.status["outcome"] != "fenced":
                    finalize_from_status(ctx, cur, ex.status)
                    return
            reconcile_job(ctx, row.job_id)
        except Exception:  # noqa: BLE001 - the next recover/reconcile request picks the row up again
            pass
    t = threading.Thread(target=run, name=f"attach-{row.job_id[:8]}", daemon=True)
    ctx.monitors.append(t)
    t.start()
    return t


def recover_all(ctx: Context) -> dict:
    """Startup recovery: audit logs first (rotation roll-forward, tail repair), then every unit and every open row (Design 9.4 'Startup recovery')."""
    from . import maintenance
    report = {"audit": {}, "attached": [], "reconciled": [], "orphans": [], "pruned": maintenance.prune(ctx)}
    report["audit_errors"] = {}
    for name, log in (("priv", ctx.priv_log), ("agent", ctx.agent_log)):
        if log is not None:
            try:
                report["audit"][name] = log.recover()
            except (AuditDown, AuditCorrupt) as e:        # privd must come up (and answer DENY_AUDIT_DOWN / status) even if a log is damaged or - for the agent's own log - locked by a hostile agent
                report["audit_errors"][name] = f"{type(e).__name__}: {e}"
    rows = {r.job_id: r for r in ctx.ledger.open_rows()}
    units = list(ctx.backend.list_op_units())
    known = {r.worker_unit for r in rows.values() if r.worker_unit}
    for u in units:
        if u not in known:
            ctx.backend.stop(u)
            ctx.audit("recovery", {"orphan_unit": u, "action": "stopped (no ledger row)"})
            report["orphans"].append(u)
    for row in rows.values():
        if row.state not in ("started", "effect_done", "reconciling"):
            continue
        ex = examine(ctx, row)
        if ex.kind == "active":
            attach_monitor(ctx, row)
            report["attached"].append(row.job_id)
        else:
            kind, _ = reconcile_job(ctx, row.job_id)
            report["reconciled"].append((row.job_id, kind))
    return report
