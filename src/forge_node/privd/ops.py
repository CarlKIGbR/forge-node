"""Effects and probes of the ops in this release's table. They run inside the op unit (worker) or, for probes, in privd during reconciliation (read-only)."""
import hashlib
import os

from .. import canon
from .worker import EffectContext, EffectRefused

MARK = "effect.mark"


def _marker(priv_state: str) -> bytes:
    """Optional operator-provided marker file under the privileged state directory; its content is part of the plan (so a plan can go stale)."""
    try:
        fd = os.open(os.path.join(priv_state, "selftest.marker"), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return b""
    try:
        return os.read(fd, 4096)
    finally:
        os.close(fd)


def noop_plan(ctx: EffectContext) -> dict:
    return {"op": ctx.op, "params": ctx.params, "marker_sha256": hashlib.sha256(_marker(ctx.priv_state)).hexdigest()}


def noop_effect(ctx: EffectContext) -> dict:
    plan = noop_plan(ctx)
    plan_hash = canon.digest(plan)
    if ctx.dry_run:
        return {"plan": plan, "plan_hash": plan_hash, "output": "dry-run", "post_digest": None}
    if ctx.plan_hash is not None and ctx.plan_hash != plan_hash:               # recomputed UNDER the effect lock, right before acting
        raise EffectRefused("DENY_STALE_PLAN", "the plan recomputed under the effect lock differs from the approved one")
    fd = os.open(os.path.join(ctx.work_dir, MARK), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)       # THE effect: one marker file in the attempt's own directory
    try:
        os.write(fd, b"applied\n")
        os.fsync(fd)
    finally:
        os.close(fd)
    return {"plan_hash": plan_hash, "output": "ok", "post_digest": hashlib.sha256(b"applied\n").hexdigest()}


def noop_probe(work_dir: str) -> str:
    """Idempotency class `probe` (Design 9.4): the effect is observable. applied = the marker exists; not_applied = the attempt's directory exists and has none; else unknown."""
    try:
        if os.path.isdir(work_dir) and not os.path.islink(work_dir):
            return "applied" if os.path.lexists(os.path.join(work_dir, MARK)) else "not_applied"
    except OSError:
        pass
    return "unknown"


EFFECTS = {"selftest.noop": noop_effect}
