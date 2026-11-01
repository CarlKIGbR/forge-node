"""Retention (Design 9.4: terminal rows are kept >= 90 days): old terminal ledger rows with their per-attempt work directories and per-job lock files, expired plans. Runs at start and
hourly. Only what can no longer change is removed; every condition is evaluated by the database / on the object at deletion time."""
import os
import shutil
from datetime import timedelta

from .. import protocol
from .core import Context, FileLock, job_lock_path
from .units import UnitError, op_unit_name

RETENTION_DAYS = 90


def prune(ctx: Context) -> dict:
    now = ctx.now()
    gone = ctx.ledger.prune_terminal(protocol.fmt_ts(now - timedelta(days=RETENTION_DAYS)))
    dirs = locks = 0
    for job_id, attempt in gone:
        for n in range(1, attempt + 1):
            try:
                ctx.backend.forget(op_unit_name(job_id, n))
            except (UnitError, OSError):
                pass                                                                  # housekeeping only
            wd = os.path.join(ctx.paths.work, f"{job_id}-{n}")
            if os.path.isdir(wd) and not os.path.islink(wd):
                shutil.rmtree(wd, ignore_errors=True)
                dirs += 1
        try:
            with FileLock(job_lock_path(ctx.paths, job_id), blocking=False):          # never unlink a lock somebody holds
                os.unlink(job_lock_path(ctx.paths, job_id))
                locks += 1
        except (BlockingIOError, FileNotFoundError):
            pass
    plans = ctx.ledger.prune_plans(now.timestamp())
    return {"rows": len(gone), "work_dirs": dirs, "locks": locks, "plans": plans}
