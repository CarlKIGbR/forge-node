"""The program that runs INSIDE an op unit (Design 9.4 'worker identity and fencing'). `python -m forge_node.privd.worker <work_dir>`.

Everything it needs is in `<work_dir>/request.json`, written by privd (root-only directory); the command line carries only the directory. Sequence:
  1. take the EFFECT LOCK (flock LOCK_EX on <lock_dir>/fx-<sha256(effect_key)[:32]>.lock). It lives in this process, so it survives privd dying and is released if the worker dies;
  2. WHILE HOLDING IT re-read the ledger row (read-only): the effect proceeds only if state == started AND fence AND attempt equal the ones this worker was started with. Reconcile bumps
     the fence first, so a surviving worker finds a mismatch and exits without an effect (status `fenced`, FAIL_FENCED);
  3. run the op's effect function (dry_run: only compute the plan);
  4. write status.json atomically (temp, fsync, rename, fsync dir) as the LAST act. The worker writes nowhere else and never touches the audit log."""
import fcntl
import hashlib
import json
import os
import stat
import sys
import traceback
from typing import Callable, Mapping

from .. import canon
from .ledger import Ledger

STATUS = "status.json"
REQUEST = "request.json"


class EffectRefused(Exception):
    """The effect step decided, under the effect lock, not to act (e.g. the plan it recomputes differs from the approved one). The code is a design reason code."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail)
        self.code, self.detail = code, detail


class EffectContext:
    def __init__(self, req: dict, work_dir: str):
        self.job_id, self.attempt, self.op, self.params = req["job_id"], req["attempt"], req["op"], req["params"]
        self.dry_run, self.plan_hash, self.work_dir = req["dry_run"], req.get("plan_hash"), work_dir
        self.priv_state = req["priv_state"]


Effect = Callable[[EffectContext], dict]


def lock_path(lock_dir: str, effect_key: str) -> str:
    return os.path.join(lock_dir, "fx-" + hashlib.sha256(effect_key.encode()).hexdigest()[:32] + ".lock")


def write_status(work_dir: str, doc: dict) -> None:
    dfd = os.open(work_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        tmp = STATUS + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
        try:
            data = canon.canonical(doc) + b"\n"
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(tmp, STATUS, src_dir_fd=dfd, dst_dir_fd=dfd)
        os.fsync(dfd)
    finally:
        os.close(dfd)


def read_status(work_dir: str) -> dict | None:
    """status.json if it is complete and well-formed, else None (a missing or torn file means 'interrupted')."""
    try:
        dfd = os.open(work_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        fd = os.open(STATUS, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
    except OSError:
        return None
    finally:
        os.close(dfd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 256 * 1024:
            return None
        raw = os.read(fd, 256 * 1024 + 1)
    finally:
        os.close(fd)
    try:
        doc = canon.loads(raw.rstrip(b"\n"))
    except canon.CanonError:
        return None
    if not isinstance(doc, dict) or doc.get("outcome") not in ("done", "failed", "fenced") or not isinstance(doc.get("job_id"), str):
        return None
    return doc


def run(work_dir: str, effects: Mapping[str, Effect], *, owner_uid: int) -> int:
    dfd = os.open(work_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        st = os.fstat(dfd)
        if st.st_uid != owner_uid or st.st_mode & 0o077:
            raise SystemExit("work directory must be owner-only")
        fd = os.open(REQUEST, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
        try:
            fst = os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode) or fst.st_uid != owner_uid or fst.st_mode & 0o077 or fst.st_size > 64 * 1024:
                raise SystemExit("request must be an owner-only regular file")
            req = canon.loads(os.read(fd, 64 * 1024 + 1))
        finally:
            os.close(fd)
    finally:
        os.close(dfd)
    base = {"job_id": req["job_id"], "attempt": req["attempt"], "fence": req["fence"]}
    lk = os.open(lock_path(req["lock_dir"], req["effect_key"]), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(lk, fcntl.LOCK_EX)
        led = Ledger(req["ledger_path"], read_only=True)
        try:
            row = led.get(req["job_id"])
        finally:
            led.close()
        if row is None or row.state != "started" or row.fence != req["fence"] or row.attempt != req["attempt"]:
            write_status(work_dir, {**base, "outcome": "fenced", "code": "FAIL_FENCED", "ledger_state": None if row is None else row.state, "ledger_fence": None if row is None else row.fence})
            return 0
        effect = effects.get(req["op"])
        if effect is None:
            write_status(work_dir, {**base, "outcome": "failed", "code": "FAIL_EXEC", "detail": "no effect registered for this op"})
            return 0
        try:
            result = effect(EffectContext(req, work_dir))
            write_status(work_dir, {**base, "outcome": "done", **result})
        except SystemExit:
            raise
        except EffectRefused as e:
            write_status(work_dir, {**base, "outcome": "failed", "code": e.code, "detail": e.detail[:300]})
        except Exception as e:  # noqa: BLE001
            write_status(work_dir, {**base, "outcome": "failed", "code": "FAIL_EXEC", "detail": f"{type(e).__name__}: {e}"[:300]})
            traceback.print_exc(file=sys.stderr)
        return 0
    finally:
        os.close(lk)
