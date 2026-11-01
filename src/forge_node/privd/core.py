"""Shared types of privd: paths, the process context, the request/peer/denial types, small locks. No behaviour that decides anything lives here."""
import fcntl
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Mapping

from .. import protocol
from ..audit.log import AuditAdmin
from ..audit.spec import AuditCorrupt, AuditDown
from ..gates import Gate
from .ledger import Ledger
from .lease import LeaseStore
from .optable import OpTable
from .policy_store import PolicyStore

KINDS = ("exec", "lease.put", "t0", "status", "selfcheck", "reconcile", "policy.apply", "audit.rotate", "lockdown")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")


@dataclass(frozen=True)
class Paths:
    priv_state: str        # /var/lib/forge-node-priv
    run_dir: str           # /run/forge-node
    policy_dir: str        # /etc/forge-node/policy
    allowed_signers: str   # /etc/forge-node/allowed_signers
    local_stop: str        # /etc/forge-node/LOCAL_STOP

    @property
    def ledger(self) -> str:
        return os.path.join(self.priv_state, "ledger.sqlite")

    @property
    def locks(self) -> str:
        return os.path.join(self.priv_state, "locks")

    @property
    def work(self) -> str:
        return os.path.join(self.priv_state, "work")

    @property
    def serial_file(self) -> str:
        return os.path.join(self.priv_state, "serial")

    @property
    def lease_file(self) -> str:
        return os.path.join(self.run_dir, "lease")

    @property
    def socket(self) -> str:
        return os.path.join(self.run_dir, "priv.sock")


@dataclass(frozen=True)
class Peer:
    pid: int
    uid: int
    gid: int


@dataclass(frozen=True)
class Request:
    kind: str
    peer: Peer
    body: dict


class Deny(Exception):
    """A pipeline step refuses. code = design reason code; the gate records it (audit + ledger) and replies; nothing later runs."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


@dataclass
class Context:
    """Everything privd works with. EVERY field is required: there is no default that could stand in for a missing guard input (G27)."""
    node: str
    paths: Paths
    clock: Callable[[], datetime]
    ledger: Ledger
    priv_log: AuditAdmin
    agent_log: AuditAdmin | None
    backend: object
    optable: OpTable
    gates: Mapping[str, Gate]
    ssh_keygen: str
    owner_uid: int
    agent_uid: int
    policies: PolicyStore
    leases: LeaseStore
    argv_for: Callable[[str, str, str | None], list]   # (role, name, work_dir) -> argv inside the unit; role: op | op-selfcheck | probe | probe-selfcheck
    version: str
    sleep: Callable[[float], None]
    monotonic: Callable[[], float]
    _lock: threading.Lock = field(default_factory=threading.Lock)
    monitors: list = field(default_factory=list)
    denial_window: list = field(default_factory=lambda: [0.0, 0, 0])      # [window start, written, suppressed]
    worker_started: dict = field(default_factory=dict)                    # (job_id, attempt) -> ctx.monotonic() when this process started the unit (a wall clock that jumps must not shorten a worker's budget)

    def now(self) -> datetime:
        return self.clock()

    def audit(self, type_: str, fields: dict) -> dict:
        """Append to priv.jsonl. Anything that stops the append is DENY_AUDIT_DOWN (retryable): privd refuses to act if it cannot record."""
        try:
            return self.priv_log.append(type_, fields)
        except (AuditDown, AuditCorrupt) as e:
            raise Deny("DENY_AUDIT_DOWN", f"priv log cannot be appended ({type(e).__name__})") from e

    def join_monitors(self, timeout: float = 30.0) -> None:
        for t in list(self.monitors):
            t.join(timeout)


class FileLock:
    """flock on a file in the root-only lock directory. `blocking=False` raises BlockingIOError when held."""

    def __init__(self, path: str, blocking: bool):
        self.path, self.blocking, self.fd = path, blocking, -1

    def __enter__(self):
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if self.blocking else fcntl.LOCK_NB))
        except BaseException:
            os.close(fd)
            raise
        self.fd = fd
        return self

    def __exit__(self, *a):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def job_lock_path(paths: Paths, job_id: str) -> str:
    if not _UUID.match(job_id):
        raise ValueError("job id must be a canonical uuid")
    return os.path.join(paths.locks, f"job-{job_id}.lock")


def work_dir_path(paths: Paths, job_id: str, attempt: int) -> str:
    if not _UUID.match(job_id) or isinstance(attempt, bool) or not isinstance(attempt, int) or not 1 <= attempt <= 1000:
        raise ValueError("bad job id / attempt")
    return os.path.join(paths.work, f"{job_id}-{attempt}")


def result_doc(*, attempt: int, status: str, reason_code: str | None, output: str, seq_range, plan_hash: str | None) -> dict:
    doc = {"attempt": attempt, "status": status, "reason_code": reason_code, "output": output[:4096], "audit_seq_range": seq_range, "plan_hash": plan_hash}
    protocol.validate_result(doc)
    return doc
