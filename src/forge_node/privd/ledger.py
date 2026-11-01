"""Durable execution ledger (Design 9.4): `ledger.sqlite` in the root-only state directory (stdlib sqlite3, WAL, synchronous=FULL).

Tables: exec (one row per job: the state machine below), rate_events, circuits, plans, t3_nonces (schema only; N7 uses it), target_locks, meta. All state changes are single
`BEGIN IMMEDIATE` transactions with compare-and-swap conditions on the current state, so concurrent deliveries, reconcile requests and retry claims are serialized by the database
itself in addition to the per-job file lock.

States: received -> started -> effect_done -> committed (terminal), reconciling, denied_retryable, denied (terminal), failed (terminal), aborted_safe (retryable with attempt+1),
indeterminate (blocks the target). `PRAGMA user_version` is the state schema (release switcher window, Design 13.E); schema changes are expand-only."""
import json
import os
import sqlite3
import threading
from dataclasses import dataclass

from .. import canon, protocol

STATE_SCHEMA = 1
IN_PROGRESS = ("received", "started", "effect_done", "reconciling")
TERMINAL = ("committed", "denied", "failed")
RESULT_STATES = ("committed", "denied", "failed", "aborted_safe", "indeterminate", "dry_run")
OPEN_STATES = ("received", "started", "effect_done", "reconciling", "indeterminate")      # reported in poll.open_jobs (protocol.NODE_OPEN_STATES)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS exec(
  job_id TEXT PRIMARY KEY, attempt INTEGER NOT NULL, op TEXT NOT NULL, effect_key TEXT NOT NULL, params_sha256 TEXT NOT NULL, state TEXT NOT NULL, fence INTEGER NOT NULL DEFAULT 1,
  worker_unit TEXT, worker_invocation_id TEXT, worker_started_at TEXT, worker_dir TEXT, plan_hash TEXT, pre_digest TEXT, post_digest TEXT, result_json TEXT,
  claimed_at TEXT NOT NULL, updated_at TEXT NOT NULL, delivery_seq INTEGER NOT NULL, dry_run INTEGER NOT NULL DEFAULT 0, eff_dry_run INTEGER NOT NULL DEFAULT 0,
  requester_identity TEXT);
CREATE INDEX IF NOT EXISTS exec_state ON exec(state);
CREATE TABLE IF NOT EXISTS rate_events(id INTEGER PRIMARY KEY AUTOINCREMENT, bucket TEXT NOT NULL, ts REAL NOT NULL, job_id TEXT);
CREATE INDEX IF NOT EXISTS rate_bucket_ts ON rate_events(bucket, ts);
CREATE TABLE IF NOT EXISTS circuits(op TEXT PRIMARY KEY, state TEXT NOT NULL, consecutive_failures INTEGER NOT NULL, since TEXT, acked_by TEXT);
CREATE TABLE IF NOT EXISTS plans(plan_hash TEXT PRIMARY KEY, job_id TEXT NOT NULL, op TEXT NOT NULL, params_sha256 TEXT NOT NULL, plan_json TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS t3_nonces(nonce TEXT PRIMARY KEY, job_id TEXT, used_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS target_locks(effect_key TEXT PRIMARY KEY, job_id TEXT NOT NULL, reason TEXT NOT NULL, since TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""


class LedgerError(Exception):
    pass


class SchemaTooNew(LedgerError):
    pass


class TargetBusy(LedgerError):
    """The atomic start was refused: the target is locked by an indeterminate job, or (mutating) another job's worker may still be running."""


@dataclass(frozen=True)
class Row:
    job_id: str
    attempt: int
    op: str
    effect_key: str
    params_sha256: str
    state: str
    fence: int
    worker_unit: str | None
    worker_invocation_id: str | None
    worker_started_at: str | None
    worker_dir: str | None
    plan_hash: str | None
    pre_digest: str | None
    post_digest: str | None
    result: dict | None
    claimed_at: str
    updated_at: str
    delivery_seq: int
    dry_run: bool                 # as requested by the job (part of the identity of the request)
    eff_dry_run: bool             # as executed (observe / dry_run_only force it)
    requester_identity: str | None


def _row(r) -> Row | None:
    if r is None:
        return None
    d = dict(r)
    res = d.pop("result_json")
    d["result"] = json.loads(res) if res else None
    d["dry_run"] = bool(d["dry_run"])
    d["eff_dry_run"] = bool(d["eff_dry_run"])
    return Row(**d)


@dataclass(frozen=True)
class Claim:
    kind: str            # new | in_progress | replay | retry | conflict
    row: Row


def _ts(dt) -> str:
    return protocol.fmt_ts(dt)


class Ledger:
    def __init__(self, path: str, *, read_only: bool = False):
        self.path = path
        self._lock = threading.RLock()
        if read_only:
            self._c = sqlite3.connect(f"file:{path}?mode=ro", uri=True, isolation_level=None, check_same_thread=False, timeout=30)
            self._c.row_factory = sqlite3.Row
            return
        fresh = not os.path.exists(path)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            st = os.fstat(fd)
            if st.st_nlink != 1 or st.st_mode & 0o077:
                raise LedgerError("ledger file must have one link and mode 0600")
        finally:
            os.close(fd)
        self._c = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=30)
        self._c.row_factory = sqlite3.Row
        self._c.execute("PRAGMA journal_mode=WAL")
        self._c.execute("PRAGMA synchronous=FULL")
        ver = self._c.execute("PRAGMA user_version").fetchone()[0]
        if ver > STATE_SCHEMA:
            raise SchemaTooNew(f"ledger schema {ver} is newer than this release supports ({STATE_SCHEMA})")
        self._c.executescript(_SCHEMA)
        if ver < STATE_SCHEMA:
            self._c.execute(f"PRAGMA user_version={STATE_SCHEMA}")

    def close(self):
        with self._lock:
            self._c.close()

    # -------------------------------------------------------------------------------------------------------------------- tx
    def _tx(self):
        return _Tx(self)

    # ------------------------------------------------------------------------------------------------------------------ meta
    def meta_get(self, k: str, default=None):
        with self._lock:
            r = self._c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
            return r[0] if r else default

    def meta_set(self, k: str, v: str) -> None:
        with self._tx() as c:
            c.execute("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))

    def meta_set_max_int(self, k: str, v: int) -> int:
        """Monotonic counters (lease seq): the stored value only ever grows."""
        with self._tx() as c:
            r = c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
            cur = int(r[0]) if r else 0
            if v > cur:
                c.execute("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))
                cur = v
            return cur

    # ----------------------------------------------------------------------------------------------------------------- exec
    def get(self, job_id: str) -> Row | None:
        with self._lock:
            return _row(self._c.execute("SELECT * FROM exec WHERE job_id=?", (job_id,)).fetchone())

    def claim(self, job_id: str, delivery_seq: int, op: str, effect_key: str, params_sha256: str, dry_run: bool, requester: str | None, now) -> Claim:
        """Atomic claim (Design 9.4). new: first time seen; in_progress: a non-terminal row exists (duplicate delivery); replay: terminal row, the stored result is returned;
        retry: denied_retryable (same attempt) or aborted_safe (attempt+1) re-claimed; conflict: same job_id, different request."""
        t = _ts(now)
        with self._tx() as c:
            r = _row(c.execute("SELECT * FROM exec WHERE job_id=?", (job_id,)).fetchone())
            if r is None:
                c.execute("INSERT INTO exec(job_id,attempt,op,effect_key,params_sha256,state,fence,claimed_at,updated_at,delivery_seq,dry_run,eff_dry_run,requester_identity) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                          (job_id, 1, op, effect_key, params_sha256, "received", 1, t, t, delivery_seq, int(dry_run), int(dry_run), requester))
                return Claim("new", _row(c.execute("SELECT * FROM exec WHERE job_id=?", (job_id,)).fetchone()))
            if r.op != op or r.params_sha256 != params_sha256 or r.dry_run != dry_run:
                return Claim("conflict", r)
            if r.state in IN_PROGRESS:
                return Claim("in_progress", r)
            if r.state == "denied_retryable":
                c.execute("UPDATE exec SET state='received', delivery_seq=?, updated_at=?, result_json=NULL WHERE job_id=? AND state='denied_retryable'", (max(delivery_seq, r.delivery_seq), t, job_id))
                return Claim("retry", _row(c.execute("SELECT * FROM exec WHERE job_id=?", (job_id,)).fetchone()))
            if r.state == "aborted_safe":
                c.execute("UPDATE exec SET state='received', attempt=attempt+1, delivery_seq=?, updated_at=?, result_json=NULL, worker_unit=NULL, worker_invocation_id=NULL, "
                          "worker_started_at=NULL, worker_dir=NULL, post_digest=NULL WHERE job_id=? AND state='aborted_safe'", (max(delivery_seq, r.delivery_seq), t, job_id))
                return Claim("retry", _row(c.execute("SELECT * FROM exec WHERE job_id=?", (job_id,)).fetchone()))
            return Claim("replay", r)                               # committed, denied, failed, indeterminate: the stored result stands

    def _cas(self, c, job_id: str, attempt: int, frm: tuple, sets: dict, now) -> bool:
        cols = ", ".join(f"{k}=?" for k in (*sets, "updated_at"))
        q = f"UPDATE exec SET {cols} WHERE job_id=? AND attempt=? AND state IN ({','.join('?' * len(frm))})"
        cur = c.execute(q, (*sets.values(), _ts(now), job_id, attempt, *frm))
        return cur.rowcount == 1

    def mark_started(self, job_id: str, attempt: int, worker_unit: str, worker_dir: str, pre_digest: str | None, plan_hash: str | None, eff_dry_run: bool, mutating: bool, now) -> Row:
        """Pipeline step 17: persisted BEFORE the worker starts (unit name, directory, current fence, whether it runs as a dry run). The target-lock and one-mutating-op-per-node checks are
        made IN THE SAME TRANSACTION as the received -> started transition, so two jobs cannot both pass them and both start (the checks of step 16 are only an early exit)."""
        with self._tx() as c:
            r = _row(c.execute("SELECT * FROM exec WHERE job_id=?", (job_id,)).fetchone())
            if r is None or r.attempt != attempt or r.state != "received":
                raise LedgerError("job is not in state received")
            if c.execute("SELECT 1 FROM target_locks WHERE effect_key=?", (r.effect_key,)).fetchone():
                raise TargetBusy("the target is locked by an indeterminate job")
            if mutating and c.execute("SELECT 1 FROM exec WHERE state IN ('started','effect_done','reconciling') AND job_id<>? LIMIT 1", (job_id,)).fetchone():
                raise TargetBusy("another mutating op is in flight on this node/target")
            if not self._cas(c, job_id, attempt, ("received",), {"state": "started", "worker_unit": worker_unit, "worker_dir": worker_dir, "pre_digest": pre_digest, "plan_hash": plan_hash,
                                                                  "eff_dry_run": int(eff_dry_run)}, now):
                raise LedgerError("job is not in state received")
            return _row(c.execute("SELECT * FROM exec WHERE job_id=?", (job_id,)).fetchone())

    def set_invocation(self, job_id: str, attempt: int, invocation_id: str, started_at) -> None:
        with self._tx() as c:
            c.execute("UPDATE exec SET worker_invocation_id=?, worker_started_at=?, updated_at=? WHERE job_id=? AND attempt=?", (invocation_id, _ts(started_at), _ts(started_at), job_id, attempt))

    def mark_effect_done(self, job_id: str, attempt: int, post_digest: str | None, now) -> bool:
        with self._tx() as c:
            return self._cas(c, job_id, attempt, ("started", "reconciling"), {"state": "effect_done", "post_digest": post_digest}, now)

    def finish(self, job_id: str, attempt: int, state: str, result: dict, now, *, frm: tuple = ("received", "started", "effect_done", "reconciling")) -> bool:
        """Terminal or retryable outcome (committed, failed, denied, denied_retryable, aborted_safe, indeterminate)."""
        if state not in ("committed", "failed", "denied", "denied_retryable", "aborted_safe", "indeterminate"):
            raise LedgerError(f"bad final state {state}")
        with self._tx() as c:
            return self._cas(c, job_id, attempt, frm, {"state": state, "result_json": canon.canonical_text(result)}, now)

    def begin_reconcile(self, job_id: str, now) -> Row | None:
        """Bump the fence and set `reconciling` in ONE transaction, before anything is looked at (Design 9.4 item 2). None if the row is not in an interruptible state."""
        with self._tx() as c:
            r = _row(c.execute("SELECT * FROM exec WHERE job_id=?", (job_id,)).fetchone())
            if r is None or r.state not in ("started", "effect_done", "reconciling"):
                return None
            c.execute("UPDATE exec SET state='reconciling', fence=fence+1, updated_at=? WHERE job_id=?", (_ts(now), job_id))
            return _row(c.execute("SELECT * FROM exec WHERE job_id=?", (job_id,)).fetchone())

    def open_rows(self) -> list[Row]:
        with self._lock:
            return [_row(r) for r in self._c.execute("SELECT * FROM exec WHERE state IN ('received','started','effect_done','reconciling','indeterminate') ORDER BY claimed_at")]

    def known_job_ids(self) -> set[str]:
        with self._lock:
            return {r[0] for r in self._c.execute("SELECT job_id FROM exec")}

    def nonterminal_count(self) -> int:
        with self._lock:
            return self._c.execute("SELECT COUNT(*) FROM exec WHERE state IN ('received','started','effect_done','reconciling')").fetchone()[0]

    def busy_with_other(self, job_id: str) -> Row | None:
        """One mutating op per node at a time (Design 9.2): another job whose worker may still be running."""
        with self._lock:
            return _row(self._c.execute("SELECT * FROM exec WHERE state IN ('started','effect_done','reconciling') AND job_id<>? LIMIT 1", (job_id,)).fetchone())

    def effect_busy(self, effect_key: str, job_id: str) -> Row | None:
        with self._lock:
            return _row(self._c.execute("SELECT * FROM exec WHERE effect_key=? AND state IN ('started','effect_done','reconciling') AND job_id<>? LIMIT 1", (effect_key, job_id)).fetchone())

    def prune_terminal(self, cutoff_ts: str) -> list[tuple[str, int]]:
        """Remove terminal rows (committed, denied, failed) last updated before `cutoff_ts` (Design 9.4: terminal rows are kept >= 90 days; a re-delivery of such a job is rejected by
        expiry anyway). Rows that can still change (received, started, effect_done, reconciling, denied_retryable, aborted_safe, indeterminate) are never touched. The condition is part of
        the DELETE itself, so a row that moved on in between is not removed."""
        with self._tx() as c:
            rows = c.execute("SELECT job_id, attempt FROM exec WHERE state IN ('committed','denied','failed') AND updated_at < ?", (cutoff_ts,)).fetchall()
            for r in rows:
                c.execute("DELETE FROM exec WHERE job_id=? AND state IN ('committed','denied','failed') AND updated_at < ?", (r["job_id"], cutoff_ts))
            return [(r["job_id"], r["attempt"]) for r in rows]

    def prune_plans(self, now_ts: float) -> int:
        with self._tx() as c:
            return c.execute("DELETE FROM plans WHERE expires_at <= ?", (now_ts,)).rowcount

    # ------------------------------------------------------------------------------------------------------------ target locks
    def lock_target(self, effect_key: str, job_id: str, reason: str, now) -> None:
        with self._tx() as c:
            c.execute("INSERT OR IGNORE INTO target_locks(effect_key, job_id, reason, since) VALUES(?,?,?,?)", (effect_key, job_id, reason, _ts(now)))

    def target_lock(self, effect_key: str) -> dict | None:
        with self._lock:
            r = self._c.execute("SELECT * FROM target_locks WHERE effect_key=?", (effect_key,)).fetchone()
            return dict(r) if r else None

    def unlock_target(self, effect_key: str, job_id: str) -> bool:
        with self._tx() as c:
            return c.execute("DELETE FROM target_locks WHERE effect_key=? AND job_id=?", (effect_key, job_id)).rowcount == 1

    # --------------------------------------------------------------------------------------------------------------- rate
    def rate_take(self, bucket: str, limits: list[tuple[int, int]], now_ts: float, job_id: str | None) -> bool:
        """Sliding-window buckets in ONE transaction: allowed only if every (max_events, window_s) holds; then the event is recorded. A clock that steps back cannot refund events:
        an event stays counted while ts > now - window, and ts of later events is never lowered."""
        with self._tx() as c:
            for mx, win in limits:
                n = c.execute("SELECT COUNT(*) FROM rate_events WHERE bucket=? AND ts > ?", (bucket, now_ts - win)).fetchone()[0]
                if n >= mx:
                    return False
            c.execute("INSERT INTO rate_events(bucket, ts, job_id) VALUES(?,?,?)", (bucket, now_ts, job_id))
            horizon = max((w for _, w in limits), default=0)
            if horizon:
                c.execute("DELETE FROM rate_events WHERE bucket=? AND ts <= ? AND ts <= ?", (bucket, now_ts - horizon - 86400, now_ts))
            return True

    # ------------------------------------------------------------------------------------------------------------- circuits
    def circuit(self, op: str) -> dict:
        with self._lock:
            r = self._c.execute("SELECT * FROM circuits WHERE op=?", (op,)).fetchone()
            return dict(r) if r else {"op": op, "state": "closed", "consecutive_failures": 0, "since": None, "acked_by": None}

    def circuit_record(self, op: str, ok: bool, threshold: int, now) -> str:
        """3 consecutive FAIL_* of an op flip it to open (= dry_run_only); only an acknowledgement closes it again."""
        with self._tx() as c:
            r = c.execute("SELECT * FROM circuits WHERE op=?", (op,)).fetchone()
            state = r["state"] if r else "closed"
            n = r["consecutive_failures"] if r else 0
            if state == "open":
                return "open"
            n = 0 if ok else n + 1
            state = "open" if n >= threshold else "closed"
            c.execute("INSERT INTO circuits(op,state,consecutive_failures,since,acked_by) VALUES(?,?,?,?,NULL) ON CONFLICT(op) DO UPDATE SET state=excluded.state, "
                      "consecutive_failures=excluded.consecutive_failures, since=CASE WHEN excluded.state='open' THEN excluded.since ELSE circuits.since END",
                      (op, state, n, _ts(now) if state == "open" else None))
            return state

    def circuit_ack(self, op: str, who: str) -> bool:
        with self._tx() as c:
            return c.execute("UPDATE circuits SET state='closed', consecutive_failures=0, acked_by=? WHERE op=? AND state='open'", (who, op)).rowcount == 1

    # --------------------------------------------------------------------------------------------------------------- plans
    def plan_put(self, plan_hash: str, job_id: str, op: str, params_sha256: str, plan: dict, now_ts: float, ttl_s: int = 1800) -> None:
        with self._tx() as c:
            c.execute("INSERT OR REPLACE INTO plans(plan_hash, job_id, op, params_sha256, plan_json, created_at, expires_at) VALUES(?,?,?,?,?,?,?)",
                      (plan_hash, job_id, op, params_sha256, canon.canonical_text(plan), now_ts, now_ts + ttl_s))

    def plan_get(self, plan_hash: str, now_ts: float) -> dict | None:
        with self._lock:
            r = self._c.execute("SELECT * FROM plans WHERE plan_hash=? AND expires_at > ?", (plan_hash, now_ts)).fetchone()
            if r is None:
                return None
            d = dict(r)
            d["plan"] = json.loads(d.pop("plan_json"))
            return d


class _Tx:
    def __init__(self, ledger: Ledger):
        self.l = ledger

    def __enter__(self):
        self.l._lock.acquire()
        try:
            self.l._c.execute("BEGIN IMMEDIATE")
        except BaseException:
            self.l._lock.release()
            raise
        return self.l._c

    def __exit__(self, et, ev, tb):
        try:
            self.l._c.execute("COMMIT" if et is None else "ROLLBACK")
        finally:
            self.l._lock.release()
        return False
