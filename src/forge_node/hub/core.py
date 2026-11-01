"""Hub-Kern (Design 3.2-3.5, 8.1, 9.1, 9.4): Lease- und Job-Signatur, Job-Warteschlange mit Idempotenz, Ergebnis-Spiegel, Audit-Senke mit Kettenpruefung,
Querpruefung gegen das privilegierte Log, Quarantaene. Kein HTTP hier (server.py) und kein Schreibzugriff auf STOP (killswitch.py ist nur lesend).

Gates a)-d): enqueue_job() und deliver_next() fragen forge_node.gates.decide() - in N1 ist damit jede Operation oberhalb T0 gesperrt (kein Job wird signiert)."""
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from psycopg.types.json import Jsonb

from .. import canon, chain, gates, protocol, redact
from ..protocol import ProtoError
from . import files, killswitch, params as params_mod

JOB_TTL_S = protocol.JOB_MAX_TTL_S
MAX_OPEN_JOBS_PER_NODE = 200
VERIFY_PAGE = 5000
FULL_VERIFY_EVERY = 1440          # Durchlaeufe (bei 60 s Takt: taeglich); dazwischen nur neue Records
# Ablehnungen, die der Agent selbst ausspricht, ohne dass privd je gefragt wurde (kein privd-Link, Agent-Audit unten, privd nicht erreichbar): es gibt keine priv-Spur, es wurde nichts ausgefuehrt
AGENT_LOCAL_DENIALS = frozenset({"DENY_TIER_DISABLED", "DENY_AUDIT_DOWN", "DENY_STALE_LEASE"})
_ACTIVE_STATES = ("issued", "in_progress")
TERMINAL = ("committed", "dry_run", "denied", "failed", "expired")


class JobDenied(Exception):
    """Der Hub signiert/queued diesen Job nicht. code = Reason-Code des Designs."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


class JobConflict(Exception):
    """Gleiche job_id, anderer Inhalt: der Effect-Key ist schon vergeben."""


class AuthError(Exception):
    pass


@dataclass
class JobRequest:
    node: str
    tier: int
    op: str
    params: dict = field(default_factory=dict)
    requester: dict = field(default_factory=lambda: {"identity": "meta", "planner_call_id": None, "run_id": None, "project": None})
    dry_run: bool = False
    plan_hash: str | None = None
    job_id: str | None = None
    owner_sig: str | None = None


@dataclass
class Enqueued:
    job_id: str
    state: str
    created: bool          # neue Zeile angelegt
    requeued: bool = False  # wiederholbarer Endzustand -> erneut zugestellt (Design 3.2: gleiche job_id)


class Signer:
    """Signiert Leases und Jobs mit dem Hub-Gate-Schluessel (Namespace forge-node-hub). Der Schluessel wird nur gelesen (Pfad aus der Konfiguration), nie erzeugt."""

    def __init__(self, key_path, key_id: str, ssh_keygen: str = "ssh-keygen"):
        self.key_path, self.key_id, self.ssh_keygen = key_path, key_id, ssh_keygen

    def seal(self, payload: dict) -> dict:
        return protocol.seal(payload, self.key_path, self.key_id, self.ssh_keygen)


def _floor(dt: datetime) -> datetime:
    return dt.astimezone(timezone.utc).replace(microsecond=0)


class Hub:
    def __init__(self, cfg, db, signer: Signer, clock=None, gate_set=gates.GATES, sleep=time.sleep):
        self.cfg, self.db, self.signer = cfg, db, signer
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.gates = gate_set
        self.sleep = sleep
        self._cursor: dict[tuple[str, str], tuple[int, str]] = {}
        self._passes = 0

    # ------------------------------------------------------------------------------------------------------------- nodes
    def authenticate(self, conn, node_id: str, cert_sha256: str) -> dict:
        """mTLS-Identitaet (Zertifikat-Fingerprint + SAN-Node) gegen die Registry: nur aktive Knoten, Fingerprint muss zur Zeile passen."""
        row = conn.execute("SELECT * FROM node.nodes WHERE node_id = %s", (node_id,)).fetchone()
        if row is None or row["status"] != "active" or row["cert_sha256"] != cert_sha256:
            raise AuthError("unknown, inactive or mismatching node certificate")
        return row

    def _node(self, conn, node_id: str, lock: bool = False) -> dict | None:
        return conn.execute("SELECT * FROM node.nodes WHERE node_id = %s" + (" FOR UPDATE" if lock else ""), (node_id,)).fetchone()

    # ------------------------------------------------------------------------------------------------------ hub audit chain
    def _lock_chain(self, conn, node: str, source: str):
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (f"fn-audit:{node}:{source}",))

    def _head(self, conn, node: str, source: str) -> tuple[int, str]:
        h = conn.execute("SELECT seq, hash FROM node.audit_heads WHERE node_id=%s AND source=%s", (node, source)).fetchone()
        return (h["seq"], h["hash"]) if h else (0, chain.GENESIS_HASH)

    def _insert_audit(self, conn, rec: dict, source: str, stored: dict, redacted: bool):
        conn.execute(
            "INSERT INTO node.audit (node_id, source, seq, ts, type, job_id, attempt, prev_hash, hash, redacted, record) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (rec["node"], source, rec["seq"], protocol.parse_ts(rec["ts"]), rec["type"], rec.get("job_id"), rec.get("attempt"), rec["prev_hash"], rec["hash"], redacted, Jsonb(stored)))

    def audit_hub(self, conn, node: str, type_: str, now: datetime, **fields):
        """Hub-eigene Kette (source='hub'); in der Transaktion des Aufrufers, serialisiert pro Knoten."""
        self._lock_chain(conn, node, "hub")
        seq, prev = self._head(conn, node, "hub")
        rec = chain.seal_record({"ts": protocol.fmt_ts(now), "node": node, "type": type_, **redact.redact_obj(fields)}, seq + 1, prev)
        self._insert_audit(conn, rec, "hub", rec, False)
        return rec

    def alert(self, conn, node: str, kind: str, key: str, detail: dict):
        conn.execute("INSERT INTO node.alerts (node_id, kind, dedupe_key, detail) VALUES (%s,%s,%s,%s) ON CONFLICT (node_id, kind, dedupe_key) DO NOTHING",
                     (node, kind, key[:200], Jsonb(redact.redact_obj(detail))))

    def quarantine(self, node: str, kind: str, key: str, detail: dict):
        """Eigene Transaktion: auch wenn die aufrufende Operation scheitert, bleibt die Quarantaene bestehen."""
        now = self.clock()
        with self.db.tx() as conn:
            row = conn.execute("UPDATE node.nodes SET quarantine=true, quarantine_reason=%s, quarantined_at=%s WHERE node_id=%s AND NOT quarantine RETURNING node_id",
                               (f"{kind}: {key}"[:300], now, node)).fetchone()
            self.alert(conn, node, kind, key, detail)
            if row:
                self.audit_hub(conn, node, "quarantine", now, reason=kind, key=key[:200])

    # --------------------------------------------------------------------------------------------------------------- leases
    def issue_lease(self, conn, node_id: str) -> dict:
        """Neue Lease mit streng steigender seq (persistent). STOP/Projekt-Stopps/Quarantaene werden hier gelesen; jeder Lesefehler => stop=true (fail closed)."""
        now = _floor(self.clock())
        row = conn.execute("UPDATE node.nodes SET lease_seq = lease_seq + 1 WHERE node_id = %s RETURNING lease_seq, quarantine", (node_id,)).fetchone()
        projects, ok = killswitch.stopped_projects(self.cfg.control_dir)
        stop = killswitch.stop_active(self.cfg.control_dir) or not ok or len(projects) > 256      # zu viele Projekt-Stopps passen nicht in die Lease: dann global stoppen (fail closed)
        projects = projects[:256]
        payload = {"typ": "lease", "v": protocol.PROTOCOL_VERSION, "node": node_id, "seq": row["lease_seq"], "issued_at": protocol.fmt_ts(now),
                   "valid_until": protocol.fmt_ts(now + timedelta(seconds=self.cfg.lease_valid_s)), "stop": stop, "stopped_projects": projects, "quarantine": bool(row["quarantine"])}
        return self.signer.seal(payload)

    # ------------------------------------------------------------------------------------------------------- job enqueueing
    def enqueue_job(self, req: JobRequest) -> Enqueued:
        """Autorisierung + Gates + Idempotenz; legt die Zeile `queued` an. Signiert wird erst bei der Zustellung (deliver_next), unter dem Dispatch-Lock."""
        try:
            return self._enqueue(req)
        except JobDenied as d:
            now = self.clock()
            try:
                with self.db.tx() as conn:
                    if self._node(conn, req.node) is not None:
                        self.audit_hub(conn, req.node, "denial", now, job_id=req.job_id, op=str(req.op)[:64], tier=req.tier if isinstance(req.tier, int) else None,
                                       reason_code=d.code, detail=d.detail[:200])
            except Exception:  # noqa: BLE001 - die Ablehnung selbst darf nie an einer Audit-Stoerung scheitern
                pass
            raise

    def _enqueue(self, req: JobRequest) -> Enqueued:
        now = self.clock()
        try:
            if not protocol.is_node_id(req.node):
                raise JobDenied("DENY_PARAM", "node id")
            if isinstance(req.tier, bool) or req.tier not in protocol.TIERS:
                raise JobDenied("DENY_PARAM", "tier")
            if not isinstance(req.op, str):
                raise JobDenied("DENY_OP_UNKNOWN", "op")
            req.job_id = protocol.check_uuid(req.job_id) if req.job_id else protocol.new_uuid()
            protocol.validate_requester(req.requester)
            if req.plan_hash is not None and not protocol.is_hex64(req.plan_hash):
                raise JobDenied("DENY_PARAM", "plan_hash")
            if req.owner_sig is not None and (not isinstance(req.owner_sig, str) or len(req.owner_sig) > 8192):
                raise JobDenied("DENY_PARAM", "owner_sig")
            if not isinstance(req.dry_run, bool):
                raise JobDenied("DENY_PARAM", "dry_run")
        except ProtoError as e:
            raise JobDenied("DENY_PARAM", e.detail or e.code) from e
        project = req.requester.get("project")
        with self.db.tx() as conn:
            node = self._node(conn, req.node)
            if node is None or node["status"] != "active":
                raise JobDenied("DENY_NOT_ALLOWLISTED", "node is not registered/active")
            try:
                if not isinstance(req.params, dict) or len(canon.canonical(req.params)) > params_mod.MAX_PARAMS_BYTES:
                    raise ProtoError("DENY_PARAM", "params must be a canonical JSON object <= 16 KiB")
                if req.op in gates.OPS and gates.OPS[req.op].tier == req.tier:
                    params_mod.validate(req.op, req.tier, req.params)
            except ProtoError as e:
                raise JobDenied(e.code, e.detail) from e
            except canon.CanonError as e:
                raise JobDenied("DENY_PARAM", str(e)[:200]) from e
            d = gates.decide(req.op, req.tier, node["profile"], req.params, self.gates)
            if not d.allowed:
                raise JobDenied(d.code, d.detail)
            if req.tier >= 1:
                if killswitch.stop_active(self.cfg.control_dir):
                    raise JobDenied("DENY_STOP", "global STOP is active")
                projects, ok = killswitch.stopped_projects(self.cfg.control_dir)
                if not ok or (project is not None and project in projects):
                    raise JobDenied("DENY_STOP", "project is stopped")
                if node["quarantine"]:
                    raise JobDenied("DENY_QUARANTINE", "node is quarantined")
            deadline = now + timedelta(seconds=self.cfg.queue_ttl_s)
            if conn.execute("SELECT count(*) AS n FROM node.jobs WHERE node_id=%s AND state IN ('queued','issued','in_progress')", (req.node,)).fetchone()["n"] >= MAX_OPEN_JOBS_PER_NODE:
                raise JobDenied("DENY_RATE", f"more than {MAX_OPEN_JOBS_PER_NODE} open jobs for this node")
            row = conn.execute(
                "INSERT INTO node.jobs (job_id, node_id, tier, op, params, dry_run, plan_hash, requester, project, owner_sig, state, queued_at, queue_deadline) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'queued',%s,%s) ON CONFLICT (job_id) DO NOTHING RETURNING job_id, state",
                (req.job_id, req.node, req.tier, req.op, Jsonb(req.params), req.dry_run, req.plan_hash, Jsonb(req.requester), project, req.owner_sig, now, deadline)).fetchone()
            if row is not None:
                self.audit_hub(conn, req.node, "job_issue", now, job_id=req.job_id, op=req.op, tier=req.tier, decision="queued", dry_run=req.dry_run, requester=req.requester)
                return Enqueued(req.job_id, "queued", created=True)
            old = conn.execute("SELECT * FROM node.jobs WHERE job_id=%s FOR UPDATE", (req.job_id,)).fetchone()
            same = (old["node_id"], old["tier"], old["op"], old["params"], old["dry_run"], old["plan_hash"], old["requester"]) == (req.node, req.tier, req.op, req.params, req.dry_run, req.plan_hash, req.requester)
            if not same:
                raise JobConflict("job_id already used for a different request")
            if old["state"] in ("denied_retryable", "aborted_safe"):
                # Design 3.2/9.4: wiederholbarer Endzustand -> dieselbe job_id wird erneut zugestellt (delivery_seq+1 bei der Zustellung)
                conn.execute("UPDATE node.jobs SET state='queued', queue_deadline=%s WHERE job_id=%s", (deadline, req.job_id))
                self.audit_hub(conn, req.node, "job_issue", now, job_id=req.job_id, op=req.op, tier=req.tier, decision="requeued", previous_state=old["state"])
                return Enqueued(req.job_id, "queued", created=False, requeued=True)
            return Enqueued(req.job_id, old["state"], created=False)

    def job_state(self, job_id: str) -> dict | None:
        with self.db.tx() as conn:
            return conn.execute(
                "SELECT job_id, node_id, tier, op, state, delivery_seq, result_status, result_reason, result_attempt, result_output, result_plan_hash, result_at, reported_state FROM node.jobs WHERE job_id=%s",
                (job_id,)).fetchone()

    # ------------------------------------------------------------------------------------------------------------- delivery
    def deliver_next(self, node_id: str) -> dict | None:
        """Naechsten Job fuer den Knoten signieren und zustellen (hoechstens einer). Ab T1: Dispatch-Lock von der letzten STOP-Pruefung bis zum Commit der Zeile `issued`."""
        now = _floor(self.clock())
        with self.db.tx() as conn:
            conn.execute("UPDATE node.jobs SET state='expired' WHERE node_id=%s AND state IN ('queued','issued') AND queue_deadline < %s AND (state='queued' OR expires_at < %s)",
                         (node_id, now, now))
            cand = conn.execute(
                "SELECT job_id, tier, op FROM node.jobs WHERE node_id=%s AND queue_deadline >= %s AND (state='queued' OR (state='issued' AND expires_at < %s AND reported_state IS NULL)) "
                "ORDER BY queued_at LIMIT 1", (node_id, now, now)).fetchone()
        if cand is None:
            return None
        if cand["tier"] == 0:
            return self._sign_delivery(node_id, cand["job_id"], now, locked=False)
        try:
            with killswitch.dispatch_lock(self.cfg.control_dir, self.cfg.lock_timeout_s):
                return self._sign_delivery(node_id, cand["job_id"], now, locked=True)
        except (killswitch.LockTimeout, OSError):
            return None       # fail closed: ohne Lock wird nichts signiert

    def _sign_delivery(self, node_id: str, job_id: str, now: datetime, locked: bool) -> dict | None:
        with self.db.tx() as conn:
            node = self._node(conn, node_id, lock=True)
            job = conn.execute("SELECT * FROM node.jobs WHERE job_id=%s FOR UPDATE", (job_id,)).fetchone()
            if node is None or node["status"] != "active" or job is None or job["node_id"] != node_id:
                return None
            if not (job["state"] == "queued" or (job["state"] == "issued" and job["expires_at"] < now and job["reported_state"] is None)):
                return None                                    # inzwischen zugestellt/ausgefuehrt
            if job["tier"] >= 1:
                projects, ok = killswitch.stopped_projects(self.cfg.control_dir)
                if killswitch.stop_active(self.cfg.control_dir) or not ok or (job["project"] and job["project"] in projects) or node["quarantine"]:
                    return None                                # bleibt queued; kein Signieren waehrend STOP/Quarantaene
                if node["clock_skew_s"] is not None and abs(node["clock_skew_s"]) > protocol.CLOCK_SKEW_MAX_S:
                    return None
            d = gates.decide(job["op"], job["tier"], node["profile"], job["params"], self.gates)
            if not d.allowed:
                conn.execute("UPDATE node.jobs SET state='expired' WHERE job_id=%s", (job_id,))
                self.audit_hub(conn, node_id, "denial", now, job_id=job_id, op=job["op"], tier=job["tier"], reason_code=d.code, detail=d.detail[:200], phase="delivery")
                return None
            seq = job["delivery_seq"] + 1
            payload = {"typ": "job", "v": protocol.PROTOCOL_VERSION, "job_id": str(job["job_id"]), "delivery_seq": seq, "node": node_id, "tier": job["tier"], "op": job["op"],
                       "params": job["params"], "dry_run": job["dry_run"], "plan_hash": job["plan_hash"], "requester": job["requester"],
                       "issued_at": protocol.fmt_ts(now), "expires_at": protocol.fmt_ts(now + timedelta(seconds=JOB_TTL_S)), "owner_sig": job["owner_sig"]}
            env = self.signer.seal(payload)
            conn.execute("UPDATE node.jobs SET state='issued', delivery_seq=%s, issued_at=%s, expires_at=%s, delivered_at=%s, signed=%s, reported_state=NULL WHERE job_id=%s",
                         (seq, now, now + timedelta(seconds=JOB_TTL_S), now, Jsonb(env), job_id))
            self.audit_hub(conn, node_id, "job_issue", now, job_id=str(job_id), op=job["op"], tier=job["tier"], decision="issued", delivery_seq=seq,
                           kid=env["key_id"], payload_sha256=canon.sha256_hex(env["payload"].encode("utf-8")))
            return env

    # ----------------------------------------------------------------------------------------------------------------- poll
    def poll(self, node_id: str, body: dict) -> dict:
        body = protocol.validate_poll_request(body)
        wait = min(body.get("wait_s", 0), self.cfg.long_poll_max_s)
        now = self.clock()
        reconcile = self._heartbeat(node_id, body, now)
        stop0 = killswitch.stop_active(self.cfg.control_dir)
        job = None
        deadline = time.monotonic() + wait
        while True:
            job = self.deliver_next(node_id)
            if job is not None or time.monotonic() >= deadline or killswitch.stop_active(self.cfg.control_dir) != stop0:
                break
            self.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
        with self.db.tx() as conn:
            lease = self.issue_lease(conn, node_id)
        return {"v": protocol.PROTOCOL_VERSION, "lease": lease, "jobs": [job] if job else [], "reconcile": reconcile,
                "policy_serial_latest": files.latest_serial(self.cfg.policy_dir, node_id), "server_time": protocol.fmt_ts(self.clock())}

    def _heartbeat(self, node_id: str, body: dict, now: datetime) -> list[str]:
        """Heartbeat, Meldungen des Node-Ledgers (open_jobs), Audit-Kopf-Abgleich, Reconcile-Liste."""
        skew = int((protocol.parse_ts(body["clock"]) - _floor(now)).total_seconds())
        bad_head = None
        with self.db.tx() as conn:
            self._node(conn, node_id, lock=True)
            conn.execute("UPDATE node.nodes SET last_seen=%s, agent_version=%s, policy_serial=%s, policy_sha256=%s, clock_skew_s=%s WHERE node_id=%s",
                         (now, body["version"], body["policy"]["serial"], body["policy"]["sha256"] or None, skew, node_id))
            if abs(skew) > protocol.CLOCK_SKEW_MAX_S:
                self.alert(conn, node_id, "clock_skew", now.strftime("%Y%m%d%H"), {"skew_s": skew})
            listed = set()
            for oj in body["open_jobs"]:
                listed.add(oj["job_id"])
                job = conn.execute("SELECT job_id, node_id, state FROM node.jobs WHERE job_id=%s FOR UPDATE", (oj["job_id"],)).fetchone()
                if job is None or job["node_id"] != node_id:
                    self.alert(conn, node_id, "unknown_open_job", oj["job_id"], {"job_id": oj["job_id"], "state": oj["state"]})
                    continue
                if job["state"] not in _ACTIVE_STATES:
                    continue
                conn.execute("UPDATE node.jobs SET reported_state=%s, reported_at=%s WHERE job_id=%s", (oj["state"], now, oj["job_id"]))
                if job["state"] == "issued":
                    conn.execute("UPDATE node.jobs SET state='in_progress' WHERE job_id=%s", (oj["job_id"],))
                if oj["state"] == "indeterminate":
                    conn.execute("UPDATE node.jobs SET state='indeterminate' WHERE job_id=%s AND state IN ('issued','in_progress')", (oj["job_id"],))
                    self.alert(conn, node_id, "indeterminate_job", oj["job_id"], {"job_id": oj["job_id"], "attempt": oj["attempt"]})
            conn.execute("UPDATE node.jobs SET reported_state=NULL WHERE node_id=%s AND state IN ('issued','in_progress') AND NOT (job_id = ANY(%s::uuid[]))", (node_id, list(listed)))
            # Audit-Koepfe: ein Node, dessen lokaler Kopf HINTER dem bestaetigten Hub-Kopf liegt oder bei gleicher seq einen anderen Hash hat, hat sein Log verloren/gegabelt
            for src, h in body["audit_heads"].items():
                hseq, hhash = self._head(conn, node_id, src)
                if h["seq"] < hseq or (h["seq"] == hseq and hseq > 0 and h["hash"] != hhash):
                    bad_head = (src, h["seq"], hseq)
            rows = conn.execute("SELECT job_id FROM node.jobs WHERE node_id=%s AND state='in_progress' AND delivered_at < %s "
                                "AND (reconcile_requested_at IS NULL OR reconcile_requested_at < %s) ORDER BY delivered_at LIMIT 8",
                                (node_id, now - timedelta(seconds=self.cfg.reconcile_after_s), now - timedelta(seconds=60))).fetchall()
            ids = [str(r["job_id"]) for r in rows]
            if ids:
                conn.execute("UPDATE node.jobs SET reconcile_requested_at=%s WHERE job_id = ANY(%s::uuid[])", (now, ids))
        if bad_head:
            self.quarantine(node_id, "chain_break", f"{bad_head[0]}-head-behind", {"source": bad_head[0], "node_seq": bad_head[1], "hub_seq": bad_head[2]})
        return ids

    # --------------------------------------------------------------------------------------------------------------- results
    def accept_result(self, node_id: str, job_id: str, body: dict) -> dict:
        protocol.check_uuid(job_id)
        body = protocol.validate_result(body)
        now = self.clock()
        new_state = protocol.result_to_state(body["status"], body["reason_code"])
        conflict = None
        with self.db.tx() as conn:
            job = conn.execute("SELECT * FROM node.jobs WHERE job_id=%s FOR UPDATE", (job_id,)).fetchone()
            if job is None or job["node_id"] != node_id:
                raise ProtoError("BAD_REQUEST", "unknown job")
            if job["state"] in ("queued", "expired") or job["delivery_seq"] < 1:
                raise ProtoError("BAD_REQUEST", "job was never delivered")
            same = (job["result_status"], job["result_reason"], job["result_attempt"]) == (body["status"], body["reason_code"], body["attempt"])
            if same and job["state"] == new_state:
                return {"ok": True, "state": job["state"], "duplicate": True}
            if job["state"] in TERMINAL:
                conflict = "different result for a terminal job"
            elif job["result_attempt"] is not None and body["attempt"] < job["result_attempt"]:
                return {"ok": True, "state": job["state"], "duplicate": True, "stale": True}
            if conflict is None:
                out = body["output"]
                out = redact.redact_full(out) if job["op"] == "logs.unit" else redact.redact_light(out)
                if len(out) > 65536:
                    out = out[:65536]
                conn.execute(
                    "UPDATE node.jobs SET state=%s, result_status=%s, result_reason=%s, result_attempt=%s, result_output=%s, result_plan_hash=%s, result_seq_lo=%s, result_seq_hi=%s, result_at=%s, "
                    "reported_state=NULL WHERE job_id=%s",
                    (new_state, body["status"], body["reason_code"], body["attempt"], out, body["plan_hash"], (body["audit_seq_range"] or [None, None])[0],
                     (body["audit_seq_range"] or [None, None])[1], now, job_id))
                self.audit_hub(conn, node_id, "job_result", now, job_id=job_id, attempt=body["attempt"], status=body["status"], reason_code=body["reason_code"], state=new_state,
                               output_sha256=canon.sha256_hex(body["output"].encode("utf-8")))
                if new_state == "indeterminate":
                    self.alert(conn, node_id, "indeterminate_job", job_id, {"job_id": job_id, "attempt": body["attempt"]})
        if conflict:
            self.quarantine(node_id, "result_conflict", job_id, {"job_id": job_id, "why": conflict})
            raise ProtoError("BAD_REQUEST", "conflicting result")
        return {"ok": True, "state": new_state, "duplicate": False}

    # ----------------------------------------------------------------------------------------------------------- audit sink
    def ingest_audit(self, node_id: str, body: dict) -> dict:
        """Batch eines Node-Logs (agent|priv). Prueft je Record Struktur, Hash, seq-Lueckenlosigkeit und prev_hash gegen den gespeicherten Kopf; ein Bruch
        quarantaeniert den Node (nach dem Commit des gueltigen Praefixes). Antwort: hoechste bestaetigte seq je Quelle."""
        if not isinstance(body, dict) or set(body) != {"source", "records"} or body["source"] not in ("agent", "priv") or not isinstance(body["records"], list):
            raise ProtoError("BAD_REQUEST", "audit batch: {source: agent|priv, records: [...]}")
        source, records = body["source"], body["records"]
        if not records or len(records) > protocol.MAX_AUDIT_BATCH:
            raise ProtoError("BAD_REQUEST", f"1..{protocol.MAX_AUDIT_BATCH} records per batch")
        violation = None
        stored = 0
        with self.db.tx() as conn:
            self._lock_chain(conn, node_id, source)
            seq, prev = self._head(conn, node_id, source)
            for rec in records:
                try:
                    chain.validate_record(rec, node_id, source)
                except chain.RecordError as e:
                    violation = ("chain_break", f"{source}-malformed", {"source": source, "why": str(e)[:200]}, rec.get("seq") if isinstance(rec, dict) else None)
                    break
                if rec["seq"] <= seq:
                    old = conn.execute("SELECT hash FROM node.audit WHERE node_id=%s AND source=%s AND seq=%s", (node_id, source, rec["seq"])).fetchone()
                    if old is None or old["hash"] != rec["hash"]:
                        violation = ("chain_break", f"{source}-fork-{rec['seq']}", {"source": source, "seq": rec["seq"], "why": "record differs from the stored one"}, rec["seq"])
                        break
                    continue                                    # Wiederholung eines gespeicherten Records
                if rec["seq"] != seq + 1:
                    violation = ("audit_gap", f"{source}-gap-{seq + 1}", {"source": source, "expected": seq + 1, "got": rec["seq"]}, rec["seq"])
                    break
                if rec["prev_hash"] != prev:
                    violation = ("chain_break", f"{source}-prev-{rec['seq']}", {"source": source, "seq": rec["seq"], "why": "prev_hash does not match the stored head"}, rec["seq"])
                    break
                if chain.record_hash(rec) != rec["hash"]:
                    violation = ("chain_break", f"{source}-hash-{rec['seq']}", {"source": source, "seq": rec["seq"], "why": "hash does not match content"}, rec["seq"])
                    break
                clean = redact.redact_obj(rec)
                self._insert_audit(conn, rec, source, clean, clean != rec)
                seq, prev = rec["seq"], rec["hash"]
                stored += 1
        if violation:
            kind, key, detail, bad_seq = violation
            self.quarantine(node_id, kind, key, detail)
        with self.db.tx() as conn:
            hseq, _ = self._head(conn, node_id, source)
        out = {"ok": violation is None, "acked": {source: hseq}, "stored": stored}
        if violation:
            out["rejected"] = {"seq": violation[3], "reason": violation[1]}
        return out

    # -------------------------------------------------------------------------------------------------------- verification
    def verify_chains(self, node_id: str, full: bool = True) -> list[str]:
        """Rechnet die gespeicherten Ketten neu (hash/prev/seq), seitenweise. full=False setzt hinter dem zuletzt geprueften Record fort (Cursor im Prozess).
        Zeilen mit redacted=true koennen den Hash nicht mehr belegen: dort nur Verkettung."""
        problems: list[str] = []
        for source in ("agent", "priv", "hub"):
            seq, prev = (1, chain.GENESIS_HASH) if full else self._cursor.get((node_id, source), (1, chain.GENESIS_HASH))
            broken = False
            while not broken:
                with self.db.tx() as conn:
                    rows = conn.execute("SELECT seq, prev_hash, hash, redacted, record FROM node.audit WHERE node_id=%s AND source=%s AND seq >= %s ORDER BY seq LIMIT %s",
                                        (node_id, source, seq, VERIFY_PAGE)).fetchall()
                for r in rows:
                    rec = r["record"]
                    if r["seq"] != seq:
                        problems.append(f"{source}: seq gap, expected {seq} got {r['seq']}")
                    elif r["prev_hash"] != prev:
                        problems.append(f"{source}: seq {seq} prev_hash broken")
                    elif not r["redacted"] and chain.record_hash(rec) != r["hash"]:
                        problems.append(f"{source}: seq {seq} content does not match its hash")
                    elif rec.get("seq") != r["seq"] or rec.get("hash") != r["hash"] or rec.get("prev_hash") != r["prev_hash"]:
                        problems.append(f"{source}: seq {seq} record/columns disagree")
                    else:
                        prev, seq = r["hash"], seq + 1
                        continue
                    broken = True
                    break
                if len(rows) < VERIFY_PAGE:
                    break
            if not broken:
                self._cursor[(node_id, source)] = (seq, prev)
            else:
                self._cursor.pop((node_id, source), None)
        return problems

    def crosscheck(self, node_id: str) -> list[dict]:
        """Querpruefung Hub-Jobs <-> privilegiertes Log (Design 8.1). Aufzeichnungen, die juenger als crosscheck_grace_s sind, zaehlen nicht (Audit-Versand ist asynchron).
        Fehlt zu einem ausgefuehrten T1+-Job die priv-Spur, oder verweist eine priv-Spur auf einen unbekannten Job: Anomalie => Quarantaene. Intent ohne Abschluss > 10 min: Alert."""
        now = self.clock()
        cutoff = now - timedelta(seconds=self.cfg.crosscheck_grace_s)
        anomalies: list[dict] = []
        with self.db.tx() as conn:
            jobs = conn.execute("SELECT job_id, tier, op, state, result_status, result_reason, result_attempt FROM node.jobs WHERE node_id=%s AND tier >= 1 AND result_at IS NOT NULL AND result_at < %s", (node_id, cutoff)).fetchall()
            for j in jobs:
                recs = conn.execute("SELECT type, attempt FROM node.audit WHERE node_id=%s AND source='priv' AND job_id=%s", (node_id, j["job_id"])).fetchall()
                att = j["result_attempt"]
                # Design 8.1: Zuordnung ueber job_id UND attempt. Records anderer Versuche zaehlen nicht; nur ein `denial` vor dem Claim darf ohne attempt sein.
                types = {r["type"] for r in recs if r["attempt"] == att or (r["type"] == "denial" and r["attempt"] is None)}
                st = j["result_status"]
                if st in ("committed", "failed", "aborted_safe", "indeterminate"):
                    ok = "intent" in types and bool(types & {"result", "recovery"})
                    if not ok and st == "failed" and j["result_reason"] == "FAIL_PRECHECK":
                        ok = "denial" in types and "intent" not in types              # failed before any intent existed (nothing was started): privd recorded a denial, not intent+result
                elif st == "dry_run":
                    ok = bool(types & {"intent", "result"})
                else:                                                                 # denied
                    ok = bool(types & {"denial", "result"})
                    if not ok and not types and j["result_reason"] in AGENT_LOCAL_DENIALS:
                        ok = True                                                     # the agent denied it itself (no audit log / no privd link / privd unreachable): nothing reached privd, nothing ran
                if not ok:
                    anomalies.append({"kind": "crosscheck_mismatch", "key": f"missing-{j['job_id']}", "detail": {"job_id": str(j["job_id"]), "hub_status": st, "hub_attempt": att, "priv_types": sorted(types), "priv_attempts": sorted({r["attempt"] for r in recs if r["attempt"] is not None})}})
            orphans = conn.execute(
                "SELECT DISTINCT a.job_id FROM node.audit a LEFT JOIN node.jobs j ON j.job_id=a.job_id AND j.node_id=a.node_id "
                "WHERE a.node_id=%s AND a.source='priv' AND a.job_id IS NOT NULL AND a.type IN ('intent','result','recovery','denial') AND j.job_id IS NULL AND a.ts < %s", (node_id, cutoff)).fetchall()
            for o in orphans:
                anomalies.append({"kind": "crosscheck_mismatch", "key": f"orphan-{o['job_id']}", "detail": {"job_id": str(o["job_id"]), "why": "priv record without a hub job"}})
            opens = conn.execute(
                "SELECT i.job_id, i.attempt FROM node.audit i WHERE i.node_id=%s AND i.source='priv' AND i.type='intent' AND i.ts < %s AND NOT EXISTS ("
                "SELECT 1 FROM node.audit r WHERE r.node_id=i.node_id AND r.source='priv' AND r.job_id=i.job_id AND r.type IN ('result','recovery') AND COALESCE(r.attempt,0) >= COALESCE(i.attempt,0))",
                (node_id, now - timedelta(minutes=10))).fetchall()
            for o in opens:
                self.alert(conn, node_id, "intent_open", f"{o['job_id']}-{o['attempt']}", {"job_id": str(o["job_id"]), "attempt": o["attempt"]})
        for a in anomalies:
            self.quarantine(node_id, a["kind"], a["key"], a["detail"])
        return anomalies

    def verify_node(self, node_id: str, full: bool = True) -> dict:
        problems = self.verify_chains(node_id, full)
        for p in problems:
            self.quarantine(node_id, "chain_break", "verify-" + p[:120], {"why": p})
        return {"chain_problems": problems, "crosscheck": self.crosscheck(node_id)}

    def run_verification(self) -> dict:
        """Periodische Pruefung aller aktiven Knoten + Heartbeat-Verlust (> 5 min) + Partitionen fuer die naechsten Monate."""
        now = self.clock()
        out = {}
        with self.db.tx() as conn:
            nodes = [r["node_id"] for r in conn.execute("SELECT node_id FROM node.nodes WHERE status='active'")]
            for r in conn.execute("SELECT node_id, last_seen FROM node.nodes WHERE status='active' AND last_seen IS NOT NULL AND last_seen < %s", (now - timedelta(minutes=5),)):
                self.alert(conn, r["node_id"], "heartbeat_lost", r["last_seen"].strftime("%Y%m%d%H%M")[:11], {"last_seen": protocol.fmt_ts(r["last_seen"])})
            for i in range(0, 4):
                m = (now.replace(day=1) + timedelta(days=32 * i)).replace(day=1).date()
                conn.execute("SELECT node.audit_ensure_partition(%s)", (m,))
        full = self._passes % FULL_VERIFY_EVERY == 0
        self._passes += 1
        for n in nodes:
            out[n] = self.verify_node(n, full)
        return out
