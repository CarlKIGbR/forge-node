"""Wire protocol (Design 3.2, 3.4): Lease, Job, Poll, Result, Audit-Batch; hub-signierte Huellen und ihre Pruefung.

Diese Bibliothek ist stdlib-only und wird von Hub (Signieren) UND Node (Pruefen, Slices N2/N3) benutzt. Die Pruefer sind hier, damit Signieren und Verifizieren
gegen dieselbe Definition getestet werden. Alles fail-closed: jede Abweichung wirft ProtoError mit einem Reason-Code aus dem Design."""
import re
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

from . import PROTOCOL_VERSION, canon, sshsig

MAX_BODY_BYTES = 1024 * 1024
LEASE_MAX_VALID_S = 60
JOB_MAX_TTL_S = 120
CLOCK_SKEW_MAX_S = 60
LONG_POLL_MAX_S = 30
MAX_OUTPUT_BYTES = 64 * 1024
MAX_AUDIT_BATCH = 500
MAX_PAYLOAD_BYTES = 64 * 1024

REASON_CODES = frozenset("""DENY_STOP DENY_LOCAL_STOP DENY_QUARANTINE DENY_STALE_LEASE DENY_CLOCK DENY_AUDIT_DOWN DENY_JOB_SIGNATURE DENY_JOB_EXPIRED DENY_POLICY_INVALID
DENY_TIER_DISABLED DENY_OP_UNKNOWN DENY_OP_MODE DENY_PARAM DENY_PROTECTED DENY_NOT_ALLOWLISTED DENY_WINDOW DENY_RATE DENY_CIRCUIT_OPEN DENY_STALE_PLAN
DENY_NEEDS_OWNER_SIG DENY_TARGET_LOCKED DENY_QUOTA DENY_NO_QUOTA_BACKEND DENY_NO_WORKLOAD_LIMITS DENY_CLOSURE_CHANGED FAIL_PRECHECK FAIL_EXEC FAIL_POSTCHECK FAIL_FENCED INDETERMINATE""".split())
# Wiederholbar: eine spaetere Zustellung derselben job_id kann gelingen. Alle anderen Ablehnungen sind fuer diese job_id endgueltig.
RETRYABLE_DENIALS = frozenset(f"DENY_{x}" for x in "STOP LOCAL_STOP QUARANTINE STALE_LEASE CLOCK AUDIT_DOWN WINDOW RATE CIRCUIT_OPEN TARGET_LOCKED".split())
RESULT_STATUSES = frozenset({"committed", "dry_run", "denied", "failed", "aborted_safe", "indeterminate"})
# Ledger-Zustaende, die der Node in open_jobs meldet (nicht terminal, Design 9.4)
NODE_OPEN_STATES = frozenset({"received", "started", "effect_done", "reconciling", "indeterminate"})
TIERS = (0, 1, 2, 3)

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_NODE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}\Z")
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}\Z")
_OP_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}\Z")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}\Z")
_VER_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}\Z")
_KEYID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}\Z")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\Z")


class ProtoError(Exception):
    """code = Reason-Code des Designs (oder 'BAD_REQUEST' fuer Schemafehler auf dem Hub)."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail
        self.job_id = None                  # set by verify_job when the signature HAD verified (a hub-signed job that is merely expired / not yet valid)


# ----------------------------------------------------------------------------------------------------------------- time
def fmt_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(s) -> datetime:
    if not isinstance(s, str) or not _TS_RE.match(s):
        raise ProtoError("BAD_REQUEST", "timestamp must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as e:
        raise ProtoError("BAD_REQUEST", "invalid timestamp") from e


# ------------------------------------------------------------------------------------------------------ small validators
def _bad(msg: str):
    raise ProtoError("BAD_REQUEST", msg)


def _keys(obj, required: set, optional: set = frozenset(), what: str = "object"):
    if not isinstance(obj, dict):
        _bad(f"{what} must be an object")
    missing = required - obj.keys()
    extra = obj.keys() - required - optional
    if missing:
        _bad(f"{what}: missing {sorted(missing)}")
    if extra:
        _bad(f"{what}: unknown {sorted(extra)}")


def _int(v, lo, hi, what):
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        _bad(f"{what} must be an integer in {lo}..{hi}")
    return v


def _str(v, what, rx=None, maxlen=256, empty=False):
    if not isinstance(v, str) or (not empty and not v) or len(v) > maxlen or (rx is not None and not rx.match(v)):
        _bad(f"{what} invalid")
    return v


def _bool(v, what):
    if not isinstance(v, bool):
        _bad(f"{what} must be a boolean")
    return v


def is_node_id(s) -> bool:
    return isinstance(s, str) and bool(_NODE_RE.match(s))


def is_slug(s) -> bool:
    return isinstance(s, str) and bool(_SLUG_RE.match(s))


def is_hex64(s) -> bool:
    return isinstance(s, str) and bool(_HEX64_RE.match(s))


def is_version(s) -> bool:
    return isinstance(s, str) and bool(_VER_RE.match(s))


def new_uuid() -> str:
    return str(uuid.uuid4())


def check_uuid(s, what="job_id") -> str:
    if not isinstance(s, str):
        _bad(f"{what} must be a uuid")
    try:
        u = uuid.UUID(s)
    except ValueError as e:
        raise ProtoError("BAD_REQUEST", f"{what} must be a uuid") from e
    if str(u) != s:
        _bad(f"{what} must be a canonical lowercase uuid")
    return s


# ------------------------------------------------------------------------------------------------------ lease and job
def validate_lease(p: dict) -> dict:
    _keys(p, {"typ", "v", "node", "seq", "issued_at", "valid_until", "stop", "stopped_projects", "quarantine"}, what="lease")
    if p["typ"] != "lease" or p["v"] != PROTOCOL_VERSION:
        _bad("lease: wrong typ/version")
    _str(p["node"], "lease.node", _NODE_RE)
    _int(p["seq"], 1, canon.MAX_INT, "lease.seq")
    a, b = parse_ts(p["issued_at"]), parse_ts(p["valid_until"])
    if not a < b <= a + timedelta(seconds=LEASE_MAX_VALID_S):
        _bad(f"lease: valid_until must be within {LEASE_MAX_VALID_S} s after issued_at")
    _bool(p["stop"], "lease.stop")
    _bool(p["quarantine"], "lease.quarantine")
    sp = p["stopped_projects"]
    if not isinstance(sp, list) or len(sp) > 256 or any(not is_slug(x) for x in sp) or sp != sorted(set(sp)):
        _bad("lease.stopped_projects must be a sorted list of unique slugs")
    return p


def validate_requester(r: dict) -> dict:
    _keys(r, {"identity", "planner_call_id", "run_id", "project"}, what="requester")
    _str(r["identity"], "requester.identity", _SLUG_RE)
    for k in ("planner_call_id", "run_id"):
        if r[k] is not None:
            _int(r[k], 0, canon.MAX_INT, f"requester.{k}")
    if r["project"] is not None:
        _str(r["project"], "requester.project", _SLUG_RE)
    return r


def validate_job(p: dict) -> dict:
    _keys(p, {"typ", "v", "job_id", "delivery_seq", "node", "tier", "op", "params", "dry_run", "plan_hash", "requester", "issued_at", "expires_at", "owner_sig"}, what="job")
    if p["typ"] != "job" or p["v"] != PROTOCOL_VERSION:
        _bad("job: wrong typ/version")
    check_uuid(p["job_id"])
    _int(p["delivery_seq"], 1, 1_000_000, "job.delivery_seq")
    _str(p["node"], "job.node", _NODE_RE)
    if p["tier"] not in TIERS or isinstance(p["tier"], bool):
        _bad("job.tier invalid")
    _str(p["op"], "job.op", _OP_RE)
    if not isinstance(p["params"], dict):
        _bad("job.params must be an object")
    _bool(p["dry_run"], "job.dry_run")
    if p["plan_hash"] is not None and not is_hex64(p["plan_hash"]):
        _bad("job.plan_hash must be sha256 hex")
    validate_requester(p["requester"])
    a, b = parse_ts(p["issued_at"]), parse_ts(p["expires_at"])
    if not a < b <= a + timedelta(seconds=JOB_MAX_TTL_S):
        _bad(f"job: expires_at must be within {JOB_MAX_TTL_S} s after issued_at")
    if p["owner_sig"] is not None and not isinstance(p["owner_sig"], str):
        _bad("job.owner_sig must be a string or null")
    return p


@dataclass(frozen=True)
class GateKey:
    id: str
    pub: str
    not_after: date

    def expired_at(self, now: datetime) -> bool:
        return now.astimezone(timezone.utc).date() > self.not_after


def parse_gate_keys(raw) -> dict[str, GateKey]:
    """hub_gate_keys aus der signierten Policy: [{id, pub, not_after:'YYYY-MM-DD'}]."""
    if not isinstance(raw, list) or not raw:
        raise ProtoError("DENY_POLICY_INVALID", "hub_gate_keys must be a non-empty list")
    out: dict[str, GateKey] = {}
    for k in raw:
        try:
            _keys(k, {"id", "pub", "not_after"}, what="hub_gate_key")
            _str(k["id"], "hub_gate_key.id", _KEYID_RE, 64)
            _str(k["not_after"], "hub_gate_key.not_after", _DATE_RE, 10)
            na = date.fromisoformat(k["not_after"])
            pub = sshsig.normalize_pub(k["pub"])
        except (ProtoError, ValueError, sshsig.SigError) as e:
            raise ProtoError("DENY_POLICY_INVALID", f"hub_gate_keys: {e}") from e
        if k["id"] in out:
            raise ProtoError("DENY_POLICY_INVALID", "duplicate hub gate key id")
        out[k["id"]] = GateKey(k["id"], pub, na)
    return out


# --------------------------------------------------------------------------------------------------- signed envelopes
def seal(payload: dict, key_path, key_id: str, ssh_keygen: str = "ssh-keygen") -> dict:
    """{'payload': kanonischer JSON-Text, 'sig': armored, 'key_id'}. typ steckt im Payload (ein Lease ist nie als Job gueltig)."""
    if payload.get("typ") not in ("lease", "job"):
        raise ProtoError("BAD_REQUEST", "payload.typ must be lease or job")
    (validate_lease if payload["typ"] == "lease" else validate_job)(payload)
    text = canon.canonical_text(payload)
    if len(text) > MAX_PAYLOAD_BYTES:
        raise ProtoError("BAD_REQUEST", "payload too large")
    try:
        sig = sshsig.sign(text.encode("utf-8"), key_path, sshsig.NS_HUB, ssh_keygen)
    except sshsig.SigError as e:
        raise ProtoError("DENY_JOB_SIGNATURE", f"cannot sign: {e}") from e
    return {"payload": text, "sig": sig, "key_id": key_id}


def open_envelope(env, gate_keys: dict[str, GateKey], expect_typ: str, now: datetime, ssh_keygen: str) -> dict:
    """Prueft Schluessel-Liste (Revokation = Schluessel fehlt in der Policy), Ablauf des Schluessels, Signatur im Namespace forge-node-hub,
    Kanonizitaet des Textes, typ und Schema. Liefert den Payload."""
    code = "DENY_STALE_LEASE" if expect_typ == "lease" else "DENY_JOB_SIGNATURE"
    try:
        if not isinstance(env, dict) or set(env) != {"payload", "sig", "key_id"}:
            raise ProtoError(code, "malformed envelope")
        text, sig, key_id = env["payload"], env["sig"], env["key_id"]
        if not isinstance(text, str) or not isinstance(sig, str) or not isinstance(key_id, str) or len(text) > MAX_PAYLOAD_BYTES:
            raise ProtoError(code, "malformed envelope")
        key = gate_keys.get(key_id)
        if key is None:
            raise ProtoError(code, "gate key not listed in policy")
        if key.expired_at(now):
            raise ProtoError(code, "gate key expired")
        try:
            sshsig.verify(text.encode("utf-8"), sig, sshsig.NS_HUB, key.id, sshsig.allowed_signers_text([(key.id, key.pub, sshsig.NS_HUB)]), ssh_keygen)
        except sshsig.SigError as e:
            raise ProtoError(code, "bad signature") from e
        if not canon.is_canonical(text):
            raise ProtoError(code, "payload not canonical")
        p = canon.loads(text)
        if not isinstance(p, dict) or p.get("typ") != expect_typ:
            raise ProtoError(code, "wrong payload type")
        (validate_lease if expect_typ == "lease" else validate_job)(p)
        return p
    except canon.CanonError as e:
        raise ProtoError(code, f"payload: {e}") from e
    except ProtoError as e:
        if e.code == "BAD_REQUEST":
            raise ProtoError(code, e.detail) from e
        raise


def verify_lease(env, gate_keys: dict[str, GateKey], node: str, now: datetime, last_seq: int, ssh_keygen: str) -> dict:
    """privd-Seite (Pipeline Schritt 3 und 5): nur neuere seq, nur vor valid_until, Skew gegen issued_at <= 60 s."""
    p = open_envelope(env, gate_keys, "lease", now, ssh_keygen)
    if p["node"] != node:
        raise ProtoError("DENY_STALE_LEASE", "lease for another node")
    if p["seq"] <= last_seq:
        raise ProtoError("DENY_STALE_LEASE", "lease seq not newer")
    if now > parse_ts(p["valid_until"]):
        raise ProtoError("DENY_STALE_LEASE", "lease expired")
    if abs((now - parse_ts(p["issued_at"])).total_seconds()) > CLOCK_SKEW_MAX_S:
        raise ProtoError("DENY_CLOCK", "clock skew vs lease issued_at")
    return p


def verify_job(env, gate_keys: dict[str, GateKey], node: str, now: datetime, ssh_keygen: str) -> dict:
    """privd-Seite (Schritt 2): Signatur, node, issued_at <= now <= expires_at. 'Noch nicht gueltig' toleriert denselben Skew (60 s), den Schritt 5 erlaubt; Ablauf ist strikt."""
    p = open_envelope(env, gate_keys, "job", now, ssh_keygen)
    if p["node"] != node:
        raise ProtoError("DENY_JOB_SIGNATURE", "job for another node")
    for bad, code, detail in ((now > parse_ts(p["expires_at"]), "DENY_JOB_EXPIRED", "job expired"),
                               (now < parse_ts(p["issued_at"]) - timedelta(seconds=CLOCK_SKEW_MAX_S), "DENY_CLOCK", "job issued in the future")):
        if bad:
            e = ProtoError(code, detail)
            e.job_id = p["job_id"]
            raise e
    return p


# ------------------------------------------------------------------------------------------------- poll / result / audit
def validate_poll_request(b: dict) -> dict:
    _keys(b, {"v", "version", "policy", "clock", "spool_depth", "audit_heads", "open_jobs"}, {"wait_s"}, "poll")
    if b["v"] != PROTOCOL_VERSION:
        _bad("poll: unsupported protocol version")
    _str(b["version"], "version", _VER_RE, 64)
    _keys(b["policy"], {"serial", "sha256"}, what="policy")
    _int(b["policy"]["serial"], 0, 10**9, "policy.serial")
    if b["policy"]["sha256"] != "" and not is_hex64(b["policy"]["sha256"]):
        _bad("policy.sha256 invalid")
    parse_ts(b["clock"])
    _int(b["spool_depth"], 0, 10**9, "spool_depth")
    heads = b["audit_heads"]
    if not isinstance(heads, dict) or not heads.keys() <= {"agent", "priv"}:
        _bad("audit_heads: only agent/priv")
    for src, h in heads.items():
        _keys(h, {"seq", "hash"}, what=f"audit_heads.{src}")
        _int(h["seq"], 0, canon.MAX_INT, "audit_heads.seq")
        if not is_hex64(h["hash"]):
            _bad("audit_heads.hash invalid")
    oj = b["open_jobs"]
    if not isinstance(oj, list) or len(oj) > 64:
        _bad("open_jobs must be a list (<= 64)")
    for j in oj:
        _keys(j, {"job_id", "state", "attempt"}, what="open_jobs[]")
        check_uuid(j["job_id"])
        if j["state"] not in NODE_OPEN_STATES:
            _bad("open_jobs.state invalid")
        _int(j["attempt"], 1, 1000, "open_jobs.attempt")
    if "wait_s" in b:
        _int(b["wait_s"], 0, LONG_POLL_MAX_S, "wait_s")
    return b


def validate_result(b: dict) -> dict:
    _keys(b, {"attempt", "status", "reason_code", "output", "audit_seq_range", "plan_hash"}, what="result")
    _int(b["attempt"], 1, 1000, "attempt")
    if b["status"] not in RESULT_STATUSES:
        _bad("status invalid")
    rc = b["reason_code"]
    if rc is not None and rc not in REASON_CODES:
        _bad("reason_code unknown")
    if b["status"] in ("committed", "dry_run"):
        if rc is not None:
            _bad("reason_code must be null for committed/dry_run")
    elif rc is None:
        _bad("reason_code required for this status")
    if b["status"] == "denied" and not rc.startswith("DENY_"):
        _bad("denied needs a DENY_* reason")
    if b["status"] in ("failed", "aborted_safe") and not (rc.startswith("FAIL_") or rc.startswith("DENY_")):
        _bad("failed/aborted_safe needs a FAIL_* or DENY_* reason")
    if b["status"] == "indeterminate" and rc != "INDETERMINATE":
        _bad("indeterminate needs reason INDETERMINATE")
    if not isinstance(b["output"], str) or len(b["output"].encode("utf-8")) > MAX_OUTPUT_BYTES:
        _bad(f"output must be a string <= {MAX_OUTPUT_BYTES} bytes")
    r = b["audit_seq_range"]
    if r is not None:
        if not isinstance(r, list) or len(r) != 2:
            _bad("audit_seq_range must be [first,last] or null")
        lo = _int(r[0], 0, canon.MAX_INT, "audit_seq_range")
        hi = _int(r[1], 0, canon.MAX_INT, "audit_seq_range")
        if hi < lo:
            _bad("audit_seq_range reversed")
    if b["plan_hash"] is not None and not is_hex64(b["plan_hash"]):
        _bad("plan_hash invalid")
    return b


def result_to_state(status: str, reason_code: str | None) -> str:
    """Hub-Zustand aus dem Node-Ergebnis (Design 3.2: wiederholbare Ablehnungen vs. endgueltige)."""
    if status == "denied":
        return "denied_retryable" if reason_code in RETRYABLE_DENIALS else "denied"
    return status


TERMINAL_STATES = frozenset({"committed", "dry_run", "denied", "failed", "expired"})
