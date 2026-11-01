"""The agent's link to privd (Design 3.3, 8.2): the ONLY way the agent causes anything privileged. Every method sends one request over the root-owned socket and returns privd's answer;
privd re-verifies everything (job signature, lease, policy, window, rate ...) - what the agent checks first is advisory.

It also owns the agent's audit log (audit.jsonl): the agent is that log's single writer process. If the log cannot be appended, nothing above T0 is relayed (fail closed)."""
from ..audit.log import Appender
from ..audit.spec import AuditCorrupt, AuditDown
from ..privd.client import PrivClient, PrivUnavailable

EXEC_TIMEOUT_S = 150.0


class PrivLink:
    def __init__(self, *, client: PrivClient, audit: Appender | None, log):
        self.client, self.audit, self.log = client, audit, log

    # ---- the agent's own audit log -------------------------------------------------------------------------------------------
    def record(self, type_: str, fields: dict) -> int | None:
        """Append to audit.jsonl; the sequence number, or None when the log cannot be written (callers decide whether that matters: T0 continues, relays stop)."""
        if self.audit is None:
            return None
        try:
            return self.audit.append(type_, fields)["seq"]
        except (AuditDown, AuditCorrupt, ValueError) as e:
            self.log(f"audit: cannot append ({type(e).__name__})")
            return None

    def audit_head(self) -> dict | None:
        if self.audit is None:
            return None
        try:
            seq, h = self.audit.head()
            return {"seq": seq, "hash": h}
        except (AuditDown, AuditCorrupt):
            return None

    # ---- privd -----------------------------------------------------------------------------------------------------------------
    def _ask(self, kind: str, body: dict, timeout: float | None = None) -> dict | None:
        try:
            return self.client.request(kind, body, timeout)
        except PrivUnavailable as e:
            self.log(f"privd: {e}")
            return None

    def status(self) -> dict | None:
        r = self._ask("status", {})
        return r["status"] if r and r.get("ok") and isinstance(r.get("status"), dict) else None

    def put_lease(self, envelope: dict) -> bool:
        r = self._ask("lease.put", {"lease": envelope})
        if r is None or not r.get("ok"):
            self.log(f"privd refused the lease ({None if r is None else r.get('code')})")
            return False
        return True

    def execute(self, envelope: dict) -> dict | None:
        return self._ask("exec", {"job": envelope}, EXEC_TIMEOUT_S)

    def reconcile(self, job_id: str) -> dict | None:
        return self._ask("reconcile", {"job_id": job_id})

    def apply_policy(self, raw_b64: str, sig: str) -> dict | None:
        return self._ask("policy.apply", {"policy_b64": raw_b64, "sig": sig})
