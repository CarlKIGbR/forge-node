"""Audit shipping (Design 3.2 `POST /v1/audit`, 8.1): the agent reads the agent log and the privileged log and sends them to the hub in batches. The hub verifies the chain, stores the
records INSERT-only, cross-checks them against its own job table and answers with the highest sequence it holds per log. Shipping never writes to the logs; the acknowledged sequence is
kept in the agent's state directory (so a restart does not start from the beginning, and the privileged side - `privctl audit-purge` - gets its `--acked` values from the hub)."""
import json
import os

from .. import canon
from ..audit import reader
from ..audit.spec import LogSpec
from ..t0 import confined

BATCH = 200
BATCHES_PER_CYCLE = 5
ACK_FILE = "audit-acks.json"


class AuditShipper:
    def __init__(self, *, specs: dict[str, LogSpec], node: str, state_dir: str, log):
        self.specs, self.node, self.state_dir, self.log = specs, node, state_dir, log
        self.acked = self._load()
        self.cursors: dict[str, reader.Cursor | None] = {}
        self.warned: set[str] = set()

    def _load(self) -> dict:
        try:
            with open(os.path.join(self.state_dir, ACK_FILE), "rb") as f:
                d = json.loads(f.read(4096))
            return {k: int(v) for k, v in d.items() if k in self.specs and isinstance(v, int) and v >= 0}
        except (OSError, ValueError):
            return {}

    def _save(self) -> None:
        sfd = confined.open_dir(self.state_dir)
        try:
            try:
                os.unlink(ACK_FILE + ".tmp", dir_fd=sfd)
            except FileNotFoundError:
                pass
            confined.write_new_at(sfd, [ACK_FILE + ".tmp"], canon.canonical(self.acked), 0o600)
            confined.replace_at(sfd, ACK_FILE + ".tmp", ACK_FILE)
        finally:
            os.close(sfd)

    def _warn(self, source: str, why: str) -> None:
        """The ack file is agent-writable state: a reset or inflated value must not make shipping stop SILENTLY (said once until it clears); the hub's audit_heads cross-check is the alarm."""
        if source not in self.warned:
            self.warned.add(source)
            self.log(f"audit shipping: {why}; nothing is shipped for this log")

    def ship_once(self, client) -> dict:
        """One cycle: for each log up to BATCHES_PER_CYCLE batches. Returns {source: records stored}. HubUnreachable propagates (the caller backs off)."""
        stored = {}
        for source, spec in self.specs.items():
            n_total = 0
            for _ in range(BATCHES_PER_CYCLE):
                after = self.acked.get(source, 0)
                try:
                    cur = self.cursors.get(source) or reader.start_cursor(spec.dir, spec.prefix, self.node, spec.source, after)
                    if cur is None:
                        if reader.has_generations(spec.dir, spec.prefix):
                            self._warn(source, f"no generation of the {source} log continues from the local ack {after} (ack file reset, or the needed generation was purged)")
                        break
                    self.cursors[source] = cur
                    recs = reader.read_batch(spec.dir, spec.prefix, self.node, spec.source, cur, after, BATCH)
                except OSError as e:
                    self.log(f"audit shipping: cannot read the {source} log ({type(e).__name__})")
                    self.cursors.pop(source, None)
                    break
                if not recs:
                    if cur.next_seq - 1 < after:
                        self._warn(source, f"the local ack {after} is ahead of the log (its last record is seq {cur.next_seq - 1})")
                    else:
                        self.warned.discard(source)
                    break
                try:
                    resp = client.post_audit({"source": source, "records": recs})
                except BaseException:
                    self.cursors.pop(source, None)                    # the cursor already moved past these records: the next cycle starts again from what the hub acknowledged
                    raise
                acked = resp.get("acked", {}).get(source)
                if isinstance(acked, int) and acked > self.acked.get(source, 0):
                    self.acked[source] = acked
                    self._save()
                if not resp.get("ok"):
                    self.log(f"audit shipping: the hub rejected the {source} log ({resp.get('rejected')})")
                    self.cursors.pop(source, None)
                    break
                n_total += resp.get("stored", 0)
                if isinstance(acked, int) and acked < recs[-1]["seq"]:
                    self.cursors.pop(source, None)                    # the hub holds less than we read: start again from what it acknowledged
                    break
            stored[source] = n_total
        return stored
