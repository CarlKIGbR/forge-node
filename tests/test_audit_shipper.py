"""Reading a rotated log for shipping, and the shipper against a fake hub sink (real hub: test_agent_privd_e2e)."""
import json
import os

import pytest
from audit_helpers import AGENT_GID, NODE, Clock, admin, make_specs

from forge_node import chain
from forge_node.agent.shipper import AuditShipper, BATCH
from forge_node.audit import reader
from forge_node.audit.spec import agent_spec


@pytest.fixture
def spec(realfs):
    return make_specs(realfs)["agent"]


def fill(spec, n_per_gen, gens):
    a = admin(spec)
    a.init()
    for g in range(gens):
        for i in range(n_per_gen):
            a.append("t0", {"g": g, "i": i})
        if g < gens - 1:
            a.rotate()
    return a


def read_all(spec, after=0, limit=10 ** 6):
    cur = reader.start_cursor(spec.dir, spec.prefix, NODE, spec.source, after)
    assert cur is not None
    return reader.read_batch(spec.dir, spec.prefix, NODE, spec.source, cur, after, limit), cur


def test_reader_returns_the_whole_chain_across_generations_in_order(spec):
    fill(spec, 5, 3)
    recs, cur = read_all(spec)
    assert [r["seq"] for r in recs] == list(range(1, len(recs) + 1)) and len(recs) == 3 * 5 + 1 + 2         # records + genesis chain_link + two rotation chain_links
    assert chain.verify_chain(recs) == [] and [r["type"] for r in recs if r["type"] == "chain_link"] == ["chain_link"] * 3


def test_reader_starts_after_an_acknowledged_seq_and_continues_from_a_cursor(spec):
    a = fill(spec, 5, 3)
    for after in (0, 1, 7, 12, 17):
        recs, _ = read_all(spec, after=after)
        assert [r["seq"] for r in recs] == list(range(after + 1, 18 + 1)), after
    cur = reader.start_cursor(spec.dir, spec.prefix, NODE, spec.source, 0)
    got = []
    for limit in (4, 4, 4, 100):
        got += reader.read_batch(spec.dir, spec.prefix, NODE, spec.source, cur, 0, limit)
    assert [r["seq"] for r in got] == list(range(1, 19))
    a.append("t0", {"late": 1})
    more = reader.read_batch(spec.dir, spec.prefix, NODE, spec.source, cur, 0, 100)
    assert [r["seq"] for r in more] == [19]                                                 # the cursor picks up what was appended since


def test_junk_forged_and_torn_lines_are_never_shipped(spec):
    a = fill(spec, 3, 1)
    live = f"{spec.dir}/audit.000001/audit.000001.jsonl"
    fd = os.open(live, os.O_WRONLY | os.O_APPEND)
    os.write(fd, b"garbage\n")
    forged = dict(chain.seal_record({"ts": "2026-10-31T13:40:10Z", "node": NODE, "type": "t0"}, 999, "f" * 64))     # valid self-hash, wrong place in the chain
    os.write(fd, json.dumps(forged, sort_keys=True, separators=(",", ":")).encode() + b"\n")
    os.write(fd, b'{"torn":')                                                                # unterminated tail
    os.close(fd)
    recs, cur = read_all(spec)
    assert [r["seq"] for r in recs] == [1, 2, 3, 4] and chain.verify_chain(recs) == []
    a.append("t0", {"after": "repair"})                                                      # the writer repairs: tail_repair + record
    more = reader.read_batch(spec.dir, spec.prefix, NODE, spec.source, cur, 0, 100)
    assert [r["type"] for r in more] == ["tail_repair", "t0"] and more[0]["seq"] == 5 and chain.verify_chain(recs + more) == []


def test_no_log_or_purged_predecessor_gives_no_cursor(spec, realfs):
    assert reader.start_cursor(spec.dir, spec.prefix, NODE, spec.source, 0) is None            # no generations at all
    fill(spec, 2, 2)
    assert reader.start_cursor(spec.dir, spec.prefix, NODE, spec.source, 100) is not None     # an ack ahead of the log: the newest generation, nothing to read
    recs, _ = read_all(spec, after=100)
    assert recs == []


class FakeHubSink:
    def __init__(self):
        self.store = {}
        self.calls = []
        self.reject_at = None

    def post_audit(self, body):
        self.calls.append((body["source"], [r["seq"] for r in body["records"]]))
        head = self.store.setdefault(body["source"], [])
        for r in body["records"]:
            if self.reject_at == r["seq"]:
                return {"ok": False, "acked": {body["source"]: len(head)}, "stored": 0, "rejected": {"seq": r["seq"], "reason": "test"}}
            if r["seq"] == len(head) + 1:
                head.append(r)
        return {"ok": True, "acked": {body["source"]: len(head)}, "stored": len(body["records"])}


def test_shipper_ships_both_logs_in_batches_keeps_acks_and_resumes_after_restart(realfs, tmp_path):
    specs = make_specs(realfs)
    for k in ("priv", "agent"):
        a = admin(specs[k])
        a.init()
        for i in range(BATCH + 30):
            a.append("t0", {"i": i})
        a.rotate()
        a.append("t0", {"last": True})
    state = tmp_path / "state"
    state.mkdir()
    hub = FakeHubSink()
    s = AuditShipper(specs=specs, node=NODE, state_dir=str(state), log=print)
    total = 1 + (BATCH + 30) + 1 + 1                                   # genesis chain_link, the records, the rotation's chain_link, the record after it
    out = s.ship_once(hub)
    assert out == {"agent": total, "priv": total}
    for k in ("priv", "agent"):
        recs = hub.store[k]
        assert chain.verify_chain(recs) == [] and recs[0]["type"] == "chain_link" and len(recs) == total
    assert [c[1][0] for c in hub.calls if c[0] == "agent"] == [1, 1 + BATCH]                   # two batches of at most BATCH records
    assert json.loads((state / "audit-acks.json").read_text()) == {"agent": len(hub.store["agent"]), "priv": len(hub.store["priv"])}
    # a restarted agent continues after the persisted ack: nothing is sent again, a new record is
    n_calls = len(hub.calls)
    s2 = AuditShipper(specs=specs, node=NODE, state_dir=str(state), log=print)
    assert s2.ship_once(hub) == {"agent": 0, "priv": 0} and len(hub.calls) == n_calls
    a = admin(specs["agent"])
    a.append("t0", {"new": 1})
    s2.ship_once(hub)
    assert hub.calls[-1] == ("agent", [total + 1]) and len(hub.store["agent"]) == total + 1


def test_shipper_stops_on_a_rejection_and_restarts_from_the_hub_ack(realfs, tmp_path):
    specs = {"agent": make_specs(realfs)["agent"]}
    a = admin(specs["agent"])
    a.init()
    for i in range(10):
        a.append("t0", {"i": i})
    hub = FakeHubSink()
    hub.reject_at = 6
    logs = []
    s = AuditShipper(specs=specs, node=NODE, state_dir=str(tmp_path), log=logs.append)
    s.ship_once(hub)
    assert len(hub.store["agent"]) == 5 and any("rejected" in m for m in logs)
    hub.reject_at = None
    s.ship_once(hub)
    assert len(hub.store["agent"]) == 11


def test_a_transient_hub_failure_does_not_make_the_shipper_skip_the_batch(realfs, tmp_path):
    """Round 2 (minor): the cursor moved past the records before the post; after a HubUnreachable the next cycles shipped nothing (until a restart or a rejection)."""
    from forge_node.agent.client import HubUnreachable
    specs = make_specs(realfs)
    for k in ("priv", "agent"):
        a = admin(specs[k])
        a.init()
        for i in range(5):
            a.append("t0", {"i": i})
    hub = FakeHubSink()

    class Flaky:
        def __init__(self):
            self.fail = True

        def post_audit(self, body):
            if self.fail:
                self.fail = False
                raise HubUnreachable("down")
            return hub.post_audit(body)
    state = tmp_path / "st"
    state.mkdir()
    sh = AuditShipper(specs={"agent": specs["agent"], "priv": specs["priv"]}, node=NODE, state_dir=str(state), log=lambda m: None)
    client = Flaky()
    with pytest.raises(HubUnreachable):
        sh.ship_once(client)
    out = sh.ship_once(client)                                                                    # the very next cycle ships everything again
    assert out == {"agent": 6, "priv": 6} or sum(out.values()) == 12, out
    assert [r["seq"] for r in hub.store["agent"]] == list(range(1, 7)) and [r["seq"] for r in hub.store["priv"]] == list(range(1, 7))
