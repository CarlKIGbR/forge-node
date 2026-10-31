"""Hub-Audit-Senke: Kettenpruefung beim Eingang, Quarantaene bei Bruch, Redaktion, Neuberechnung und Querpruefung gegen das privilegierte Log. Braucht Postgres."""
import copy
import json
import threading
import uuid
from datetime import timedelta

import psycopg
import pytest

from conftest import add_node
from forge_node import chain
from forge_node.hub.core import JobRequest
from forge_node.protocol import ProtoError

pytestmark = pytest.mark.db


def _chain(node="g2", n=3, start=1, prev=chain.GENESIS_HASH, typ="t0", ts="2026-10-31T13:40:10Z", **extra):
    recs = []
    for i in range(start, start + n):
        r = chain.seal_record({"ts": ts, "node": node, "type": typ, "note": f"r{i}", **extra}, i, prev)
        recs.append(r)
        prev = r["hash"]
    return recs


def _q(adm, node="g2"):
    return adm.execute("SELECT quarantine, quarantine_reason FROM node.nodes WHERE node_id=%s", (node,)).fetchone()


def _alerts(adm):
    return [(r["kind"], r["dedupe_key"]) for r in adm.execute("SELECT kind, dedupe_key FROM node.alerts ORDER BY id")]


def test_valid_batch_stored_acked_and_chain_verifies(hub, adm):
    recs = _chain(n=5)
    out = hub.ingest_audit("g2", {"source": "priv", "records": recs})
    assert out == {"ok": True, "acked": {"priv": 5}, "stored": 5}
    assert hub.verify_chains("g2") == [] and not _q(adm)["quarantine"]
    assert adm.execute("SELECT count(*) AS n FROM node.audit WHERE source='priv'").fetchone()["n"] == 5


def test_incremental_batches_and_replay_are_idempotent(hub, adm):
    a = [r for r in _chain(typ="relay", n=6)]
    assert hub.ingest_audit("g2", {"source": "agent", "records": a[:3]})["acked"] == {"agent": 3}
    assert hub.ingest_audit("g2", {"source": "agent", "records": a[:3]})["stored"] == 0          # Wiederholung
    assert hub.ingest_audit("g2", {"source": "agent", "records": a[2:]})["acked"] == {"agent": 6}  # ueberlappend
    assert not _q(adm)["quarantine"] and hub.verify_chains("g2") == []


def test_sources_are_independent_chains(hub):
    hub.ingest_audit("g2", {"source": "priv", "records": _chain(n=2)})
    hub.ingest_audit("g2", {"source": "agent", "records": _chain(typ="relay", n=3)})
    hub.ingest_audit("g1", {"source": "priv", "records": _chain(node="g1", n=1)})
    assert hub.verify_chains("g2") == [] and hub.verify_chains("g1") == []


def test_gap_quarantines_and_keeps_valid_prefix(hub, adm):
    recs = _chain(n=5)
    out = hub.ingest_audit("g2", {"source": "priv", "records": [recs[0], recs[1], recs[3], recs[4]]})
    assert not out["ok"] and out["acked"] == {"priv": 2} and out["rejected"]["seq"] == 4
    assert _q(adm)["quarantine"] and ("audit_gap", "priv-gap-3") in _alerts(adm)
    assert hub.verify_chains("g2") == [] or all("hub" in p or "priv" not in p for p in hub.verify_chains("g2"))


def test_prev_hash_break_hash_mismatch_fork_and_malformed_each_quarantine(hub, adm):
    base = _chain(n=2)
    hub.ingest_audit("g2", {"source": "priv", "records": base})

    def attempt(rec, reason_part):
        adm.execute("UPDATE node.nodes SET quarantine=false")
        out = hub.ingest_audit("g2", {"source": "priv", "records": [rec]})
        assert not out["ok"] and reason_part in out["rejected"]["reason"], out
        assert _q(adm)["quarantine"]
        assert out["acked"] == {"priv": 2}

    attempt(chain.seal_record({"ts": "2026-10-31T13:40:10Z", "node": "g2", "type": "t0"}, 3, "f" * 64), "prev")
    bad = copy.deepcopy(chain.seal_record({"ts": "2026-10-31T13:40:10Z", "node": "g2", "type": "t0"}, 3, base[1]["hash"]))
    bad["note"] = "changed after sealing"
    attempt(bad, "hash")
    fork = chain.seal_record({"ts": "2026-10-31T13:40:10Z", "node": "g2", "type": "t0", "different": 1}, 2, base[0]["hash"])
    attempt(fork, "fork")
    attempt(dict(base[0], node="g3"), "malformed")
    attempt({"seq": 3}, "malformed")


def test_record_types_must_match_the_source(hub, adm):
    out = hub.ingest_audit("g2", {"source": "agent", "records": _chain(typ="intent", n=1)})
    assert not out["ok"] and "malformed" in out["rejected"]["reason"] and _q(adm)["quarantine"]


def test_hub_source_and_bad_batches_are_rejected_without_quarantine(hub, adm):
    for body in ({"source": "hub", "records": _chain(typ="job_issue", n=1)}, {"source": "priv", "records": []}, {"source": "priv"}, {"records": []}, [],
                 {"source": "priv", "records": _chain(n=1), "x": 1}, {"source": "priv", "records": _chain(n=501)}):
        with pytest.raises(ProtoError):
            hub.ingest_audit("g2", body)
    assert not _q(adm)["quarantine"] and adm.execute("SELECT count(*) AS n FROM node.audit WHERE source<>'hub'").fetchone()["n"] == 0


def test_hub_redacts_again_and_keeps_node_hash(hub, adm):                              # Redaktion am Hub (Design 8.4)
    recs = _chain(n=2, excerpt="ran with password=CANARYhunter2 and ghp_CANARYabcdef123456")
    assert hub.ingest_audit("g2", {"source": "priv", "records": recs})["ok"]
    rows = adm.execute("SELECT redacted, record, hash FROM node.audit WHERE source='priv' ORDER BY seq").fetchall()
    assert all(r["redacted"] for r in rows) and "CANARY" not in json.dumps([r["record"] for r in rows])
    assert [r["hash"] for r in rows] == [r["hash"] for r in recs]
    assert hub.verify_chains("g2") == []                                              # Verkettung bleibt pruefbar


def test_unredacted_records_are_stored_verbatim_and_content_verified_later(hub, adm):
    hub.ingest_audit("g2", {"source": "priv", "records": _chain(n=2)})
    assert not any(r["redacted"] for r in adm.execute("SELECT redacted FROM node.audit"))
    adm.execute("SET session_replication_role = replica")                             # Test: Manipulation unter Umgehung der Trigger (Superuser)
    adm.execute("UPDATE node.audit SET record = jsonb_set(record, '{note}', '\"edited\"') WHERE seq=2 AND source='priv'")
    adm.execute("SET session_replication_role = origin")
    problems = hub.verify_chains("g2")
    assert problems and "seq 2 content does not match its hash" in problems[0]
    res = hub.verify_node("g2")
    assert res["chain_problems"] and _q(adm)["quarantine"]


def test_verify_detects_deleted_middle_record_even_with_trigger_bypass(hub, adm):
    hub.ingest_audit("g2", {"source": "priv", "records": _chain(n=4)})
    adm.execute("SET session_replication_role = replica")
    adm.execute("DELETE FROM node.audit WHERE seq=2 AND source='priv'")
    adm.execute("SET session_replication_role = origin")
    assert "seq gap" in hub.verify_chains("g2")[0]


def test_concurrent_overlapping_batches_store_each_record_once(hub, hubdb, adm, hubcfg, gate, clock):      # Hub-Seite von test_concurrent_appends_unique_seq_and_unbroken_chain
    from forge_node.hub.core import Hub, Signer

    recs = _chain(n=40)
    results, errs = [], []

    def worker(batch):
        h = Hub(hubcfg, hubdb, Signer(gate["priv"], gate["id"]), clock=clock)
        try:
            results.append(h.ingest_audit("g2", {"source": "priv", "records": batch}))
        except Exception as e:  # noqa: BLE001
            errs.append(e)

    batches = [recs[:25], recs[10:], recs[:40], recs[20:35]]
    ts = [threading.Thread(target=worker, args=(b,)) for b in batches for _ in range(2)]
    [t.start() for t in ts]
    [t.join(30) for t in ts]
    assert not errs, errs
    assert adm.execute("SELECT count(*) AS n, max(seq) AS m FROM node.audit WHERE source='priv'").fetchone() == {"n": 40, "m": 40}
    assert not _q(adm)["quarantine"] and hub.verify_chains("g2") == []


def test_db_rejects_duplicate_gap_and_fork_even_from_a_buggy_hub(hub, hubdb, adm):             # DB ist die letzte Verteidigungslinie
    recs = _chain(n=3)
    hub.ingest_audit("g2", {"source": "priv", "records": recs[:2]})
    with hubdb.tx() as c:
        for bad, code in ((recs[1], "23505"), (recs[2] | {"seq": 4}, "23514"), (_chain(n=1, start=3, prev="e" * 64)[0], "23514")):
            with pytest.raises(psycopg.Error) as e:
                with c.transaction():
                    c.execute("INSERT INTO node.audit (node_id,source,seq,ts,type,prev_hash,hash,record) VALUES ('g2','priv',%s,'2026-10-31T13:40:10Z','t0',%s,%s,'{}')",
                              (bad["seq"], bad["prev_hash"], bad["hash"]))
            assert e.value.sqlstate == code


# ========================================================================================================= crosscheck (hub jobs <-> priv log)
def _job_row(adm, job_id, tier=1, status="committed", result_at="2026-10-31T13:00:00Z", op="dir.ensure", node="g2", attempt=1):
    adm.execute(
        "INSERT INTO node.jobs (job_id,node_id,tier,op,params,dry_run,requester,project,state,delivery_seq,queue_deadline,issued_at,expires_at,delivered_at,result_status,result_attempt,result_at) "
        "VALUES (%s,%s,%s,%s,'{}',false,'{\"identity\":\"meta\"}',NULL,%s,1,'2026-11-01T00:00:00Z','2026-10-31T12:59:00Z','2026-10-31T13:01:00Z','2026-10-31T12:59:00Z',%s,%s,%s)",
        (job_id, node, tier, op, status if status in ("committed", "failed", "dry_run", "denied", "aborted_safe", "indeterminate") else "committed", status, attempt, result_at))


def _priv(hub, node, specs):
    """specs: [(type, job_id, attempt, ts)] -> eine priv-Kette."""
    prev, recs = chain.GENESIS_HASH, []
    for i, (typ, jid, att, ts) in enumerate(specs, 1):
        r = chain.seal_record({"ts": ts, "node": node, "type": typ, "job_id": jid, "attempt": att}, i, prev)
        recs.append(r)
        prev = r["hash"]
    assert hub.ingest_audit(node, {"source": "priv", "records": recs})["ok"]


def test_crosscheck_matching_intent_result_is_clean(hub, adm):
    j = str(uuid.uuid4())
    _job_row(adm, j)
    _priv(hub, "g2", [("intent", j, 1, "2026-10-31T13:00:00Z"), ("result", j, 1, "2026-10-31T13:00:05Z")])
    assert hub.crosscheck("g2") == [] and not _q(adm)["quarantine"]


def test_priv_job_crosscheck_mismatch_quarantines(hub, adm):                         # test_priv_job_crosscheck_mismatch_quarantines
    j = str(uuid.uuid4())
    _job_row(adm, j)                                                                 # Hub sagt: committed. Das priv-Log kennt den Job nicht.
    an = hub.crosscheck("g2")
    assert [a["key"] for a in an] == [f"missing-{j}"] and _q(adm)["quarantine"]
    assert ("crosscheck_mismatch", f"missing-{j}") in _alerts(adm)


def test_crosscheck_intent_without_result_for_committed_job_is_mismatch(hub, adm):
    j = str(uuid.uuid4())
    _job_row(adm, j)
    _priv(hub, "g2", [("intent", j, 1, "2026-10-31T13:00:00Z")])
    assert hub.crosscheck("g2") and _q(adm)["quarantine"]


def test_crosscheck_accepts_recovery_record_instead_of_result(hub, adm):
    j = str(uuid.uuid4())
    _job_row(adm, j)
    _priv(hub, "g2", [("intent", j, 1, "2026-10-31T13:00:00Z"), ("recovery", j, 1, "2026-10-31T13:03:00Z")])
    assert hub.crosscheck("g2") == []


def test_crosscheck_priv_record_without_hub_job_is_mismatch(hub, adm):
    j = str(uuid.uuid4())
    _priv(hub, "g2", [("intent", j, 1, "2026-10-31T13:00:00Z"), ("result", j, 1, "2026-10-31T13:00:05Z")])
    an = hub.crosscheck("g2")
    assert [a["key"] for a in an] == [f"orphan-{j}"] and _q(adm)["quarantine"]


def test_crosscheck_ignores_young_results_audit_shipping_is_asynchronous(hub, adm, clock):
    j = str(uuid.uuid4())
    _job_row(adm, j, result_at="2026-10-31T13:38:00Z")                               # 2 min alt < 5 min Karenz
    assert hub.crosscheck("g2") == [] and not _q(adm)["quarantine"]
    clock.advance(400)
    assert hub.crosscheck("g2")


def test_crosscheck_denied_and_dry_run_jobs(hub, adm):
    d, r = str(uuid.uuid4()), str(uuid.uuid4())
    _job_row(adm, d, status="denied")
    _job_row(adm, r, status="dry_run")
    _priv(hub, "g2", [("denial", d, None, "2026-10-31T13:00:00Z"), ("result", r, 1, "2026-10-31T13:00:05Z")])
    assert hub.crosscheck("g2") == []


def test_crosscheck_open_intent_older_than_10_minutes_alerts_without_quarantine(hub, adm, clock):
    j = str(uuid.uuid4())
    _priv(hub, "g2", [("intent", j, 1, "2026-10-31T13:20:00Z")])
    _job_row(adm, j, status="indeterminate", result_at="2026-10-31T13:39:30Z")      # Job existiert (kein Orphan), Ergebnis noch jung
    hub.crosscheck("g2")
    assert ("intent_open", f"{j}-1") in _alerts(adm) and not _q(adm)["quarantine"]


def test_run_verification_checks_all_nodes_and_creates_partitions(hub, adm, clock):
    j = str(uuid.uuid4())
    _job_row(adm, j)
    out = hub.run_verification()
    assert set(out) == {"g2", "g1"} and out["g2"]["crosscheck"] and _q(adm)["quarantine"] and not _q(adm, "g1")["quarantine"]


def test_heartbeat_loss_alert(hub, adm, clock):
    adm.execute("UPDATE node.nodes SET last_seen=%s WHERE node_id='g2'", (clock() - timedelta(minutes=6),))
    hub.run_verification()
    assert any(k == "heartbeat_lost" for k, _ in _alerts(adm))


def test_quarantine_is_audited_once_and_idempotent(hub, adm):
    hub.quarantine("g2", "chain_break", "k1", {"a": 1})
    hub.quarantine("g2", "chain_break", "k1", {"a": 1})
    hub.quarantine("g2", "audit_gap", "k2", {})
    assert adm.execute("SELECT count(*) AS n FROM node.audit WHERE source='hub' AND type='quarantine'").fetchone()["n"] == 1
    assert len(_alerts(adm)) == 2
    assert hub.verify_chains("g2") == []


def test_hub_cannot_lift_quarantine(hub):
    hub.quarantine("g2", "chain_break", "k1", {})
    with hub.db.tx() as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute("UPDATE node.nodes SET quarantine=false WHERE node_id='g2'")
