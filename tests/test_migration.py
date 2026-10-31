"""Schema node (Migration 0001): Struktur, INSERT-only Audit, Grants der Hub-Rolle. Braucht Postgres (scripts/run-tests.sh)."""
import re
from pathlib import Path

import psycopg
import pytest

from conftest import ROOT, add_node
from forge_node import chain

pytestmark = pytest.mark.db


def _rec(node, seq, prev, **kw):
    return chain.seal_record({"ts": "2026-10-31T13:40:10Z", "node": node, "type": "t0", **kw}, seq, prev)


def _ins(c, r, source="priv", redacted=False):
    import json

    c.execute("INSERT INTO node.audit (node_id, source, seq, ts, type, job_id, attempt, prev_hash, hash, redacted, record) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
              (r["node"], source, r["seq"], r["ts"], r["type"], r.get("job_id"), r.get("attempt"), r["prev_hash"], r["hash"], redacted, json.dumps(r)))


def test_migration_idempotent_and_versioned(dsn):
    from forge_node.hub.migrate import migrate

    assert migrate(dsn) == []
    with psycopg.connect(dsn) as c:
        assert [r[0] for r in c.execute("SELECT version FROM node.schema_migrations")] == ["0001_node_schema"]


def test_grants_script_matches_migration():
    mig = (ROOT / "migrations" / "0001_node_schema.sql").read_text()
    blk = re.search(r"-- BEGIN nodehub-grants\n(.*?)-- END nodehub-grants", mig, re.S).group(1)
    assert blk in (ROOT / "scripts" / "sql" / "nodehub_grants.sql").read_text()


def test_grants_script_and_role_script_apply_idempotently(adm):
    adm.execute((ROOT / "scripts" / "sql" / "nodehub_role.sql").read_text())
    adm.execute((ROOT / "scripts" / "sql" / "nodehub_grants.sql").read_text())
    adm.execute((ROOT / "scripts" / "sql" / "nodehub_grants.sql").read_text())


def test_partitions_current_month_exist_plus_default(adm):
    names = {r["relname"] for r in adm.execute("SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid WHERE i.inhparent='node.audit'::regclass")}
    assert "audit_default" in names and len(names) >= 14
    assert adm.execute("SELECT node.audit_ensure_partition(now()::date)").fetchone()["audit_ensure_partition"] == "exists"
    assert adm.execute("SELECT node.audit_ensure_partition((now() + interval '20 months')::date)").fetchone()["audit_ensure_partition"] == "created"


def test_chain_guard_accepts_sequence_and_rejects_dup_gap_fork(adm):
    add_node(adm)
    r1 = _rec("g2", 1, chain.GENESIS_HASH)
    r2 = _rec("g2", 2, r1["hash"])
    _ins(adm, r1)
    _ins(adm, r2)
    for bad, code in ((r2, "23505"), (_rec("g2", 4, r2["hash"]), "23514"), (_rec("g2", 3, "f" * 64), "23514")):
        with pytest.raises(psycopg.Error) as e:
            _ins(adm, bad)
        assert e.value.sqlstate == code
    h = adm.execute("SELECT seq, hash FROM node.audit_heads WHERE node_id='g2' AND source='priv'").fetchone()
    assert h["seq"] == 2 and h["hash"] == r2["hash"]
    assert adm.execute("SELECT count(*) AS n FROM node.audit").fetchone()["n"] == 2


def test_chains_are_per_node_and_source(adm):
    add_node(adm, "g2")
    add_node(adm, "g3", cert="b" * 64)
    for node, source in (("g2", "priv"), ("g2", "agent"), ("g3", "priv")):
        _ins(adm, _rec(node, 1, chain.GENESIS_HASH), source)
    assert adm.execute("SELECT count(*) AS n FROM node.audit_heads").fetchone()["n"] == 3


def test_hub_audit_update_delete_truncate_blocked(adm, hubdb):
    add_node(adm)
    r1 = _rec("g2", 1, chain.GENESIS_HASH)
    _ins(adm, r1)
    # Hub-Rolle: keine Rechte
    with hubdb.tx() as c:
        for sql in ("UPDATE node.audit SET type='x'", "DELETE FROM node.audit", "TRUNCATE node.audit", "UPDATE node.audit_heads SET seq=0", "DELETE FROM node.audit_heads"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with c.transaction():
                    c.execute(sql)
    # Eigentuemer/Superuser: Trigger blockiert trotzdem (auch direkt auf der Partition)
    part = adm.execute("SELECT tableoid::regclass::text AS p FROM node.audit LIMIT 1").fetchone()["p"]
    for sql in ("UPDATE node.audit SET type='x'", "DELETE FROM node.audit", "TRUNCATE node.audit", f"TRUNCATE {part}", f"DELETE FROM {part}", f"UPDATE {part} SET type='x'", "TRUNCATE node.audit_default",
                "DELETE FROM node.audit_heads", "TRUNCATE node.audit_heads"):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            adm.execute(sql)
    assert adm.execute("SELECT count(*) AS n FROM node.audit").fetchone()["n"] == 1


def test_hub_can_insert_audit_but_not_advance_head_directly(adm, hubdb):
    add_node(adm)
    with hubdb.tx() as c:
        _ins(c, _rec("g2", 1, chain.GENESIS_HASH))
    assert adm.execute("SELECT seq FROM node.audit_heads").fetchone()["seq"] == 1


def test_late_created_partition_is_also_truncate_protected(adm):
    adm.execute("SELECT node.audit_ensure_partition((now() + interval '30 months')::date)")
    name = adm.execute("SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid WHERE i.inhparent='node.audit'::regclass AND c.relname LIKE 'audit_2%' ORDER BY 1 DESC LIMIT 1").fetchone()["relname"]
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        adm.execute(f"TRUNCATE node.{name}")


def test_retention_function_refuses_young_partitions(adm, hubdb):
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        adm.execute("SELECT node.audit_drop_partition(date_trunc('month', now())::date)")
    with hubdb.tx() as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute("SELECT node.audit_drop_partition(date '2020-01-01')")


def test_out_of_range_timestamp_lands_in_default_partition(adm):
    add_node(adm)
    r = chain.seal_record({"ts": "2031-01-01T00:00:00Z", "node": "g2", "type": "t0"}, 1, chain.GENESIS_HASH)
    _ins(adm, r)
    assert adm.execute("SELECT tableoid::regclass::text AS p FROM node.audit").fetchone()["p"] == "node.audit_default"


def test_hub_role_cannot_write_node_status_or_cert(adm, hubdb):
    add_node(adm)
    with hubdb.tx() as c:
        for sql in ("UPDATE node.nodes SET status='active'", "UPDATE node.nodes SET cert_sha256=repeat('c',64)", "DELETE FROM node.nodes", "UPDATE node.nodes SET profile='t0'"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with c.transaction():
                    c.execute(sql)
        c.execute("UPDATE node.nodes SET lease_seq = lease_seq + 1")
        with pytest.raises(psycopg.Error):
            with c.transaction():
                c.execute("UPDATE node.nodes SET lease_seq = lease_seq + 5")


def test_hub_cannot_lift_quarantine_but_can_set_it(adm, hubdb, ownerdb):
    add_node(adm)
    with hubdb.tx() as c:
        c.execute("UPDATE node.nodes SET quarantine=true, quarantine_reason='test', quarantined_at=now()")
    with hubdb.tx() as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute("UPDATE node.nodes SET quarantine=false")
    adm.execute("UPDATE node.nodes SET quarantine=false")


def test_revoked_node_cannot_be_reactivated(adm):
    add_node(adm)
    adm.execute("UPDATE node.nodes SET status='revoked'")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        adm.execute("UPDATE node.nodes SET status='active'")


def test_jobs_terminal_states_and_identity_immutable(adm):
    import json

    add_node(adm)
    jid = "11111111-1111-4111-8111-111111111111"
    adm.execute("INSERT INTO node.jobs (job_id,node_id,tier,op,params,dry_run,requester,state,queue_deadline) VALUES (%s,'g2',0,'inv.host','{}',false,%s,'queued',now()+interval '1 hour')",
                (jid, json.dumps({"identity": "meta"})))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        adm.execute("UPDATE node.jobs SET op='inv.disks'")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        adm.execute("UPDATE node.jobs SET state='committed'")                 # queued -> committed ist nicht erlaubt (nie signiert)
    adm.execute("UPDATE node.jobs SET state='issued', delivery_seq=1, issued_at=now(), expires_at=now()+interval '2 min'")
    adm.execute("UPDATE node.jobs SET state='committed', result_status='committed', result_at=now()")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        adm.execute("UPDATE node.jobs SET state='failed'")
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        adm.execute("DELETE FROM node.jobs")
