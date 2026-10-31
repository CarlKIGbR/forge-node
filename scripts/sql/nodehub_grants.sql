-- forge-node N1: Grants der Rolle forge_nodehub (NACH Migration 0001 ausfuehrbar, idempotent). Derselbe DO-Block wie in migrations/0001_node_schema.sql
-- (test_migration.py::test_grants_script_matches_migration vergleicht beide). Hub-Rolle: kein UPDATE/DELETE/TRUNCATE auf node.audit, kein Zugriff auf core.*/mem.*,
-- kein Schreibrecht auf nodes.status/cert_sha256 (Registrierung und Widerruf macht der Owner ueber das Cockpit, N7).
DO $g$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'forge_nodehub') THEN
    GRANT USAGE ON SCHEMA node TO forge_nodehub;
    REVOKE ALL ON ALL TABLES IN SCHEMA node FROM forge_nodehub;
    GRANT SELECT ON node.nodes, node.jobs, node.audit, node.audit_heads, node.alerts TO forge_nodehub;
    GRANT UPDATE (lease_seq, quarantine, quarantine_reason, quarantined_at, agent_version, policy_serial, policy_sha256, last_seen, clock_skew_s) ON node.nodes TO forge_nodehub;
    GRANT INSERT ON node.jobs, node.audit, node.alerts TO forge_nodehub;
    GRANT UPDATE (state, delivery_seq, queue_deadline, issued_at, expires_at, delivered_at, signed, reported_state, reported_at, reconcile_requested_at,
                  result_status, result_reason, result_attempt, result_output, result_plan_hash, result_seq_lo, result_seq_hi, result_at, updated_at) ON node.jobs TO forge_nodehub;
    GRANT USAGE ON SEQUENCE node.alerts_id_seq TO forge_nodehub;
    GRANT EXECUTE ON FUNCTION node.audit_ensure_partition(date) TO forge_nodehub;
  END IF;
END $g$;
