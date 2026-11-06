-- forge-node Slice N1 (Design docs/design/FORGE_NODE.md 3.2, 8.1, 9.4): Schema `node` des Hubs.
-- Tabellen: nodes (Registry, Lease-Zaehler, Quarantaene), jobs (Spiegel des Node-Ledgers, 9.4), audit (INSERT-only, hash-verkettet, monatliche Partitionen), audit_heads (Ketten-Kopf je node+source),
--           alerts (Ausgang fuer node_alert; die Weiterleitung ins Postfach core.escalations kommt mit N7).
-- Rolle forge_nodehub: nur die Rechte unten (rollen-geschuetzt wie core 0010/0012); scripts/sql/nodehub_role.sql legt sie an, scripts/sql/nodehub_grants.sql traegt dieselben Grants.
-- Eigentuemer aller Objekte ist die migrierende Rolle, NICHT forge_nodehub: die Hub-Rolle kann Trigger weder abschalten noch Tabellen aendern.
-- Das Schema `node` legt hub/migrate.py an (oder der DB-Superuser: CREATE SCHEMA node AUTHORIZATION forge_core). Kein CREATE SCHEMA IF NOT EXISTS hier: PostgreSQL prueft CREATE auf der Datenbank zuerst, die Produktionsrolle forge_core hat nur CONNECT.

-- ---------------------------------------------------------------------------------------------------------------------------------------------
-- Generische Trigger-Funktionen (gelten auch fuer Eigentuemer und Superuser; nur session_replication_role=replica / DISABLE TRIGGER umgeht sie)
-- ---------------------------------------------------------------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION node.forbid_change() RETURNS trigger LANGUAGE plpgsql AS $f$
BEGIN
  RAISE EXCEPTION '% on %.% is not allowed (insert-only audit evidence)', TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME USING ERRCODE = '42501';
END $f$;

-- Argumente: Spaltennamen, die sich nie aendern duerfen.
CREATE OR REPLACE FUNCTION node.guard_immutable() RETURNS trigger LANGUAGE plpgsql AS $f$
DECLARE c text; o jsonb := to_jsonb(OLD); n jsonb := to_jsonb(NEW);
BEGIN
  FOREACH c IN ARRAY TG_ARGV LOOP
    IF o -> c IS DISTINCT FROM n -> c THEN
      RAISE EXCEPTION 'column %.%.% is immutable', TG_TABLE_SCHEMA, TG_TABLE_NAME, c USING ERRCODE = '42501';
    END IF;
  END LOOP;
  RETURN NEW;
END $f$;

-- ---------------------------------------------------------------------------------------------------------------------------------------------
-- nodes
-- ---------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE node.nodes (
  node_id          text PRIMARY KEY CHECK (node_id ~ '^[a-z0-9][a-z0-9-]{0,31}$'),
  profile          text NOT NULL CHECK (profile IN ('full','t0')),
  status           text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','revoked')),
  cert_sha256      text UNIQUE CHECK (cert_sha256 IS NULL OR cert_sha256 ~ '^[0-9a-f]{64}$'),   -- SHA-256 des Zertifikats (DER); vom Owner nach Fingerprint-Vergleich eingetragen
  lease_seq        bigint NOT NULL DEFAULT 0 CHECK (lease_seq >= 0),                           -- streng steigend, persistent: Lease-Replay ist ausgeschlossen
  quarantine       boolean NOT NULL DEFAULT false,
  quarantine_reason text,
  quarantined_at   timestamptz,
  agent_version    text,
  policy_serial    integer,
  policy_sha256    text CHECK (policy_sha256 IS NULL OR policy_sha256 ~ '^[0-9a-f]{64}$'),
  last_seen        timestamptz,
  clock_skew_s     integer,
  created_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT nodes_active_has_cert CHECK (status <> 'active' OR cert_sha256 IS NOT NULL)
);

CREATE OR REPLACE FUNCTION node.nodes_guard() RETURNS trigger LANGUAGE plpgsql AS $f$
BEGIN
  IF OLD.status = 'revoked' AND NEW.status <> 'revoked' THEN
    RAISE EXCEPTION 'node % is revoked; register a new node id/certificate instead', OLD.node_id USING ERRCODE = '42501';
  END IF;
  IF NEW.lease_seq <> OLD.lease_seq AND NEW.lease_seq <> OLD.lease_seq + 1 THEN
    RAISE EXCEPTION 'lease_seq must increase by exactly 1' USING ERRCODE = '42501';
  END IF;
  -- Quarantaene setzt der Hub selbst, aufheben darf ihn nur der Betriebsleiter/Owner (andere Rolle), nie der Hub
  IF OLD.quarantine AND NOT NEW.quarantine AND current_user = 'forge_nodehub' THEN
    RAISE EXCEPTION 'the hub role cannot lift a quarantine' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END $f$;
CREATE TRIGGER nodes_guard BEFORE UPDATE ON node.nodes FOR EACH ROW EXECUTE FUNCTION node.nodes_guard();
CREATE TRIGGER nodes_identity BEFORE UPDATE ON node.nodes FOR EACH ROW EXECUTE FUNCTION node.guard_immutable('node_id','profile','created_at');
CREATE TRIGGER nodes_no_delete BEFORE DELETE OR TRUNCATE ON node.nodes FOR EACH STATEMENT EXECUTE FUNCTION node.forbid_change();

-- ---------------------------------------------------------------------------------------------------------------------------------------------
-- jobs: Hub-Spiegel des Node-Ledgers. job_id = Idempotenzschluessel (Effect-Key des Graphen). Endzustaende sind unveraenderlich.
-- ---------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE node.jobs (
  job_id            uuid PRIMARY KEY,
  node_id           text NOT NULL REFERENCES node.nodes(node_id),
  tier              smallint NOT NULL CHECK (tier BETWEEN 0 AND 3),
  op                text NOT NULL CHECK (op ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
  params            jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(params) = 'object' AND length(params::text) <= 16384),
  dry_run           boolean NOT NULL,
  plan_hash         text CHECK (plan_hash IS NULL OR plan_hash ~ '^[0-9a-f]{64}$'),
  requester         jsonb NOT NULL CHECK (jsonb_typeof(requester) = 'object'),
  project           text,
  owner_sig         text,
  state             text NOT NULL CHECK (state IN ('queued','issued','in_progress','committed','dry_run','denied_retryable','denied','failed','aborted_safe','indeterminate','expired')),
  delivery_seq      integer NOT NULL DEFAULT 0 CHECK (delivery_seq >= 0),
  queued_at         timestamptz NOT NULL DEFAULT now(),
  queue_deadline    timestamptz NOT NULL,
  issued_at         timestamptz,
  expires_at        timestamptz,
  delivered_at      timestamptz,
  signed            jsonb,                      -- zuletzt zugestellte Huelle {payload, sig, key_id}
  reported_state    text,                       -- Ledger-Zustand laut Node (open_jobs im Poll); nur Planungshilfe, nie Autoritaet
  reported_at       timestamptz,
  reconcile_requested_at timestamptz,
  result_status     text CHECK (result_status IS NULL OR result_status IN ('committed','dry_run','denied','failed','aborted_safe','indeterminate')),
  result_reason     text,
  result_attempt    integer,
  result_output     text CHECK (result_output IS NULL OR length(result_output) <= 65536),    -- bereits am Hub redigiert (redact.py)
  result_plan_hash  text CHECK (result_plan_hash IS NULL OR result_plan_hash ~ '^[0-9a-f]{64}$'),
  result_seq_lo     bigint,
  result_seq_hi     bigint,
  result_at         timestamptz,
  updated_at        timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT jobs_issued_has_times CHECK (state IN ('queued','expired') OR (issued_at IS NOT NULL AND expires_at IS NOT NULL AND delivery_seq >= 1))
);
CREATE INDEX jobs_node_state_idx ON node.jobs (node_id, state, queued_at);

CREATE OR REPLACE FUNCTION node.job_transition_ok(o text, n text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $f$
  SELECT CASE o
    WHEN 'queued'           THEN n IN ('queued','issued','expired')
    WHEN 'issued'           THEN n IN ('issued','in_progress','committed','dry_run','denied_retryable','denied','failed','aborted_safe','indeterminate','expired')
    WHEN 'in_progress'      THEN n IN ('in_progress','committed','dry_run','denied_retryable','denied','failed','aborted_safe','indeterminate')
    WHEN 'denied_retryable' THEN n IN ('denied_retryable','queued')
    WHEN 'aborted_safe'     THEN n IN ('aborted_safe','queued')
    WHEN 'indeterminate'    THEN n IN ('indeterminate','committed','aborted_safe')        -- aufgeloest nur durch Rekonziliation / ledger.resolve (N3/N6)
    ELSE false                                                                             -- committed, dry_run, denied, failed, expired: endgueltig
  END
$f$;

CREATE OR REPLACE FUNCTION node.jobs_guard() RETURNS trigger LANGUAGE plpgsql AS $f$
BEGIN
  IF NOT node.job_transition_ok(OLD.state, NEW.state) THEN
    RAISE EXCEPTION 'job % may not change state % -> %', OLD.job_id, OLD.state, NEW.state USING ERRCODE = '42501';
  END IF;
  IF NEW.delivery_seq < OLD.delivery_seq THEN
    RAISE EXCEPTION 'delivery_seq must not decrease' USING ERRCODE = '42501';
  END IF;
  -- Ein Endzustand haelt auch seine Ergebnisspalten fest
  IF OLD.state IN ('committed','dry_run','denied','failed','expired') THEN
    RAISE EXCEPTION 'job % is terminal (%)', OLD.job_id, OLD.state USING ERRCODE = '42501';
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END $f$;
CREATE TRIGGER jobs_guard BEFORE UPDATE ON node.jobs FOR EACH ROW EXECUTE FUNCTION node.jobs_guard();
CREATE TRIGGER jobs_identity BEFORE UPDATE ON node.jobs FOR EACH ROW
  EXECUTE FUNCTION node.guard_immutable('job_id','node_id','tier','op','params','dry_run','plan_hash','requester','project','owner_sig','queued_at');
CREATE TRIGGER jobs_no_delete BEFORE DELETE OR TRUNCATE ON node.jobs FOR EACH STATEMENT EXECUTE FUNCTION node.forbid_change();

-- ---------------------------------------------------------------------------------------------------------------------------------------------
-- audit: INSERT-only, monatliche Partitionen, eine Kette je (node_id, source). source: agent | priv (vom Node geliefert) | hub (vom Hub selbst geschrieben).
-- Eindeutigkeit (node_id, source, seq) ueber alle Partitionen erzwingt audit_heads + Trigger (ein PK ueber Partitionen muss den Partitionsschluessel ts enthalten).
-- ---------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE node.audit_heads (
  node_id    text NOT NULL REFERENCES node.nodes(node_id),
  source     text NOT NULL CHECK (source IN ('agent','priv','hub')),
  seq        bigint NOT NULL CHECK (seq >= 0),
  hash       text NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (node_id, source)
);

CREATE TABLE node.audit (
  node_id     text NOT NULL REFERENCES node.nodes(node_id),
  source      text NOT NULL CHECK (source IN ('agent','priv','hub')),
  seq         bigint NOT NULL CHECK (seq >= 1),
  ts          timestamptz NOT NULL,
  type        text NOT NULL CHECK (type ~ '^[a-z0-9_]{1,32}$'),
  job_id      uuid,
  attempt     integer,
  prev_hash   text NOT NULL CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
  hash        text NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
  redacted    boolean NOT NULL DEFAULT false,      -- true: der Hub hat noch etwas geschwaerzt; 'hash' gilt fuer den vom Node gesendeten Wortlaut (am Eingang geprueft), nicht mehr fuer 'record'
  record      jsonb NOT NULL CHECK (length(record::text) <= 32768),
  received_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (node_id, source, seq, ts)
) PARTITION BY RANGE (ts);
CREATE INDEX audit_job_idx ON node.audit (node_id, job_id) WHERE job_id IS NOT NULL;
CREATE INDEX audit_node_ts_idx ON node.audit (node_id, source, ts);

-- Kettenwaechter: seq muss genau Kopf+1 sein und prev_hash muss der Kopf-Hash sein; der Kopf wird hier (SECURITY DEFINER) fortgeschrieben und ist unter FOR UPDATE serialisiert.
-- Damit sind Duplikate, Luecken und Forks auch bei direktem INSERT durch die Hub-Rolle unmoeglich.
CREATE OR REPLACE FUNCTION node.audit_chain_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, node AS $f$
DECLARE h node.audit_heads%ROWTYPE;
BEGIN
  INSERT INTO node.audit_heads (node_id, source, seq, hash) VALUES (NEW.node_id, NEW.source, 0, repeat('0', 64)) ON CONFLICT DO NOTHING;
  SELECT * INTO h FROM node.audit_heads WHERE node_id = NEW.node_id AND source = NEW.source FOR UPDATE;
  IF NEW.seq <= h.seq THEN
    RAISE EXCEPTION 'audit %/%: seq % already stored (head %)', NEW.node_id, NEW.source, NEW.seq, h.seq USING ERRCODE = '23505';
  ELSIF NEW.seq <> h.seq + 1 THEN
    RAISE EXCEPTION 'audit %/%: gap, seq % after head %', NEW.node_id, NEW.source, NEW.seq, h.seq USING ERRCODE = '23514';
  ELSIF NEW.prev_hash <> h.hash THEN
    RAISE EXCEPTION 'audit %/%: prev_hash of seq % does not match the head hash', NEW.node_id, NEW.source, NEW.seq USING ERRCODE = '23514';
  END IF;
  UPDATE node.audit_heads SET seq = NEW.seq, hash = NEW.hash, updated_at = now() WHERE node_id = NEW.node_id AND source = NEW.source;
  RETURN NEW;
END $f$;

CREATE TRIGGER audit_chain_guard BEFORE INSERT ON node.audit FOR EACH ROW EXECUTE FUNCTION node.audit_chain_guard();
CREATE TRIGGER audit_no_change BEFORE UPDATE OR DELETE ON node.audit FOR EACH ROW EXECUTE FUNCTION node.forbid_change();
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON node.audit FOR EACH STATEMENT EXECUTE FUNCTION node.forbid_change();
CREATE TRIGGER audit_heads_no_delete BEFORE DELETE OR TRUNCATE ON node.audit_heads FOR EACH STATEMENT EXECUTE FUNCTION node.forbid_change();

CREATE TABLE node.audit_default PARTITION OF node.audit DEFAULT;      -- faengt Records ausserhalb der angelegten Monate auf: Audit faellt nie an einer fehlenden Partition aus
CREATE TRIGGER audit_default_no_truncate BEFORE TRUNCATE ON node.audit_default FOR EACH STATEMENT EXECUTE FUNCTION node.forbid_change();

-- Monatspartition anlegen (idempotent). Ein Monat, fuer den die Default-Partition schon Zeilen hat, kann nicht mehr angelegt werden -> Rueckgabe 'blocked'.
CREATE OR REPLACE FUNCTION node.audit_ensure_partition(p_month date) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, node AS $f$
DECLARE m date := date_trunc('month', p_month)::date; nm text := 'audit_' || to_char(m, 'YYYYMM');
BEGIN
  IF m < date '2026-01-01' OR m > (date_trunc('month', now())::date + interval '36 months') THEN
    RAISE EXCEPTION 'partition month % out of the allowed range', m USING ERRCODE = '22023';
  END IF;
  IF to_regclass('node.' || quote_ident(nm)) IS NOT NULL THEN RETURN 'exists'; END IF;
  BEGIN
    EXECUTE format('CREATE TABLE node.%I PARTITION OF node.audit FOR VALUES FROM (%L) TO (%L)', nm, m, (m + interval '1 month')::date);
  EXCEPTION WHEN check_violation THEN
    RETURN 'blocked';
  END;
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON node.%I FOR EACH STATEMENT EXECUTE FUNCTION node.forbid_change()', nm || '_no_truncate', nm);
  RETURN 'created';
END $f$;

-- Aufbewahrung >= 400 Tage: eine Partition darf erst verworfen werden, wenn ihr letzter Tag laenger als 400 Tage zurueckliegt. Nur der Eigentuemer (Owner-Wartung) darf das; nie die Hub-Rolle.
CREATE OR REPLACE FUNCTION node.audit_drop_partition(p_month date) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, node AS $f$
DECLARE m date := date_trunc('month', p_month)::date; nm text := 'audit_' || to_char(m, 'YYYYMM');
BEGIN
  IF (m + interval '1 month')::date > (now() - interval '400 days')::date THEN
    RAISE EXCEPTION 'audit retention is >= 400 days; partition % is too young to drop', nm USING ERRCODE = '42501';
  END IF;
  IF to_regclass('node.' || quote_ident(nm)) IS NULL THEN RETURN 'absent'; END IF;
  EXECUTE format('DROP TABLE node.%I', nm);
  RETURN 'dropped';
END $f$;
REVOKE ALL ON FUNCTION node.audit_drop_partition(date) FROM PUBLIC;

DO $$
DECLARE i int; m date;
BEGIN
  FOR i IN -1 .. 12 LOOP
    PERFORM node.audit_ensure_partition((date_trunc('month', now())::date + (i || ' months')::interval)::date);
  END LOOP;
END $$;

-- ---------------------------------------------------------------------------------------------------------------------------------------------
-- alerts: Ausgang fuer node_alert (Design 11). Dedupe je (node, kind, key); die Weiterleitung nach core.escalations folgt mit N7.
-- ---------------------------------------------------------------------------------------------------------------------------------------------
CREATE TABLE node.alerts (
  id           bigserial PRIMARY KEY,
  node_id      text NOT NULL REFERENCES node.nodes(node_id),
  kind         text NOT NULL CHECK (kind IN ('chain_break','audit_gap','result_conflict','crosscheck_mismatch','intent_open','indeterminate_job','unknown_open_job','clock_skew','heartbeat_lost')),
  dedupe_key   text NOT NULL CHECK (length(dedupe_key) BETWEEN 1 AND 200),
  detail       jsonb NOT NULL CHECK (length(detail::text) <= 4096),
  created_at   timestamptz NOT NULL DEFAULT now(),
  forwarded_at timestamptz,
  UNIQUE (node_id, kind, dedupe_key)
);
CREATE TRIGGER alerts_no_delete BEFORE DELETE OR TRUNCATE ON node.alerts FOR EACH STATEMENT EXECUTE FUNCTION node.forbid_change();

-- ---------------------------------------------------------------------------------------------------------------------------------------------
-- Rollen-Grants (nur wenn die Rolle schon existiert; sonst scripts/sql/nodehub_role.sql + nodehub_grants.sql)
-- ---------------------------------------------------------------------------------------------------------------------------------------------
-- BEGIN nodehub-grants
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
-- END nodehub-grants
