#!/usr/bin/env bash
# forge-nodehub database bootstrap (N5-prep), run on the forge host from the hub GO - in the pattern of forge-core/scripts/create_graph_role.sh:
#   scripts/create_nodehub_role.sh /srv/forge/work/forge-core [--rotate]
# 1. role forge_nodehub (nodehub_role.sql) + password in forge-core/secrets/nodehub_db_password (0600, never in argv/env/output), CONNECT on the database;
# 2. schema `node` OWNED BY forge_core, created here by the database superuser: forge_core has CONNECT only and cannot create a schema (not even CREATE SCHEMA IF NOT EXISTS).
# The migration itself (docker compose --profile nodehub-migrate run --rm nodehub-migrate) runs afterwards as forge_core and also applies the hub grants (migration 0001). Repeatable.
set -euo pipefail
NODE="$(cd "$(dirname "$0")/.." && pwd)"
CORE="$(cd "${1:?forge-core directory}" && pwd)"
cd "$CORE"
PG=${FORGE_PG_CONTAINER:-forge-postgres-1}
DB=${FORGE_DB_NAME:-forge}
umask 077
. scripts/lib_dbsecret.sh
mkdir -p secrets
if [ ! -s secrets/nodehub_db_password ] || [ "${2:-}" = "--rotate" ]; then gen_secret_file secrets/nodehub_db_password; fi
chmod 600 secrets/nodehub_db_password
pw=$(cat secrets/nodehub_db_password)
docker exec -i "$PG" sh -c 'psql -v ON_ERROR_STOP=1 -q -U "$POSTGRES_USER" -d postgres' < "$NODE/scripts/sql/nodehub_role.sql"
docker exec -i "$PG" sh -c 'psql -v ON_ERROR_STOP=1 -q -U "$POSTGRES_USER" -d postgres' <<SQL
\set pw '$pw'
SELECT format('ALTER ROLE forge_nodehub PASSWORD %L', :'pw') \gexec
GRANT CONNECT ON DATABASE $DB TO forge_nodehub;
SQL
docker exec -i "$PG" sh -c "psql -v ON_ERROR_STOP=1 -q -U \"\$POSTGRES_USER\" -d $DB" <<'SQL'
CREATE SCHEMA IF NOT EXISTS node AUTHORIZATION forge_core;
SQL
echo "ok: role forge_nodehub (secrets/nodehub_db_password), schema node owned by forge_core; next: nodehub-migrate, then the hub"
