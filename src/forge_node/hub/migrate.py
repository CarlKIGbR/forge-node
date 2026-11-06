"""python -m forge_node.hub.migrate : migrations/NNNN_*.sql, je eine Transaktion, Versionstabelle node.schema_migrations. Laeuft als Migrationsrolle (Eigentuemerin), nicht als forge_nodehub."""
import os
import sys
from pathlib import Path

import psycopg

LOCK_ID = 7_340_101
SCHEMA_HINT = ("schema node does not exist and the migration role may not create schemas (production's forge_core has CONNECT only): create it once as the database superuser, like core/mem/lg: "
               "CREATE SCHEMA node AUTHORIZATION forge_core;")
DEFAULT_DIR = Path(__file__).resolve().parents[3] / "migrations"


class MigrateError(RuntimeError):
    pass


def migrate(dsn: str, migrations_dir: Path | None = None, password: str | None = None) -> list[str]:
    d = Path(migrations_dir or os.environ.get("FORGE_NODE_MIGRATIONS_DIR") or DEFAULT_DIR)
    files = sorted(d.glob("[0-9][0-9][0-9][0-9]_*.sql"))
    applied: list[str] = []
    kw = {"autocommit": True}
    if password:
        kw["password"] = password
    with psycopg.connect(dsn, **kw) as conn:
        conn.execute("SELECT pg_advisory_lock(%s)", (LOCK_ID,))
        try:
            if conn.execute("SELECT 1 FROM pg_namespace WHERE nspname = 'node'").fetchone() is None:                 # NOT `CREATE SCHEMA IF NOT EXISTS`: PostgreSQL checks CREATE on the database before it looks for the schema
                try:
                    conn.execute("CREATE SCHEMA node")
                except psycopg.errors.InsufficientPrivilege as e:
                    raise MigrateError(SCHEMA_HINT) from e
            conn.execute("CREATE TABLE IF NOT EXISTS node.schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())")
            done = {r[0] for r in conn.execute("SELECT version FROM node.schema_migrations")}
            for f in files:
                if f.stem in done:
                    continue
                with conn.transaction():
                    conn.execute(f.read_text(encoding="utf-8"))
                    conn.execute("INSERT INTO node.schema_migrations (version) VALUES (%s)", (f.stem,))
                applied.append(f.stem)
        finally:
            conn.execute("SELECT pg_advisory_unlock(%s)", (LOCK_ID,))
    return applied


def main() -> int:
    dsn = os.environ.get("FORGE_NODEHUB_MIGRATE_DSN")
    if not dsn:
        print("FORGE_NODEHUB_MIGRATE_DSN is required", file=sys.stderr)
        return 2
    pwf = os.environ.get("FORGE_NODEHUB_MIGRATE_PASSWORD_FILE")
    try:
        applied = migrate(dsn, password=Path(pwf).read_text().rstrip("\r\n") if pwf else None)
    except MigrateError as e:
        print(f"node migration: {e}", file=sys.stderr)
        return 3
    print("node migrations applied:", ", ".join(applied) if applied else "none (up to date)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
