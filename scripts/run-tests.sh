#!/usr/bin/env bash
# Tests ohne Installation auf dem Host: Wegwerf-Postgres (--network none, nur Unix-Socket in einem Temp-Verzeichnis) + Test-Container mit dem Repo (read-only) und dem
# ssh-keygen des Hosts (samt Loader/Bibliotheken als Shim, weil das Test-Image kein OpenSSH enthaelt). Beides wird am Ende entfernt. Nichts wird auf dem Host installiert.
#   scripts/run-tests.sh [pytest-Argumente]
# Umgebung: FN_TEST_IMAGE (Default forge-core/tests:local, Python 3.12 + pytest + psycopg), FN_PG_IMAGE (Default: IMG_PGVECTOR aus forge-core/images.lock).
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
IMG="${FN_TEST_IMAGE:-forge-core/tests:local}"
PGIMG="${FN_PG_IMAGE:-$(sed -n 's/^IMG_PGVECTOR=//p' "$HERE/../forge-core/images.lock" 2>/dev/null | head -1)}"
[ -n "$PGIMG" ] || { echo "FN_PG_IMAGE nicht gesetzt und forge-core/images.lock nicht gefunden" >&2; exit 2; }
T="$(mktemp -d /tmp/fn-tests.XXXXXX)"; chmod 755 "$T"
SOCK="$T/pg"; mkdir "$SOCK"; chmod 777 "$SOCK"
SHIM="$T/shim"; mkdir -p "$SHIM/lib" "$SHIM/bin"
PGNAME="fn-n1-pg-$$"
# Das Postgres-Image setzt das Socket-Verzeichnis auf 3777 (sticky): die Socket-Dateien gehoeren uid 999 und werden als root aus einem Container entfernt.
cleanup() {
    docker rm -f "$PGNAME" >/dev/null 2>&1 || true
    docker run --rm --network none -v "$T:/t" --entrypoint sh "$IMG" -c 'rm -rf /t/pg' >/dev/null 2>&1 || true
    rm -rf "$T"
}
trap cleanup EXIT

# ssh-keygen des Hosts als Shim (eigener Loader + Bibliotheken, unabhaengig von der libc des Test-Images)
KG="$(command -v ssh-keygen)"
cp "$KG" "$SHIM/ssh-keygen.real"
ldd "$KG" | awk '/=>/ {print $3} /ld-linux/ {print $1}' | while read -r l; do [ -f "$l" ] && cp -L "$l" "$SHIM/lib/"; done
LOADER="$(basename "$(ldd "$KG" | awk '/ld-linux/ {print $1}')")"
printf '#!/bin/sh\nexec /shim/lib/%s --library-path /shim/lib /shim/ssh-keygen.real "$@"\n' "$LOADER" > "$SHIM/bin/ssh-keygen"; chmod +x "$SHIM/bin/ssh-keygen"

docker run -d --name "$PGNAME" --network none -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_USER=postgres -v "$SOCK:/var/run/postgresql" \
  --tmpfs /var/lib/postgresql/data:rw,mode=1777 "$PGIMG" -c listen_addresses='' -c fsync=off -c max_connections=100 >/dev/null
for _ in $(seq 1 60); do docker exec "$PGNAME" pg_isready -q -U postgres 2>/dev/null && break; sleep 0.5; done
docker exec "$PGNAME" pg_isready -q -U postgres || { echo "Postgres kam nicht hoch" >&2; exit 1; }
docker run --rm --network none --tmpfs /tmp:rw,exec,mode=1777 -v "$HERE:/w:ro" -v "$SOCK:/pgsock" -v "$SHIM:/shim:ro" -w /w \
  -e PATH="/shim/bin:/app/.venv/bin:/usr/local/bin:/usr/bin:/bin" -e PYTHONDONTWRITEBYTECODE=1 -e FORGE_NODE_TEST_DSN="host=/pgsock user=postgres dbname=postgres" \
  --entrypoint python3 "$IMG" -m pytest "$@"
