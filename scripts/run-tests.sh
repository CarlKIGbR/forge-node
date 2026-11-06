#!/usr/bin/env bash
# Tests ohne Installation auf dem Host: Wegwerf-Postgres (--network none, nur Unix-Socket in einem Temp-Verzeichnis) + Test-Container mit dem Repo (read-only) und dem
# ssh-keygen des Hosts (samt Loader/Bibliotheken als Shim, weil das Test-Image kein OpenSSH enthaelt). Beides wird am Ende entfernt. Nichts wird auf dem Host installiert.
#   scripts/run-tests.sh [pytest-Argumente]      (FN_REPEAT=n: n aufeinanderfolgende pytest-Prozesse im selben Container, Abbruch beim ersten Fehler - Flake-Nachweis)
# Umgebung: FN_TEST_IMAGE (Default forge-core/tests:local, Python 3.12 + pytest + psycopg), FN_PG_IMAGE (Default: IMG_PGVECTOR aus forge-core/images.lock).
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
IMG="${FN_TEST_IMAGE:-forge-core/tests:local}"
PGIMG="${FN_PG_IMAGE:-$(sed -n 's/^IMG_PGVECTOR=//p' "$HERE/../forge-core/images.lock" 2>/dev/null | head -1)}"
[ -n "$PGIMG" ] || { echo "FN_PG_IMAGE nicht gesetzt und forge-core/images.lock nicht gefunden" >&2; exit 2; }
T="$(mktemp -d /tmp/fn-tests.XXXXXX)"; chmod 755 "$T"
SOCK="$T/pg"; mkdir "$SOCK"; chmod 777 "$SOCK"
# N3 (gate D): real-filesystem audit tests. A directory on the HOST's ext4 (below $T, i.e. below /tmp) is bind-mounted into the test container, which alone gets CAP_LINUX_IMMUTABLE
# (chattr +a / +i); no mount, no loop device, no --privileged. The inode flags are cleared and the directory emptied by the cleanup below, even after a failed run.
FSDIR="$T/fs"; mkdir "$FSDIR"; chmod 755 "$FSDIR"
SHIM="$T/shim"; mkdir -p "$SHIM/lib" "$SHIM/bin"
PGNAME="fn-n1-pg-$$"
# Das Postgres-Image setzt das Socket-Verzeichnis auf 3777 (sticky): die Socket-Dateien gehoeren uid 999 und werden als root aus einem Container entfernt.
cleanup() {
    docker rm -f "$PGNAME" >/dev/null 2>&1 || true
    docker run --rm --network none --cap-add LINUX_IMMUTABLE -v "$T:/t" -v "$HERE/scripts:/s:ro" --entrypoint sh "$IMG" -c 'rm -rf /t/pg; python3 /s/clear_flags.py /t/fs' >/dev/null 2>&1 || true
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
docker run --rm --network none --cap-add LINUX_IMMUTABLE --tmpfs /tmp:rw,exec,mode=1777 -v "$HERE:/w:ro" -v "$SOCK:/pgsock" -v "$FSDIR:/realfs" -v "$SHIM:/shim:ro" -w /w \
  -e FN_REAL_FS=/realfs -e PATH="/shim/bin:/app/.venv/bin:/usr/local/bin:/usr/bin:/bin" -e PYTHONDONTWRITEBYTECODE=1 -e PYTHONPATH=/w/scripts -e FN_COV="${FN_COV:-}" -e FN_REPEAT="${FN_REPEAT:-1}" -e FORGE_NODE_TEST_DSN="host=/pgsock user=postgres dbname=postgres" \
  --entrypoint sh "$IMG" -c 'n=$FN_REPEAT; i=0; while [ "$i" -lt "$n" ]; do i=$((i+1)); python3 -m pytest "$@" || { echo "FN_REPEAT: run $i of $n FAILED"; exit 1; }; done; [ "$n" -gt 1 ] && echo "FN_REPEAT: $n of $n consecutive runs passed"; exit 0' sh "$@"
