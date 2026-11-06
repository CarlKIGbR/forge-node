#!/usr/bin/env bash
# forge-nodehub image (N5-prep): local build on the forge host, nothing is started. The base is forge-core's app image; it is found by its LOCAL TAG (BuildKit would try to pull a bare image ID),
# and that tag must be exactly the image pinned in forge-core/images.lock. Prints the pin line for images.lock (the GO appends it; this script changes no file outside the Docker image store).
#   scripts/build-hub.sh [forge-core-dir]        (default ../forge-core)
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CORE="${1:-$HERE/../forge-core}"
PIN="$(sed -n 's/^IMG_FORGE_CORE_APP=//p' "$CORE/images.lock" | head -1)"
[ -n "$PIN" ] || { echo "IMG_FORGE_CORE_APP not found in $CORE/images.lock" >&2; exit 2; }
ID="$(docker image inspect -f '{{.Id}}' forge-core/app:build 2>/dev/null || true)"
[ "$ID" = "$PIN" ] || { echo "forge-core/app:build is '$ID' but images.lock pins '$PIN' - build/pull the pinned image first" >&2; exit 3; }
HEAD="$(git -C "$HERE" rev-parse --short=12 HEAD)"
git -C "$HERE" diff --quiet HEAD -- Dockerfile src migrations || { echo "working tree differs from HEAD in Dockerfile/src/migrations - commit first" >&2; exit 4; }
docker build -q --build-arg BASE_IMAGE=forge-core/app:build --build-arg FORGE_UID="${FORGE_UID:-994}" --build-arg FORGE_GID="${FORGE_GID:-981}" -t "forge-node/hub:build-$HEAD" -t forge-node/hub:build "$HERE" >/dev/null
HID="$(docker image inspect -f '{{.Id}}' "forge-node/hub:build-$HEAD")"
echo "built forge-node/hub:build-$HEAD"
echo "IMG_FORGE_NODEHUB=$HID"
