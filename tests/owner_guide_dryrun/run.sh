#!/usr/bin/env bash
# Owner-guide dry run: builds a throw-away "host" container (Ubuntu 24.04, git 2.43, forge uid 994/gid 980, forgebox 981, secrets/ drwx--S--- forge, user carl = sudo but NOT in forgebox, user owner = the Mac)
# and EXECUTES every bash block of docs/reports/N5PREP_OWNER_GUIDE.md in order as the right user under set -euo pipefail. Stubbed (listed in the output): systemd, Docker/psql, iptables, curl/hub, openssl s_client,
# ssh/scp (= local user carl), the pager, `doctor` (permission check + injected verdict), the agent. Real: sudo, permissions, git, openssl, ssh-keygen (passphrase prompts through a pty), release build/sign,
# install-first, privctl audit-init/policy-apply/status/audit-verify against a REAL privd, chattr on ext4, container_net probe against a dummy interface (--cap-add NET_ADMIN: one `ip link add` inside the container's own netns, --network none stays), useradd/userdel, forge-docker-user.sh.
#   tests/owner_guide_dryrun/run.sh [--host g2|g3|g1|g4] [--doctor-rc N]       env: FN_OPS_DIR (forge-ops checkout; default ../forge-ops-n5prep or ../forge-ops)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; NODE="$(cd "$HERE/../.." && pwd)"
OPS="${FN_OPS_DIR:-}"; for c in "$NODE/../forge-ops-n5prep" "$NODE/../forge-ops"; do [ -n "$OPS" ] || { [ -f "$c/bin/forge-docker-user.sh" ] && OPS="$c"; }; done
[ -f "$OPS/bin/forge-docker-user.sh" ] || { echo "forge-ops checkout not found (FN_OPS_DIR)" >&2; exit 2; }
IMG=forge-node/owner-guide-dryrun:local
docker build -q -t "$IMG" "$HERE" >/dev/null
T="$(mktemp -d /tmp/fn-guide.XXXXXX)"; chmod 755 "$T"; mkdir "$T/varlog"; chmod 755 "$T/varlog"
cleanup() { docker run --rm --cap-add LINUX_IMMUTABLE -v "$T:/t" -v "$NODE/scripts:/s:ro" --entrypoint sh "$IMG" -c 'python3 /s/clear_flags.py /t/varlog; rm -rf /t/varlog' >/dev/null 2>&1 || true; rm -rf "$T"; }
trap cleanup EXIT
docker run --rm --network none --cap-add LINUX_IMMUTABLE --cap-add NET_ADMIN -v "$T/varlog:/var/log" -v "$NODE:/src/node:ro" -v "$OPS:/src/ops:ro" "$IMG" "$@"
