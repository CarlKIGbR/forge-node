Head: 67530a9 / ops 476d335
REWORK round 2 of 3 for N5-prep (re-verify n-689b29da = REWORK). forge-node `n5prep` 67530a9 (base 7971649, 1 commit) · forge-ops `n5prep` 476d335 (unchanged: no ops code changed). Nothing merged, installed, started or applied. Done at 23:15 UTC (stop was 00:55).
Full guide (German, 16 blocks, 385 lines — more than this report's cap; changed blocks quoted below): `docs/reports/N5PREP_OWNER_GUIDE.md`.

## The class fix: owner-guide dry-run harness
`tests/owner_guide_dryrun/run.sh [--host g2|g3|g1|g4] [--doctor-rc N]` (+ `tests/test_owner_guide_dryrun.py`, skipped inside run-tests.sh because it needs Docker): an Ubuntu 24.04 container (git 2.43) with forge uid 994/gid 980, forgebox 981, `forge-core/secrets` = `drwx--S--- forge:forgebox`, user `carl` (sudo, NOT in forgebox), user `owner` (the Mac), kmuai-owned /opt/kmu-ai, the same paths. It EXECUTES every bash block as the user its `<!-- run: mac|host -->` marker names (a block without marker fails the run), in guide order, in a pty (passphrase prompts answered), under the guide's own `set -euo pipefail`, then checks post-conditions (owners/modes, files, stub logs).
Real in the harness: sudo/permissions, git, openssl, ssh-keygen with passphrase, `release build/sign`, `install-first`, `privctl audit-init/policy-apply/status/audit-verify` against a REAL privd (socket-activation stub), chattr on ext4 (CAP_LINUX_IMMUTABLE), useradd/userdel, `forge-docker-user.sh` (install-unit, apply, confirm, restore dry-run), the uninstall.
**Stubbed (listed in every run):** systemctl/systemd-run/journalctl/timedatectl (`link`/`disable` really create/remove unit links), `forge-node doctor` (needs systemd transient units: runs as forgenode, checks pyz/key/cert/CA/policy readability, verdict injected), Docker + Postgres (`docker exec … sh -c` runs with a logging psql), iptables (state file), curl (keeps the real exit 77 for an unreadable `--cacert`) and `openssl s_client` (no hub), ssh/scp (= local user carl), pager, sudo password prompts.
| block | result g2 (and g4) | block | result |
|---|---|---|---|
| 00 Teil 1 Mac keys+CA | pass | 08 5.1 fn.env + scp | pass |
| 01 Teil 2 build (2 passphrases) | pass | 09 5.2 segment 1 (real install-first, audit-init) | pass |
| 02 3.1 hub keys on g2 | pass | 10 5.3 Mac sign cert+policy | pass |
| 03 3.2 sign hub cert | pass | 11 5.4 segment 2 (real privd policy-apply/status) | pass (doctor stubbed) |
| 04 4.1 boot copy | pass (iptables/systemd stubbed) | 12 5.5 registration | pass (psql stubbed) |
| 05 4.2 apply | pass (stubbed) | 13 6a host check | pass |
| 06 4.2 g3/VPN tests | pass (s_client stubbed) | 14 6b hub query | pass (psql stubbed) |
| 07 4.3 confirm + boot proof | pass (stubbed) | 15 7.6 uninstall (real chattr/rm/userdel) | pass |
Runs: g2 16/16, g4 16/16, `--doctor-rc 1`: block 5.4 prints `== FEHLER`, "Agent wird NICHT gestartet", agent never enabled (12/12 expected).
**Does the harness catch the class?** 6 reintroduced regressions, each killed in its own block: `sudo git` (M-4) → [04]; `curl` without sudo (M-5) → [05]; old `chattr -a *.jsonl` glob (M-2) → [15]; `scp` from `secrets/` (M-3) → [03]; `git -C /opt/kmu-ai` as carl → [09]; `rm /tmp/<NID>.csr` without sudo → [11].

## MAJOR fixes
| # | where (before → after) | fix | proof |
|---|---|---|---|
| M-4 | guide:111@01f66c5 → Teil 4.1 | `sudo -u forge git --no-pager -C /srv/forge/work/forge-ops log -1 …` (no safe.directory anywhere; `--no-pager`: the harness showed git paging on a tty hangs the block) | harness [04]; mutant `sudo git` killed |
| M-5 | guide:125@01f66c5 → Teil 4.2 | `sudo curl -s --cacert …/secrets/nodehub/ca.crt …` (+ note) | harness [05] (curl stub exits 77 for a file carl cannot read); mutant killed |

## Found by the harness beyond the re-verify (all fixed)
1. **`( set -e … ) && echo OK || echo FEHLER` ignores `set -e` inside the subshell** (bash: -e is off in `&&` lists). Rework 1's "stops the block" claim was false for ALL 16 blocks — e.g. a failing `privctl audit-init` still printed `== OK`. Now every block is a standalone `( set -euo pipefail … )` followed by `rc=$?; if [ $rc = 0 ]; then echo "== OK"; else echo "== FEHLER (rc=$rc)"; fi` (login blocks `ssh -t` only when rc=0). Tests: structure of all 16 blocks + a mechanism test showing the old form runs on after `false` and the new one stops.
2. `ev()` ran `git -C /opt/kmu-ai` as carl (repo owned by another user ⇒ "dubious ownership", evidence recorded the error): now `sudo -u "$(stat -c %U /opt/kmu-ai)" git …`; harness checks the HEAD hash is in the evidence file.
3. Harness-only (not guide) corrections: `/var/log` must be root-owned for `audit-init` (as on a host); sudo `-v` prompt; psql stub must not read a tty.

## MINOR status (n-689b29da)
m-a fixed (`privctl status`, `audit-verify`, `doctor`, `cmp` on their own lines, no `&& echo`; with finding 1 they now stop the block) · m-b fixed (`ssh … 'openssl s_client … | grep -q "CONNECTION ESTABLISHED"'`) · m-c fixed (`< file && rm -f file`: a failed INSERT no longer ends OK) · m-d fixed (finding 2) · m-e: boot-time window (Docker starts the hub before the restore unit; a failed hub restore leaves 8094 open) is now also in guide Teil 4 with the advice to reboot g2 only after agreement with the Betriebsleitung (ops README already had it).

## Suites
- forge-node full, uid 994, `timeout 1800 scripts/run-tests.sh -q` on a `git archive` export of 67530a9: **1289 passed, 3 skipped** (the 3 Docker-only harness tests) in 7:03. `test_n5prep.py` 38 (36 + 2: block structure, mechanism).
- forge-ops: all 9 scripts rc 0 (ci_gates 56, docker_user_hub 45, evidence_order 47, heartbeat 14, postbote 40, restart 13, run_kind 213, stop 54, write_result 153); unchanged code.
- Not covered: stubbed pieces above (real systemd/doctor/iptables/Docker/hub, a real reboot). The hub GO is still not sent.

## Corrected blocks of the OWNER INSTALL GUIDE (verbatim)
**4.1**
```bash
(
set -euo pipefail
FW=/srv/forge/work/forge-ops/bin/forge-docker-user.sh
sudo -u forge git --no-pager -C /srv/forge/work/forge-ops log -1 --format='forge-ops: %H %s'        # == <OPS_SHA> aus der Merge-Meldung
sudo $FW --dry-run --install-unit               # nur ansehen: install → /usr/local/sbin, 2 Units, daemon-reload, enable (kein Start)
sudo $FW --install-unit
sudo cmp $FW /usr/local/sbin/forge-docker-user.sh
echo "Boot-Kopie identisch"
grep -c -- '--hub' /usr/local/sbin/forge-docker-user.sh
sudo $FW --dry-run --hub                        # 3 iptables-Zeilen (2x ACCEPT /29, 1x DROP), Timer-Zeile "--remove --hub", "# 0. Boot-Kopie ... ok"
)
rc=$?; if [ $rc = 0 ]; then echo "== OK"; else echo "== FEHLER: STOP (rc=$rc)"; fi
```
**4.2**
```bash
(
set -euo pipefail
sudo /srv/forge/work/forge-ops/bin/forge-docker-user.sh --hub
sudo iptables -S DOCKER-USER | grep -c forge-nodehub        # 3
sudo curl -s --cacert /srv/forge/work/forge-core/secrets/nodehub/ca.crt https://192.168.10.4:8094/healthz        # {"ok":true,...}  (`sudo`: `secrets/` ist für carl nicht lesbar. Hinweis: dieser Aufruf von g2 aus läuft NICHT durch DOCKER-USER, er beweist die Regel nicht)
)
rc=$?; if [ $rc = 0 ]; then echo "== OK: jetzt die Tests unten (aus dem /29 von g3 und von ausserhalb), dann 4.3"; else echo "== FEHLER: STOP (Timer rollt zurück) (rc=$rc)"; fi
```
**5.5 (m-c)**
```bash
(
set -euo pipefail
cd ~/forge-node-owner; set -a; . ./fn.env; set +a
FP=$(openssl x509 -in issued/$NID.crt -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'); echo "$FP"      # 64 Hex, klein; == dem in 5.3 notierten Wert
printf "%s" "$FP" | grep -Eq '^[0-9a-f]{64}$' || { echo "FINGERABDRUCK UNGUELTIG"; false; }
printf "SET ROLE forge_core;\nINSERT INTO node.nodes (node_id, profile, status, cert_sha256) VALUES ('%s','t0','active','%s');\nSELECT node_id, profile, status, left(cert_sha256,12) AS fp FROM node.nodes ORDER BY node_id;\n" "$NID" "$FP" > register-$NID.sql
cat register-$NID.sql                                              # lesen
scp -i ~/.ssh/sshcarljump01 register-$NID.sql carl@192.168.10.4:/tmp/
ssh -t -i ~/.ssh/sshcarljump01 carl@192.168.10.4 "sudo docker exec -i forge-postgres-1 sh -c 'psql -v ON_ERROR_STOP=1 -U \"\$POSTGRES_USER\" -d forge' < /tmp/register-$NID.sql && rm -f /tmp/register-$NID.sql"
# Zertifikat erneuert (alle 90 Tage)?  UPDATE node.nodes SET cert_sha256='<neu>' WHERE node_id='<NID>';  (gleiche Technik)
)
rc=$?; if [ $rc = 0 ]; then echo "== OK"; else echo "== FEHLER: STOP (rc=$rc)"; fi
```
