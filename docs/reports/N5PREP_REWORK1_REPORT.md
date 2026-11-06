Head: 01f66c5 / ops 476d335
REWORK round 1 of 3 for N5-prep (verify n-09d83249 = REWORK). forge-node `n5prep` 01f66c5 (base 416317a, 1 commit) · forge-ops `n5prep` 476d335 (base 4c508dc, 1 commit). Nothing merged, installed, started or applied.
Full guide (German, copy-paste, 16 command blocks, all `bash -n`-checked): `docs/reports/N5PREP_OWNER_GUIDE.md` (350 lines — more than this report's 140-line cap; the corrected parts are quoted verbatim below). Hub GO: `N5PREP_HUB_GO.md` (+1 line: the owner renews the boot copy first).

## MAJOR fixes
| # | where (before → after) | fix | proof |
|---|---|---|---|
| M-1 | README.md:62@4c508dc, guide:89@416317a → ops `bin/forge-docker-user.sh:142-146,182,213`, README:62-66, guide Teil 4.1–4.3 (l.103-146) | guide runs `sudo $FW --install-unit` (root copy + units; no rules, no start) BEFORE the rules; `--hub` and `--confirm --hub` now REFUSE (exit 1, nothing changed) unless `/usr/local/sbin/forge-docker-user.sh` is byte-identical to the script (`cmp`); dry-run prints WARNUNG; README corrected incl. the boot-ordering window (Docker starts the hub a few seconds before the unit); boot proof after confirm: installed copy `--dry-run --restore` shows 3 `forge-nodehub` inserts | ops tests 30 → 45: no/stale copy ⇒ apply+confirm refuse, no marker; master script 77df871 as boot copy restores 0 hub rules and `--hub` refuses; `--install-unit` ⇒ identical copy, unit ExecStart = root copy `--restore`; **reboot simulation**: apply+confirm, then the INSTALLED copy `--restore` inserts 3 hub (8094, accepts before DROP) + 8 edge rules, no timer. 7 fail on 4c508dc; 4 hand mutants (drop either check, `cmp`→true, skip hub restore) killed |
| M-2 | guide:244@416317a → guide Teil 7.6 (l.320-347) | `sudo find /var/log/forge-node-priv /var/log/forge-node-agent -name '*.jsonl' -exec chattr -i -a {} +` after the tar backup; block is `set -euo pipefail`; verifies every directory/user/unit is gone; deletes dangling unit links | `test_guide_uninstall_removes_sealed_audit_logs_of_the_real_layout` (real ext4, root): real layout `<dir>/priv.NNNNNN/priv.NNNNNN.jsonl` built by `AuditAdmin` (sealed +a+i, live +a); the old glob `chattr -a dir/*.jsonl` fails; the guide's own `rm -rf` line fails with EPERM on the sealed tree; the guide's find line, then its rm line ⇒ both log trees gone |
| M-3 | guide:73-74@416317a → guide Teil 3.1/3.2 (l.67-100) | on g2 `sudo install -m 0644 -o "$(id -un)" $S/hub.csr /tmp/hub.csr` (+ gate pub), `scp` from /tmp, then `rm` | `test_files_owned_by_other_users_…`: no scp/ssh source path outside /tmp/ anywhere in the guide; staging lines present |

## MINOR status
m-1 fixed: `sudo -u forge …` + `sudo chgrp forgebox …` (no `-g`: a sudoers rule `(forge : forgebox)` is not assumed) + a `stat` check for `600 forge:forgebox` · m-2 fixed: every block is `( set -euo pipefail … ) && echo "== OK" || echo "== FEHLER"`, so a failed guard stops the block (the agent starts only when `doctor` = 0, `rc` captured) and the login shell never gets `set -e` (test: all 16 blocks) · m-3 fixed: the text says doctor's hub check is `/healthz` only and proves nothing about registration; Teil 6 has a hub-side `now()-last_seen` query for every host · m-4 fixed: `build_policy_store()` extracted from `build_context`; test pins the `release_table_ops` wiring (mutant `table.names` killed) · m-5 fixed (message says 8094 is OFFEN; tested) · m-6 fixed: evidence is readable lines in /var/tmp (`fn-ev.sh`, `fn-ev-before-<NID>.txt`) and the diff is judged per line; Teil 4 says the local `curl` does not pass DOCKER-USER — the g3 `s_client` and a VPN negative test do.
Same classes re-checked over the whole guide (found beyond the verify): `carl` cannot `rm` `/tmp/fn-src.tar` (forge's) or `/tmp/<NID>.csr` (forgenode's) in the sticky /tmp ⇒ `sudo rm`; `id forgenode`, `df`, `ss | grep -c` under `pipefail` ⇒ `|| true`; the `A && B || C` slip in the sudoers check ⇒ `if`; the evidence file sat in /tmp and was deleted by the cleanup ⇒ /var/tmp.

## Suites (git-archive exports, uid 994)
- forge-node full: `timeout 1800 scripts/run-tests.sh -q` at 01f66c5: **1287 passed, 0 failed** (7:00).
- `tests/test_n5prep.py`: 36 tests (30 + 6 new). On 416317a with the new file: **6 fail, 30 pass** (subshell/set-e, other-users paths, boot-copy order, real-layout uninstall, quoting, production wiring).
- forge-ops, all 9 scripts rc 0: ci_gates 56, docker_user_hub **45** (was 30), evidence_order 47, heartbeat 14, postbote 40, restart 13, run_kind 213, stop 54, write_result 153.
- Hand mutants: ops 4/4 killed; forge-node guide/wiring 8/8 killed (no `chattr -i`, hub CSR not staged, no install-unit step, `table.names`, carl `rm`, old glob, block without `set -e`, boot proof off).

## Still not proven
The node-side install on a real host (systemd, `chattr`, `useradd`) and an actual reboot of g2 were not run — only the simulated boot path (installed copy `--restore` against stub iptables) and the real-ext4 removal of an audit tree. The hub GO is still not sent.

## Corrected parts of the OWNER INSTALL GUIDE (verbatim; the rest is in the file)
**3.1 g2: hub keys, public parts via /tmp (M-3, m-1)**
```bash
(
set -euo pipefail
S=/srv/forge/work/forge-core/secrets/nodehub
sudo install -d -m 0750 -o forge -g forgebox $S
sudo -u forge sh -c "umask 077; openssl ecparam -name prime256v1 -genkey -noout -out $S/hub.key"
sudo -u forge openssl req -new -key $S/hub.key -subj "/CN=forge-nodehub" -out $S/hub.csr
sudo -u forge ssh-keygen -t ed25519 -N '' -C forge-node-hub-gate -f $S/gate_ed25519
sudo chgrp forgebox $S/hub.key $S/hub.csr $S/gate_ed25519 $S/gate_ed25519.pub        # forges Standardgruppe ist 980, die Compose-Gruppe forgebox (981); GO-Preflight P1 erwartet forge:forgebox
test "$(sudo stat -c '%a %U:%G' $S/hub.key $S/gate_ed25519 | sort -u)" = "600 forge:forgebox" || { echo "MODI/GRUPPE FALSCH"; false; }
# Public-Teile für den Mac nach /tmp (carl-eigen, 0644 — nur Public-Daten): secrets/ ist für carl nicht lesbar
sudo install -m 0644 -o "$(id -un)" $S/hub.csr /tmp/hub.csr
sudo install -m 0644 -o "$(id -un)" $S/gate_ed25519.pub /tmp/hub_gate_ed25519.pub
ls -l /tmp/hub.csr /tmp/hub_gate_ed25519.pub
) && echo "== OK" || echo "== FEHLER: STOP"
```
**4.1 Boot-Kopie erneuern (M-1)**
```bash
(
set -euo pipefail
FW=/srv/forge/work/forge-ops/bin/forge-docker-user.sh
sudo git -C /srv/forge/work/forge-ops log -1 --format='forge-ops: %H %s'        # == <OPS_SHA> aus der Merge-Meldung
sudo $FW --dry-run --install-unit               # nur ansehen: install → /usr/local/sbin, 2 Units, daemon-reload, enable (kein Start)
sudo $FW --install-unit
sudo cmp $FW /usr/local/sbin/forge-docker-user.sh && echo "Boot-Kopie identisch"
grep -c -- '--hub' /usr/local/sbin/forge-docker-user.sh
sudo $FW --dry-run --hub                        # 3 iptables-Zeilen (2x ACCEPT /29, 1x DROP), Timer-Zeile "--remove --hub", "# 0. Boot-Kopie ... ok"
) && echo "== OK" || echo "== FEHLER: STOP"
```
**4.3 Bestätigen + Boot-Nachweis (M-1)**
```bash
(
set -euo pipefail
sudo /srv/forge/work/forge-ops/bin/forge-docker-user.sh --confirm --hub
sudo iptables -S DOCKER-USER | grep forge-nodehub
n=$(sudo /usr/local/sbin/forge-docker-user.sh --dry-run --restore | grep -c '^iptables -I.*forge-nodehub' || true)
[ "$n" = 3 ] && echo "Boot-Pfad (Root-Kopie --restore) legt die 3 Hub-Regeln wieder an" || { echo "BOOT-PFAD OHNE HUB-REGELN - Betriebsleitung"; false; }
) && echo "== OK" || echo "== FEHLER: STOP"
```
**7.6 Deinstallation (M-2)**
```bash
(
set -euo pipefail
NID=g2                                          # der Host, den du deinstallierst
sudo /opt/forge-node/current/bin/privctl lockdown || echo "(lockdown nicht möglich - weiter mit systemctl)"
sudo systemctl disable --now forge-node-audit-rotate.timer forge-node-agent.service forge-node-privd.socket forge-node-privd.service || true
for u in $(systemctl list-unit-files --no-legend 'forge-node-*' | awk '{print $1}'); do sudo systemctl disable "$u" 2>/dev/null || true; done
sudo find /etc/systemd/system -maxdepth 2 -name 'forge-node-*' -xtype l -delete       # verwaiste Links in den entfernten Release-Baum
sudo systemctl daemon-reload
sudo tar -czf /root/forge-node-audit-$(hostname)-$(date +%Y%m%d).tgz -C /var/log forge-node-priv forge-node-agent          # Beweise zuerst sichern
sudo ls -l /root/forge-node-audit-$(hostname)-$(date +%Y%m%d).tgz
sudo find /var/log/forge-node-priv /var/log/forge-node-agent -name '*.jsonl' -exec chattr -i -a {} +                       # Siegel (+a +i) lösen, sonst scheitert rm mit EPERM
sudo rm -f /usr/local/sbin/forge-node-release
sudo rm -rf /opt/forge-node /etc/forge-node /var/lib/forge-node /var/lib/forge-node-priv /var/log/forge-node-priv /var/log/forge-node-agent /run/forge-node
sudo userdel forgenode
# Nachweis, dass wirklich alles weg ist:
for d in /opt/forge-node /etc/forge-node /var/lib/forge-node /var/lib/forge-node-priv /var/log/forge-node-priv /var/log/forge-node-agent /usr/local/sbin/forge-node-release; do
  if sudo test -e "$d"; then echo "NOCH DA: $d"; false; fi
done
if id forgenode >/dev/null 2>&1; then echo "Benutzer forgenode existiert noch"; false; fi
if systemctl list-unit-files --no-legend 'forge-node-*' | grep -q .; then echo "Units noch da"; false; fi
. /var/tmp/fn-ev.sh; ev > /var/tmp/fn-ev-after-uninstall-$NID.txt
diff /var/tmp/fn-ev-before-$NID.txt /var/tmp/fn-ev-after-uninstall-$NID.txt && echo "EVIDENZ UNVERAENDERT" || echo "Differenz einzeln bewerten (vor Tagen aufgenommen; Container/mtimes driften auch ohne uns)"
) && echo "== OK: deinstalliert" || echo "== FEHLER: unvollständig - Ausgabe an die Betriebsleitung, nichts von Hand 'nachbessern'"
```
