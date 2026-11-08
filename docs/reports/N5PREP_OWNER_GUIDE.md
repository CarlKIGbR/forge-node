# forge-node T0 — Installationsanleitung für den Owner (alle vier Hosts, Profil `t0`)

Stand: N5-prep rework 1 + probefix (Version 0.5.1) (Branch `n5prep`, noch NICHT gemergt — die Befehle gelten für den gemergten Stand; `<MAIN_SHA>`/`<OPS_SHA>` stehen in der Merge-Meldung). Alle Blöcke sind Copy-and-paste; jeder `bash`-Block wird in den Tests auf Syntax geprüft.
**Betriebsleiter-Entscheidung:** alle vier Hosts bekommen vorerst das Profil `t0` (nur Lesen): **kein** forge-root-Volume, **kein** Loop-Volume, **kein** `selftest.noop`-Code, Policy `global_mode: observe`, `tiers_enabled: [0]`. Die Schritte „Loop-Volume" (13.C C3) und die Werte `full`/100 GiB/50 GiB entfallen. `full` bleibt für spätere T1-Schritte im Code (`template(nid, "full")`).
**Regeln:** pro Server eine SSH-Sitzung die ganze Zeit offen lassen (Rollback-Anker). Nie zwischen 02:00 und 05:45 Berlin, nie sonntags vor 06:00. Reihenfolge **g2 → g3 → g1 → g4** mit ≥ 1 Tag Beobachtung dazwischen; g4 (Live-Trading) zuletzt und nur mit deiner ausdrücklichen Zustimmung. Es wird nichts an sshd, sudoers oder Docker geändert (kein Docker-Neustart).
**Wie die Blöcke funktionieren:** jeder Block ist eine Subshell `( set -euo pipefail … )`, danach prüft eine Zeile `rc=$?` und schreibt `== OK` oder `== FEHLER (rc=…)`. Scheitert ein Befehl, endet NUR der Block; die SSH-Sitzung bleibt offen (kein `set -e` in deiner Login-Shell). Wichtig: die Subshell steht **allein** auf ihrer Zeile — in einer `&&`/`||`-Liste würde bash `set -e` darin ignorieren. Dann **stoppen und die Betriebsleitung informieren** — den Block nicht „reparieren" und nicht Rechte an `secrets/` o. ä. verbiegen. Der Login in einen Server (`ssh -t -i ~/.ssh/sshcarljump01 carl@<IP>`) steht jeweils im Text; ein Server-Block endet mit `== OK`; erst danach `exit`.
Dateien, die `forge`/`forgenode` anlegen, kann `carl` weder lesen noch löschen (Sticky-/tmp, `secrets/` ist `drwx--S--- forge`): Übergaben laufen deshalb immer über `sudo install … /tmp/…` bzw. `sudo rm`.

Reihenfolge der Teile: **Teil 1** (Mac, einmalig) → **Teil 2** (Release bauen) → **Teil 3** (Hub auf g2; GO an die Betriebsleitung) → **Teil 4** (Firewall 8094 + Boot-Kopie) → **Teil 5** (je Host: g2, g3, g1, g4) → **Teil 6** (Prüfung) → **Teil 7** (Rückgängig).

## Teil 1 — Mac, einmalig: Owner-Schlüssel und CA (13.A)
Voraussetzungen auf dem Mac: `ssh-keygen` (OpenSSH ≥ 8.1), `openssl`, **Python ≥ 3.12** (`python3 --version`; sonst `brew install python@3.12` und unten `python3.12` statt `python3`).
<!-- run: mac -->
```bash
(
set -euo pipefail
umask 077
mkdir -p ~/forge-node-owner/{ca,issued,release,policy} && cd ~/forge-node-owner

# A1: Owner-Signierschlüssel. ssh-keygen fragt zweimal nach einer PASSPHRASE: setzen und sicher aufbewahren.
ssh-keygen -t ed25519 -a 100 -C "forge-node-owner" -f owner_ed25519
printf 'owner@forge namespaces="forge-node-policy,forge-node-approval,forge-node-release" %s\n' \
  "$(cut -d' ' -f1,2 owner_ed25519.pub)" > allowed_signers
ssh-keygen -lf owner_ed25519.pub            # diesen Fingerabdruck (SHA256:...) notieren; er muss auf jedem Server wieder erscheinen

# A2: mTLS-CA (EC P-256, 5 Jahre); der Schlüssel verlässt den Mac nie
cat > ca/ca.cnf <<'EOF'
[req]
distinguished_name=dn
x509_extensions=v3_ca
prompt=no
[dn]
CN=forge-node-ca
[v3_ca]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
EOF
openssl ecparam -name prime256v1 -genkey -noout -out ca/ca.key
openssl req -x509 -new -key ca/ca.key -sha256 -days 1825 -config ca/ca.cnf -out ca/ca.crt
openssl x509 -in ca/ca.crt -noout -fingerprint -sha256 -dates
)
rc=$?; if [ $rc = 0 ]; then echo "== OK"; else echo "== FEHLER: STOP (rc=$rc)"; fi
```
Sichern (Offline-Kopie, z. B. verschlüsselter USB-Stick): `~/forge-node-owner/owner_ed25519` und `ca/ca.key`. Ohne sie lässt sich nichts mehr signieren; mit ihnen in falschen Händen schon.

## Teil 2 — Mac: Release bauen und signieren (je Version)
Das Release wird auf dem Mac aus genau dem gemergten Commit gebaut; der Schlüssel bleibt dort. `release build` signiert zweimal (Manifest, Tarball): **zweimal Passphrase auf dem Mac-Terminal**. (Alternative mit einer Eingabe: `ssh-add ~/forge-node-owner/owner_ed25519`, dann `--key ~/forge-node-owner/owner_ed25519.pub`.) Die Quelle holt `carl` über `/tmp` (das Repo gehört `forge`).
<!-- run: mac -->
```bash
(
set -euo pipefail
VER=0.5.1                              # Versionsname dieses Releases (0.5.0 hatte den doctor-Fehler probe:net/container_net: nicht mehr verwenden)
SHA='<MAIN_SHA>'                       # ersetzen: Commit aus der Merge-Meldung (40 Hex)
printf '%s' "$SHA" | grep -Eq '^[0-9a-f]{40}$' || { echo "SHA FEHLT"; false; }
cd ~/forge-node-owner
ssh -t -i ~/.ssh/sshcarljump01 carl@192.168.10.4 "sudo -u forge sh -c 'git -C /srv/forge/work/forge-node archive --format=tar --prefix=fn-src/ $SHA > /tmp/fn-src.tar' && sudo chmod 644 /tmp/fn-src.tar"
scp -i ~/.ssh/sshcarljump01 carl@192.168.10.4:/tmp/fn-src.tar ~/forge-node-owner/fn-src-$VER.tar
ssh -t -i ~/.ssh/sshcarljump01 carl@192.168.10.4 'sudo rm -f /tmp/fn-src.tar'          # die Datei gehört forge: carl darf sie im Sticky-/tmp nicht selbst löschen
mkdir -p src-$VER && tar -xf fn-src-$VER.tar -C src-$VER
cd src-$VER/fn-src
PYTHONPATH=src python3 -m forge_node.cli release build $VER t0 --out ~/forge-node-owner/release --key ~/forge-node-owner/owner_ed25519
# Erwartet: tar:/sig:/sha256:/signer: ; "signer: SHA256:..." == Fingerabdruck aus A1; "both signatures verified locally"
ls -l ~/forge-node-owner/release/
)
rc=$?; if [ $rc = 0 ]; then echo "== OK"; else echo "== FEHLER: STOP (rc=$rc)"; fi
```
Das t0-Release enthält die Policy-Vorlagen für **alle vier** Hosts (`policy/policy-g1…g4.json`, jeweils `profile: t0`, `observe`, `tiers_enabled: [0]`, ohne `forge_roots`).

## Teil 3 — Hub auf g2 (13.B; einmalig)
**3.1 Owner: Schlüssel auf g2 erzeugen** (Hub-Server-Schlüssel + Gate-Schlüssel bleiben auf g2; nur die Public-Teile gehen zum Mac). Login: `ssh -t -i ~/.ssh/sshcarljump01 carl@192.168.10.4`, dann auf carlgpu2:
<!-- run: host -->
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
)
rc=$?; if [ $rc = 0 ]; then echo "== OK"; else echo "== FEHLER: STOP (rc=$rc)"; fi
```
**3.2 Mac: Hub-Zertifikat signieren, zurückspielen.**
<!-- run: mac -->
```bash
(
set -euo pipefail
cd ~/forge-node-owner
scp -i ~/.ssh/sshcarljump01 carl@192.168.10.4:/tmp/hub.csr issued/
scp -i ~/.ssh/sshcarljump01 carl@192.168.10.4:/tmp/hub_gate_ed25519.pub issued/hub_gate_ed25519.pub
ssh -i ~/.ssh/sshcarljump01 carl@192.168.10.4 'rm -f /tmp/hub.csr /tmp/hub_gate_ed25519.pub'
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:192.168.10.4,DNS:forge-nodehub.lan\n' > issued/ext_hub.cnf
openssl x509 -req -in issued/hub.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial -days 365 -sha256 -extfile issued/ext_hub.cnf -out issued/hub.crt
openssl x509 -in issued/hub.crt -noout -subject -enddate; openssl x509 -in issued/hub.crt -noout -text | grep -A1 'Alternative Name'     # CN=forge-nodehub, IP Address:192.168.10.4 (kein '-ext': das LibreSSL des Mac kennt es nicht)
scp -i ~/.ssh/sshcarljump01 issued/hub.crt ca/ca.crt carl@192.168.10.4:/tmp/
ssh -t -i ~/.ssh/sshcarljump01 carl@192.168.10.4 \
  'sudo install -m 0644 -o forge -g forgebox /tmp/hub.crt /tmp/ca.crt /srv/forge/work/forge-core/secrets/nodehub/ && rm -f /tmp/hub.crt /tmp/ca.crt && sudo ls -l /srv/forge/work/forge-core/secrets/nodehub/'
)
rc=$?; if [ $rc = 0 ]; then echo "== OK"; else echo "== FEHLER: STOP (rc=$rc)"; fi
```
Erwartet in der letzten Ausgabe: `hub.key` und `gate_ed25519` `-rw------- forge forgebox`, `hub.crt`/`ca.crt`/`gate_ed25519.pub` `-rw-r--r-- forge forgebox`.
**3.3 GO an die Betriebsleitung:** „Hub-Deploy freigeben" (den fertigen GO-Text liefert N5PREP_REPORT.md). Sie baut das Image, legt Rolle und Schema an, migriert und startet NUR den Hub (Port 8094 nur auf 192.168.10.4). Das Ergebnis (`/healthz` ok, Container healthy) abwarten, bevor Teil 4 beginnt.

## Teil 4 — Firewall 8094 (forge-ops, nach dem Merge; mit 5-Minuten-Timer)
Der `--hub`-Regelsatz ist von den Edge-Regeln (443/8443) getrennt: 8094 auf 192.168.10.4 nur aus 192.168.10.0/29 und 192.168.30.0/29, nie aus dem VPN, sonst DROP. **Jeder Regel-Aufruf braucht `--hub`.** Zwischen Hub-Start (Teil 3.3) und diesem Teil ist 8094 nur auf der LAN-IP offen und verlangt ein Client-Zertifikat deiner CA (mTLS): das Fenster kurz halten. **Restfenster beim Reboot von g2:** Docker startet den Hub (`restart: unless-stopped`) einige Sekunden vor der Unit, die die Hub-Regeln wiederherstellt; scheitert dieser Restore, ist 8094 (nur mTLS davor) offen und die Unit meldet es auf stderr. Darum g2 nach der Installation nur nach Absprache mit der Betriebsleitung neu starten.
**Boot-Kopie:** beim Reboot führt `forge-docker-user.service` die ROOT-Kopie `/usr/local/sbin/forge-docker-user.sh --restore` aus, nicht das Repo-Script. Ohne Schritt 4.1 käme der Hub-Port nach einem Reboot OHNE Regeln zurück (aus jedem Netz, auch VPN, offen). Darum verweigern `--hub` und `--confirm --hub` ohne identische Boot-Kopie (Exit 1, nichts geändert). Login: `ssh -t -i ~/.ssh/sshcarljump01 carl@192.168.10.4`, dann auf carlgpu2:
**4.1 Boot-Kopie erneuern (ändert keine Regeln, startet nichts):**
<!-- run: host -->
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
**4.2 Anwenden** (der Timer rollt in 300 s zurück, solange du nicht bestätigst):
<!-- run: host -->
```bash
(
set -euo pipefail
sudo /srv/forge/work/forge-ops/bin/forge-docker-user.sh --hub
sudo iptables -S DOCKER-USER | grep -c forge-nodehub        # 3
sudo curl -s --cacert /srv/forge/work/forge-core/secrets/nodehub/ca.crt https://192.168.10.4:8094/healthz        # {"ok":true,...}  (`sudo`: `secrets/` ist für carl nicht lesbar. Hinweis: dieser Aufruf von g2 aus läuft NICHT durch DOCKER-USER, er beweist die Regel nicht)
)
rc=$?; if [ $rc = 0 ]; then echo "== OK: jetzt die Tests unten (aus dem /29 von g3 und von ausserhalb), dann 4.3"; else echo "== FEHLER: STOP (Timer rollt zurück) (rc=$rc)"; fi
```
Tests (andere Sitzung, Mac): aus dem Netz 192.168.30.0/29 muss es gehen, von ausserhalb (VPN 10.200.0.0/29 / ein Gerät dort) nicht.
<!-- run: mac -->
```bash
(
set -euo pipefail
ssh -i ~/.ssh/sshcarljump01 carl@192.168.30.3 'openssl s_client -connect 192.168.10.4:8094 -brief </dev/null 2>&1 | grep -q "CONNECTION ESTABLISHED"'      # Exit 0 nur bei CONNECTION ESTABLISHED
)
rc=$?; if [ $rc = 0 ]; then echo "== OK"; else echo "== FEHLER: Router-Regel TCP/8094 von 192.168.30.0/29 nötig (Owner) — NICHT bestätigen, der Timer rollt zurück (rc=$rc)"; fi
# Mac über VPN?  Dann muss dies nach ~5 s mit Timeout/Fehler scheitern:   nc -z -w 5 192.168.10.4 8094; echo "rc=$?"    (rc≠0 erwartet)
```
**4.3 Bestätigen** (innerhalb der 5 Minuten) **und Boot-Nachweis:**
<!-- run: host -->
```bash
(
set -euo pipefail
sudo /srv/forge/work/forge-ops/bin/forge-docker-user.sh --confirm --hub
sudo iptables -S DOCKER-USER | grep forge-nodehub
n=$(sudo /usr/local/sbin/forge-docker-user.sh --dry-run --restore | grep -c '^iptables -I.*forge-nodehub' || true)
[ "$n" = 3 ] && echo "Boot-Pfad (Root-Kopie --restore) legt die 3 Hub-Regeln wieder an" || { echo "BOOT-PFAD OHNE HUB-REGELN - Betriebsleitung"; false; }
)
rc=$?; if [ $rc = 0 ]; then echo "== OK"; else echo "== FEHLER: STOP (rc=$rc)"; fi
```

## Teil 5 — je Host (g2 → g3 → g1 → g4)
Werte (alle `t0`, kein Volume):

| | g2 (carlgpu2) | g3 (carlgpu3) | g1 (carlgpu1) | g4 (carlgpu4) |
|---|---|---|---|---|
| `NID` / `IP` | `g2` / `192.168.10.4` | `g3` / `192.168.30.3` | `g1` / `192.168.10.3` | `g4` / `192.168.30.4` |
| `PROFILE` / `FORGE_ROOT` | `t0` / `none` | `t0` / `none` | `t0` / `none` | `t0` / `none` |
| Extra vorher | Hub oben (Teil 3), Regel bestätigt (Teil 4); **Docker nicht neu starten** | M022-Job-Stand mit dem pe_packer-Verantwortlichen klären; `free -m` ansehen | keine ufw-Änderung nötig; n8n/Redis-Regeln nicht anfassen | `free -m`: ≥ 300 MiB „available" **und** deine Zustimmung; Handelszeiten beachten; sshd unberührt |
| Verbindungstest vor 5.4 | Loopback/LAN | `openssl s_client -connect 192.168.10.4:8094 -brief </dev/null` muss gehen | wie g2 (gleiches /29) | wie g3 (gleiches /29) |
| Danach warten | 1 Tag | 1 Tag | 1 Tag | — |

**5.1 Mac: `fn.env` für den Host** (Beispiel g2 — für jeden Host nur `NID` und `IP` ändern); der Block endet mit dem Login auf dem Server.
<!-- run: mac -->
```bash
(
set -euo pipefail
cd ~/forge-node-owner
cat > fn.env <<EOF
NID=g2
IP=192.168.10.4
VER=0.5.1
PROFILE=t0
FORGE_ROOT=none
FORGE_ROOT_BYTES=0
MIN_FREE_BYTES=0
EOF
set -a; . ./fn.env; set +a
test -f release/forge-node-$VER-$PROFILE.tar.sig
scp -i ~/.ssh/sshcarljump01 fn.env release/forge-node-$VER-$PROFILE.tar release/forge-node-$VER-$PROFILE.tar.sig allowed_signers carl@$IP:/tmp/
)
rc=$?; if [ $rc = 0 ]; then ssh -t -i ~/.ssh/sshcarljump01 carl@$(sed -n 's/^IP=//p' ~/forge-node-owner/fn.env); else echo "== FEHLER (rc=$rc): STOP"; fi
```
**5.2 Server, Segment 1** (Sitzung offen lassen): Vorprüfung, Evidenz vorher, Release prüfen, Benutzer/Verzeichnisse, Release-Baum, Node-Schlüssel.
<!-- run: host -->
```bash
(
set -euo pipefail
set -a; . /tmp/fn.env; set +a; : "${NID:?}" "${IP:?}" "${VER:?}" "${PROFILE:?}" "${FORGE_ROOT:?}"
[ "$PROFILE" = t0 ] && [ "$FORGE_ROOT" = none ] || { echo "FALSCHE WERTE: t0/none erwartet"; false; }
sudo -v

# C1 Vorprüfung (nur lesend)
date; TZ=Europe/Berlin date +%H:%M; timedatectl | grep -E 'Time zone|synchronized'
free -m | sed -n 1,3p; df -h / /srv/models /srv/kmu-ai 2>/dev/null || true
ss -tlnH | grep -c ':8094 ' || true                 # g1/g3/g4: 0 ; g2: 1 (der Hub)
python3 --version; python3 -c 'import sys; sys.exit(sys.version_info < (3,12))' || { echo "PYTHON ZU ALT"; false; }
id forgenode 2>&1 | head -1 || true                 # "no such user" erwartet
! id forgenode >/dev/null 2>&1 || { echo "forgenode existiert schon"; false; }
ls /etc/sudoers.d/ | grep -i forge || echo "kein forge-sudoers (erwartet: für immer keins)"
# Evidenz vorher (KMU/Trading dürfen sich durch die Installation nicht ändern); als Datei, damit sie in jeder späteren Shell da ist
cat > /var/tmp/fn-ev.sh <<'EOT'
ev() { systemctl list-units 'kmu-*' 'tradebot-*' 'secmpro*' --all --no-legend | awk '{print $1,$3,$4}'; echo "--- docker"; sudo docker ps -a --format '{{.Names}} {{.Image}}' | sort
       echo "--- git/mtime"; if [ -d /opt/kmu-ai ]; then sudo -u "$(stat -c %U /opt/kmu-ai)" git -C /opt/kmu-ai rev-parse HEAD 2>&1 || true; else echo "kein /opt/kmu-ai"; fi; stat -c '%n %Y' /opt/kmu-ai /srv/models 2>&1 || true; echo "--- listeners"; ss -tlnH | awk '{print $4}' | sort; }
EOT
. /var/tmp/fn-ev.sh; ev > /var/tmp/fn-ev-before-$NID.txt; wc -l /var/tmp/fn-ev-before-$NID.txt

# C2 Release prüfen
awk '{print $3,$4}' /tmp/allowed_signers | ssh-keygen -lf -                  # == Fingerabdruck aus A1
ssh-keygen -Y verify -f /tmp/allowed_signers -I owner@forge -n forge-node-release \
  -s /tmp/forge-node-$VER-$PROFILE.tar.sig < /tmp/forge-node-$VER-$PROFILE.tar        # erwartet: Good "forge-node-release" signature

# C3 Benutzer und Verzeichnisse (kein Loop-Volume im Profil t0)
sudo useradd --system --user-group --home-dir /var/lib/forge-node --create-home --shell /usr/sbin/nologin forgenode
sudo install -d -m 0755 -o root -g root /etc/forge-node /etc/forge-node/policy
printf 'FORGE_NODE_NODE_ID=%s\n' "$NID" | sudo tee /etc/forge-node/node.env >/dev/null
sudo install -d -m 0700 -o forgenode -g forgenode /etc/forge-node/pki
sudo install -d -m 0755 -o root -g root /opt/forge-node /opt/forge-node/releases
sudo install -d -m 0700 -o root -g root /var/lib/forge-node-priv
sudo install -d -m 0750 -o root -g forgenode /var/log/forge-node-priv
sudo install -d -m 0755 -o root -g root      /var/log/forge-node-agent
sudo install -m 0644 -o root -g root /tmp/allowed_signers /etc/forge-node/allowed_signers

# C4 Release-Baum und Units
sudo mkdir -p /opt/forge-node/releases/$VER
sudo tar -xf /tmp/forge-node-$VER-$PROFILE.tar -C /opt/forge-node/releases/$VER --strip-components=1 --no-same-owner
sudo chown -R root:root /opt/forge-node/releases/$VER
sudo install -m 0755 -o root -g root /opt/forge-node/releases/$VER/sbin/forge-node-release /usr/local/sbin/forge-node-release
sudo /usr/local/sbin/forge-node-release install-first $VER        # prüft das signierte Manifest, setzt 'current', verlinkt die Units (startet nichts)
sudo /opt/forge-node/current/bin/privctl audit-init               # beweist das Siegel-Protokoll auf dem Log-Dateisystem, legt Ledger und erste Logs an
ls -l /opt/forge-node/current /etc/systemd/system | grep forge-node; sudo ls -l /var/log/forge-node-priv /var/log/forge-node-agent

# C5 Node-Schlüssel + CSR (als forgenode); die CSR nach /tmp, denn das Home von forgenode ist für carl nicht lesbar
sudo -u forgenode sh -c 'umask 077; openssl ecparam -name prime256v1 -genkey -noout -out /etc/forge-node/pki/node.key'
sudo -u forgenode sh -c 'umask 022; openssl req -new -key /etc/forge-node/pki/node.key -subj "/CN=forge-node-'"$NID"'" -out /tmp/'"$NID"'.csr'
ls -l /tmp/$NID.csr
)
rc=$?; if [ $rc = 0 ]; then echo "== OK (jetzt: exit)"; else echo "== FEHLER: STOP, Sitzung offen lassen (rc=$rc)"; fi
```
**5.3 Mac: Zertifikat und Policy signieren.**
<!-- run: mac -->
```bash
(
set -euo pipefail
cd ~/forge-node-owner; set -a; . ./fn.env; set +a
scp -i ~/.ssh/sshcarljump01 carl@$IP:/tmp/$NID.csr issued/
printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=URI:urn:forge:node:$NID\n" > issued/ext_$NID.cnf
openssl x509 -req -in issued/$NID.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial -days 90 -sha256 -extfile issued/ext_$NID.cnf -out issued/$NID.crt
openssl x509 -in issued/$NID.crt -noout -fingerprint -sha256 -subject -enddate        # Fingerabdruck notieren (für 5.5)
tar -xOf release/forge-node-$VER-$PROFILE.tar forge-node-$VER/policy/policy-$NID.json > policy/policy-$NID.json
HUB_PIN=$(openssl x509 -in issued/hub.crt -outform der | openssl dgst -sha256 -hex | awk '{print $NF}')
HUB_GATE=$(cut -d' ' -f1,2 issued/hub_gate_ed25519.pub)
sed -i.bak -e "s|__HUB_TLS_PIN__|$HUB_PIN|" -e "s|__HUB_GATE_PUB__|$HUB_GATE|" policy/policy-$NID.json && rm policy/policy-$NID.json.bak
if grep -n "__" policy/policy-$NID.json; then echo "UNAUSGEFUELLTE PLATZHALTER"; false; fi
grep -E '"(profile|global_mode)"' policy/policy-$NID.json; grep -A2 '"tiers_enabled"' policy/policy-$NID.json
if grep -q forge_roots policy/policy-$NID.json; then echo "forge_roots in einer t0-Policy"; false; fi
grep -q '"profile": "t0"' policy/policy-$NID.json && grep -q '"global_mode": "observe"' policy/policy-$NID.json
less policy/policy-$NID.json                                      # einmal ganz lesen (q beendet)
( cd src-$VER/fn-src && PYTHONPATH=src python3 -m forge_node.cli release sign ~/forge-node-owner/policy/policy-$NID.json --key ~/forge-node-owner/owner_ed25519 --namespace forge-node-policy )
scp -i ~/.ssh/sshcarljump01 issued/$NID.crt ca/ca.crt policy/policy-$NID.json policy/policy-$NID.json.sig carl@$IP:/tmp/
)
rc=$?; if [ $rc = 0 ]; then ssh -t -i ~/.ssh/sshcarljump01 carl@$(sed -n 's/^IP=//p' ~/forge-node-owner/fn.env); else echo "== FEHLER (rc=$rc): STOP"; fi
```
**5.4 Server, Segment 2** (neue Shell ⇒ `fn.env` wieder laden). Der Agent wird nur gestartet, wenn `doctor` mit 0 endet.
<!-- run: host -->
```bash
(
set -euo pipefail
set -a; . /tmp/fn.env; set +a; : "${NID:?}" "${IP:?}" "${VER:?}" "${PROFILE:?}"
sudo install -m 0644 -o forgenode -g forgenode /tmp/$NID.crt /etc/forge-node/pki/node.crt
sudo install -m 0644 -o forgenode -g forgenode /tmp/ca.crt   /etc/forge-node/pki/ca.crt
sudo systemctl enable --now forge-node-privd.socket
sudo /opt/forge-node/current/bin/privctl policy-apply /tmp/policy-$NID.json /tmp/policy-$NID.json.sig
sudo /opt/forge-node/current/bin/privctl status                    # policy serial 1, mode observe, lease: none yet
rc=0; sudo -u forgenode env FORGE_NODE_NODE_ID=$NID /usr/bin/python3 -I /opt/forge-node/current/forge-node.pyz doctor || rc=$?
echo "doctor exit: $rc"                                            # 0 = OK, 1 = FEHLER, 4 = Hub antwortete 5xx (warten, nochmal)
[ "$rc" = 0 ] || { echo "doctor != 0: Agent wird NICHT gestartet"; false; }
sudo systemctl enable --now forge-node-agent.service forge-node-audit-rotate.timer
sudo systemctl status forge-node-agent.service forge-node-privd.socket --no-pager | head -12
rm -f /tmp/forge-node-$VER-$PROFILE.tar /tmp/forge-node-$VER-$PROFILE.tar.sig /tmp/allowed_signers /tmp/$NID.crt /tmp/ca.crt /tmp/policy-$NID.json /tmp/policy-$NID.json.sig
sudo rm -f /tmp/$NID.csr                                           # gehört forgenode
rm -f /tmp/fn.env
)
rc=$?; if [ $rc = 0 ]; then echo "== OK (jetzt: exit)"; else echo "== FEHLER: STOP, Sitzung offen lassen (fn.env bleibt in /tmp) (rc=$rc)"; fi
```
**Scheitert `doctor` hier (Exit 1) und nennt `probe:net`/`probe:container_net`: Das Release ist 0.5.0 (Selbstprüfungs-Fehler, nur g2 betroffen) — weiter mit `docs/reports/PROBEFIX_OWNER_UPGRADE.md` (Upgrade auf 0.5.1), nicht reparieren.**
Solange der Host noch nicht registriert ist (5.5), antwortet der Hub dem Agenten mit 403: im Journal erwartbar. `doctor` prüft hier nur `/healthz` (Pin, TLS) — „hub: ok" beweist die Registrierung NICHT; den Beweis liefert `last_seen` in Teil 6.
**5.5 Registrierung des Hosts (statt Cockpit /nodes — die Seite existiert noch nicht, sie kommt mit N7).** Der Hub schreibt `status`/`cert_sha256` nie selbst; die Zeile legt der Owner in `node.nodes` an, nachdem er den Fingerabdruck verglichen hat. **Profil `t0`**: es ist in der Tabelle unveränderlich — ein späterer Wechsel auf `full` braucht eine neue Registrierung (neuer Eintrag).
<!-- run: mac -->
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
Die Policy ist `global_mode: observe`: es verändert sich nichts, Runde 0 (§14) beginnt.

## Teil 6 — Prüfung je Host (~2 Minuten nach 5.5)
Auf dem Host (Login wie in 5.1; `NID` auf den geprüften Host setzen):
<!-- run: host -->
```bash
(
set -euo pipefail
NID=g2                                          # der Host, den du gerade prüfst (g2|g3|g1|g4)
sudo systemctl is-active forge-node-privd.socket forge-node-agent.service forge-node-audit-rotate.timer      # 3x active
sudo /opt/forge-node/current/bin/privctl status                 # Policy-Serial 1, observe
sudo /opt/forge-node/current/bin/privctl audit-verify           # Ketten gültig
sudo -u forgenode env FORGE_NODE_NODE_ID=$NID /usr/bin/python3 -I /opt/forge-node/current/forge-node.pyz doctor
echo "doctor exit 0"
sudo journalctl -u forge-node-agent.service -n 30 --no-pager                  # keine Fehler-Schleife (403 nur VOR 5.5)
if ls /etc/sudoers.d/ | grep -qi forge; then echo "forge-sudoers gefunden"; false; fi; echo "kein forge-sudoers (richtig)"
. /var/tmp/fn-ev.sh; ev > /var/tmp/fn-ev-after-$NID.txt
diff /var/tmp/fn-ev-before-$NID.txt /var/tmp/fn-ev-after-$NID.txt && echo "EVIDENZ UNVERAENDERT" || echo "Differenz oben einzeln bewerten (Container/mtimes ändern sich auch ohne uns); entscheidend: nichts mit kmu-/tradebot-/secmpro-Bezug, kein neuer Listener ausser 8094 auf g2"
)
rc=$?; if [ $rc = 0 ]; then echo "== OK"; else echo "== FEHLER: STOP (rc=$rc)"; fi
```
Hub-Seite (vom Mac, für JEDEN Host): `last_seen` jünger als 2 Minuten und `policy_serial` 1 beweisen die Registrierung und den laufenden Agenten:
<!-- run: mac -->
```bash
(
set -euo pipefail
ssh -t -i ~/.ssh/sshcarljump01 carl@192.168.10.4 "sudo docker exec -i forge-postgres-1 sh -c 'psql -U \"\$POSTGRES_USER\" -d forge -c \"SELECT node_id, profile, status, policy_serial, now() - last_seen AS seit FROM node.nodes ORDER BY 1\"'"
)
rc=$?; if [ $rc = 0 ]; then echo "== OK"; else echo "== FEHLER: STOP (rc=$rc)"; fi
```
Nach g1/g3/g4 gilt zusätzlich: in der `diff`-Ausgabe darf bei „listeners" nichts Neues stehen (kein neuer Listener).

## Teil 7 — Rückgängig (je Host, jede Stufe einzeln)
1. **Alle pausieren:** `/srv/forge/work/forge-ops/bin/forge-stop "forge-node pause"` (zurück: `forge-release`). T0 liest weiter.
2. **Einen Host pausieren:** `sudo touch /etc/forge-node/LOCAL_STOP` (zurück: `sudo rm /etc/forge-node/LOCAL_STOP`).
3. **Einen Host sperren (nichts über T0):** `sudo /opt/forge-node/current/bin/privctl lockdown`.
4. **Host beim Hub widerrufen:** `UPDATE node.nodes SET status='revoked' WHERE node_id='<NID>';` (Technik wie 5.5, `SET ROLE forge_core;` voran).
5. **Release zurück:** `sudo /usr/local/sbin/forge-node-release status`, dann `check <ALTVER>` und `switch <ALTVER>` (vor dem ersten Wechsel gibt es keine alte Version: dann Stufe 6).
6. **Host vollständig deinstallieren** (t0: kein Volume, nichts zu behalten außer dem Audit-Archiv). Die Audit-Logs liegen als `<Verz>/<Präfix>.NNNNNN/<Präfix>.NNNNNN.jsonl`, live mit `+a`, versiegelt mit `+a +i`; das priv-Verzeichnis (0750 root:forgenode) kann `carl` nicht auflisten — deshalb `sudo find`. Login auf dem Host, dann:
<!-- run: host -->
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
)
rc=$?; if [ $rc = 0 ]; then echo "== OK: deinstalliert"; else echo "== FEHLER: unvollständig - Ausgabe an die Betriebsleitung, nichts von Hand 'nachbessern' (rc=$rc)"; fi
```
7. **Hub (nur g2):** Container stoppen/entfernen (`docker compose … rm -sf forge-nodehub`, Betriebsleitung) und `sudo /srv/forge/work/forge-ops/bin/forge-docker-user.sh --remove --hub` (entfernt die Hub-Regeln und die Bestätigungsmarke; die Boot-Kopie bleibt, sie ist rückwärtskompatibel). Das Schema `node` bleibt (enthält das Audit-Archiv der Hub-Seite); löschen nur auf ausdrückliche Anweisung.
Eine offene Root-SSH-Sitzung ist der Anker: es gibt keine sudoers-Änderung, ein Fehler kann `sudo` nicht aussperren.

## Teil 8 — Reihenfolge-Kurzfassung
`Teil 1` → `Teil 2` → `Teil 3` (+ GO) → `Teil 4` (4.1 Boot-Kopie, 4.2 anwenden+testen, 4.3 bestätigen) → **g2:** 5.1–5.5, Teil 6 → *1 Tag* → **g3:** 5.1–5.5, Teil 6 → *1 Tag* → **g1:** 5.1–5.5, Teil 6 → *1 Tag* → **g4:** (Zustimmung, Handelszeiten, `free -m`) 5.1–5.5, Teil 6. Danach 72 h M1/Revision-Daten (Design §14).
