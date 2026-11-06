# forge-node T0 — Installationsanleitung für den Owner (alle vier Hosts, Profil `t0`)

Stand: N5-prep (Branch `n5prep`, noch NICHT gemergt — die Befehle gelten für den gemergten Stand; `<MAIN_SHA>` steht in der Merge-Meldung). Alle Blöcke sind Copy-and-paste; jeder `bash`-Block wird in den Tests auf Syntax geprüft.
**Betriebsleiter-Entscheidung:** alle vier Hosts bekommen vorerst das Profil `t0` (nur Lesen): **kein** forge-root-Volume, **kein** Loop-Volume, **kein** `selftest.noop`-Code, Policy `global_mode: observe`, `tiers_enabled: [0]`. Die Schritte „Loop-Volume" (13.C C3) und die Werte `full`/100 GiB/50 GiB entfallen. `full` bleibt für spätere T1-Schritte im Code (`template(nid, "full")`).
**Regeln:** pro Server eine SSH-Sitzung die ganze Zeit offen lassen (Rollback-Anker). Nie zwischen 02:00 und 05:45 Berlin, nie sonntags vor 06:00. Reihenfolge **g2 → g3 → g1 → g4** mit ≥ 1 Tag Beobachtung dazwischen; g4 (Live-Trading) zuletzt und nur mit deiner ausdrücklichen Zustimmung. SSH als `carl` mit `~/.ssh/sshcarljump01`; es wird nichts an sshd, sudoers oder Docker geändert (kein Docker-Neustart).
**Bei jeder Abweichung vom „erwartet" stoppen und die Betriebsleitung informieren — nicht weitermachen.**

Reihenfolge der Teile: **Teil 1** (Mac, einmalig) → **Teil 2** (Release bauen, einmal je Version) → **Teil 3** (Hub auf g2, einmalig; enthält ein GO an die Betriebsleitung) → **Teil 4** (Firewall 8094) → **Teil 5** (je Host: g2, g3, g1, g4) → **Teil 6** (Prüfung) → **Teil 7** (Rückgängig).

## Teil 1 — Mac, einmalig: Owner-Schlüssel und CA (13.A)
Voraussetzungen auf dem Mac: `ssh-keygen` (OpenSSH ≥ 8.1), `openssl`, **Python ≥ 3.12** (`python3 --version`; sonst `brew install python@3.12` und unten `python3.12` statt `python3`).
```bash
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
```
Sichern (Offline-Kopie, z. B. verschlüsselter USB-Stick): `~/forge-node-owner/owner_ed25519` und `ca/ca.key`. Ohne sie lässt sich nichts mehr signieren; mit ihnen in falschen Händen schon.

## Teil 2 — Mac: Release bauen und signieren (je Version)
Das Release wird auf dem Mac aus genau dem gemergten Commit gebaut; der Schlüssel bleibt dort. `release build` signiert zweimal (Manifest, Tarball): **zweimal Passphrase auf dem Mac-Terminal**. (Alternative mit einer Eingabe: `ssh-add ~/forge-node-owner/owner_ed25519`, dann `--key ~/forge-node-owner/owner_ed25519.pub`.)
```bash
export VER=0.5.0                       # Versionsname dieses Releases
SHA='<MAIN_SHA>'                       # ersetzen: Commit aus der Merge-Meldung (40 Hex)
printf '%s' "$SHA" | grep -Eq '^[0-9a-f]{40}$' || echo "SHA FEHLT - STOP"
cd ~/forge-node-owner
ssh -t -i ~/.ssh/sshcarljump01 carl@192.168.10.4 "sudo -u forge sh -c 'git -C /srv/forge/work/forge-node archive --format=tar --prefix=fn-src/ $SHA > /tmp/fn-src.tar' && sudo chmod 644 /tmp/fn-src.tar"
scp -i ~/.ssh/sshcarljump01 carl@192.168.10.4:/tmp/fn-src.tar ~/forge-node-owner/fn-src-$VER.tar
ssh -i ~/.ssh/sshcarljump01 carl@192.168.10.4 'rm -f /tmp/fn-src.tar'
mkdir -p src-$VER && tar -xf fn-src-$VER.tar -C src-$VER
cd src-$VER/fn-src
PYTHONPATH=src python3 -m forge_node.cli release build $VER t0 --out ~/forge-node-owner/release --key ~/forge-node-owner/owner_ed25519
# Erwartet: 4 Zeilen tar:/sig:/sha256:/signer: ; "signer: SHA256:..." == der Fingerabdruck aus A1; "both signatures verified locally"
cd ~/forge-node-owner && ls -l release/
```
Das t0-Release enthält die Policy-Vorlagen für **alle vier** Hosts (`policy/policy-g1…g4.json`, jeweils `profile: t0`, `observe`, `tiers_enabled: [0]`, ohne `forge_roots`).

## Teil 3 — Hub auf g2 (13.B; einmalig)
**3.1 Owner: Schlüssel auf g2 erzeugen** (Hub-Server-Schlüssel + Gate-Schlüssel; beide bleiben auf g2, nur die Public-Teile gehen zum Mac).
```bash
ssh -t -i ~/.ssh/sshcarljump01 carl@192.168.10.4
# --- auf carlgpu2 ---
sudo install -d -m 0750 -o forge -g forgebox /srv/forge/work/forge-core/secrets/nodehub
sudo -u forge sh -c 'umask 077; openssl ecparam -name prime256v1 -genkey -noout -out /srv/forge/work/forge-core/secrets/nodehub/hub.key'
sudo -u forge openssl req -new -key /srv/forge/work/forge-core/secrets/nodehub/hub.key -subj "/CN=forge-nodehub" -out /srv/forge/work/forge-core/secrets/nodehub/hub.csr
sudo -u forge ssh-keygen -t ed25519 -N '' -C forge-node-hub-gate -f /srv/forge/work/forge-core/secrets/nodehub/gate_ed25519
exit
```
**3.2 Mac: Hub-Zertifikat signieren, zurückspielen.**
```bash
cd ~/forge-node-owner
scp -i ~/.ssh/sshcarljump01 carl@192.168.10.4:/srv/forge/work/forge-core/secrets/nodehub/hub.csr issued/
scp -i ~/.ssh/sshcarljump01 carl@192.168.10.4:/srv/forge/work/forge-core/secrets/nodehub/gate_ed25519.pub issued/hub_gate_ed25519.pub
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:192.168.10.4,DNS:forge-nodehub.lan\n' > issued/ext_hub.cnf
openssl x509 -req -in issued/hub.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial -days 365 -sha256 -extfile issued/ext_hub.cnf -out issued/hub.crt
openssl x509 -in issued/hub.crt -noout -subject -ext subjectAltName -enddate     # CN=forge-nodehub, IP:192.168.10.4
scp -i ~/.ssh/sshcarljump01 issued/hub.crt ca/ca.crt carl@192.168.10.4:/tmp/
ssh -t -i ~/.ssh/sshcarljump01 carl@192.168.10.4 \
  'sudo install -m 0644 -o forge -g forgebox /tmp/hub.crt /tmp/ca.crt /srv/forge/work/forge-core/secrets/nodehub/ && rm /tmp/hub.crt /tmp/ca.crt && sudo ls -l /srv/forge/work/forge-core/secrets/nodehub/'
```
**3.3 GO an die Betriebsleitung:** „Hub-Deploy freigeben" (den fertigen GO-Text liefert N5PREP_REPORT.md). Sie baut das Image, legt Rolle und Schema an, migriert und startet NUR den Hub (Port 8094 nur auf 192.168.10.4). Das Ergebnis (`/healthz` ok, Container healthy) abwarten, bevor Teil 4 beginnt.

## Teil 4 — Firewall 8094 (forge-ops, nach dem Merge; mit 5-Minuten-Timer)
Der `--hub`-Regelsatz ist von den Edge-Regeln (443/8443) getrennt: 8094 auf 192.168.10.4 nur aus 192.168.10.0/29 und 192.168.30.0/29, nie aus dem VPN, sonst DROP. **Jeder Aufruf braucht `--hub`.** Zwischen Hub-Start (Teil 3.3) und diesem Teil ist 8094 nur auf der LAN-IP offen und verlangt ein Client-Zertifikat deiner CA (mTLS): das Fenster kurz halten.
```bash
ssh -t -i ~/.ssh/sshcarljump01 carl@192.168.10.4
# --- auf carlgpu2 ---
FW=/srv/forge/work/forge-ops/bin/forge-docker-user.sh
sudo $FW --dry-run --hub                    # nur ansehen: 3 iptables-Zeilen (2x ACCEPT /29, 1x DROP), Timer-Zeile "--remove --hub"
sudo $FW --hub                              # wendet an, Rollback-Timer 300 s läuft
curl -s --cacert /srv/forge/work/forge-core/secrets/nodehub/ca.crt https://192.168.10.4:8094/healthz        # {"ok":true,...}
sudo $FW --confirm --hub                    # INNERHALB von 5 Minuten, sonst nimmt der Timer die Regeln wieder weg
sudo iptables -S DOCKER-USER | grep forge-nodehub        # 3 Regeln
```
Aus dem Netz 192.168.30.0/29 (nach dem Anwenden, vor dem `--confirm`, in einer zweiten Sitzung): `ssh -i ~/.ssh/sshcarljump01 carl@192.168.30.3 'openssl s_client -connect 192.168.10.4:8094 -brief </dev/null 2>&1 | head -3'` muss „CONNECTION ESTABLISHED" zeigen. Falls nicht: Router-Regel TCP/8094 von 192.168.30.0/29 ist nötig (Owner) — nicht bestätigen, Timer rollt zurück.

## Teil 5 — je Host (g2 → g3 → g1 → g4)
Werte (alle `t0`, kein Volume):

| | g2 (carlgpu2) | g3 (carlgpu3) | g1 (carlgpu1) | g4 (carlgpu4) |
|---|---|---|---|---|
| `NID` / `IP` | `g2` / `192.168.10.4` | `g3` / `192.168.30.3` | `g1` / `192.168.10.3` | `g4` / `192.168.30.4` |
| `PROFILE` / `FORGE_ROOT` | `t0` / `none` | `t0` / `none` | `t0` / `none` | `t0` / `none` |
| Extra vorher | Hub oben (Teil 3), Regel bestätigt (Teil 4); **Docker nicht neu starten** | M022-Job-Stand mit dem pe_packer-Verantwortlichen klären; `free -m` ansehen | keine ufw-Änderung nötig; n8n/Redis-Regeln nicht anfassen | `free -m`: ≥ 300 MiB „available" **und** deine Zustimmung; Handelszeiten beachten; sshd unberührt |
| Verbindungstest vor 5.5 | Loopback/LAN | `openssl s_client -connect 192.168.10.4:8094 -brief </dev/null` muss gehen | wie g2 (gleiches /29) | wie g3 (gleiches /29) |
| Danach warten | 1 Tag | 1 Tag | 1 Tag | — |

**5.1 Mac: `fn.env` für den Host** (Beispiel g2 — für jeden Host nur `NID` und `IP` ändern).
```bash
cd ~/forge-node-owner
cat > fn.env <<EOF
NID=g2
IP=192.168.10.4
VER=0.5.0
PROFILE=t0
FORGE_ROOT=none
FORGE_ROOT_BYTES=0
MIN_FREE_BYTES=0
EOF
set -a; . ./fn.env; set +a
scp -i ~/.ssh/sshcarljump01 fn.env release/forge-node-$VER-$PROFILE.tar release/forge-node-$VER-$PROFILE.tar.sig allowed_signers carl@$IP:/tmp/
ssh -t -i ~/.ssh/sshcarljump01 carl@$IP
```
**5.2 Server, Segment 1** (Sitzung offen lassen): Vorprüfung, Release prüfen, Benutzer/Verzeichnisse, Release-Baum, Node-Schlüssel.
```bash
set -a; . /tmp/fn.env; set +a; : "${NID:?}" "${IP:?}" "${VER:?}" "${PROFILE:?}" "${FORGE_ROOT:?}"
[ "$PROFILE" = t0 ] && [ "$FORGE_ROOT" = none ] || { echo "FALSCHE WERTE: t0/none erwartet - STOP"; false; }

# C1 Vorprüfung (nur lesend)
date; TZ=Europe/Berlin date +%H:%M; timedatectl | grep -E 'Time zone|synchronized'
free -m | sed -n 1,3p; df -h / /srv/models /srv/kmu-ai 2>/dev/null
ss -tlnH | grep -c ':8094 ' || true                 # g1/g3/g4: 0 ; g2: 1 (der Hub)
python3 --version; python3 -c 'import sys; sys.exit(sys.version_info < (3,12))' && echo "python ok (>= 3.12)" || echo "PYTHON ZU ALT - STOP"
id forgenode 2>&1 | head -1                          # "no such user" erwartet
ls /etc/sudoers.d/ | grep -i forge || echo "kein forge-sudoers (erwartet: für immer keins)"
# Evidenz vorher (KMU/Trading dürfen sich durch die Installation nicht ändern)
ev() { systemctl list-units 'kmu-*' 'tradebot-*' 'secmpro*' --all --no-legend | awk '{print $1,$3,$4}' | sha256sum; sudo docker ps -a --format '{{.Names}} {{.Image}}' | sort | sha256sum
       git -C /opt/kmu-ai rev-parse HEAD 2>&1; stat -c %Y /opt/kmu-ai /srv/models 2>&1; ss -tlnH | sort | sha256sum; }
ev | tee /tmp/fn-ev-before.txt

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
ls -l /opt/forge-node/current /var/log/forge-node-priv /var/log/forge-node-agent; ls -l /etc/systemd/system | grep forge-node

# C5 Node-Schlüssel + CSR (als forgenode)
sudo -u forgenode sh -c 'umask 077; openssl ecparam -name prime256v1 -genkey -noout -out /etc/forge-node/pki/node.key'
sudo -u forgenode sh -c 'umask 022; openssl req -new -key /etc/forge-node/pki/node.key -subj "/CN=forge-node-'"$NID"'" -out /tmp/'"$NID"'.csr'
exit
```
**5.3 Mac: Zertifikat und Policy signieren.**
```bash
cd ~/forge-node-owner; set -a; . ./fn.env; set +a
scp -i ~/.ssh/sshcarljump01 carl@$IP:/tmp/$NID.csr issued/                  # (nicht aus /var/lib/forge-node: das Home von forgenode ist für carl nicht lesbar)
printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=URI:urn:forge:node:$NID\n" > issued/ext_$NID.cnf
openssl x509 -req -in issued/$NID.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial -days 90 -sha256 -extfile issued/ext_$NID.cnf -out issued/$NID.crt
openssl x509 -in issued/$NID.crt -noout -fingerprint -sha256 -subject -enddate        # Fingerabdruck notieren (für 5.5)
tar -xOf release/forge-node-$VER-$PROFILE.tar forge-node-$VER/policy/policy-$NID.json > policy/policy-$NID.json
HUB_PIN=$(openssl x509 -in issued/hub.crt -outform der | openssl dgst -sha256 -hex | awk '{print $NF}')
HUB_GATE=$(cut -d' ' -f1,2 issued/hub_gate_ed25519.pub)
sed -i.bak -e "s|__HUB_TLS_PIN__|$HUB_PIN|" -e "s|__HUB_GATE_PUB__|$HUB_GATE|" policy/policy-$NID.json && rm policy/policy-$NID.json.bak
grep -n "__" policy/policy-$NID.json && echo "UNAUSGEFUELLTE PLATZHALTER - STOP" || echo "Platzhalter ersetzt"
grep -E '"(profile|global_mode)"|forge_roots' policy/policy-$NID.json; grep -A2 '"tiers_enabled"' policy/policy-$NID.json
# erwartet: "profile": "t0", "global_mode": "observe", tiers_enabled [0], KEIN forge_roots
less policy/policy-$NID.json                                      # einmal ganz lesen
cd src-$VER/fn-src && PYTHONPATH=src python3 -m forge_node.cli release sign ~/forge-node-owner/policy/policy-$NID.json --key ~/forge-node-owner/owner_ed25519 --namespace forge-node-policy; cd ~/forge-node-owner
scp -i ~/.ssh/sshcarljump01 issued/$NID.crt ca/ca.crt policy/policy-$NID.json policy/policy-$NID.json.sig carl@$IP:/tmp/
ssh -t -i ~/.ssh/sshcarljump01 carl@$IP
```
**5.4 Server, Segment 2** (neue Shell ⇒ `fn.env` wieder laden).
```bash
set -a; . /tmp/fn.env; set +a; : "${NID:?}" "${IP:?}" "${VER:?}" "${PROFILE:?}"
sudo install -m 0644 -o forgenode -g forgenode /tmp/$NID.crt /etc/forge-node/pki/node.crt
sudo install -m 0644 -o forgenode -g forgenode /tmp/ca.crt   /etc/forge-node/pki/ca.crt
sudo systemctl enable --now forge-node-privd.socket
sudo /opt/forge-node/current/bin/privctl policy-apply /tmp/policy-$NID.json /tmp/policy-$NID.json.sig
sudo /opt/forge-node/current/bin/privctl status                    # policy serial 1, mode observe, lease: none yet
sudo -u forgenode env FORGE_NODE_NODE_ID=$NID /usr/bin/python3 -I /opt/forge-node/current/forge-node.pyz doctor
echo "doctor exit: $?"                                             # 0 = OK (hub: 'unregistered' ist jetzt normal), 1 = FEHLER -> STOP, 4 = Hub antwortete 5xx -> warten, nochmal; Agent NICHT starten
# erst wenn doctor 0 war, und erst nach 5.5 (Registrierung) bleibt der Agent dauerhaft verbunden; starten darf man ihn schon jetzt:
sudo systemctl enable --now forge-node-agent.service forge-node-audit-rotate.timer
sudo systemctl status forge-node-agent.service forge-node-privd.socket --no-pager | head -12
rm -f /tmp/forge-node-$VER-$PROFILE.tar /tmp/forge-node-$VER-$PROFILE.tar.sig /tmp/allowed_signers /tmp/$NID.crt /tmp/ca.crt /tmp/policy-$NID.json /tmp/policy-$NID.json.sig /tmp/fn.env
exit
```
**5.5 Registrierung des Hosts (statt Cockpit /nodes — die Seite existiert noch nicht, sie kommt mit N7).** Der Hub schreibt `status`/`cert_sha256` nie selbst; die Zeile legt der Owner in `node.nodes` an, nachdem er den Fingerabdruck verglichen hat. **Profil `t0`**: es ist in der Tabelle unveränderlich — ein späterer Wechsel auf `full` braucht eine neue Registrierung (neuer Eintrag).
```bash
cd ~/forge-node-owner; set -a; . ./fn.env; set +a
FP=$(openssl x509 -in issued/$NID.crt -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'); echo "$FP"      # 64 Hex, klein; == dem in 5.3 notierten Wert
printf "%s" "$FP" | grep -Eq '^[0-9a-f]{64}$' || echo "FINGERABDRUCK UNGUELTIG - STOP"
printf "SET ROLE forge_core;\nINSERT INTO node.nodes (node_id, profile, status, cert_sha256) VALUES ('%s','t0','active','%s');\nSELECT node_id, profile, status, left(cert_sha256,12) AS fp FROM node.nodes ORDER BY node_id;\n" "$NID" "$FP" > register-$NID.sql
cat register-$NID.sql                                              # lesen
scp -i ~/.ssh/sshcarljump01 register-$NID.sql carl@192.168.10.4:/tmp/
ssh -t -i ~/.ssh/sshcarljump01 carl@192.168.10.4 "sudo docker exec -i forge-postgres-1 sh -c 'psql -v ON_ERROR_STOP=1 -U \"\$POSTGRES_USER\" -d forge' < /tmp/register-$NID.sql; rm -f /tmp/register-$NID.sql"
# Zertifikat erneuert (alle 90 Tage)?  UPDATE node.nodes SET cert_sha256='<neu>' WHERE node_id='<NID>';  (gleiche Technik)
```
Die Policy ist `global_mode: observe`: es verändert sich nichts, Runde 0 (§14) beginnt.

## Teil 6 — Prüfung je Host (auf dem Host; ~2 Minuten nach 5.5)
```bash
export NID=g2                                  # der Host, den du gerade prüfst (g2|g3|g1|g4)
sudo systemctl is-active forge-node-privd.socket forge-node-agent.service forge-node-audit-rotate.timer      # 3x active
sudo /opt/forge-node/current/bin/privctl status && sudo /opt/forge-node/current/bin/privctl audit-verify         # Policy-Serial 1, observe; Ketten gültig
sudo -u forgenode env FORGE_NODE_NODE_ID=$NID /usr/bin/python3 -I /opt/forge-node/current/forge-node.pyz doctor; echo "doctor exit: $?"     # 0, hub: ok (nicht mehr 'unregistered')
sudo journalctl -u forge-node-agent.service -n 30 --no-pager                  # keine Fehler-Schleife
ls /etc/sudoers.d/ | grep -i forge || echo "kein forge-sudoers (richtig)"
ev | diff /tmp/fn-ev-before.txt - && echo "EVIDENZ UNVERAENDERT"                # g2: ss-Hash ändert sich nur durch den Hub (8094), alles andere nicht
```
(`ev` ist die Funktion aus 5.2; in einer neuen Shell zuerst die `ev() {...}`-Zeilen aus 5.2 einfügen. `/tmp/fn-ev-before.txt` bleibt bis zur Prüfung liegen.) Auf g2 zusätzlich die Hub-Seite: `ssh -t -i ~/.ssh/sshcarljump01 carl@192.168.10.4 "sudo docker exec -i forge-postgres-1 sh -c 'psql -U \"\$POSTGRES_USER\" -d forge -c \"SELECT node_id, status, policy_serial, last_seen FROM node.nodes ORDER BY 1\"'"` — `last_seen` jünger als 2 Minuten, `policy_serial` 1. Nach g1/g3/g4 gilt zusätzlich: `ss -tlnH | sort | sha256sum` unverändert gegenüber `/tmp/fn-ev-before.txt` (kein neuer Listener).

## Teil 7 — Rückgängig (je Host, jede Stufe einzeln)
1. **Alle pausieren:** `/srv/forge/work/forge-ops/bin/forge-stop "forge-node pause"` (zurück: `forge-release`). T0 liest weiter.
2. **Einen Host pausieren:** `sudo touch /etc/forge-node/LOCAL_STOP` (zurück: `sudo rm /etc/forge-node/LOCAL_STOP`).
3. **Einen Host sperren (nichts über T0):** `sudo /opt/forge-node/current/bin/privctl lockdown`.
4. **Host beim Hub widerrufen:** `UPDATE node.nodes SET status='revoked' WHERE node_id='<NID>';` (Technik wie 5.5, `SET ROLE forge_core;` voran).
5. **Release zurück:** `sudo /usr/local/sbin/forge-node-release status`, dann `check <ALTVER>` und `switch <ALTVER>` (vor dem ersten Wechsel gibt es keine alte Version: dann Stufe 6).
6. **Host vollständig deinstallieren** (t0: kein Volume, nichts zu behalten außer dem Audit-Archiv):
```bash
sudo /opt/forge-node/current/bin/privctl lockdown
sudo systemctl disable --now forge-node-audit-rotate.timer forge-node-agent.service forge-node-privd.socket forge-node-privd.service
for u in $(systemctl list-unit-files --no-legend 'forge-node-*' | awk '{print $1}'); do sudo systemctl disable "$u" 2>/dev/null; done
sudo systemctl daemon-reload
sudo chattr -a /var/log/forge-node-priv/*.jsonl /var/log/forge-node-agent/*.jsonl
sudo tar -czf /root/forge-node-audit-$(hostname)-$(date +%Y%m%d).tgz -C /var/log forge-node-priv forge-node-agent          # Beweise behalten
sudo rm -f /usr/local/sbin/forge-node-release
sudo rm -rf /opt/forge-node /etc/forge-node /var/lib/forge-node /var/lib/forge-node-priv /var/log/forge-node-priv /var/log/forge-node-agent /run/forge-node
sudo userdel forgenode
ev | diff /tmp/fn-ev-before.txt - && echo "EVIDENZ UNVERAENDERT"
```
7. **Hub (nur g2):** Container stoppen/entfernen (`docker compose ... rm -sf forge-nodehub`, Betriebsleitung) und `sudo /srv/forge/work/forge-ops/bin/forge-docker-user.sh --remove --hub`. Das Schema `node` bleibt (enthält das Audit-Archiv der Hub-Seite); löschen nur auf ausdrückliche Anweisung.
Eine offene Root-SSH-Sitzung ist der Anker: es gibt keine sudoers-Änderung, ein Fehler kann `sudo` nicht aussperren.

## Teil 8 — Reihenfolge-Kurzfassung
`Teil 1` → `Teil 2` → `Teil 3` (+ GO) → `Teil 4` → **g2:** 5.1–5.5, Teil 6 → *1 Tag* → **g3:** 5.1–5.5, Teil 6 → *1 Tag* → **g1:** 5.1–5.5, Teil 6 → *1 Tag* → **g4:** (Zustimmung, Handelszeiten, `free -m`) 5.1–5.5, Teil 6. Danach 72 h M1/Revision-Daten (Design §14).
