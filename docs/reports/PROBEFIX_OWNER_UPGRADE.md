# forge-node 0.5.0 → 0.5.1 auf g2 (carlgpu2) — Owner-Schritte nach dem fehlgeschlagenen ersten `doctor`

Ausgangslage (g2, 08.11.): 0.5.0 per `install-first` installiert, privd-Socket aktiv, Policy Serial 1 angewendet, Agent **nicht** gestartet, `doctor` meldete `probe:net` und `probe:container_net` als FAIL. Ursache: ein Fehler in der Selbstprüfung von forge-node selbst (`docs/reports/PROBEFIX_DIAG.md`), **kein** Sandbox-Problem und **keine** Änderung an Units, Rechten oder Policy. 0.5.1 ändert nur `forge-node.pyz`.

**Was gleich bleibt:** Owner-Schlüssel, CA, `/etc/forge-node/allowed_signers`, Node-Zertifikat, **Policy Serial 1 (kein `policy-apply` nötig** — die Policy-Vorlagen in 0.5.0 und 0.5.1 sind byte-identisch, `release check` prüft, dass die installierte Policy zum Release passt), Units, `forge-node-release` selbst (kein `self-update`), Hub, Firewall.
**Welches Kommando:** `forge-node-release switch 0.5.1`. Es stoppt die (nie gestartete) Node, setzt `current` auf 0.5.1, startet den privd-Socket, führt **`doctor --after-switch` mit dem Code von 0.5.1** aus und startet **erst bei bestandenem doctor** Agent und Rotations-Timer (`enable` + `start`) — das ist der Schritt „doctor → Agent starten" aus 5.4 in einem Aufruf. Ein manuelles `doctor` *vor* dem `switch` kann 0.5.1 nicht prüfen: die Selbstprüfungen laufen mit dem Code, auf den `current` zeigt.
**Wenn doctor auch mit 0.5.1 scheitert:** `switch` versucht 0.5.0 zurückzusetzen, dessen doctor ebenfalls scheitert, und endet mit Exit 3 und der Meldung „STOPPED and disabled" (nichts läuft, der Agent war ohnehin nie gestartet). Dann **stoppen**, die JSON-Ausgabe (`failure`) der Betriebsleitung geben; nichts reparieren. Ein späteres `switch` aktiviert die Units wieder.
Regeln wie in der Hauptanleitung: nie zwischen 02:00 und 05:45 Berlin, SSH-Sitzung offen lassen. **Alle Mac-Blöcke sind Skripte** (Heredoc + `bash datei`): der Mac-Standard `zsh` kennt `#`-Kommentare in eingefügten Zeilen nicht (M-168), `bash` schon.

## U1 — Mac: Release 0.5.1 bauen und signieren (zwei Passphrase-Eingaben)
`<FIX_SHA>` = der Commit aus der Meldung der Betriebsleitung (40 Hex; der Stand von `probefix` bzw. der Merge-Commit).
<!-- run: mac -->
```bash
cat > ~/forge-node-owner/u1-build.sh <<'FNEOF'
set -euo pipefail
VER=0.5.1
SHA='<FIX_SHA>'
printf '%s' "$SHA" | grep -Eq '^[0-9a-f]{40}$' || { echo "SHA FEHLT"; false; }
cd ~/forge-node-owner
test -f release/forge-node-0.5.0-t0.tar || { echo "0.5.0-Release fehlt in release/ (Vergleich)"; false; }
ssh -t -i ~/.ssh/sshcarljump01 carl@192.168.10.4 "sudo -u forge sh -c 'git -C /srv/forge/work/forge-node archive --format=tar --prefix=fn-src/ $SHA > /tmp/fn-src.tar' && sudo chmod 644 /tmp/fn-src.tar"
scp -i ~/.ssh/sshcarljump01 carl@192.168.10.4:/tmp/fn-src.tar ~/forge-node-owner/fn-src-$VER.tar
ssh -t -i ~/.ssh/sshcarljump01 carl@192.168.10.4 'sudo rm -f /tmp/fn-src.tar'
mkdir -p src-$VER && tar -xf fn-src-$VER.tar -C src-$VER
cd src-$VER/fn-src
PYTHONPATH=src python3 -m forge_node.cli release build $VER t0 --out ~/forge-node-owner/release --key ~/forge-node-owner/owner_ed25519
cd ~/forge-node-owner
ls -l release/
# Kontrolle: die Policy-Vorlage von g2 ist in 0.5.0 und 0.5.1 identisch => kein policy-apply
tar -xOf release/forge-node-0.5.0-t0.tar forge-node-0.5.0/policy/policy-g2.json > /tmp/pol-050.json
tar -xOf release/forge-node-$VER-t0.tar forge-node-$VER/policy/policy-g2.json > /tmp/pol-051.json
cmp /tmp/pol-050.json /tmp/pol-051.json && echo "POLICY IDENTISCH (kein policy-apply noetig)"
rm -f /tmp/pol-050.json /tmp/pol-051.json
test -f release/forge-node-$VER-t0.tar.sig
scp -i ~/.ssh/sshcarljump01 release/forge-node-$VER-t0.tar release/forge-node-$VER-t0.tar.sig carl@192.168.10.4:/tmp/
FNEOF
bash ~/forge-node-owner/u1-build.sh
rc=$?; if [ $rc = 0 ]; then echo "== OK"; else echo "== FEHLER: STOP (rc=$rc)"; fi
```
Erwartet: `signer: SHA256:…` = Fingerabdruck aus A1, „both signatures verified locally", `POLICY IDENTISCH`, am Ende zwei `scp`-Zeilen. Danach Login auf g2: `ssh -t -i ~/.ssh/sshcarljump01 carl@192.168.10.4`

## U2 — g2: Release prüfen und auspacken (ändert noch nichts Laufendes)
<!-- run: host -->
```bash
(
set -euo pipefail
VER=0.5.1; PROFILE=t0
sudo -v
test -s /tmp/forge-node-$VER-$PROFILE.tar && test -s /tmp/forge-node-$VER-$PROFILE.tar.sig
ssh-keygen -Y verify -f /etc/forge-node/allowed_signers -I owner@forge -n forge-node-release \
  -s /tmp/forge-node-$VER-$PROFILE.tar.sig < /tmp/forge-node-$VER-$PROFILE.tar        # erwartet: Good "forge-node-release" signature
test ! -e /opt/forge-node/releases/$VER
sudo mkdir -p /opt/forge-node/releases/$VER
sudo tar -xf /tmp/forge-node-$VER-$PROFILE.tar -C /opt/forge-node/releases/$VER --strip-components=1 --no-same-owner
sudo chown -R root:root /opt/forge-node/releases/$VER
sudo /usr/local/sbin/forge-node-release check $VER                  # Manifest, Signatur, Dateien, Policy-Schema; ändert nichts
sudo /usr/local/sbin/forge-node-release status
)
rc=$?; if [ $rc = 0 ]; then echo "== OK"; else echo "== FEHLER: STOP, Sitzung offen lassen (rc=$rc)"; fi
```
Erwartet: `status` zeigt `current` = 0.5.0, `check` meldet 0.5.1 als gültig. Fehler hier = nichts wurde verändert.

## U3 — g2: umschalten (= doctor + Agent-Start)
Dauert ca. 2–4 Minuten ohne Ausgabe (14 Selbstprüfungen, 6 s Abstand; der Hub wird geprüft).
<!-- run: host -->
```bash
(
set -euo pipefail
VER=0.5.1
sudo /usr/local/sbin/forge-node-release switch $VER             # Erwartet: {"switched": "0.5.1", "from": "0.5.0", "doctor": "ok", ...} und Exit 0
sudo /usr/local/sbin/forge-node-release status
readlink /opt/forge-node/current /opt/forge-node/previous        # releases/0.5.1  releases/0.5.0
sudo /opt/forge-node/current/bin/privctl status                    # policy serial 1, mode observe
)
rc=$?; if [ $rc = 0 ]; then echo "== OK"; else echo "== FEHLER: STOP (rc=$rc) - JSON oben der Betriebsleitung geben, nichts reparieren"; fi
```

## U4 — g2: doctor einmal von Hand (Beleg) und aufräumen
<!-- run: host -->
```bash
(
set -euo pipefail
NID=g2
rc=0; sudo -u forgenode env FORGE_NODE_NODE_ID=$NID /usr/bin/python3 -I /opt/forge-node/current/forge-node.pyz doctor | tee /var/tmp/fn-doctor-0.5.1.txt || rc=$?
echo "doctor exit: $rc"                                            # 0 = OK
[ "$rc" = 0 ]
grep -E '"check": "probe:(net|container_net)"' /var/tmp/fn-doctor-0.5.1.txt        # beide "status": "ok"
sudo systemctl status forge-node-agent.service forge-node-privd.socket --no-pager | head -12
rm -f /tmp/forge-node-0.5.0-t0.tar /tmp/forge-node-0.5.0-t0.tar.sig /tmp/forge-node-0.5.1-t0.tar /tmp/forge-node-0.5.1-t0.tar.sig /tmp/allowed_signers /tmp/$NID.crt /tmp/ca.crt /tmp/policy-$NID.json /tmp/policy-$NID.json.sig /tmp/fn.env
sudo rm -f /tmp/$NID.csr
)
rc=$?; if [ $rc = 0 ]; then echo "== OK (jetzt: exit)"; else echo "== FEHLER: STOP (rc=$rc)"; fi
```
Das manuelle `doctor` darf nur nach dem `switch` laufen (der Agent läuft dann bereits; `doctor` ändert nichts). Solange der Host noch nicht registriert ist, antwortet der Hub dem Agenten mit 403 — im Journal erwartbar.

## U5 — weiter wie in der Hauptanleitung
**5.5 Registrierung** (Mac-Block `register-g2.sql`, unverändert; `~/forge-node-owner/fn.env` und `issued/g2.crt` aus 5.1/5.3 existieren bereits), danach **Teil 6** (Prüfung, `last_seen` < 2 min, `policy_serial` 1). Rollback bleibt Teil 7 der Hauptanleitung (ein `switch 0.5.0` würde 0.5.0 wieder in Betrieb nehmen, dessen doctor scheitert: nicht tun).
