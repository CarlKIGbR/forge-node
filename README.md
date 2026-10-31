# forge-node

Kontrollierte operative Autoritaet auf carlgpu1-4 (Design: `docs/design/FORGE_NODE.md`, ADR-025). Dieses Repo enthaelt den Code ab Slice **N1** (Klasse kritisch); **N2** (Agent, T0) ist dazugekommen.

**Stand N1 (nur T0-Pfad, nichts installiert):** Protokoll, Hub-Skelett (`forge_node.hub`), Gate-Key-Signatur von Leases/Jobs, Schema `node` mit INSERT-only Audit, STOP-Anbindung (lesend),
Gates A-D (`forge_node/gates.py`, alle unerfuellt). Kein `privd`, kein Agent, keine Policy-Anwendung, keine T1/T2/T3-Ausfuehrung. Der Hub wird nicht gebaut, nicht gestartet, nicht installiert; es gibt
keine Units, keine sudoers-Dateien, keine erzeugten Schluessel. Die DOCKER-USER-Regel fuer Port 8094 liegt im Repo `forge-ops` (`forge-docker-user.sh --hub`).

**Stand N2 (nur T0, nichts installiert):** Agent (`forge_node.agent`: mTLS-Client mit CA- **und** Leaf-Pin, Policy-Sicht, Lease-/Job-Pruefung, Poll-Schleife) und T0-Schicht (`forge_node.t0`: ein bewachter Pfad `engine.T0Engine.execute`,
geschlossene Befehlstabelle `runner`, bewachter Dateizugriff `fsread`, Bereinigung/Umschlag `sanitize`, Spool/Sampler, `ro-probe`-Programme `probes` + Draht-Vertrag `wire` + Haertungsdaten `hardening`). Kein `privd`, kein Audit-Datei-Schreiber
(Gate D bleibt unerfuellt, N3), keine Op oberhalb T0, keine Units/sudoers/Schluessel. Abnahmeliste: Design 16.2; Bericht: `docs/reports/N2_REPORT.md`.

## Layout
- `src/forge_node/` - stdlib-Bibliothek: `canon` (kanonisches JSON), `sshsig` (`ssh-keygen -Y`, vier Namespaces), `protocol` (Lease/Job/Poll/Result, Pruefer fuer die Node-Seite), `chain` (Audit-Hash-Kette),
  `redact`, `gates` (Betriebsleiter-Entscheid: Gates A-D, Op-Register, `policy_gate_violations`).
- `src/forge_node/hub/` - Hub: `core` (Jobs, Leases, Audit-Senke, Querpruefung, Quarantaene), `server` (mTLS-HTTPS, stdlib), `killswitch` (nur lesen + Dispatch-Lock), `files` (signierte Policy/Releases ausliefern),
  `config`, `db` (psycopg), `migrate`.
- `src/forge_node/t0/` - T0-Schicht (stdlib): `engine` (der eine Pfad), `runner` (Befehlstabelle), `fsread`, `policy` (Policy-Sicht, Signatur), `collect` (Agent-Sektionen), `probes` (Root-Sektionen), `wire`, `hardening`, `spool`, `metrics`, `usage`, `sanitize`, `parse`, `window`, `limits`.
- `src/forge_node/agent/` - Agent: `client` (gepinnter mTLS), `loop` (Poll, Jobs, Policy-Nachladen), `config`, `__main__`.
- `migrations/0001_node_schema.sql`, `scripts/sql/nodehub_{role,grants}.sql` - Schema `node`, Rolle `forge_nodehub` (kein UPDATE/DELETE/TRUNCATE auf `node.audit`).
- `Dockerfile`, `deploy/compose.nodehub.yaml` - Hub-Image/Compose-Dienst (Publish nur `192.168.10.4:8094`); in N1 weder gebaut noch ausgefuehrt.

## Tests
`scripts/run-tests.sh [pytest-Args]` startet ein Wegwerf-Postgres (`--network none`, nur Unix-Socket) und einen Test-Container mit dem Repo (read-only) und dem `ssh-keygen` des Hosts; beides wird danach entfernt.
Ohne `FORGE_NODE_TEST_DSN` werden die DB-Tests uebersprungen. Mutations-Stichproben (kritische Zweige, ~12 min): `python3 scripts/mutation_spotcheck.py [id ...]`. Zeilenabdeckung (ohne `coverage`, Python 3.12 `sys.monitoring`): `FN_COV=1 scripts/run-tests.sh -p linecov_plugin -q`. Die Schluessel und die Test-PKI entstehen fluechtig im Temp-Verzeichnis des Tests.
