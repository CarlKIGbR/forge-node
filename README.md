# forge-node

Kontrollierte operative Autoritaet auf carlgpu1-4 (Design: `docs/design/FORGE_NODE.md`, ADR-025). Dieses Repo enthaelt den Code ab Slice **N1** (Klasse kritisch).

**Stand N1 (nur T0-Pfad, nichts installiert):** Protokoll, Hub-Skelett (`forge_node.hub`), Gate-Key-Signatur von Leases/Jobs, Schema `node` mit INSERT-only Audit, STOP-Anbindung (lesend),
Gates A-D (`forge_node/gates.py`, alle unerfuellt). Kein `privd`, kein Agent, keine Policy-Anwendung, keine T1/T2/T3-Ausfuehrung. Der Hub wird nicht gebaut, nicht gestartet, nicht installiert; es gibt
keine Units, keine sudoers-Dateien, keine erzeugten Schluessel. Die DOCKER-USER-Regel fuer Port 8094 liegt im Repo `forge-ops` (`forge-docker-user.sh --hub`).

## Layout
- `src/forge_node/` - stdlib-Bibliothek: `canon` (kanonisches JSON), `sshsig` (`ssh-keygen -Y`, vier Namespaces), `protocol` (Lease/Job/Poll/Result, Pruefer fuer die Node-Seite), `chain` (Audit-Hash-Kette),
  `redact`, `gates` (Betriebsleiter-Entscheid: Gates A-D, Op-Register, `policy_gate_violations`).
- `src/forge_node/hub/` - Hub: `core` (Jobs, Leases, Audit-Senke, Querpruefung, Quarantaene), `server` (mTLS-HTTPS, stdlib), `killswitch` (nur lesen + Dispatch-Lock), `files` (signierte Policy/Releases ausliefern),
  `config`, `db` (psycopg), `migrate`.
- `migrations/0001_node_schema.sql`, `scripts/sql/nodehub_{role,grants}.sql` - Schema `node`, Rolle `forge_nodehub` (kein UPDATE/DELETE/TRUNCATE auf `node.audit`).
- `Dockerfile`, `deploy/compose.nodehub.yaml` - Hub-Image/Compose-Dienst (Publish nur `192.168.10.4:8094`); in N1 weder gebaut noch ausgefuehrt.

## Tests
`scripts/run-tests.sh [pytest-Args]` startet ein Wegwerf-Postgres (`--network none`, nur Unix-Socket) und einen Test-Container mit dem Repo (read-only) und dem `ssh-keygen` des Hosts; beides wird danach entfernt.
Ohne `FORGE_NODE_TEST_DSN` werden die DB-Tests uebersprungen. Die Schluessel und die Test-PKI entstehen fluechtig im Temp-Verzeichnis des Tests.
