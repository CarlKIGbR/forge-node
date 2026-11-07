Head: 9e98a2e
forge-node `n5prep` (base main 7a46e8b, 8 commits: scope, CLI+t0, migrate fix, hub image fix, role script, guide/GO, G27 fix, test sharpening) · forge-ops `n5prep` @4c508dc (base master 77df871, 2 commits: n1 `--hub` port + owner-flow tests). Built only: no merge, nothing installed, no hub started in production, no firewall change applied. Head line = the tested code state; this report is the next commit.
Docs: `docs/reports/N5PREP_SCOPE.md` (STEP 0) · `N5PREP_OWNER_GUIDE.md` (full guide, German, 255 lines) · `N5PREP_HUB_GO.md`. SPEC check: the t0 decision **narrows** 13.D/4.7, it does not contradict them (gated features already forbid tiers>0): no SPEC-QUESTION.

## Suite
- forge-node full suite, uid 994, `timeout 1800 scripts/run-tests.sh -q`: **1281 passed, 0 failed (7:02)** at 41f7019. First run at 49b9d26: 1275 passed, 3 failed (G27 `cmd_*` scan counted the new `cmd_build/cmd_sign`; two "subprocess importers" pins) — fixed in 41f7019 (renamed `run_*`, pins name `release/cli.py`).
- forge-ops `tests/test_docker_user_hub.sh`: **30 passed, 0 failed** (27 from n1, rebased onto master 77df871 + 3 new owner-flow tests); `bash -n bin/forge-docker-user.sh` ok.
- New `tests/test_n5prep.py`: **30 tests**. Base 7a46e8b (shims for the 2 missing imports, otherwise it cannot even collect): **28 fail, 2 pass** (the g1/g4 template cases were already t0); branch: 30 pass. `test_n5prep.py` re-run at 9e98a2e (one assertion + one doc line after the suite): 30 passed.

## Tests (item → what is proven)
| # | Item | Tests (`tests/test_n5prep.py`) | base |
|---|---|---|---|
| 1 | release CLI | pty plays the owner's terminal: `build` asks the passphrase twice, tar+manifest signatures verify (C2 way), wrong passphrase ⇒ rc 1 and no artifact; `ssh-keygen` runs with inherited stdio (spy: no `capture_output`/stdin/env); `sign` namespace-bound; wrong pub caught; key mode/overwrite/version guards; reproducible; stdlib+3.12 only; not in the pyz | fail |
| 2 | t0 everywhere | all 4 templates t0/observe/[0]/no forge_roots/no selftest and validate with the real t0 optable; t0 artifact carries g1–g4, `full` still g2/g3 (+forge_roots); no op code in the pyz; **privd (t0 release) rejects** tier 1/2/3, t1/t2 ops, workloads, forge root, vm_pool, t3, and any `profile: full` policy — with production gates and with every gate open; end-to-end through `policy.apply` | fail (g1/g4 pass) |
| 3 | hub deploy | migration works as CONNECT-only `forge_core` (exit 3 + instruction if the schema is missing); 0001 has no CREATE SCHEMA; image keeps `/app/node-migrations` apart, migrator globs `NNNN_node_*.sql`; `build-hub.sh`/`create_nodehub_role.sh` shape | fail |
| 5/6 | order, guide | install order g2,g3,g1,g4; every guide block passes `bash -n`; guide installs t0/none only, every firewall call has `--hub`, privctl/switcher/CLI commands exist | fail |
| 4 | firewall | forge-ops: dry-run/apply/confirm/restore/remove for `--hub`, Edge unchanged, dry-run mutates nothing, no marker before `--confirm --hub` | (n/a: file absent on master) |
Hand mutants (12, `/tmp/n5hub/mut.py`): 13 variants of the new code (policy_store, policy_full, migrate glob/schema, policies, cli capture/verify/leftovers/key-mode/overwrite, Dockerfile, 0001): 13 killed. Two survived the first pass and were fixed: m4 was equivalent (my mutant only touched the branch where both forms fail alike; the real regression m4b is killed), m11 (key-mode guard) hid behind ssh-keygen's own refusal — the test now asserts our message.

## Found by rehearsal (beyond the 6 items; all fixed or flagged)
1. **Hub migration cannot run in production**: prod `forge_core` has CONNECT only; `CREATE SCHEMA IF NOT EXISTS node` (migrate.py and 0001) fails "permission denied for database" even when the schema exists. Rehearsed on a restore of the pre-g1stack dump + guard bootstrap ×2. Fixed; schema is created once by the superuser (`create_nodehub_role.sh`).
2. **Hub image would have run forge-core's migrations**: `COPY migrations ./migrations` merged with the base image's `/app/migrations` (0001_init…0020). Fixed (`/app/node-migrations`, glob `*_node_*`).
3. BuildKit cannot `FROM sha256:<id>`: `build-hub.sh` uses `forge-core/app:build` after checking it equals the pin.
4. Policy hole: a t0 policy with `t1.vm_pool` passed once gate B is met; and a t0 release accepted `profile: full` policies. Both refused now.
5. **Cockpit /nodes does not exist** (N7): node registration is an owner SQL (`INSERT INTO node.nodes … 'active'`), in the guide (5.5, quoting rehearsed). `node.nodes.profile` is **immutable**: a t0-registered g2/g3 cannot become `full` in place — later T1 needs a new registration (decision below).
6. Design 13.C reads the CSR from forgenode's home (not readable for `carl`): guide uses /tmp. Design 13.B firewall calls lack `--hub` (they would touch the Edge rules): guide has it. macOS LibreSSL has no `-ext`: avoided. Mac needs Python ≥ 3.12.
7. Hub rehearsal (throwaway compose project, 127.0.0.1:18094, own network, torn down; no :8094 listener on this host after the teardown, nothing else touched): healthy; 401 no cert / 403 unregistered / 404 registered; owner commands 13.A/B/C5 and release build → C2 verify → policy fill/sign/verify → privd t0 parse run end to end with a throwaway key.

## For the Betriebsleiter
(a) merge forge-node `n5prep` and forge-ops `n5prep`, give `<MAIN_SHA>`/`<OPS_SHA>`; (b) accept that g2/g3 t0 ⇒ new registration for a later `full` (or choose now to register with the profile you want); (c) not done: the agent's behaviour while unregistered (403 loop) is only read, not run; the node-side install (systemd, chattr, loop-free) is untested on a real host — first run is g2; (d) the hub GO below is NOT sent.

## Hub GO (ready to send; also `N5PREP_HUB_GO.md`)
```
GO nodehub-deploy — class produktion. NOT YET SENT; send when the owner has finished guide parts 3.1/3.2 and the Betriebsleiter has merged forge-node `n5prep` (main) and forge-ops `n5prep` (master).
Window: one sitting, not 02:00–05:45 Berlin, not Sunday < 06:00, no STOP active. Inputs: forge-node main `<MAIN_SHA>`, forge-core master `<CORE_SHA>` (≥ bebbc28), forge-ops master `<OPS_SHA>`.
Not part of this GO (abort if tempted): firewall/iptables/ufw (the owner applies `forge-docker-user.sh --hub` himself, guide part 4), registering a node, any other service start/restart, any docker restart, any change of existing pins in images.lock.

Needs (exact), all under /srv/forge/work/forge-core unless absolute:
 owner-made, verified in P1:  secrets/nodehub/hub.key (0600 forge:forgebox) · hub.crt (0644) · ca.crt (0644) · gate_ed25519 (0600) · gate_ed25519.pub (0644)   [hub.csr may remain]
 made by this GO:             secrets/nodehub_db_password (0600, create_nodehub_role.sh) · data/nodehub/policy and data/nodehub/release (0750 forge) · images.lock line IMG_FORGE_NODEHUB + regenerated .env
 already there:               secrets/db_password (forge_core, used by nodehub-migrate) · /srv/forge/post/control (kill-switch dir, mounted rw) · network forge_core · forge-postgres-1 · image forge-core/app:build (== IMG_FORGE_CORE_APP)
 database:                    role forge_nodehub (LOGIN, CONNECT only + the grants of migration 0001) · schema `node` OWNED BY forge_core, created here by the superuser: forge_core has CONNECT only and cannot create schemas
 listener:                    host 192.168.10.4:8094/tcp only (compose publish `host_ip: 192.168.10.4`), container user 994:981, read_only, cap_drop ALL

P (read-only preflight; any miss => abort and report, change nothing)
 P1 files: `ls -l secrets/nodehub`; `openssl verify -CAfile secrets/nodehub/ca.crt secrets/nodehub/hub.crt`; SAN is IP:192.168.10.4 and EKU serverAuth (`openssl x509 -in ... -noout -ext subjectAltName,extendedKeyUsage`); key matches cert
    (`diff <(openssl x509 -in secrets/nodehub/hub.crt -pubkey -noout) <(openssl pkey -in secrets/nodehub/hub.key -pubout)`); `ssh-keygen -y -f secrets/nodehub/gate_ed25519 | cut -d' ' -f1,2` == `cut -d' ' -f1,2 secrets/nodehub/gate_ed25519.pub`; not_after of hub.crt > 300 days.
 P2 state: `ss -tlnH | grep -c ':8094 '` = 0; `docker ps -a --format '{{.Names}}' | grep -ci nodehub` = 0; `docker network inspect forge_core`; `docker inspect -f '{{.State.Health.Status}}' forge-postgres-1` = healthy;
    `[ "$(docker image inspect -f '{{.Id}}' forge-core/app:build)" = "$(sed -n 's/^IMG_FORGE_CORE_APP=//p' images.lock)" ]`; `docker ps --format '{{.Names}} {{.CreatedAt}}' | sort > /tmp/nodehub-before.txt`.
S (steps, in this order)
 1 Backup: `pg_dump -Fc` of database forge via forge-postgres-1 to /srv/forge/work/backups/pre-nodehub_<ts>.dump (same recipe as pre-g1stack); report size and TOC line count.
 2 `cd /srv/forge/work/forge-node && scripts/create_nodehub_role.sh /srv/forge/work/forge-core`  (role + password file + schema node; repeatable; no password in argv/env/output)
 3 `install -d -m 0750 data/nodehub/policy data/nodehub/release`   (as forge: otherwise compose creates them root-owned)
 4 `cd /srv/forge/work/forge-node && scripts/build-hub.sh /srv/forge/work/forge-core` -> prints `IMG_FORGE_NODEHUB=sha256:...`; append that ONE line to forge-core/images.lock, run `scripts/mkenv.sh`, commit on master ("re-pin: IMG_FORGE_NODEHUB"), push per the usual recipe.
 5 `C="docker compose -p forge-core -f compose.yaml -f /srv/forge/work/forge-node/deploy/compose.nodehub.yaml"`; `$C config -q`; `$C --profile nodehub-migrate run --rm nodehub-migrate`
    expect `node migrations applied: 0001_node_schema`; run it a second time: `none (up to date)`. (Exit 3 with "create it once as the database superuser" => step 2 was skipped.)
 6 `$C up -d --no-deps forge-nodehub`   (only this service; nothing else is recreated)
V (verify; report every output)
 V1 `docker ps` shows forge-core-forge-nodehub-1 `healthy` (<= 60 s); `docker logs forge-core-forge-nodehub-1 | tail` has "listening on 0.0.0.0:8094" and no traceback.
 V2 `ss -tlnH | grep ':8094 '` shows ONLY 192.168.10.4:8094; `docker port forge-core-forge-nodehub-1` = `8094/tcp -> 192.168.10.4:8094`.
 V3 `curl -s --cacert secrets/nodehub/ca.crt https://192.168.10.4:8094/healthz` -> `{"hub":"forge-nodehub","ok":true,...}`; without a client certificate `POST /v1/poll` -> 401.
 V4 DB (as the superuser inside forge-postgres-1, privileges of the hub role via `SET ROLE forge_nodehub;` — no password involved): `SELECT count(*) FROM node.nodes` works, `SELECT 1 FROM core.approvals` is "permission denied";
    `\dt node.*` lists the node tables owned by forge_core; `SELECT evtname, evtenabled FROM pg_event_trigger` = guard_ddl_command_end|A and guard_sql_drop|A (guard intact).
 V5 `docker ps --format '{{.Names}} {{.CreatedAt}}' | sort | diff /tmp/nodehub-before.txt -` shows exactly one new line (the hub); no other container recreated. Report `iptables -S DOCKER-USER | grep -c forge-nodehub` (0 until the owner applies the rule).
Rollback (only on failure or owner request): `$C rm -sf forge-nodehub`; revert the images.lock/.env commit; schema `node`, role and dump stay unless the owner orders `DROP SCHEMA node CASCADE; DROP ROLE forge_nodehub` (restore point: the pre-nodehub dump).
Report: first line `Head: <sha of the forge-core re-pin commit>`; then P/S/V outputs, image id, dump path+size, the before/after container diff, anything unexpected.
Evidence behind this text (N5-prep rehearsals, nothing of it ran in production): (1) restore of the pre-g1stack dump into a throwaway PG + guard bootstrap of master x2 + migrate as a non-superuser forge_core with CONNECT only: `CREATE SCHEMA IF NOT EXISTS node` failed with "permission denied for database forge" (fixed: schema pre-created, migrator no longer creates it); (2) the hub image's /app/migrations held forge-core's 0001_init..0020 next to 0001_node_schema (fixed: /app/node-migrations + glob `NNNN_node_*.sql`); (3) BuildKit cannot use a bare image ID as FROM (fixed: build-hub.sh uses the local tag after checking it equals the pin); (4) overlay in a throwaway compose project on 127.0.0.1:18094: healthy, 401 without / 403 with an unregistered / 404-not-500 with a registered client certificate.
```

## OWNER INSTALL GUIDE (condensed; full copy-paste text: `docs/reports/N5PREP_OWNER_GUIDE.md`)
Profil **t0 auf allen vier Hosts**: kein forge-root/Loop-Volume, kein selftest.noop, `observe`, `tiers_enabled [0]`. Nie 02:00–05:45 Berlin / So < 06:00; SSH-Sitzung je Host offen lassen; ≥ 1 Tag zwischen den Hosts.
1. **Mac einmalig** (Teil 1): `ssh-keygen -t ed25519 -a 100 -C forge-node-owner -f owner_ed25519` (Passphrase!), `allowed_signers`, CA (`openssl ecparam … ca.crt`), Fingerabdruck notieren, `owner_ed25519` + `ca.key` offline sichern.
2. **Release bauen** (Teil 2): Quelle per `git archive <MAIN_SHA>` von g2, dann `PYTHONPATH=src python3 -m forge_node.cli release build 0.5.0 t0 --out ~/forge-node-owner/release --key ~/forge-node-owner/owner_ed25519` (zweimal Passphrase; prüft die Signaturen lokal).
3. **Hub auf g2** (Teil 3): hub.key/CSR/gate-Schlüssel auf g2 → Mac signiert hub.crt → zurück nach `forge-core/secrets/nodehub/` → **GO an die Betriebsleitung** (Text oben) → warten auf „healthy".
4. **Firewall** (Teil 4, nach dem Merge): `sudo forge-docker-user.sh --dry-run --hub` → `sudo … --hub` (Timer 300 s) → Test (`/healthz`; von 192.168.30.0/29 `openssl s_client -connect 192.168.10.4:8094`) → `sudo … --confirm --hub` binnen 5 min.
5. **Je Host** (Teil 5), Reihenfolge und Werte:
| | g2 | g3 | g1 | g4 (zuletzt) |
|---|---|---|---|---|
| NID / IP | g2 / 192.168.10.4 | g3 / 192.168.30.3 | g1 / 192.168.10.3 | g4 / 192.168.30.4 |
| vorher | Hub + Regel bestätigt; Docker nicht neu starten | M022-Stand klären, `free -m` | keine ufw-Änderung | `free -m` ≥ 300 MiB, deine Zustimmung, Handelszeiten |
| Verbindung | LAN | `openssl s_client -connect 192.168.10.4:8094 -brief` | wie g2 | wie g3 |
   Ablauf je Host: 5.1 `fn.env` (PROFILE=t0, FORGE_ROOT=none) + scp → 5.2 Server-Segment 1 (Vorprüfung inkl. Python ≥ 3.12, `ev`-Evidenz vorher, Release-Signatur, Benutzer/Verzeichnisse, `install-first`, `privctl audit-init`, Node-Key+CSR) → 5.3 Mac (Node-Zertifikat signieren, Policy aus dem Release füllen+signieren: `release sign … --namespace forge-node-policy`) → 5.4 Server-Segment 2 (`policy-apply`, `privctl status`, `doctor` → Exit 0; Agent+Timer starten) → 5.5 Registrierung per SQL (Fingerabdruck, `SET ROLE forge_core; INSERT INTO node.nodes … 't0','active'`).
6. **Prüfung je Host** (Teil 6): 3 Units `active`; `privctl status` (Serial 1, observe) + `audit-verify`; `doctor` Exit 0 (hub ok); Journal ohne Fehlerschleife; kein forge-sudoers; `ev | diff` = Evidenz unverändert (g1/g3/g4: auch kein neuer Listener; g2: nur 8094); Hub-Seite `node.nodes.last_seen` < 2 min.
7. **Rückgängig** (Teil 7, je Stufe einzeln): `forge-stop`/`forge-release`; `touch /etc/forge-node/LOCAL_STOP`; `privctl lockdown`; Widerruf `UPDATE node.nodes SET status='revoked'`; `forge-node-release switch <alt>`; vollständige Deinstallation (Audit-Archiv sichern, Units disable, `rm -rf /opt/forge-node /etc/forge-node …`, `userdel forgenode`, Evidenz-Vergleich); Hub: `rm -sf forge-nodehub` + `forge-docker-user.sh --remove --hub`.
