GO nodehub-deploy — class produktion. NOT YET SENT; send when the owner has finished guide parts 3.1/3.2 and the Betriebsleiter has merged forge-node `n5prep` (main) and forge-ops `n5prep` (master).
Window: one sitting, not 02:00–05:45 Berlin, not Sunday < 06:00, no STOP active. Inputs: forge-node main `<MAIN_SHA>`, forge-core master `<CORE_SHA>` (≥ bebbc28), forge-ops master `<OPS_SHA>`.
Not part of this GO (abort if tempted): firewall/iptables/ufw (the owner first renews the root boot copy with `forge-docker-user.sh --install-unit`, then applies and confirms `--hub` himself, guide part 4), registering a node, any other service start/restart, any docker restart, any change of existing pins in images.lock.

Needs (exact), all under /srv/forge/work/forge-core unless absolute:
 owner-made, verified in P1:  secrets/nodehub/hub.key (0600 forge:forgebox) · hub.crt (0644) · ca.crt (0644) · gate_ed25519 (0600) · gate_ed25519.pub (0644)   [hub.csr may remain]
 made by this GO:             secrets/nodehub_db_password (0600, create_nodehub_role.sh) · data/nodehub/policy and data/nodehub/release (0750 forge) · images.lock line IMG_FORGE_NODEHUB + regenerated .env
 already there:               secrets/db_password (forge_core, used by nodehub-migrate) · /srv/forge/post/control (kill-switch dir, mounted rw) · network forge-core_forge_core · forge-postgres-1 · image forge-core/app:build (== IMG_FORGE_CORE_APP)
 database:                    role forge_nodehub (LOGIN, CONNECT only + the grants of migration 0001) · schema `node` OWNED BY forge_core, created here by the superuser: forge_core has CONNECT only and cannot create schemas
 listener:                    host 192.168.10.4:8094/tcp only (compose publish `host_ip: 192.168.10.4`), container user 994:981, read_only, cap_drop ALL

P (read-only preflight; any miss => abort and report, change nothing)
 P1 files: `ls -l secrets/nodehub`; `openssl verify -CAfile secrets/nodehub/ca.crt secrets/nodehub/hub.crt`; SAN is IP:192.168.10.4 and EKU serverAuth (`openssl x509 -in ... -noout -ext subjectAltName,extendedKeyUsage`); key matches cert
    (`diff <(openssl x509 -in secrets/nodehub/hub.crt -pubkey -noout) <(openssl pkey -in secrets/nodehub/hub.key -pubout)`); `ssh-keygen -y -f secrets/nodehub/gate_ed25519 | cut -d' ' -f1,2` == `cut -d' ' -f1,2 secrets/nodehub/gate_ed25519.pub`; not_after of hub.crt > 300 days.
 P2 state: `ss -tlnH | grep -c ':8094 '` = 0; `docker ps -a --format '{{.Names}}' | grep -ci nodehub` = 0; `docker network inspect forge-core_forge_core`; `docker inspect -f '{{.State.Health.Status}}' forge-postgres-1` = healthy;
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
