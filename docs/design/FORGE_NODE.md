# forge-node — controlled operational authority on carlgpu1–4 (design gate, no implementation)

Status: DESIGN **revision 1**, for decision by the Betriebsleiter / Owner · 2026-10-31 · class produktion (touches the KMU hosts and the Live-Trading host)
Repo: `/srv/forge/work/forge-node` (new, design only). Nothing in this document has been installed, started, or changed on any server. All checks quoted below were read-only.
Inputs read: forge-docs `INVENTUR_AUSWERTUNG` (28.10.), `KMU_INFRA_KORRELATION` v2, `ARCHITEKTUR_ADR_MEILENSTEINE` (ADR-001…021, §8 security, §9 GPU modes, §12 ports), `BETRIEBSHANDBUCH`, `ROADMAP` (31.10. 09:05), `MAENGELLISTE` (M-84, M-92, M-94, M-95, M-97), `KONTEXT_UEBERGABE_AKTIV`; forge-core master (`killswitch.py`, `mcp_planner.py`, `state.py`, `config/state_allowlist.yaml`, migration 0011 escalations); forge-ops (`forge-stop`, `forge-docker-user.sh`); forge-core-f5c2 `F5C2_RUN_GRAPH.md` (style, ledger semantics); live read-only facts of carlgpu2 (listeners, filesystems, tools, container labels).
Language: English prose, German domain terms kept (Betriebsleiter, Eingang, Inventur, Revision, Not-Aus, Sperrfenster) as in the code base.
Window rule: authored 11:04 Berlin, outside 02:00–05:45. The same window is built into the design (§9.5).

**Principle (Betriebsleiter decision):** full control, but tiered, audited and revocable. There is no unrestricted root shell for an LLM-driven system — not as a feature, not as a fallback.

---------------------------------------------------------------------------------------------------

## 0. Summary of the design

1. **Pull, not push.** `forge-node-agent` on each server opens an **outbound mTLS** connection to the hub `forge-nodehub` on carlgpu2 (`192.168.10.4:8094`, LAN only). **No new inbound port on carlgpu1/3/4, no sshd change, no firewall change on them.** No internet path in either direction (§5).
2. **The node trusts the owner's key, not the hub.** Allowlists are a **signed policy** (`ssh-keygen -Y`, owner key, namespace `forge-node-policy`), verified by a root-owned script on the node. A compromised hub, planner or agent can only act *inside* what the owner signed (§7).
3. **Four tiers.** T0 read (agent uid, redacted) · T1 forge-owned management (`forge.*` containers, `forge` libvirt pool, forge dirs on the second SSD) · T2 narrow sudoers → fixed root-owned scripts with parameter validation, plan-hash and windows · T3 = owner approval with a prepared command (§4).
4. **No wildcard sudoers.** The sudoers fragment is *generated* from the signed policy (one line per op×target), checked with `visudo -cf`, and every script re-validates against the installed policy (§4.4, §7.3).
5. **Deny by default, protected set first.** KMU frozen areas (`/opt/kmu-ai`, `/srv/models`, `/srv/kmu-ai`), the Live-Trading host carlgpu4 and everything in the "protected set" are evaluated *before* any allow rule and can only be changed by an owner-signed policy that carries an explicit `frozen_ack`. On carlgpu4 the T1/T2/T3 helpers are **not even installed** (T0-only profile) (§10).
6. **Audit is append-only on three independent paths:** agent log (`chattr +a`, hash chain), root-written privileged log (the authoritative record of what actually ran as root), and hub Postgres (`node.audit`, INSERT-only, chain verified). Missing audit = fail-closed (§8).
7. **Kill switch is first-class:** existing `control/STOP` (same `.dispatch.lock` exclusion as dispatch), plus a node-local `LOCAL_STOP`, plus fail-closed staleness (no fresh hub heartbeat ⇒ no T1/T2). T0 keeps working during STOP (§9.1).
8. **Rate limits, circuit breakers, dry-run:** every mutating op has a dry-run that produces a `plan_hash`; apply requires the matching hash; new ops start `dry_run_only` until the owner signs promotion; global `observe` mode for rollout (§9.2–9.4).
9. **Planner / graph integration** via forge-mcp tools (`node_*`), job idempotency key = graph effect key, escalations into the existing owner inbox (new kinds `node_action`, `node_alert`), T3 through the existing `approvals_request` (§11).
10. **First use:** read-only **Revision round (Inventur v2) + F7a passive measurement** on all four servers — T0 only, no sudo beyond one fixed read-only probe, nothing frozen is modified (§14).
11. **Choice vs alternatives:** a thin purpose-built agent beats Ansible+SSH, Salt and SSH forced-commands on exactly the constraints that matter here: no inbound ports/sshd changes on frozen hosts, per-call policy/audit/kill-switch, no master that is root everywhere (§2).
12. **Honest residual risk:** on carlgpu2 the executor user `forge` is in the `docker` group (root-equivalent, ADR-008). The tiers there bound the *planner→node API path*, not a compromised executor. Recommended end state: remove `docker` from `forge` once T1 is mature (§12, OQ-10).

---------------------------------------------------------------------------------------------------

## 1. Goals, non-goals, constraints

**Goals**
- Give the Betriebsleiter (and through it the graph) *operational eyes and hands* on all four servers: inventory, metrics, logs, start/stop of forge-owned things, a short list of privileged maintenance operations.
- Replace the ad-hoc owner-installed pieces over time: the `state_get` host collector (M-85d), the planned F7 "sudoers drop-in for scene switches", repeated manual Inventur dumps.
- Every action attributable (who asked, which run, which policy), reversible or at least bounded, stoppable within seconds.

**Non-goals**
- No general remote shell, no `docker exec`, no arbitrary file read/write, no arbitrary `systemctl`.
- No orchestration/scheduling of workloads (that stays Compose per host, k3s later — ADR-001).
- No management of KMU services, Tradebot, SecMPro, nexus. They are *observed* (T0, metadata) and otherwise out of scope until the owner signs otherwise.
- No new secrets store. Keys are owner-generated (§6); forge-node never stores provider keys.
- Not a replacement for `grant_worker_host.sh` (F6 worker lanes: SSH key for project executors on g3/g4). Different purpose, different user, different key; they must never share either.

**Constraints taken from the inventory (28.10.) and live checks (31.10.)**
- Heterogeneous hosts: Ubuntu 24.04 (g1–g3) vs **26.04 (g4)**; Python 3.12 vs **3.14.4 (g4)**; node 18 on g2/g3; **`pip`/`uv` missing** on most hosts; Docker 29.2–29.8; docker GID 984 vs 995 (g4). → agent is **stdlib-only Python** shipped as one zipapp; no `pip install`, no package install at all.
- sshd `AllowUsers` differs per host (g2: only `carl`; g4: `tbpost@10.200.0.2`, `carl`, drop-in `60-tradebot-tbpost.conf`) and "on g4 touch nothing". → no ssh-based channel.
- Firewalls: g1 ufw active default-deny; g2/g3/g4 ufw inactive/INPUT ACCEPT; Docker publishes bypass ufw. → agent opens no listener.
- Routing: two /29 subnets, gateways 192.168.10.1 and 192.168.30.1. 30.x→10.3 is proven (NFS 2049, Redis 6379). **30.x→192.168.10.4:8094 is not proven** (router firewall not inventoried) → pre-flight test (§13).
- carlgpu2 live facts: `unattended-upgrades` **enabled** (`20auto-upgrades`), NTP synchronized, TZ Europe/Berlin, ext4 everywhere (so `chattr +a` works), no `smartctl`/`nvme-cli`/`virsh`/`needrestart`, `nvidia-smi` present, **no container carries a `forge.*` label today** (only one sandbox PG has `forge.sandbox_pg=1`), plus leftover test containers (`f5c-review2-*-pg`, `f5brecheck-*-pg`).
- The executor unit (`forge-postbote`) has `NoNewPrivileges` — **the agent unit must not**, because it uses `sudo`. The agent gets other hardening instead (§4.5).
- Second SSD: on **every** server the second NVMe is KMU storage (g1 `/srv/kmu-ai`, g2/g3/g4 `/srv/models`) — see OQ-1. `/srv/forge` on g2 lives on the system disk.

---------------------------------------------------------------------------------------------------

## 2. Alternatives and decision

| Criterion | **forge-node (pull agent + signed policy + sudo→scripts)** | Ansible + SSH, restricted keys | SaltStack | Plain SSH forced-commands |
|---|---|---|---|---|
| Inbound ports / sshd changes on KMU/Trading hosts | **none** (outbound only) | sshd `AllowUsers` + keys on all four (g2/g4 differ; g4 "touch nothing") | master↔minion 4505/4506 inbound to master; minion daemon on every host | sshd + `authorized_keys` on all four |
| What a stolen central credential gives | hub cert ⇒ only ops allowed by the *node-local signed* policy, inside windows/rate limits, all audited by root-written log | SSH client key on carlgpu2 ⇒ every forced command / every playbook task, **no** central rate limit, STOP or audit unless re-implemented per host | Salt master compromise = root on all minions (the "unrestricted root" we exclude) | same as Ansible: key on carlgpu2 = all commands, any time |
| Per-call policy (params, windows, plan-hash) | native | per-playbook, bypassed by any ad-hoc `ansible -m shell`; restricted keys limit *commands*, not *policy* | pillar/ACLs possible but coarse (`client_acl`, `peer`), fragile | in a wrapper script per host, duplicated |
| Kill switch / STOP integration | hub + node-local + staleness fail-closed | external (wrap playbook runs) | external | external |
| Audit | hash-chained agent log + root priv log + Postgres | controller log only (target side: sshd/sudo logs) | master job cache; returners | sshd log + wrapper log |
| New software on frozen hosts | one stdlib zipapp, ≤8 small scripts (g1/g4: 4) | Python on target (present) + Ansible on controller; modules write temp files, `become` | **salt-minion + deps** (pip-free? no — package/venv), big surface | none |
| Dry-run / plan-hash | designed in | `--check` is best-effort per module | `test=True` best-effort | none |
| Offline/hub-down behaviour | fail-closed, T0 spool | n/a (push) | minion keeps running, may apply cached states | n/a |
| Cost | **we write and maintain ~2–3 kLOC** (agent+hub+scripts) and must test the sudoers/lint surface | low | medium–high (ops of a master) | very low |

**Decision: forge-node**, because the three properties that matter most here — *no inbound surface on KMU/Trading hosts*, *authorization that lives on the node and not in a central secret*, *uniform audit + STOP + rate-limit* — are exactly what the three alternatives cannot give without rebuilding the same agent logic around them. Salt is rejected outright (master = root everywhere). Ansible/SSH-forced-commands remain valid **tools for the owner** (e.g. ad-hoc owner maintenance) but not as the channel the LLM-driven system uses.
**Honest counter-argument and tripwire:** if the op set stayed "T0 read only" forever, hub-held SSH forced-commands would be cheaper and adequate. The decision is justified by T1/T2. Tripwire: if after round 0 + 3 months nobody has requested a T1/T2 op, freeze at T0 and do not build N5–N7 (§15).

---------------------------------------------------------------------------------------------------

## 3. Architecture

```
carlgpu2 (192.168.10.4)                                    carlgpuN (any server)
┌─────────────────────────────────────────────┐            ┌────────────────────────────────────────────────┐
│ planner / graph / Betriebsleiter            │            │ forge-node-agent  (uid forgenode, no docker    │
│   │ MCP tools node_* (forge-mcp, audited)   │            │   group, no NoNewPrivileges, IP-filtered)      │
│   ▼                                         │            │   │ poll ◄── outbound mTLS (TLS1.3, client cert)│
│ forge-nodehub  (container, 192.168.10.4:8094)│◄───────────┤   │                                            │
│   • authz per identity/project/tier         │  mTLS      │   ├─ T0 readers (own uid, /proc, nvidia-smi)   │
│   • reads control/STOP (+ .dispatch.lock)   │  pull      │   ├─ sudo ► t0-probe / t0-journal (root, ro)   │
│   • job queue, plans, proposals             │            │   ├─ sudo ► t1-* (root; docker/libvirt)        │
│   • audit sink  → Postgres schema `node`    │            │   ├─ sudo ► t2-* (root; fixed scripts)         │
│   • escalations → core.escalations (inbox)  │            │   └─ audit.jsonl (+a, chain)                   │
│ Postgres (forge)  forge_nodehub role        │            │ root: /usr/local/libexec/forge-node/*          │
│ control/STOP   (touch / rm / forge-stop)    │            │ root: priv.jsonl (+a)  ◄ authoritative         │
└─────────────────────────────────────────────┘            │ owner key (public only) /etc/forge-node/       │
        ▲ owner: Cockpit /nodes (approve node, T3 inbox)   └────────────────────────────────────────────────┘
        ▲ owner on Mac: CA key, policy-signing key, release signing, T3 approvals — private keys never leave the Mac
```

Components and where they live:

| Component | Where | Owner/uid | Notes |
|---|---|---|---|
| `forge-node-agent` (zipapp, stdlib only) | `/opt/forge-node/releases/<ver>/forge-node.pyz`, symlink `current` | root-owned, runs as `forgenode` | one unit `forge-node-agent.service` |
| Root helpers | `/usr/local/libexec/forge-node/` | `root:root 0755` (never writable by `forgenode`) | profile decides which exist: `full` (g2,g3), `t0` (g1,g4) |
| Policy + trust anchor | `/etc/forge-node/{allowed_signers,policy/}` | `root:root` 0644/0640 | applied only by `apply-policy` |
| Privileged state | `/var/lib/forge-node-priv/` | `root` 0700 | policy serial, T3 nonce ledger, plan store |
| Agent state / spool | `/var/lib/forge-node/` | `forgenode` | T0 spool ring ≤ 50 MiB |
| Logs | `/var/log/forge-node/audit.jsonl` (`forgenode`, `+a`), `priv.jsonl` (`root:forgenode 0640`, `+a`) | | rotated by root timer |
| Hub `forge-nodehub` | carlgpu2, container from forge-core (new slice), `192.168.10.4:8094` only | non-root container uid | port 8094 is free today (checked `ss`); reserved list in §12 of ADR doc to be amended |
| DB | schema `node` in forge Postgres, role `forge_nodehub` | | migration numbers assigned at slice time after F5c part 2's list |
| MCP surface | forge-mcp tools `node_*` | | §11 |
| Owner tools | `fnctl`-style commands = plain `ssh-keygen`/`openssl` in §13; a convenience wrapper may come later | Mac | not required for installation |

Protocol (HTTPS, TLS 1.3 only, HTTP/1.1, JSON, `Content-Length` bounded ≤ 1 MiB):
- `POST /v1/poll` (long-poll ≤ 30 s) → `{stop, hub_time, policy_serial_latest, jobs[≤1]}`. Doubles as heartbeat (agent sends version, policy serial+hash, clock, spool depth, audit head `seq/hash`).
- `POST /v1/jobs/{job_id}/result` · `POST /v1/audit` (batch with ack of highest `seq`) · `GET /v1/policy/{serial}` (signed blob + sig; verification is the node's job) · `GET /v1/release/{ver}` (signed artifact; install still needs the owner, §13).
- Job envelope: `{job_id (uuid = idempotency key), node, tier, op, params, dry_run, plan_hash?, requester{identity, planner_call_id, run_id, project}, issued_at, expires_at (≤120 s to pick up)}`.
- Result: `{job_id, status ∈ ok|dry_run|denied|failed|aborted, reason_code, output(redacted, ≤64 KiB), audit_seq_range, plan_hash?}`.
- Reason codes (stable, tested): `DENY_STOP, DENY_LOCAL_STOP, DENY_QUARANTINE, DENY_STALE_HUB, DENY_CLOCK, DENY_AUDIT_DOWN, DENY_POLICY_INVALID, DENY_TIER_DISABLED, DENY_OP_UNKNOWN, DENY_OP_MODE (dry_run_only), DENY_PARAM, DENY_PROTECTED, DENY_NOT_ALLOWLISTED, DENY_WINDOW, DENY_RATE, DENY_CIRCUIT_OPEN, DENY_STALE_PLAN, DENY_NEEDS_OWNER_SIG, FAIL_PRECHECK, FAIL_EXEC, FAIL_POSTCHECK`.

**Node decision pipeline (fixed order; every step that denies still writes an audit record):**
1 kill-switch state seen & fresh → 2 `LOCAL_STOP`/quarantine → 3 clock skew vs hub ≤ 60 s → 4 audit writable → 5 policy signature + serial valid → 6 tier enabled for this node → 7 op known and mode → 8 param schema → 9 **protected set** on *resolved* objects → 10 allowlist match → 11 window → 12 rate/circuit → 13 plan-hash / dry-run → 14 execute through the single *effect executor* (the only code path that mutates; dry-run short-circuits here) → 15 post-check → 16 audit + result.

---------------------------------------------------------------------------------------------------

## 4. Tiers

### 4.1 T0 — read (agent uid; root only for fixed read-only probes)

All T0 output is **data, never instructions**: size-capped, character-filtered where names are returned (same idea as `state.VALUE_RE`), delivered to the LLM inside an `untrusted` envelope.

| Op | Content (metadata only) | Source / privilege |
|---|---|---|
| `inv.host` | OS, kernel, uptime, load, CPU model/threads, RAM, **swap used/total**, NTP sync, TZ, reboot-required | `/proc`, `timedatectl` — agent uid |
| `inv.disks` | block devices, partitions, FS type, mount points, `df` per mount, **second SSD (role tag from policy)**, md/RAID (`/proc/mdstat`), NFS mounts, NVMe presence via sysfs; SMART only if `smartctl`/`nvme` exists (**absent on g2 today** → section reports `unavailable`, not an install request) | `lsblk -J`, `findmnt -J`, sysfs — agent uid |
| `inv.gpu` | per GPU: name, VRAM used/total, util, temp, power, clocks, PCIe gen/width, throttle reasons; compute apps as `pid, process name, used MiB` (no command lines — they can contain tokens) | `nvidia-smi --query-*` — agent uid (`/dev/nvidia*` are world-accessible by default; verified in round 0) |
| `inv.net` | listening sockets (proto, addr, port, process name), `DOCKER-USER`/ufw state, routes (default gateways), reachability probe of hub | `ss`; `iptables -S` via `t0-probe` |
| `inv.units` | systemd units: active/sub/result/load, failed list, timers (last/next), FragmentPath | `systemctl show`, `list-units -o json` |
| `inv.containers` | name, short id, **image id/digest**, state, restart count, **labels**, published ports, bind-mount *source paths* — **never** `Env`, `Cmd`, secrets | `t0-probe` using explicit `--format` templates, never raw `docker inspect` |
| `inv.vms` | libvirt domains and pools (if `virsh` exists; absent today) | `t0-probe` |
| `inv.pkgs` | `apt-mark showhold`, upgradable count, security-pocket pending, `unattended-upgrades` status, docker/nvidia/kernel versions | `apt-get -s`, `apt-mark` — agent uid |
| `inv.certs` | expiry (days left) of cert files named in policy + live handshake to local TLS listeners (443/8443/…); node cert and hub cert expiry | `t0-probe` for root-readable dirs (e.g. letsencrypt) |
| `inv.backups` | last-success age of allowlisted backup units (`kmu-sicherung-*`, `kmu-s2-backup`, forge backup 21:30), newest-file age in policy backup dirs, snapshot age **from marker files** — never opens restic repos or `restic.pass` | `systemctl show`, `stat` |
| `inv.git` | rev, branch, **dirty count (tracked files only)** for policy-listed repos, via `git --no-optional-locks` so `.git/index` is never rewritten in `/opt/kmu-ai`; `safe.directory` handling verified in round 0 (OQ-13) | `t0-probe` |
| `inv.access` | effective `sshd -T allowusers`, group members of `docker`/`sudo`, authorized_keys *fingerprints + comments* (no key bodies) | `t0-probe` |
| `metrics.sample` | cpu/mem/swap/load/diskio/net, gpu util/VRAM/temp/power; for time series (F7a) | agent uid, 30 s cadence max |
| `logs.unit` | `journalctl -u <unit>` for **allowlisted** units: `since` ≤ 7 d, ≤ 500 lines, ≤ 200 KiB, **redacted** at the node (patterns from the Inventur secret scan: `sk-`, `ghp_`, `github_pat_`, `xox*`, `AKIA`, `hf_`, JWT, PEM headers, `://user:pass@`, `password|token|secret|api_key|bearer|authorization` values, ≥ 32-char base64/hex), redacted again at the hub; stored redacted only | `t0-journal` (root; the agent is **not** in `systemd-journal`, so a compromised agent cannot read other units' logs) |

Rules: heavy sections (`du`, `inv.git` on large trees) only outside the window (§9.5); light sections any time. Logs of `kmu-*` and anything on g4 are **not allowlisted by default**; if the owner adds them they carry `sensitivity: customer` and the existing `effective_sensitivity`/`model_policy` guard (M-84) withholds them from non-permitted models.

### 4.2 T1 — forge-owned management

Authority comes from **ownership markers**, not names:

- **Containers:** only those with label `forge.managed=true` **and** `forge.node=<this node id>`; `forge.project=<slug>`, `forge.stack=<name>`; `forge.critical=true` excludes from T1 (postgres, litellm, edge, hub: stopping them kills audit/inbox → T2-allowlisted restart or T3). Labels are immutable after creation, so a non-forge container cannot acquire them. **Today no container has these labels** → first implementation slice adds them to forge-core/fundament/edge compose files (changes at next recreate, at a Sperrfenster-safe time), and the leftover test containers get labels or are removed by the owner (T3).
- **Ops:** `container.start|stop|restart|recreate <id>` (acts on the full container ID resolved from the name *after* the label check — no TOCTOU between check and act), `stack.put|up|down`, `dir.*`, `file.put|get`, `vm.*`.
- **Stack bundles** (new definitions) are the dangerous part: `docker` = root. Therefore:
  1. `stack.put` stores `compose.yaml` under `<forge_root>/stacks/<stack>/` (a hash is recorded).
  2. The root helper runs **`docker compose config --format json`** on it (nothing is created), and lints the *resolved* model — `extends`, `include`, env interpolation, anchors are already expanded; **the helper applies the rendered model, not the YAML** (no TOCTOU between lint and run).
  3. Lint is an **allowlist of keys**, not a denylist: unknown keys ⇒ reject. Required: image by `@sha256:` digest (no floating tags, ADR-008), local image only (`pull` disabled by default), `forge.*` labels, `user` non-root unless policy allows, `security_opt: no-new-privileges`, `mem_limit`/`cpus`/`pids_limit`, restart policy, healthcheck. Forbidden: `privileged`, `cap_add` (except policy list, default empty), `network_mode: host`, `pid|ipc: host`, `devices` (GPU only via `deploy.resources.reservations.devices` and only when the policy grants a VRAM budget), `docker.sock` or any mount whose **realpath** falls in the protected set or outside the node's `forge_roots`, ports bound to `0.0.0.0`, ports in the reserved list (§12 of the ADR doc + inventory §2), networks other than new `forge_*` networks with subnets inside `172.28.0.0/16` (inventory §5 item 3: never touch `daemon.json` address pools).
  4. `stack.up` = `docker compose -p forge-<stack> up -d` on the rendered file. `forge-<stack>` namespace prevents collision with KMU compose projects.
- **Directories on the second SSD:** `dir.ensure|du|trash|purge_trash`, `file.put|get ≤ 10 MiB`, all under `<ssd>/forge/` (OQ-1). Implementation requirement (named test): per-component walk with `O_NOFOLLOW|O_DIRECTORY`, `st_dev` must equal the allowed mount, no symlink or `..` escape. Delete = move to `.trash/<date>/`, purged after N days by a separate op with byte/count caps. **Free-space guard:** refuse any write when the filesystem would drop below `max(10 %, 200 GiB)` free, plus a per-node `max_bytes` for the forge subtree — because the SSD is shared with KMU model storage, a full disk is a KMU outage.
- **VMs:** libvirt pool `forge` (dir pool inside the forge root), domains named `forge-*` carrying forge metadata; `vm.start|shutdown` (graceful) | `vm.destroy` (needs reason, rate-limited) | `vm.define` from a lint-checked template (no hostdev, no host-path filesystem passthrough, disks only in the pool, NAT bridge only). **Disabled until libvirt exists** (not installed on g2; motivating use: F6.7 Windows test lane). Installing libvirt is a separate owner decision, not part of this design.
- T1 root helpers are reached by sudo (below), so the agent user never needs the `docker` group.

### 4.3 T2 — privileged allowlisted operations

| Op | What it does | Guards |
|---|---|---|
| `unit.start|stop|restart <unit>` | `systemctl` on **enumerated** units (`forge-edge.service`, `forge-nodehub` via compose op, `forge-docker-user.service`, …) | unit's `FragmentPath` must be `/etc/systemd/system/forge-*` or explicitly listed; pre-check "checkout = runtime" for units with a `checkout_path` (ADR-012 restart trap); `forge-postbote.service` has mode `graceful_flag` → writes the existing `post/state/restart-requested` flag instead of `systemctl restart` (M-43) |
| `scene.switch media|factory` (g2) | wraps the existing `kmu-s2-scene` (replaces the planned F7 sudoers drop-in) | refuses in window, refuses while an image job runs (script already does), VRAM proof `< 1 GiB` for `factory` |
| `apt.security_plan` / `apt.security_apply <plan_hash>` | simulated `apt-get -s` limited to the `-security` pocket; **excludes** `docker*`, `containerd*`, `nvidia*`, `libnvidia*`, `linux-*`, held packages, anything that triggers service restarts of protected units; apply only with a matching, ≤ 30 min old plan hash, inside the apt window; sets `NEEDRESTART_MODE=l`/`NEEDRESTART_SUSPEND=1`; **never reboots**; runs in a transient `systemd-run` unit (so the agent's network filter does not block mirrors) | `unattended-upgrades` is **enabled on g2** — either owner disables it (T3) so the window is authoritative, or the op only reports (OQ-12) |
| `docker.prune_plan` / `docker.prune_apply <plan_hash>` | removes only: untagged images **not** in the protection set and older than 7 d, build cache older than N d, stopped `forge.managed` containers older than N d | **Pin protection (M-97):** protection set = image *IDs* from every `images.lock` of the forge repos + IDs used by *any* container (any state) + IDs in `pins.d/*` + `forge-pinned/*` tags + images labelled `forge.pin=true`. Protection is by **ID**, not tag, because M-97 happened when a tag was overwritten and the pinned image became untagged. Never `--all`, never volumes, never networks. Default scope: g2 only |
| `image.pin <digest>` | adds to `pins.d` (risk-reducing direction ⇒ T2). `image.unpin` is T3 | |
| `policy.apply` | installs the next owner-signed policy (§7.3) | needs valid signature; no args beyond the staged file |
| `agent.restart` | restarts `forge-node-agent.service` | rate-limited |

Policy field per op: `requires: none | owner_signature`. Default `none` for forge-owned restarts; `owner_signature` for `apt.security_apply` on g1/g3 and for anything touching a unit outside `forge-*`. This is the lever that keeps a stolen hub credential from acting where it hurts most.

Asymmetry principle: ops that *reduce* risk or privilege (stop, pin, deny, quarantine) sit a tier lower than ops that *increase* it (start, unpin, widen).

### 4.4 Sudoers and scripts

- One fragment `/etc/sudoers.d/forge-node`, **generated** by `apply-policy` from the signed policy, `visudo -cf` before atomic `mv`, previous 5 versions kept. One line per op×target; **no `*` wildcards**, no shells, no editors, no `SETENV`, `Defaults:forgenode !requiretty, env_reset, secure_path` fixed. Illustration (not installed):
  `forgenode ALL=(root) NOPASSWD: /usr/local/libexec/forge-node/t2-unit restart forge-edge.service`
- Scripts are `root:root 0755` in a root-only directory, `env -i` + fixed `PATH`, `umask 077`, `set -eu`, argv only (never `eval`/shell interpolation), `flock` per op class, `timeout`, output byte-capped, each opens `priv.jsonl` and appends a record **before** acting (intent) and after (result). They re-read the installed policy and re-validate every parameter (defense in depth if sudoers is ever mis-generated).
- On g4 (Ubuntu 26.04) `sudo` may be **sudo-rs**; the generated fragment sticks to the lowest-common-denominator syntax (plain command lines) and is validated by the host's own checker; verified in round 0 (OQ-14).

### 4.5 Agent hardening (systemd)
`User=forgenode`, **no** `NoNewPrivileges` (needs sudo), but: `ProtectSystem=strict` with `ReadWritePaths=/var/lib/forge-node /var/log/forge-node`, `ProtectHome=yes`, `PrivateTmp=yes`, `ProtectKernelTunables/Modules/ControlGroups=yes`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `IPAddressDeny=any` + `IPAddressAllow=192.168.10.4/32 127.0.0.0/8` (**network egress limited to the hub**; the apt helper runs in its own transient unit), `SystemCallFilter=@system-service`, `MemoryMax=128M`, `CPUQuota=15%`, `Nice=19`, `IOWeight=10` (g4: `MemoryMax=96M`; its swap is 1.8/2.0 GiB full), `Restart=on-failure`, `RestartSec=10`.

### 4.6 T3 — everything else → owner approval

T3 is not "later"; it is the explicit fallback for anything not in policy. Two modes, both starting from a **proposal**:

1. Planner/graph calls `node_t3_propose(node, argv[], purpose, risk, rollback_argv[], preconditions, postconditions, expires_in)`. The hub stores a proposal with `command_text` (rendered exactly as it will run), `argv_sha256`, the dry-run/precheck results it could gather via T0, the rollback command, and writes an **inbox escalation** (`kind=node_action`, ≤ 400-token dossier) plus an `approvals_request(kind='node_t3', ref=<proposal_id>)` row (pending only; the planner cannot decide — R3 pattern) and a push notification.
2. **Mode A "owner executes":** Cockpit shows the copy-paste block + sha256 + rollback + postconditions. Owner runs it on the server. The hub then runs the postcondition T0 checks and records evidence; the proposal closes `done` or `postcondition_failed`.
3. **Mode B "approve once":** owner signs on the Mac: `ssh-keygen -Y sign -n forge-node-approval` over a canonical blob `{proposal_id, node, argv_sha256, not_after, nonce, frozen_ack?}`; uploads it to the Cockpit (or `scp` to the node). The node's `t3-run` (root, fixed) verifies the signature against `allowed_signers`, argv hash, node id, expiry (≤ 24 h), **single-use nonce** (ledger in `/var/lib/forge-node-priv`), runs with `timeout`, logs fully to `priv.jsonl`. A Cockpit *click* alone is **not** sufficient for Mode B: the browser session lives in the same trust zone as the planners; a signature made with a key that exists on no forge host is the only approval a node accepts.
4. Targets in the protected set require `frozen_ack:true` inside the *signed* blob; without it `t3-run` refuses even a validly signed command (guards against a casual approval touching KMU/Trading).
5. T3 is never available as a standing capability: no signed blob ⇒ no root command, ever.

### 4.7 Per-host defaults (initial policy)

| Host | Role in this design | Tiers enabled | Helper profile | Notes |
|---|---|---|---|---|
| carlgpu2 | hub + node | T0, T1, T2 (forge units, scene, apt-window, prune) | `full` | first rollout; ufw inactive; hub published on LAN IP only |
| carlgpu3 | node | T0; T1 dirs/containers only after pe_packer M022 ends | `full`, T1/T2 `dry_run_only` | busy (load ~2, swap used); pe_packer containers are **not** forge-labelled ⇒ invisible to T1 |
| carlgpu1 | node | T0 (+ optional `dir.*`) | `t0` | KMU core, GPU 29.8/32 GB busy, Postgres/Redis/nginx; no T2 |
| carlgpu4 | node | **T0 only** | `t0` (4 files) | Live-Trading; swap full; Ubuntu 26.04; installed **last**, only after the owner has seen g1–g3 behave |

---------------------------------------------------------------------------------------------------

## 5. Transport

### 5.1 Direction and addressing
- Agents dial `https://192.168.10.4:8094`. The hub listens **only** on the carlgpu2 LAN IP (container publish `192.168.10.4:8094`), never `0.0.0.0`; the local node on g2 uses the same address.
- Filter on g2: Docker publishes bypass ufw ⇒ rule in **`DOCKER-USER`** via the existing `forge-docker-user.sh` (extended in a forge-ops slice): allow TCP/8094 from `192.168.10.0/29` and `192.168.30.0/29` only, not from the VPN `10.200.0.0/29`, else DROP — deployed with the script's 5-minute rollback timer (`--confirm`).
- **Routing 192.168.10.x ↔ 192.168.30.x:** router-based (gateways .10.1/.30.1). Evidence of working 30→10: NFS from 10.3 mounted on g3/g4, Redis 6379 allowed from `192.168.30.0/24`. Return path for 10.4→30.x replies is stateful and needs no extra route. **Unproven:** a router/pfSense rule for 30.x→10.4:8094. Pre-flight (§13): hub listener up with a self-test endpoint, then from g3/g4 `openssl s_client -connect 192.168.10.4:8094 -brief </dev/null`. If it fails: owner adds one router rule (TCP 8094, src 192.168.30.0/29, dst 192.168.10.4); nothing else changes.
- **No inbound internet; no outbound internet for the agent** (systemd IP filter, §4.5). The hub has no internet requirement; ntfy/e-mail for push is the existing F5c channel, not forge-node's.
- MTU 1500 assumed; the JSON payloads are small. Clock: node refuses jobs if `|node − hub| > 60 s` (certificate validity and `expires_at` depend on time); NTP sync is part of `inv.host`.

### 5.2 mTLS details
- Private CA (EC P-256, 5 years) created **on the owner's Mac**; the CA key never touches a server. Separate from Caddy's internal CA.
- Node cert: EC P-256 keypair **generated on the node** (`forgenode` 0600), CSR signed by the owner; `CN=forge-node-<id>`, `SAN URI=urn:forge:node:<id>`, EKU `clientAuth`, **90 days**. Hub cert: SAN `IP:192.168.10.4`, EKU `serverAuth`, 1 year; key generated on carlgpu2 by the owner command in §13.
- Hub accepts a client only if (a) chain valid, (b) fingerprint is in `node.nodes` with `status='active'` (registered by the owner in the Cockpit after out-of-band fingerprint comparison), (c) not revoked. Agent pins the CA and checks the hub SAN.
- Revocation: hub deny-list (immediate) + 90-day expiry (bounded without CRL) + owner can quarantine from the node (`LOCAL_STOP`). Cert expiry of both sides is itself a T0 metric and an escalation at 14 days.
- Offline/hub-unreachable: agent keeps sampling light T0 into the spool, executes **no** T1/T2/T3-grant work (jobs only arrive via the hub anyway), and treats its STOP knowledge as stale after 90 s ⇒ fail-closed for anything mutating.

---------------------------------------------------------------------------------------------------

## 6. Identity and keys (owner-generated; never in repo, chat, brief, DB or LLM context)

| Key | Generated by / where | Lives | Purpose |
|---|---|---|---|
| Owner key (Ed25519, passphrase; **FIDO2 `ed25519-sk` recommended** if a hardware key exists) | owner, Mac, `ssh-keygen` | private: Mac only. Public: `allowed_signers` on every node and in the hub | signs policy (`-n forge-node-policy`), releases (`-n forge-node-release`), T3 approvals (`-n forge-node-approval`). Distinct namespaces ⇒ a policy signature can never be replayed as an approval |
| mTLS CA key (EC P-256) | owner, Mac, `openssl` | Mac only (offline) | signs node/hub certs |
| Node keys (EC P-256) | **on each node**, by the owner's command, as `forgenode` | `/etc/forge-node/pki/node.key` 0600 | never leaves the node; only CSR/cert move |
| Hub key | owner, on carlgpu2, `openssl` | `forge-core/secrets/nodehub/hub.key` (0640, hub uid) | server identity |
| Planner/MCP tokens | existing forge-mcp mechanism | unchanged | who may call `node_*` |

Moving material: only **public** artifacts travel (CSRs, certs, `allowed_signers`, signed policies, signed releases) via the owner's existing `scp`/`ssh` as `carl`. Fingerprints are compared out-of-band (read on Mac, typed/compared on the server). Rotation: node cert every 90 days (owner re-signs a fresh CSR; agent hot-reloads); CA at 4 years with overlap; owner key on suspicion: generate new, sign a new policy with serial+1 that replaces `allowed_signers`'s content **only via a T3 approval signed by the old key** (so key rotation can't be done by hub alone). Loss of the owner key = reinstall of `allowed_signers` at each node by the owner as root (physical/SSH access) — the system fails closed meanwhile (no new policy, no T3).

Compromise playbook (short): *planner/prompt-injection* → bounded by policy/windows/rate; owner `touch STOP`. *Hub compromised* → `touch /etc/forge-node/LOCAL_STOP` on nodes or hub deny-list; nodes still enforce policy; revoke hub cert (new CA-signed hub cert, agents re-pin). *Node agent compromised* → it holds a node key and can run only sudoers lines; `lockdown` removes them; the root `priv.jsonl` shows what ran. *Stolen node key* → hub revoke + new CSR.

---------------------------------------------------------------------------------------------------

## 7. Allowlists as signed config

### 7.1 What is signed
One canonical-JSON document per node (`policy-<id>.json`, keys sorted, UTF-8, no floats) and its detached `ssh-keygen -Y` signature. Fields:
`serial` (strictly monotonic), `not_before`, `node`, `profile`, `global_mode` (`observe|enforce`), `tiers_enabled`, `protected{paths,units,containers,networks,ports,users,gpu}` , `forge_roots[]`, `t0{units_for_logs[], cert_paths[], backup_units[], backup_dirs[], repos[]}`, `t1{label_selector, stack_roots, lint{…}, vram_budget_mib, vm_pool}`, `t2{ops[]{op, targets[], mode(dry_run_only|enforce), requires, rate, window}}`, `windows{blackout, apt}`, `redaction_version`, `circuit{fail_threshold}`.

### 7.2 Protected set evaluation
Evaluated **before** allowlists, on *resolved* objects (realpath of paths, `FragmentPath` of units, inspected container/network objects). A protected hit denies even if an allow rule matches. Changing the protected set requires a new owner-signed policy with `frozen_ack:true`; the hub has no endpoint that edits policy.

### 7.3 Applying a policy
Hub distributes → agent stages it (unprivileged) → `sudo apply-policy` (root, fixed, only the staged file) verifies: signature against `allowed_signers`, `node` matches, `serial > installed`, `not_before ≤ now`, schema valid → renders the sudoers fragment + per-script policy copy → `visudo -cf` → atomic install → writes the new serial to `/var/lib/forge-node-priv/serial` → audit. Any failure leaves the previous policy active. **Rollback is "sign the old content with serial+1"** (monotonic serial prevents replaying an old, wider policy).
Who signs: always the owner in v1. Delegation of low-risk additions (e.g. a new log unit for T0) to the Betriebsleiter via a limited signing certificate is deferred (OQ-8).

### 7.4 Illustrative policy fragment (data, not installed)
```json
{"serial":1,"node":"carlgpu2","profile":"full","global_mode":"observe","tiers_enabled":[0,1,2],
 "protected":{"paths":["/opt/kmu-ai","/srv/models","/srv/kmu-ai","/srv/tradebot","/etc/ssh","/etc/sudoers","/etc/sudoers.d","/etc/forge-node","/root"],
              "units":["kmu-*","tradebot-*","secmpro*","nexus*","ollama.service","ssh.service","docker.service","containerd.service","nginx.service","postgresql@*","redis-server.service"],
              "networks":["tb-gate0","tb-int0","172.31.250.0/24","172.31.251.0/24","172.31.252.0/24"],
              "ports":[22,80,443,5432,6379,8003,8004,8188,9102,9112,11434]},
 "forge_roots":["/srv/models/forge","/srv/forge/node"],
 "t0":{"units_for_logs":["forge-postbote.service","forge-edge.service","kmu-s2-backup.service"]},
 "t2":{"ops":[{"op":"unit.restart","targets":["forge-edge.service"],"mode":"dry_run_only","requires":"none"}]},
 "windows":{"blackout":"02:00-05:45","sunday_open":"06:00","apt":"Tue,Thu 20:00-22:00"}}
```

---------------------------------------------------------------------------------------------------

## 8. Audit log

**Three independent records, cross-checked by the hub:**

1. **Agent log** `/var/log/forge-node/audit.jsonl` — owned by `forgenode`, attribute `+a` (set by root at install; the agent holds no `CAP_LINUX_IMMUTABLE`, so it can append but never rewrite/truncate/delete; ext4 verified). Hash chain: `hash_n = sha256(hash_{n-1} ‖ canonical(record_n))`, monotonically increasing `seq`. Root timer `audit-rotate` (daily; `chattr -a` → rotate → `chattr +a`) retains 90 days on the node.
2. **Privileged log** `/var/log/forge-node/priv.jsonl` — written by the **root helpers themselves** (intent record before, result record after), `root:forgenode 0640`, `+a`. This is the authoritative statement of what ran as root and is not writable by the agent. The agent only *reads and ships* it.
3. **Hub table** `node.audit(node, source∈{agent,priv,hub}, seq, ts, prev_hash, hash, record jsonb)` — role `forge_nodehub` has INSERT (and SELECT) only; `UPDATE/DELETE/TRUNCATE` revoked and blocked by trigger; unique `(node, source, seq)`; partitioned monthly; retention ≥ 400 days. A verification query/job recomputes chains and **cross-checks**: every T1/T2 job in `node.jobs` must have matching `priv` intent+result with the same `job_id`, and every `priv` record must map to a job or to an owner T3 approval. Mismatch ⇒ node **quarantine** (jobs to that node blocked) + `node_alert` escalation.

Record fields: `ts` (UTC, plus Berlin offset), `node`, `seq`, `job_id`, `requester` (planner identity, `core.planner_calls.id`, `run_id`, project), `tier`, `op`, params (redacted), `policy_serial+sha256`, `decision` (+ `reason_code`), `dry_run`, `plan_hash`, start/end, exit, stdout/stderr sha256 + redacted excerpt ≤ 4 KiB, pre/post state digests (T1/T2), STOP state seen, cert fingerprint, agent version.
Fail-closed: if the agent cannot append locally, every non-T0 job is `DENY_AUDIT_DOWN`; if `priv.jsonl` cannot be appended, the helper refuses to act. If the hub is unreachable, records buffer on the node (bounded, ring 50 MiB; overflow ⇒ mutating ops denied, T0 sampling thinned). Redaction happens before write and again at the hub; raw output is never stored.

---------------------------------------------------------------------------------------------------

## 9. Safety controls

### 9.1 Kill switch (control/STOP)
- **Global:** the hub reads `/srv/forge/post/control/STOP` (same bind-mounted control **directory** as forge-mcp, existing semantics: file exists ⇒ active; `touch` activates; `rm` releases; unreadable ⇒ active). Before a job is handed out the hub takes the existing **`.dispatch.lock`** (flock) from the last STOP check until the job row is committed `issued` — the same exclusion as brief dispatch, so a Stop either precedes the check (job refused) or follows the committed job. Hub replies `stop:true` on every poll.
- **Node reaction:** on `stop:true` the agent denies all T1/T2/T3-grant work (`DENY_STOP`); in-flight jobs finish their current atomic step and do not start the next (`abort_on_stop` per op: `apt.apply` does not kill dpkg mid-way; `container.stop` completes). **T0 continues** — the Betriebsleiter needs eyes during an incident (rate-limited).
- **Per project:** jobs carry `project`; F5c's per-project Not-Aus applies the same way.
- **Local:** `touch /etc/forge-node/LOCAL_STOP` (owner on the server) blocks T1/T2/T3 regardless of the hub. `sudo /usr/local/libexec/forge-node/lockdown` additionally disables the sudoers fragment and stops the agent (§13 rollback).
- **Staleness:** no successful poll within 90 s ⇒ STOP assumed (fail-closed).
- **Who can release:** only the owner/Cockpit/`forge-release` — a node can never touch `control/` (no mount, no endpoint). Per M-92, nodes cannot influence the release path. Nodes can only set their own **quarantine** (integrity anomaly); global STOP is not automated from node signals (a compromised node must not be able to DoS the whole fabric).

### 9.2 Rate limits (authoritative at the node, mirrored at the hub)
Token buckets per op from policy, e.g.: T1 mutating ≤ 6/min, ≤ 60/h per node; `unit.restart` of the same unit ≤ 2 per 10 min and ≤ 6/day; `container.stop` ≤ 5/h/node; `vm.destroy` ≤ 1/h; `docker.prune_apply` ≤ 1/week; `apt.security_apply` ≤ 1/day; deletions ≤ 5 GiB/day/node; **one mutating job per node at a time**; T0 heavy ≤ 1/10 min, light ≤ 2/min. Per-identity quotas at the hub (project planner vs Betriebsleiter).
**Circuit breaker:** 3 consecutive `FAIL_*` of an op ⇒ op auto-`dry_run_only` and `node_alert` escalation; re-enable only by Betriebsleiter acknowledgement (not by the failing caller).

### 9.3 Dry-run and plans
Every mutating op implements `dry_run` through the single effect executor (no second code path). Dry-run returns `{plan, plan_hash, expires 30 min}`; apply must present the hash and the node recomputes the plan — mismatch ⇒ `DENY_STALE_PLAN`. Ops start in `mode: dry_run_only` after introduction; promotion to `enforce` is a policy change signed by the owner. `global_mode: observe` forces dry-run everywhere (used for the whole of rollout phase 1).

### 9.4 Idempotency with the Run-Graph
`job_id` = deterministic from `(graph thread, node, attempt-key)`; the hub returns the existing result for a repeated `job_id`, so at-least-once graph node execution (F5C2 §3.6 semantics) never executes an effect twice.

### 9.5 Windows
Berlin local time via `zoneinfo` (not fixed offsets; DST ended 2026-10-25). **Mutating ops (T1/T2/T3) are denied 02:00–05:45 daily and Sundays before 06:00** (KMU backup window; BETRIEBSHANDBUCH "Sperrzeiten"/ADR §9). Heavy T0 follows the same blackout; light T0 does not. `apt` has its own window (proposal: Tue/Thu 20:00–22:00, g2 only). No change while a pipeline job runs (checked per op via unit/queue state where known).

---------------------------------------------------------------------------------------------------

## 10. Protecting KMU frozen areas and Live-Trading (carlgpu4)

Defense in depth — each layer independent:

1. **Not installed.** carlgpu4 gets the `t0` profile: agent + 4 root files (`t0-probe`, `apply-policy`, `lockdown`, `audit-rotate`; `t0-journal` only if the owner allowlists logs). No docker group membership, no T1/T2/T3 helpers, `tiers_enabled:[0]` in a signed policy. g1 gets the same `t0` profile. Nothing to "misconfigure into" T2.
2. **Deny by default.** No op takes a free-form path, unit, container, image, command or port; each target must match an allowlist entry. There is no "exec", no "shell", no generic `systemctl`.
3. **Protected set first** (§7.2): `/opt/kmu-ai/**`, `/srv/kmu-ai/**`, `/srv/models/**` (except the single forge subtree), `/srv/tradebot/**`, `kmu-*`, `tradebot-*`, `secmpro*`, `nexus*`, `ollama`, DBs, nginx, NFS, sshd, docker/containerd, networks `tb-gate0`/`tb-int0` and `172.31.250–252.0/24`, Docker daemon config, users `carl|kmuai|tbpost`, secrets directories. On resolved objects (realpath, FragmentPath, container inspect), so a symlink or rename cannot dodge a name match.
4. **Frozen = metadata only for T0.** For protected paths T0 may report `stat`, `df`, git rev + tracked-dirty count (no index writes), unit state — never file contents, never `exec` inside, never `docker exec`/`cp`. Container `Env`/`Cmd` are never collected.
5. **No GPU actions on g1/g3/g4** by T1/T2 (VRAM budgets are 0 there; free VRAM 2.7 GB on g1, ~9 GB on g3, trading host untouched). GPU allocation on g2 only within `vram_budget_mib`. F9-S4's precondition "Live-Trading needs no GPU" becomes a pure T0 evidence item.
6. **Owner-only, double-keyed.** Any action on a protected object needs a T3 approval with `frozen_ack:true` inside the signed blob. The hub/Betriebsleiter can *prepare* the command but cannot satisfy it.
7. **No daemon-wide side effects.** The node never restarts `docker`/`containerd`, never edits `daemon.json`, never touches `iptables` outside the owner-run `forge-docker-user.sh`, never changes sshd/sudoers except through the signed `apply-policy` (its own fragment only). The apt op excludes docker/nvidia/kernel packages and sets needrestart to list-only; unattended-upgrade interplay is OQ-12.
8. **Footprint guard on g4.** Agent limited to ≤ 96 MiB RSS and 15 % CPU of one core at `Nice=19`; install only after `free -m` shows headroom (swap is nearly full) — otherwise the owner defers g4.
9. **Alarms instead of actions:** anomalies on protected hosts (new listener, failed unit, backup age, swap, cert expiry, dirty/rev change on `/opt/kmu-ai`) produce T0 findings and inbox alerts, never repair actions.

---------------------------------------------------------------------------------------------------

## 11. Integration with planner, graph, inbox

**MCP tools (forge-mcp, same bearer/identity + `core.planner_calls` audit as the existing Planer-Tools; audit before tool lookup, fail-closed per R6):**

| Tool | Tier | Notes |
|---|---|---|
| `node_list` | T0 | nodes, profile, tiers enabled, last heartbeat, policy serial, quarantine, STOP seen |
| `node_inventory(node, sections[], max_age_s)` | T0 | cached snapshot or fresh pull; result carries `collected_at`, `stale`, `cite` ("Stand laut node_inventory … vom <Datum>") like `state_get` |
| `node_metrics(node, window)` · `node_logs(node, unit, since, lines)` | T0 | logs `untrusted`, `sensitivity` labelled |
| `node_t1(node, op, params, dry_run=true)` | T1 | default dry-run; apply needs `plan_hash` for ops that produce one |
| `node_t2(node, op, params, plan_hash?)` | T2 | allowed only for Betriebsleiter identity (and graph `RUN` nodes acting for it) |
| `node_plan_get(plan_id)` · `node_job_get(job_id)` | T0 | |
| `node_t3_propose(…)` | T3 | creates proposal + inbox escalation + pending approval (§4.6) |

**Authorization matrix:** executors (Claude Code/Codex in lanes) get **no** `node_*` tools (they keep forge-mem/forge-tools). Project planners: T0 (their project's containers/dirs, own stack logs), `node_t1` on their own `forge.project`. Betriebsleiter (meta identity): all T0, T1, T2 (subject to policy `requires`), T3 propose. Graph `RUN` nodes (F5c part 2, LLM-free) call the same API with an idempotency key; they never bypass the hub.

**State view:** `state_get` keeps its contract (units/containers allowlist, `stale`) but its data source moves from the host collector snapshot to hub-held T0 data for carlgpu2 (and later all nodes); the owner-installed `forge-state-snapshot` timer can then be retired (additive migration, no flag day).

**Escalations (existing inbox `core.escalations`, ≤ 1400 chars ≈ 400 tokens; migration extends `kind` CHECK with `node_action` and `node_alert`):** (1) T3 proposal; (2) anomalies: cert < 14 d, backup age > 36 h, disk > 85 % or FS free < guard, unexpected GPU occupant, swap ≥ 90 % on g4, failed units on allowlist, hash-chain/priv cross-check mismatch, heartbeat lost > 5 min; (3) failed/aborted T1/T2 job or open circuit. Dossier template: host · what · why now · exact command hash · risk · rollback · expiry · evidence links. Push (ntfy/e-mail, F5c) for T3 and critical alerts. Daily 08:30 Lagebericht (F5d) consumes the latest snapshots.

**Safety-filter note (M-95 / F5f2):** node docs/briefs are phrased as verification and operations; no adversarial wording is needed anywhere in this design.

---------------------------------------------------------------------------------------------------

## 12. Threat model (condensed)

| Threat | Mitigation | Residual |
|---|---|---|
| Prompt injection via log/inventory text makes a planner ask for harm | outputs are data in an `untrusted` envelope, charset-filtered; op set has no free-form execution; policy + protected set + windows + rate limits | planner can still request *allowed* ops repeatedly → rate limits/circuit |
| Planner asks to stop a critical service (postgres, edge) | `forge.critical`, enumerated units only, `requires: owner_signature` | owner approval needed |
| Hub compromised / hub key stolen | node-local signed policy, node-local windows/rate/STOP file, root `priv.jsonl` independent of hub, `owner_signature` on high-impact ops | on **g2** the executor `forge` (docker group = root-equivalent, ADR-008) can read hub material and bypass the *hub*; tiers there bound the API path, not that account. Long-term: drop `docker` from `forge` (OQ-10) |
| Sudoers wildcard/argument injection | generated, wildcard-free fragment, scripts re-validate, argv only | script bugs → tests §16, review by second model family (G6) |
| Docker-compose as root escalation | resolved-model lint, key allowlist, no `docker` group for the agent, rendered file applied | lint completeness → named tests, owner-signed lint policy |
| Symlink/TOCTOU in dir ops | `O_NOFOLLOW` walk, `st_dev` check, act on IDs | kernel-level races mitigated by dir fds |
| Policy rollback / downgrade | monotonic serial in root-only store | owner key loss fails closed |
| Audit tampering | `+a`, chain, root-written priv log, hub INSERT-only, cross-check | root on the node can still destroy local logs; hub copy survives |
| Clock manipulation | skew vs hub; NTP metric | |
| Cert theft | 90-day certs, fingerprint registry, deny-list | |
| Disk-full on shared SSD | free-space guard, `max_bytes` | other tenants of the FS (KMU) |
| Node causes load on g4 | cgroup limits, last rollout, T0 only | swap-bound host: owner may defer |
| Unattended-upgrades vs controlled window | surfaced in `inv.pkgs`; decision OQ-12 | |

---------------------------------------------------------------------------------------------------

## 13. Install procedure (exact owner commands)

> **Validity:** these commands become executable once implementation slices N1–N3 deliver the signed release `forge-node-<VER>.tar` (+ `.sig`) and the policy templates. Until then they are the specification of the owner's steps. Keep one SSH session open per server for the whole block (rollback anchor). **Never run during 02:00–05:45 Berlin or before 06:00 on a Sunday.** Order: **carlgpu2 → carlgpu3 → carlgpu1 → carlgpu4** with ≥ 1 day of observation between servers. SSH as the owner's existing `carl` account with the existing key; no sshd change anywhere.

### 13.A Once, on the Mac (private keys stay here)

```bash
umask 077
mkdir -p ~/forge-node-owner/{ca,issued,release,policy} && cd ~/forge-node-owner

# A1 owner signing key (set a passphrase). With a FIDO2 key use: -t ed25519-sk
ssh-keygen -t ed25519 -a 100 -C "forge-node-owner" -f owner_ed25519
printf 'owner@forge namespaces="forge-node-policy,forge-node-approval,forge-node-release" %s\n' \
  "$(cut -d' ' -f1,2 owner_ed25519.pub)" > allowed_signers
ssh-keygen -lf owner_ed25519.pub            # note this fingerprint; compare on every server

# A2 mTLS CA (EC P-256, 5 years); the key never leaves this Mac
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

### 13.B Hub on carlgpu2 (once; after slice N1 has delivered the `forge-nodehub` compose service)

```bash
# on the Mac: build the hub server cert request after generating the key on carlgpu2
ssh -t -i ~/.ssh/sshcarljump01 carl@192.168.10.4
# --- on carlgpu2 ---
sudo install -d -m 0750 -o forge -g forgebox /srv/forge/work/forge-core/secrets/nodehub
sudo -u forge sh -c 'umask 077; openssl ecparam -name prime256v1 -genkey -noout -out /srv/forge/work/forge-core/secrets/nodehub/hub.key'
sudo -u forge openssl req -new -key /srv/forge/work/forge-core/secrets/nodehub/hub.key \
  -subj "/CN=forge-nodehub" -out /srv/forge/work/forge-core/secrets/nodehub/hub.csr
exit
# --- on the Mac ---
scp -i ~/.ssh/sshcarljump01 carl@192.168.10.4:/srv/forge/work/forge-core/secrets/nodehub/hub.csr ~/forge-node-owner/issued/
cd ~/forge-node-owner
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:192.168.10.4,DNS:forge-nodehub.lan\n' > issued/ext_hub.cnf
openssl x509 -req -in issued/hub.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial -days 365 -sha256 \
  -extfile issued/ext_hub.cnf -out issued/hub.crt
scp -i ~/.ssh/sshcarljump01 issued/hub.crt ca/ca.crt carl@192.168.10.4:/tmp/
ssh -t -i ~/.ssh/sshcarljump01 carl@192.168.10.4 \
  'sudo install -m 0644 -o forge -g forgebox /tmp/hub.crt /tmp/ca.crt /srv/forge/work/forge-core/secrets/nodehub/ && rm /tmp/hub.crt /tmp/ca.crt'
```
Then the hub is started by the normal forge GO flow (build + digest re-pin + migrate, no owner step), and the firewall rule is applied by the owner **with the existing timer protocol** (after the forge-ops slice has added TCP 8094 from the two rack /29s):
```bash
sudo /srv/forge/work/forge-ops/bin/forge-docker-user.sh --dry-run      # review the 8094 lines
sudo /srv/forge/work/forge-ops/bin/forge-docker-user.sh                # applies, 5-minute rollback timer
sudo /srv/forge/work/forge-ops/bin/forge-docker-user.sh --confirm      # within 5 minutes, after the checks below
```

### 13.C Per server (common body; variables per server in 13.D)

On the Mac:
```bash
cd ~/forge-node-owner
export NID=g2 IP=192.168.10.4 VER=<VER> PROFILE=full     # set per 13.D
scp -i ~/.ssh/sshcarljump01 release/forge-node-$VER.tar release/forge-node-$VER.tar.sig allowed_signers carl@$IP:/tmp/
ssh -t -i ~/.ssh/sshcarljump01 carl@$IP
```
On the server (keep the session open):
```bash
# C1 preflight (read-only) — stop and tell the Betriebsleiter if anything is off
date; TZ=Europe/Berlin date +%H:%M; timedatectl | grep -E 'Time zone|synchronized'
free -m | sed -n 1,3p; df -h / /srv/models /srv/kmu-ai 2>/dev/null
ss -tlnH | grep -c ':8094 ' || true            # must be 0 on g1/g3/g4; on g2 only after the hub is up
sudo --version | head -1; python3 --version; id forgenode 2>&1 | head -1   # 'no such user' expected

# C2 verify the release (fingerprint must match the one noted on the Mac)
awk '{print $3,$4}' /tmp/allowed_signers | ssh-keygen -lf -          # fingerprint of the owner key; compare with the Mac
ssh-keygen -Y verify -f /tmp/allowed_signers -I owner@forge -n forge-node-release \
  -s /tmp/forge-node-$VER.tar.sig < /tmp/forge-node-$VER.tar            # expect: Good "forge-node-release" signature

# C3 user, directories, append-only audit files
sudo useradd --system --user-group --home-dir /var/lib/forge-node --create-home --shell /usr/sbin/nologin forgenode
sudo install -d -m 0750 -o root      -g forgenode /etc/forge-node /etc/forge-node/policy
sudo install -d -m 0700 -o forgenode -g forgenode /etc/forge-node/pki
sudo install -d -m 0755 -o root -g root /opt/forge-node /opt/forge-node/releases /usr/local/libexec/forge-node
sudo install -d -m 0700 -o root -g root /var/lib/forge-node-priv
sudo install -d -m 0750 -o forgenode -g forgenode /var/log/forge-node
sudo install -m 0644 -o root -g root /tmp/allowed_signers /etc/forge-node/allowed_signers
sudo touch /var/log/forge-node/audit.jsonl /var/log/forge-node/priv.jsonl
sudo chown forgenode:forgenode /var/log/forge-node/audit.jsonl
sudo chown root:forgenode /var/log/forge-node/priv.jsonl && sudo chmod 0640 /var/log/forge-node/priv.jsonl
sudo chattr +a /var/log/forge-node/audit.jsonl /var/log/forge-node/priv.jsonl

# C4 release files (root-owned; only the helpers of this profile are copied)
sudo tar -xf /tmp/forge-node-$VER.tar -C /opt/forge-node/releases --no-same-owner
sudo ln -sfn /opt/forge-node/releases/forge-node-$VER /opt/forge-node/current
sudo sh -c 'for f in $(cat /opt/forge-node/current/profiles/'"$PROFILE"'.list); do install -m 0755 -o root -g root /opt/forge-node/current/libexec/$f /usr/local/libexec/forge-node/$f; done'
ls -l /usr/local/libexec/forge-node/

# C5 node key + CSR (generated here, as forgenode)
sudo -u forgenode sh -c 'umask 077; openssl ecparam -name prime256v1 -genkey -noout -out /etc/forge-node/pki/node.key'
sudo -u forgenode sh -c 'umask 022; openssl req -new -key /etc/forge-node/pki/node.key -subj "/CN=forge-node-'"$NID"'" -out /var/lib/forge-node/'"$NID"'.csr'
exit
```
On the Mac (sign, compare, send back):
```bash
scp -i ~/.ssh/sshcarljump01 carl@$IP:/var/lib/forge-node/$NID.csr issued/
printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=URI:urn:forge:node:$NID\n" > issued/ext_$NID.cnf
openssl x509 -req -in issued/$NID.csr -CA ca/ca.crt -CAkey ca/ca.key -CAcreateserial -days 90 -sha256 -extfile issued/ext_$NID.cnf -out issued/$NID.crt
openssl x509 -in issued/$NID.crt -noout -fingerprint -sha256 -subject -enddate        # note the fingerprint

# policy: start from the template in the release, edit nothing for first install, sign it
tar -xOf release/forge-node-$VER.tar forge-node-$VER/policy/policy-$NID.json > policy/policy-$NID.json
ssh-keygen -Y sign -f owner_ed25519 -n forge-node-policy policy/policy-$NID.json      # writes policy-$NID.json.sig
scp -i ~/.ssh/sshcarljump01 issued/$NID.crt ca/ca.crt policy/policy-$NID.json policy/policy-$NID.json.sig carl@$IP:/tmp/
ssh -t -i ~/.ssh/sshcarljump01 carl@$IP
```
On the server again:
```bash
# C6 certs and policy
sudo install -m 0644 -o forgenode -g forgenode /tmp/$NID.crt /etc/forge-node/pki/node.crt
sudo install -m 0644 -o forgenode -g forgenode /tmp/ca.crt   /etc/forge-node/pki/ca.crt
sudo /usr/local/libexec/forge-node/apply-policy /tmp/policy-$NID.json /tmp/policy-$NID.json.sig   # verifies, renders sudoers, visudo -cf
sudo visudo -cf /etc/sudoers.d/forge-node                                                          # must say: parsed OK

# C7 unit and start
sudo install -m 0644 /opt/forge-node/current/systemd/forge-node-agent.service /etc/systemd/system/
sudo install -m 0644 /opt/forge-node/current/systemd/forge-node-audit-rotate.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo -u forgenode /opt/forge-node/current/forge-node.pyz doctor      # clock, certs, hub reachability, policy signature, sudo -l; expect OK (hub shows 'unregistered')
sudo systemctl enable --now forge-node-agent.service forge-node-audit-rotate.timer
sudo systemctl status forge-node-agent.service --no-pager | head -8
rm -f /tmp/forge-node-$VER.tar* /tmp/allowed_signers /tmp/$NID.crt /tmp/ca.crt /tmp/policy-$NID.json*
exit
```
Register the node: open Cockpit **/nodes**, compare the shown certificate SHA-256 with the value noted on the Mac, click **Approve**. First policy is `global_mode: observe` — nothing mutates; round 0 (§14) starts.

### 13.D Per-server values and deltas

| | carlgpu2 | carlgpu3 | carlgpu1 | carlgpu4 |
|---|---|---|---|---|
| `NID / IP` | `g2` / `192.168.10.4` | `g3` / `192.168.30.3` | `g1` / `192.168.10.3` | `g4` / `192.168.30.4` |
| `PROFILE` | `full` | `full` | `t0` | `t0` |
| Tiers (first policy) | 0,1,2 — all `observe` | 0 (+1,2 `dry_run_only`) | 0 | 0 |
| Extra pre-checks | hub up (`curl -sk --cacert ca.crt https://192.168.10.4:8094/healthz`); DOCKER-USER rule confirmed; **do not restart docker** | check M022 job state with the pe_packer owner; `free -m` | no ufw change needed (outbound only); do not touch n8n/Redis rules | `free -m` shows ≥ 300 MiB available **and** owner agrees; check `sudo --version` (sudo-rs?); `sshd` untouched; trading hours considered |
| Connectivity test before step C6 | loopback/LAN | `openssl s_client -connect 192.168.10.4:8094 -brief </dev/null` must succeed; else owner adds router rule TCP/8094 from `192.168.30.0/29` | same as g2 (same /29) | same as g3 |
| Wait before next | 1 day | 1 day | 1 day | — |

### 13.E Rollback and uninstall

**Levels (each independent, each reversible):**
1. **Pause everywhere:** `/srv/forge/work/forge-ops/bin/forge-stop "forge-node pause"` (release: `forge-release`). T0 still works.
2. **Pause one node:** `sudo touch /etc/forge-node/LOCAL_STOP` (resume: `sudo rm`).
3. **Lockdown one node (no T1/T2/T3 at all):** `sudo /usr/local/libexec/forge-node/lockdown` — removes `/etc/sudoers.d/forge-node`, runs `visudo -c`, stops the agent. Manual equivalent if the script is unavailable: `sudo rm /etc/sudoers.d/forge-node && sudo visudo -c && sudo systemctl disable --now forge-node-agent.service`.
4. **Revoke:** Cockpit /nodes → Revoke (hub deny-list); on the Mac nothing else is needed (cert expires within 90 days).
5. **Uninstall a node completely:**
```bash
sudo systemctl disable --now forge-node-agent.service forge-node-audit-rotate.timer
sudo rm -f /etc/sudoers.d/forge-node && sudo visudo -c
sudo rm -f /etc/systemd/system/forge-node-agent.service /etc/systemd/system/forge-node-audit-rotate.{service,timer} && sudo systemctl daemon-reload
sudo chattr -a /var/log/forge-node/audit.jsonl /var/log/forge-node/priv.jsonl
sudo tar -czf /root/forge-node-audit-$(hostname)-$(date +%Y%m%d).tgz -C /var/log forge-node   # keep the evidence
sudo rm -rf /usr/local/libexec/forge-node /opt/forge-node /etc/forge-node /var/lib/forge-node /var/lib/forge-node-priv /var/log/forge-node
sudo userdel forgenode
docker ps -a --filter label=forge.managed=true --format '{{.Names}}'   # forge-owned containers are NOT removed automatically; list and decide
```
Forge dirs on the second SSD are kept unless the owner removes them. **Proof that nothing KMU/Trading changed:** run before the install and again after the uninstall and compare the outputs: `systemctl list-units 'kmu-*' 'tradebot-*' 'secmpro*' --all --no-legend | awk '{print $1,$3,$4}' | sha256sum`; `docker ps -a --format '{{.Names}} {{.Image}}' | sort | sha256sum` (names and images only — uptime strings change); `git -C /opt/kmu-ai rev-parse HEAD`; `stat -c %Y /opt/kmu-ai /srv/models`. T0 `inv.*` stores the same evidence automatically.
6. **Release upgrade/rollback:** new release is unpacked next to the old one; `sudo ln -sfn /opt/forge-node/releases/forge-node-<old> /opt/forge-node/current && sudo systemctl restart forge-node-agent.service`. Policy rollback = sign old content with a higher serial (§7.3).
7. **Broken sudoers safety:** the fragment is installed only after `visudo -cf`; the open root-capable SSH session during install is the anchor if a mistake is found afterwards.

---------------------------------------------------------------------------------------------------

## 14. First use case — read-only Revision (Inventur v2) and F7a measurement on all four servers

**Note on ADR-024:** the ADR document in forge-docs (export of 30.10.) ends at ADR-021; "ADR-024" is not present there (the ADR-024 hits in the repos tree belong to SecMPro and are unrelated). This section defines the round by its stated purpose — a read-only Revision/inventory round — and must be reconciled with ADR-024's text once the ADR is exported (OQ-2).

### 14.1 Round 0 — Revision / Inventur v2 (T0 only, `observe`)
- **Scope:** `inv.host`, `inv.disks` (incl. second SSD, RAID/mounts), `inv.gpu`, `inv.net`, `inv.units`, `inv.containers`, `inv.vms`, `inv.pkgs`, `inv.certs`, `inv.backups`, `inv.git`, `inv.access` on g1–g4, in install order as each node joins. No T1/T2/T3. The only privileged code that runs is the fixed read-only `t0-probe` (g4: the same file; no docker group).
- **Baseline diff against the 28.10. dump:** Docker/Compose versions (29.8.0/v5.5.1 g1, 29.8.2/v5.6.0 g2, 29.8.2/v5.5.1 g3, 29.2.1/v5.0.2 g4), apt holds (25/18/18/16), failed units (`kmu-sicherung-modelle` g1, `kmu-sicherung-system` g2/g3, `grub2-common` g4; KMU backup state per KMU_INFRA_KORRELATION v2), listeners (Redis 192.168.10.3:6379, n8n 5678, ollama `*:11434`, `0.0.0.0:2222`), ufw state, GPU occupancy (g1 29.8 GB, g3 23.6 GB, g2 ~1 GB→now factory, g4 0.5 GB), swap (g4 1.8/2.0 GiB), `/opt/kmu-ai` rev/dirty (ba6cca9 dirty 1/3, g3 8298ac1 detached), cert expiry (nginx/certbot on g1, Caddy on g2), backup age (KMU Sicherung 31.10. 03:21, snapshot 612f13f0; forge 21:30), `jq`/tooling gaps (inventory §5 item 10), unattended-upgrades state per host, docker-GID, NTP.
- **Output:** one `inventory_run` row set in `node.snapshots`, a generated diff report (stored as a forge report, indexed in the memory), and inbox findings only where a threshold is crossed. The Revision report is written **by the Betriebsleiter from the stored data**, not by a script that formats prose.
- **Acceptance (all required):** (1) all four nodes `active`, certs and policy serial as signed; (2) audit chain verifies on node and hub, `priv.jsonl` has **zero** records on g4/g1 apart from `t0-probe` intent/result pairs; (3) STOP test: `forge-stop` ⇒ within ≤ 100 s every node reports `stop` and a test T1 dry-run is `DENY_STOP`, T0 still answers; `forge-release` ⇒ resumes; (4) before/after hash comparison of KMU/Trading evidence (§13.E) shows no change; (5) agent footprint within limits on every host (RSS, CPU) over 24 h; (6) no new listener on g1/g3/g4 (`ss` diff); (7) redaction test: injected canary strings in a test unit's log never appear in hub DB; (8) one deliberate anomaly (e.g. test cert with 10 days left) raises exactly one inbox escalation.

### 14.2 F7a — measurement (ROADMAP: "Festlegung erst nach Messrunde")
**M1 passive (part of this use case, T0 only):** `metrics.sample` every 30 s for **72 h** per host covering at least one weekday, one pipeline run if any occurs, the 21:30 forge backup and the 03:00 KMU backup (read-only observation inside the window is permitted: sampling is light T0): GPU util/VRAM/temp/power/clock/throttle reasons per card and **per compute process**, CPU/RAM/swap/load, disk I/O and queue depth per device (second SSD vs system disk), PCIe link state, NVMe wear/temperature only where sysfs exposes it (no `smartctl` installed ⇒ reported `unavailable`). Output answers: real free VRAM windows per card (g1 2.7 GB, g3 ~9 GB, g2/g4 idle windows), whether the F7a draft split (g1 router+embeddings+reranker, g2 coder, g3 critic+judge, g4 large MoE/reserve) fits, and I/O contention on the shared model SSDs.
**M2 active (separate, only on carlgpu2 and only with owner go):** a T1 job writes a 20 GiB test file into the forge dir on the second SSD and measures sequential read (model-load proxy) at `ionice -c3`, and — once vLLM exists (F7) — loads a candidate model on the idle GPU in the Factory scene. Preconditions: Factory scene, no pipeline job, outside the window, free-space guard satisfied. **Not run** on g1/g3 (VRAM and SSD are KMU-owned, pipeline always busy) nor on g4 (Live-Trading; ADR-020: only by owner decision).
**Deliverable:** a measurement report in the F7a format, ready for the Betriebsleiter's GPU-plan decision (ADR-020), with raw series stored in `node.snapshots` and referenced by hash.

---------------------------------------------------------------------------------------------------

## 15. Rollout phases and slices

| Phase | Content | Exit criterion |
|---|---|---|
| P0 | This design; Betriebsleiter/Owner decisions on OQ-1…OQ-6 | approved or revised |
| P1 | g2 only, `observe`, T0 | round-0 acceptance on g2 |
| P2 | g3, g1 (T0), then g4 (T0) | round-0 acceptance on all four, 72 h M1 done |
| P3 | T1/T2 `dry_run_only` on g2, then `enforce` per op by signed promotion | dry-run plans reviewed over ≥ 1 week without surprises |
| P4 | T3 flow live (propose → inbox → owner sign) | first real T3 completed with evidence |
| P5 | VM ops (only if libvirt is introduced), g3 T1 after M022 | — |

Slices (each ends with an independent cross-model review, G6; sizes are rough):
**N1** protocol, hub skeleton, `node` schema + INSERT-only audit, STOP integration, DOCKER-USER rule (forge-ops) — 2 d · **N2** agent T0, `t0-probe`/`t0-journal`, redaction, spool — 3 d · **N3** policy format, signing/verification, `apply-policy`, sudoers generator, lockdown, release signing — 2 d · **N4** install on g2 + round 0 + M1 — 1 d + observation · **N5** T1 (labels, dir ops, stack lint/apply) — 4 d · **N6** T2 (units, scene, apt plan/apply, prune with pin protection) — 3 d · **N7** T3 + MCP tools + inbox kinds + approvals — 2 d · **N8** rollout g3/g1/g4 · **N9** VM ops (conditional).
Tripwire (§2): after N4 + 3 months without a T1/T2 request, stop at T0.

---------------------------------------------------------------------------------------------------

## 16. Named acceptance tests (to be written with the slices)

- Policy/signing: `test_policy_bad_signature_rejected`, `test_policy_serial_rollback_rejected`, `test_policy_wrong_node_rejected`, `test_policy_namespace_cross_use_rejected` (policy sig as T3 approval), `test_apply_policy_atomic_on_visudo_failure`, `test_sudoers_has_no_wildcards`.
- Pipeline: `test_denial_order_stop_before_policy`, `test_every_denial_is_audited`, `test_audit_down_denies_mutating`, `test_clock_skew_denies`, `test_stale_hub_denies_after_90s`.
- Protected set: `test_protected_realpath_symlink_escape_denied`, `test_protected_unit_fragmentpath_denied`, `test_kmu_path_metadata_only`, `test_g4_profile_has_no_t1_t2_helpers`, `test_frozen_requires_frozen_ack_in_signature`.
- T1: `test_container_label_required`, `test_container_critical_excluded`, `test_stack_unknown_key_rejected`, `test_stack_privileged_hostnet_sock_rejected`, `test_stack_mount_realpath_in_protected_rejected`, `test_stack_floating_tag_rejected`, `test_stack_applies_rendered_model_not_yaml`, `test_dir_nofollow_stdev_guard`, `test_dir_free_space_guard`, `test_dir_trash_not_delete`.
- T2: `test_unit_restart_enumerated_only`, `test_unit_checkout_equals_runtime_precheck`, `test_postbote_graceful_flag_not_restart`, `test_apt_plan_hash_mismatch_denied`, `test_apt_excludes_docker_nvidia_kernel_holds`, `test_apt_never_reboots`, `test_prune_protects_pinned_ids_after_tag_overwrite` (M-97), `test_prune_never_volumes`.
- STOP/limits: `test_stop_blocks_issue_under_dispatch_lock`, `test_stop_release_not_possible_from_node`, `test_local_stop_blocks_without_hub`, `test_rate_bucket_and_cooldown`, `test_circuit_opens_after_3_fail`, `test_blackout_window_berlin_dst`, `test_sunday_before_06`.
- Audit: `test_chain_detects_edit`, `test_agent_cannot_truncate_audit_plus_a`, `test_priv_job_crosscheck_mismatch_quarantines`, `test_hub_audit_update_delete_blocked`, `test_redaction_canaries_never_stored`.
- Integration: `test_idempotent_job_id_returns_existing`, `test_t3_nonce_single_use`, `test_t3_requires_signature_not_click`, `test_executor_has_no_node_tools`, `test_state_get_contract_unchanged`, `test_untrusted_envelope_and_customer_label`.

---------------------------------------------------------------------------------------------------

## 17. Open questions

| # | Question | Default if undecided |
|---|---|---|
| OQ-1 | **Second SSD:** on every server it is KMU model storage (`/srv/kmu-ai` g1, `/srv/models` g2/g3/g4, same filesystem as KMU data). Accept a single owner-created subtree (`/srv/models/forge/`, free-space guard + `max_bytes`), or choose another disk/partition? | g2 only, `/srv/models/forge`, 200 GiB cap; none on g1/g3/g4 |
| OQ-2 | ADR-024 is not in the exported ADR doc (ends at ADR-021). Confirm its text/number; this design should become its own ADR (proposed title "forge-node: tiered, audited node authority"). | design stands; round 0 defined by purpose |
| OQ-3 | carlgpu4: agent at all (swap 1.8/2.0 GiB full, Live-Trading)? | install last, T0 only, owner may defer |
| OQ-4 | Router: does 192.168.30.0/29 → 192.168.10.4:8094 pass? Owner adds a rule if not. Is port 8094 acceptable? | test in pre-flight |
| OQ-5 | FIDO2 hardware key available for the owner signing key? | passphrase-protected Ed25519 |
| OQ-6 | Cert lifetime 90 days with manual re-sign OK, or longer? | 90 days |
| OQ-7 | Which `kmu-*`/other unit logs may T0 read (customer-data risk)? | none |
| OQ-8 | Delegate low-risk policy additions (T0 log units) to the Betriebsleiter via a limited signing certificate? | no, owner signs everything |
| OQ-9 | T3 Mode B approval strictly by signature (recommended) or also by Cockpit click for low-risk ops on g2? | signature only |
| OQ-10 | Remove `docker` from user `forge` on carlgpu2 once T1 is mature (closes the main residual risk)? | later, own decision |
| OQ-11 | libvirt: will it be installed (F6.7 Windows lane)? | VM ops stay disabled |
| OQ-12 | `unattended-upgrades` is enabled on carlgpu2 (state elsewhere unknown): disable it so the apt window is authoritative (owner/T3), or keep it and let `apt.*` only report? | report only |
| OQ-13 | Verify in round 0: `git --no-optional-locks` + `safe.directory` for `/opt/kmu-ai` (owned by `kmuai`) without index writes. | `inv.git` limited to `rev-parse HEAD` if not clean |
| OQ-14 | Verify in round 0: is `sudo` on g4 (Ubuntu 26.04) `sudo-rs`; fragment compatibility. | plain-line fragment only |
| OQ-15 | apt window (Tue/Thu 20:00–22:00 proposed) and whether g1/g3 ever get security updates through forge-node (KMU holds: drivers, docker). | g2 only |
| OQ-16 | NTP/chrony state on g1/g3/g4 is not inventoried; required for the 60 s skew rule. | verify in pre-flight |
| OQ-17 | The existing leftover test containers on g2 (`f5c-review2-*-pg`, `f5brecheck-*-pg`) — remove/label now (they are invisible to T1 otherwise). | owner/T3 |

---------------------------------------------------------------------------------------------------

## 18. Report (M-94: full report also here)

> The head of this repository cannot be written into the file it describes (a commit hash depends on the file content). The authoritative `Head: <sha>` is the first line of the chat report and `git -C /srv/forge/work/forge-node rev-parse HEAD`.

**Summary**
- New repo `/srv/forge/work/forge-node`, one file `docs/design/FORGE_NODE.md`; design only — nothing installed, no code, no sudo, no change on any server. All checks were read-only (docs, listeners, filesystems, container labels on carlgpu2). Authored 11:04 Berlin (outside 02:00–05:45).
- Architecture: outbound-only mTLS pull agent per server → `forge-nodehub` on carlgpu2 (`192.168.10.4:8094`, LAN only, DOCKER-USER rule). No inbound port, no sshd or firewall change on g1/g3/g4. 30.x→10.4 routing is unproven and gets a pre-flight test (30→10.3 is proven by NFS/Redis).
- Authority lives on the node: owner-signed policy (`ssh-keygen -Y`), applied by a root script that generates a wildcard-free sudoers fragment. A stolen hub credential can act only inside that policy, windows and rate limits.
- Tiers: T0 read (redacted, metadata only for frozen paths); T1 `forge.managed` containers (compose rendered + key-allowlist lint), `forge` libvirt pool (disabled until libvirt exists), forge dirs on the second SSD with free-space guard; T2 enumerated units, scene switch, security-only apt with plan hash, docker prune with pin protection by image ID (M-97); T3 = proposal → inbox → owner executes or signs once (single-use nonce, `frozen_ack` for protected targets).
- Frozen areas/Live-Trading: g4 and g1 get a T0-only helper profile (T1/T2/T3 code not installed); deny-by-default; protected set evaluated first on resolved objects; no GPU/docker/daemon actions there; owner-only via signed `frozen_ack`.
- Audit: agent log (`chattr +a`, hash chain) + root-written priv log (authoritative) + Postgres `node.audit` (INSERT-only); hub cross-checks and quarantines on mismatch; fail-closed if audit is down.
- Kill switch: existing `control/STOP` with `.dispatch.lock`, `stop` on every poll, node-local `LOCAL_STOP`, lockdown, 90 s staleness fail-closed; T0 stays available; nodes cannot touch `control/`.
- Dry-run/plan-hash for every mutating op, new ops start `dry_run_only`, rollout in `observe`; rate limits and circuit breakers; blackout 02:00–05:45 and Sunday <06:00 Berlin.
- Planner/graph: `node_*` MCP tools (executors get none), idempotent `job_id`, inbox kinds `node_action`/`node_alert`, T3 through `approvals_request`; `state_get` migrates to hub data.
- Alternatives: Ansible+SSH, Salt (master = root everywhere), SSH forced-commands rejected for the LLM channel; tripwire to stop at T0 if T1/T2 are never requested.
- First use: read-only Revision (Inventur v2, diff vs 28.10.) + F7a passive 72 h measurement on all four; active I/O/GPU tests only on g2 with owner go. Eight acceptance checks defined.
- Findings that affect decisions: (a) on every server the second SSD is KMU model storage (OQ-1); (b) no container carries `forge.*` labels yet; (c) `unattended-upgrades` is enabled on g2; (d) ADR-024 is not in the exported ADR doc; (e) on g2 the executor `forge` has `docker` (root-equivalent), so tiers there do not bind a compromised executor; (f) leftover test containers on g2.

**Owner steps** (executable only after slices N1–N3 deliver the signed release; details §13)
1. Decide OQ-1 (second SSD subtree), OQ-3 (g4), OQ-4/OQ-5/OQ-12.
2. Mac, once: generate owner signing key and CA (§13.A).
3. carlgpu2: generate hub key, sign hub cert, apply the DOCKER-USER rule with `--confirm` (§13.B).
4. Per server in order g2 → g3 → g1 → g4 (never 02:00–05:45): the §13.C block (user, release, node key/CSR → sign → policy apply → start), then approve the node in Cockpit /nodes.
5. After 72 h: review the Revision diff and the F7a M1 data with the Betriebsleiter; then decide M2 and promotion of T1/T2 ops.
6. Rollback at any time: `forge-stop`, `LOCAL_STOP`, `lockdown`, uninstall block (§13.E).

**Open questions:** OQ-1…OQ-17 in §17; the ones that block P1: OQ-1, OQ-2, OQ-4, OQ-5, OQ-12.
