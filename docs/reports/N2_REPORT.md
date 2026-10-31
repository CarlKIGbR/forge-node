# forge-node Slice N2 — Report (M-94)

Head: see `git -C /srv/forge/work/forge-node-n2 rev-parse n2` (a commit cannot contain its own hash); the chat report carries it as first line.
Repo/branch: **forge-node** branch `n2` (worktree `/srv/forge/work/forge-node-n2`, base `main` = 01b416a, N1 merged). Class kritisch. Authored 20:00–22:30 Berlin (Sat 31.10.2026, outside 02:00–05:45).
Nothing installed, started, built or generated on any server: no unit files (hardening is **data** in `t0/hardening.py`), no sudoers, no keys (test keys/PKI are ephemeral in the test container), no firewall change. The only contact with a real host was a **read-only, unprivileged** run of the T0 engine on carlgpu2 (see "Live proof").

## N2 items (design §15 slice plan; acceptance list = new §16.2)
N2 per the slice plan: "agent T0, `ro-probe` op class, redaction, spool, `inv.*` incl. `inv.usage`/`inv.models`". The design had an acceptance list only for N1 (§16.1); N2-1…N2-13 in §16.2 is my derivation from the slice text, the T-tests that §16.1 assigns to N2 (`test_agent_rejects_ca_valid_hub_cert_not_in_pins`, node half of the redaction canaries) and the carried-over names that are T0 (`test_kmu_path_metadata_only`, `test_untrusted_envelope_and_customer_label`, T-APT `inv.pkgs`). A test keeps §16.2 and the code in sync (`test_design_n2_list_names_existing_tests`).

| # | Item | Status |
|---|---|---|
| N2-1 | Agent: mTLS client with CA **and** leaf pin (checked before any request byte), TLS 1.3, IP-SAN, no unpinned mode; lease/job verification with the policy's gate keys; revocation by policy serial+1; hot policy reload | done (`agent/client.py`, `agent/loop.py`) |
| N2-2 | Node-side policy view: owner signature (ns `forge-node-policy`), node, serial = file name, `not_before`, gate rules, root-owned non-writable files, no fallback to an older file; hub-delivered newer policy is verified and **staged, never activated** | done (`t0/policy.py`) |
| N2-3 | One guarded path `T0Engine.execute` (10 fixed steps), no optional guard input | done (`t0/engine.py`) |
| N2-4 | Closed command table / guarded runner | done (`t0/runner.py`, 30 commands, all read-only) |
| N2-5 | Guarded file reader (allowlist, protected set, `O_NOFOLLOW` walk, metadata-only for policy dirs) | done (`t0/fsread.py`) |
| N2-6 | `ro-probe` op class: 10 probe programs, wire contract (SO_PEERCRED-checked), hardening data from fixed tables, `probe_main`, `selfcheck` | done (`t0/probes.py`, `wire.py`, `hardening.py`, `probe_main.py`, `selfcheck.py`) — **not run inside a real transient unit** (privd is N3; `doctor` proves it) |
| N2-7 | Repository config is code (git rev without executing git; config allowlist; post-run recheck) | done |
| N2-8 | All 16 T0 ops of §4.1 (`inv.host … inv.models`, `metrics.sample`, `logs.unit`) | done; SMART collection deliberately `unavailable` (see deviations) |
| N2-9 | Redaction + charset filter + size-bounded untrusted envelope + sensitivity label | done (`t0/sanitize.py`, `redact.py` from N1) |
| N2-10 | Spool (ring ≤ 50 MiB) + sampler (≥ 30 s) + `metrics.sample` cursor reads | done (`t0/spool.py`, `metrics.py`) |
| N2-11 | Berlin window (DST, Sunday), per-op rate buckets (persisted) | done (`t0/window.py`, `t0/limits.py`) |
| N2-12 | Nothing above T0; no audit writer; STOP does not stop T0; no listener; writes confined; nothing installed | done, enforced by static tests |
| N2-13 | Live proof against real tools | done (6 real-tool tests + read-only run on carlgpu2) |

Hub side: `hub/params.py` now delegates to `t0/params.py` (one schema for hub and node) and accepts `metrics.sample` params `{after_seq, max_samples}` (needed to read the spool by cursor). No other hub change; N1 behaviour unchanged (all 302 N1 tests green).

## Betriebsleiter conditions a)–d) — which are in N2, status
| Gate | In N2? | Status |
|---|---|---|
| a) workload volumes host-visible (N5) | **no** | unmet, feature disabled: no `volume.*`/workload-start code exists; `gates.GATES["A"].met` is `False` |
| b) VM logging bounded (N9) | **no** | unmet, `vm.*` not implemented, `inv.vms` is read-only and reports `unavailable` where `virsh` is absent |
| c) unit resolver OnSuccess/OnFailure/isolate (N3, N6/N7) | **no** | unmet, no unit op, no resolver in N2 |
| d) audit sealing (N3) | **no — N2 contains no audit-file writer** | unmet. Verified by `test_no_audit_file_writer_in_n2_so_gate_d_has_nothing_to_seal` (no `seal_record`, `chattr`, `audit.jsonl`, `priv.jsonl`, `CURRENT`, rotation anywhere in `t0/` or `agent/`). The agent writes only its spool, its rate-limit file and staged policy blobs (`test_writes_are_confined_to_the_agent_state_modules`). Agent-side audit (`audit.jsonl`) and `priv.jsonl` come with N3 together with gate D; until then T0 activity is covered by the hub's own audit (`job_issue`/`job_result`) and the agent's redacted journal lines. **No mutating op is enabled**: the agent answers every tier>0 job `DENY_TIER_DISABLED` without handing it to the engine (`test_agent_denies_a_tier1_job_even_if_a_hub_with_open_gates_signs_it`), the engine denies it again, the hub signs none. `T0_OPS` ⊆ `gates.OPS` tier 0 and non-mutating (`test_n2_executes_no_mutating_op_and_has_no_privileged_execution_path`). |

## Standards applied
- **One guarded path without optional guard inputs.** Every read goes `agent loop → T0Engine.execute → (collect | probe) → sanitize.finalize`; the probes are reachable only through `wire.handle_request`/`probe_main`, which call `probes.run_probe` (it re-applies the blackout window itself). Limiter, probe transport, environment, spool, hub-cert provider, pins, `owner_uid`, `expect_uid`, clock are **required** constructor/function arguments; `execute(op, tier, params)` has no flags. `test_no_function_in_the_t0_layer_or_agent_has_an_optional_guard_input` (AST scan: no guard-named parameter has a default) and `test_engine_requires_its_guards_as_arguments` pin this. The scan already caught one violation while writing (`_PinnedConnection(pins=())`, now keyword-required).
- **Evidence re-observed before irreversible/trusting decisions:** policy file mode/owner/nlink on the *open descriptor* at every load (`fstat`), the policy directory itself, `allowed_signers`; the command binary's owner/mode on **every** `run()`; the privd peer uid via `SO_PEERCRED` on every connection **before** sending; the hub leaf pin on every new connection **before** the first request byte; the blackout window inside the probe at execution (not only at the agent); the repository's `.git/config` read before git runs and **again after** (result discarded if it changed); spool segments `lstat`-ed (regular, our uid, one link, expected name) immediately before they are unlinked; rate state re-read from disk at start, never trusted across restarts; a new policy is signature-verified at the moment it replaces the old one and a failing newest file means *no* policy (never the older file).

## Tests
`scripts/run-tests.sh` (real Postgres 17, real `ssh-keygen`, real mTLS handshakes, real `git`/`openssl`/`du`/`lsblk` in the test image): **643 passed, 0 skipped, 0 failed** (302 N1 + 341 N2). New files: `test_t0_sanitize` 11, `test_t0_runner` 14, `test_t0_fs_window_limits` 32, `test_t0_policy` 38, `test_t0_parse` 13, `test_t0_collect` 19, `test_t0_probes` 45, `test_t0_engine` 26, `test_t0_spool_metrics` 19, `test_t0_real_tools` 6, `test_t0_fuzz` 12, `test_agent_client` 9, `test_agent_e2e` 24 (agent ↔ real hub, DB, mTLS), `test_n2_branches` 45, `test_n2_scope` 28; changed N1 test files only where N1 asserted "no agent exists" (`test_deploy.py`).
Levels (kritisch): unit, integration (agent ↔ hub ↔ Postgres with real TLS), e2e job round trip, smoke/live proof, guard tests (structure/AST tests above), property/fuzz (hypothesis: envelope fit, name filter, spool reads, git-config scanner, policy parser, wire handler, every text parser on arbitrary input), mutation checks (below).
Line coverage of the N2 files (stdlib monitor `scripts/linecov_plugin.py`, `FN_COV=1 scripts/run-tests.sh -p linecov_plugin`): **98.0 %** (2743/2800 lines; the missed lines are `OSError` fallbacks, the `__main__` guard and defensive `except` arms).
Real defects found by my own tests/fuzz/live proof and fixed (not hypothetical): see "Findings during the slice".

## Mutation spot checks
59 hand-written mutants of the critical branches (gates/tier, window, rate, params, allowlists, TLS 1.3, hostname check, **pin check**, policy signature/node/serial/not_before/permissions/gates/customer rule, runner trust/slot/dash/shell/env/process-group kill, fs protected/allowlist/nofollow/sys-escape/exception pattern, git config scan and post-run recheck, journal allowlist, heavy-window in probes, ionice rule, cert key-file skip, authorized_keys options, wire peer-uid and strict request, spool O_EXCL/hard cap/eviction/owner, redaction/charset/fit, limiter take/persist, window Sunday/floor/timezone, lease/job/tier/policy-stage verification in the loop, cadence, config IP, protected-role tag, statvfs timeout, hardening NNP, gate D). Each applied to a copy, relevant tests run, restored: **first run 55 killed / 4 survived**. Survivors and what I did:
- `runner-killpg` (kill the group → kill only the child): the test only checked "marker not created"; replaced by a test that reads the background child's pid and requires it dead → now killed.
- `fs-protected` (protected-set check removed): the test accepted `not_allowed` as well as `protected`; new test protects an allowlisted file by policy and requires `protected` → now killed.
- `loop-tier` (loop hands tier>0 to the engine): outcome identical because the engine denies too; the e2e test now wraps `engine.execute` and requires that it is **never reached** → now killed.
- `engine-logs-allow` (step-5 allowlist removed): **equivalent mutant** — `_logs` repeats the check (defence in depth), the outcome is identical; the inner check has its own test (`test_engine_defence_in_depth_branches`). Left as is.
Re-run after the fixes: the three strengthened mutants are killed; the harness is `/tmp/fn-mut/mutate.py` (scratch, not shipped).

## Live proof (read-only, unprivileged `forge`, carlgpu2; only structure recorded)
All 14 non-heavy ops executed through the real engine with the real runner (heavy `inv.git`/`inv.models` deliberately skipped: they touch KMU paths, covered by real-tool tests on throw-away data instead): 14/14 `committed`, none truncated, 358 B – 47.8 KB (cap 60 KB), ≤ 0.9 s each. Cross-checks against the tools: containers parsed 36/36 (`docker ps -aq`), units 158/158 (`systemctl show`), listeners 21/21 (`ss`), mounts with protected-role tag for the five KMU mounts, 1 GPU, default gateway, pending packages 23 (0 security). As expected for a non-root, non-journal user: `sshd -T`, `iptables`, `journalctl`, docker log mtime report `error`/`None` — these belong to the root probes.
Findings that changed code/design: (1) **`/var/log/unattended-upgrades` is `root:adm 0750`** → the agent uid cannot read the last-run log (design 4.1 said "agent uid") → new root probe `uulog` returning only the parsed outcome; (2) `apt-config dump` prints an empty list head `Allowed-Origins ""` which was counted as origin drift → filtered; (3) design §4.5 `RestrictAddressFamilies` lacked `AF_NETLINK` that `ss`/`ip route` need → added to the hardening data and the design text. Also found by reading the table against real behaviour: `journalctl --since -3600s` as two argv elements was rejected by the runner's option-lookalike rule (would have failed every real `logs.unit`) → `--since=<value>` form + a contract test that **executes every table command** with representative slots (`test_every_table_command_expands_executes_and_keeps_values_as_single_argv_elements`).

## Findings during the slice (all fixed, tests added)
1. Runner: option-lookalike rule blocked a legitimate value (`--since -3600s`) — above.
2. `nvidia-smi` process names could carry arguments (`python3 --token=…`) → first word, basename only.
3. Cert probe opened `privkey*.pem` (parsed, nothing leaked, but key material must never be opened) → names containing priv/key/secret are skipped.
4. Spool: a foreign file or symlink named like the next segment crashed the spool (and the sampler thread) / could be written through → segments are created with `O_EXCL`, a taken name skips the sequence number; segments are never reopened.
5. Sampler: backwards clock jitter bypassed the 30 s cadence → absolute difference.
6. Fuzzing: `csv.Error` on stray CR (nvidia), `ip_routes`/`lsblk`/`findmnt` crashed on non-list/non-dict JSON, deep nesting, non-string fields → all parsers are total now (`test_property_no_parser_raises_on_arbitrary_text` over all 35 text parsers, `test_property_json_consuming_parsers_survive_any_json_shape`).
7. `inv.usage` materialised the whole 72 h spool (up to ~130 MB of objects vs `MemoryMax` 96–128 M) → single-pass streaming aggregation, malformed records skipped and counted.
8. Heavy ops could run > 5 min inline in the poll thread (hub alerts "heartbeat lost" at 5 min) → budgets: git 120 s total, models 150 s, probe `RuntimeMaxSec` 240 s, client wait 250 s.
9. Agent loop: unexpected exceptions in the engine or a poll cycle now become `FAIL_EXEC`/back-off instead of ending the agent thread.

## Independent review
REVIEW_PLACEHOLDER

## Deviations / decisions
- **Acceptance list for N2 did not exist** in the design (only §16.1 for N1): derived and added as §16.2 (see above); named tests that §16 assigns to privd (`test_blackout_window_berlin_dst`, `test_sunday_before_06`, `test_rate_bucket_and_cooldown`, …) are implemented here with their own names for the T0 layer; N3 will add the privd ones.
- **No agent audit file in N2** (`audit.jsonl`, chain, `audit_heads` in poll are empty `{}`) — gate D / N3, see above. T0 results are not individually chained on the node in N2.
- **Policy installation is not in N2** (privd `policy.apply`, N3). The agent reads the *installed* policy directory (`policy-<serial>.json` + `.sig`, root-owned, as `privd` will write it — layout is my reading of §7.3/§13.C and must be confirmed by N3), re-verifies it, and **stages** newer hub-delivered policies in `<state>/staging` after verifying their signature; staging activates nothing.
- **Probe sections run as `ro-probe` programs but privd does not exist**: in production N2 the agent's `SocketProbeClient` finds no socket and every root-only section reports `unavailable` ("privd socket unreachable"). The wire contract and the programs are complete and tested with a fake privd; N3 plugs `wire.handle_request` into `gate()`.
- **Hardening tables are data and unvalidated against a real systemd** (no unit installed): capability sets per probe are my reading of what each command needs (`CAP_NET_ADMIN`+`PTRACE`+`DAC_READ_SEARCH` for `net`, …). `doctor`/selfcheck in the real units (N3/N4) must confirm; `selfcheck()` exists and reports command/path availability.
- **SMART**: reported `unavailable` even where `smartctl`/`nvme` exist (needs `CAP_SYS_RAWIO`/`CAP_SYS_ADMIN`, which the probe class must not get). Design 4.1 said "only if present"; revisit when a host has the tools.
- **Rate buckets per op** (design 9.2 says "T0 heavy ≤ 1/10 min, light ≤ 2/min" under "per op"); the agent's buckets are advisory, privd's (N3) authoritative; persisted in `<state>/ratelimit.json`.
- `inv.certs` live handshake covers fixed local ports 443/8443 only (policy has no port field); hub certificate expiry comes from the pinned connection's DER.
- `PolicyView` ignores policy fields it does not use (full schema validation, `forge_roots`, `t2` ops, apt rules … is the N3 installer); it **does** reject any policy that enables a gated feature.
- Python docstrings/comments in the new modules are English (owner principle: English in repo); N1 modules are German.
- `scripts/run-tests.sh`: test tmpfs is now `exec` (needed to execute fake binaries in the runner tests; the container is `--network none`, throw-away) and `PYTHONPATH=/w/scripts` + optional `FN_COV` for the coverage plugin.
- Agent and `t0` stay stdlib-only; the hub image copies the whole package (it now contains the unused agent/t0 code; the hub imports `t0.params` only).

## Known residuals (not N2 defects, recorded for N3/N4)
- A repository's owner can still race the git-config scan (`.git/config` rewritten between scan and exec); mitigated by the command-line overrides (`core.fsmonitor=false`, `core.hooksPath=/dev/null`, no global/system config) and the post-run recheck, bounded by the probe unit (no network, no write paths, `NoNewPrivileges`, minimal caps).
- Jobs run inline in the poll thread (no concurrent polling while a job runs); worst case ~4.5 min between heartbeats.
- Rate limiting of root probes is authoritative only once privd exists.
