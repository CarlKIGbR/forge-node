# forge-node Slice N1 — Report (M-94)

Head: see `git -C /srv/forge/work/forge-node rev-parse n1` (a commit cannot contain its own hash); the chat report carries it as first line.
Repos/branches: **forge-node** branch `n1` (worktree `/srv/forge/work/forge-node-n1`, base d50f2b4); **forge-ops** branch `n1` (worktree `/srv/forge/work/forge-ops-n1`, commit 35c46f5 on base 359e77f). forge-ops `master` is unchanged (359e77f).
Nothing installed, started, built or generated on any server: no units, no sudoers, no keys (test keys/PKI are ephemeral in the test container's tmp), no firewall rule applied (forge-ops script only run with `--dry-run` and stubs). Authored 14:40–15:20 Berlin.

## N1 items (design §15 slice plan, list in design §16.1)
| Item | Status |
|---|---|
| Protocol (lease/job/result/poll/audit schemas, reason codes, canonical JSON) | done (`protocol`, `canon`) |
| Hub skeleton (mTLS TLS1.3 stdlib server, identity = CA + SAN + registered fingerprint, read-only policy/release delivery, healthz, limits) | done (`hub/server`, `hub/core`) |
| Hub gate key, lease/job signing (`ssh-keygen -Y`, ns `forge-node-hub`), node-side verifiers | done (verifiers are library code for N2/N3) |
| `node` schema + INSERT-only audit (chain guard trigger, partitions, 400 d retention fn, role grants) | done (`migrations/0001`) |
| Hub audit sink: chain/hash check, redaction, quarantine, cross-check vs priv log, incremental verification | done |
| STOP integration (read-only, `.dispatch.lock`, fail-closed) | done |
| DOCKER-USER rule TCP/8094 (forge-ops) | done as separate `--hub` rule set on branch n1; 27 stub checks |
| Hub image/compose files | delivered, not built, not run |

## Betriebsleiter conditions a)–d)
All four are **unmet and enforced as disabled** (`forge_node/gates.py`, `met` is a code constant, no env/policy override; hub signs nothing above T0; `policy_gate_violations()` for the N3 policy validator). Design rev 4 records each as a mandatory acceptance criterion of the enabling slice with named tests: a) N5 (host-visible volumes), b) N9 (continuous VM log bound), c) N3 resolver / N6, N7 (OnSuccess/OnFailure/isolate), d) N3.
**d is not in N1**: N1 contains no append-only log file writer (only the hub's INSERT-only DB table), so sealing is required in N3, which holds the audit writer. §8.3 step 4 (`fchmod` on `+a`) is marked superseded. No mutating op is enabled (every op above T0 needs gate D).
MINORs: directory guard per registered volume (design "Gated features", MINOR 1); §14.1 split into T0 acceptance vs workload/mutation acceptance (MINOR 2).

## Tests
forge-node: **296 passed** (`scripts/run-tests.sh`, real Postgres 17 + real ssh-keygen + real mTLS). Mutation spot checks (STOP check, dispatch lock, lease stop, prev_hash, hash, redaction, lease replay) each made a test fail. forge-ops: `tests/test_docker_user_hub.sh` 27/27; existing forge-edge firewall tests (12) still pass against the modified script; shellcheck clean.
Real defects found by own tests and fixed: regex `$` accepting a trailing newline (allowed_signers injection), unread bodies desynchronising keep-alive, hardlinked policy file answered 400, NUL in JSON breaking jsonb.

## Independent review
A fresh reviewer agent was started but ended with the session before reporting; **no independent findings were received**. The G6 cross-model review of N1 is therefore still outstanding.

## Deviations / decisions
- Authz matrix and per-identity rate mirror (§3.5/§11) deferred to N7 (needs MCP identities); `enqueue_job` is a library call without network surface, capped at 200 open jobs/node.
- Jobs are signed at delivery (poll), STOP checked at enqueue and again under the dispatch lock at signing.
- Per-project stop source is not defined in the design/forge-core: implemented as read-only `control/stop.d/<slug>` files.
- Added audit record types (hub: job_issue/job_result/denial/quarantine/anomaly; agent: relay). Records the hub still redacts are stored with `redacted=true`; their hash is verified at ingest only.
- Wildcard bind allowed only with `FORGE_NODEHUB_CONTAINER=1` (publish is LAN-only, tested).
- Migration kept in forge-node with its own runner/version table, not in forge-core's migrations.
- DOCKER-USER: separate rule set/tag/timer prefix/marker instead of extending the edge set (edge tests unchanged); plain `--restore` also restores confirmed hub rules.
- T-REVOKE `test_agent_rejects_ca_valid_hub_cert_not_in_pins` (agent) and all privd tests belong to N2/N3.
- Test runner uses the host `ssh-keygen` via a loader shim because the test image has no OpenSSH.
