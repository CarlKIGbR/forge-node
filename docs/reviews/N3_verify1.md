Verdict: PASS
Head: 73cda08453892662bcc7912bfef7f3f02fa36897

Verification review, 2026-11-01. Review only; no implementation changes. Blocking threshold: MAJOR. No MAJOR findings identified.

The reviewed SHA equalled `refs/heads/n3` before verification and before the report commit. The repository at `/srv/forge/work/forge-node` was on base `main`; its existing `n3` worktree at `/srv/forge/work/forge-node-n3` supplied the reviewed checkout. Base: `a72c7a673ef0203a94a15a03d581d62f60124342`. This report commit is a child of the reviewed SHA, not part of the reviewed implementation.

Read the revision-6 design, §16.3 N3-1..N3-16, N3_REPORT including round 3 and all eight residuals, and ADR-028 in the local forge-docs architecture register. The acceptance decision remains T0 only. This review does not open a gate or approve installation.

Audit verification (priority 1)

- `audit/scan.py:LineScan` limits candidate parsing to complete lines within the record-size bounds; carry/discard handling preserves line boundaries across chunks. Checked the minimum-record argument, random-junk/chunk equivalence tests, and the 16 MiB short-line regression. Both warm following and cold readers use the same chain-continuation rule.
- `audit/log.py:Appender` holds its mutex and the same root-controlled flock across CURRENT lookup, tail observation, repair, sequence allocation, append, fsync and cache update. Independent instances serialize on that flock. O_APPEND writes use their descriptor offset to distinguish their own write end from later hostile appends; an intervening valid continuation causes re-following and refusal if the claimed record lost the chain.
- `_repair_tail_locked` writes and fsyncs a terminating newline separately, follows the chain again, and only then allocates a repair/next record. A valid forged continuation lacking its newline therefore becomes the head that subsequent records continue. It cannot reserve the repair's sequence while the warm writer silently continues another branch. Repeated tail extension has bounded retries and fails closed.
- Rotation repairs, seals with +i, observes the immutable predecessor, builds a successor under 0700, sets +a before exposing its directory, and atomically replaces CURRENT. Recovery of a reachable flagless current file sets +a/+i and rotates; it does not merely re-add +a to an inode with an old writable descriptor. Purge recovery seals before hashing, preserves mismatched evidence, and reports it.
- Inspected all chmod/chown sites: file metadata is set before +a; later fchmod calls affect generation directories, lock/marker files or CURRENT temporaries. No chmod/chown/truncate is issued on a flagged log inode. The real-filesystem spies and old-descriptor tests cover this distinction.
- Root ownership, non-writable ancestor directories, O_NOFOLLOW, directory-relative opens, expected modes, gid and link count keep CURRENT, generations and lock names outside agent replacement control. Production anchors are `/` and owner uid 0.
- Inspected the crash injector: actual SIGKILL before/after mkdir, create, write, fsync, fchmod, fchown, rename, unlink, rmdir and inode-flag mutation. The suite sweeps rotation, recovery from each interrupted rotation state, init, purge, and repairing appends with fragment/empty/junk/forged-unterminated tails; checks include successful continuation, cold/warm agreement, seals and idempotence. The new flagless-live branch has a real old-descriptor regression; its post-seal states use the ordinary rotation recovery path. These are process-crash proofs, not power-cut tests; filesystem ordering and real installed-unit checks remain the report's stated limitations.

Switcher and resolver verification (priorities 2–3)

`cmd_switch` verifies both releases and compares their state windows before quiescence. Without explicit `--one-way`, a new window extending outside the current window is refused before any systemctl effect. The ledger is read after all row-producing units stop, and its non-terminal set includes `indeterminate`. Initial refusal can restart the unchanged release; rollback passes `restart_on_refusal=False`, so a failed stop/open-row check cannot restart the release that failed doctor. Restored releases also pass verification and doctor before agent/timer startup. Failure to stop is reported as unconfirmed, rather than claiming a quiet node.

The resolver rejects OnSuccess/OnFailure handlers and isolate handler modes on the design's effect set, and rejects requested job modes outside replace/fail. Active start dependencies receive the explicitly documented revision-6 treatment; stop effects are checked regardless of current activity. `StopWhenUnneeded` dependencies below conflicts and their reverse stop closure join S for start/restart/enable; stop/disable/mask and restart also include their unneeded dependencies. Missing graph data/text fails closed. No unit operation exists in the executable N3 table.

Privileged entry points and gates (priority 4)

| Surface | Enumerated entry points | Guard / effect boundary |
|---|---|---|
| privd socket | exec, lease.put, t0, status, selfcheck, reconcile, policy.apply, audit.rotate, lockdown | Exactly one `gate()` call per handler; SO_PEERCRED supplies identity; fixed pipelines. T0 probes/selfchecks are closed tables; resolve/rotation/lockdown have owner restrictions; policy relay requires the owner's signature and production gate validation. |
| privctl | audit_init, audit_verify, audit_rotate, audit_purge, policy_apply, status, lockdown, unit_closure, circuit_ack | All nine `cmd_*` start with `require_root`. |
| release switcher | check, install_first, switch, self_update | All four `cmd_*` start with `verify_release`; production entry also requires euid 0; rollback verifies again. Status observes only. |
| Worker/probe executables | opworker run/selfcheck; fixed probe run/selfcheck dispatch | No setuid elevation; root-side starts occur only in gate.py. Worker effects require protected request/work directories, effect lock and a matching started row/fence/attempt. |
| Daemon startup/maintenance | recover_all, pending-policy/release audit, pruning | Internal daemon lifecycle, not additional socket verbs; production root-controlled state and fixed paths. Transport parsing does not access effect state. |

G27 combines counted entry points, guard dominance, behavioural rejection with side-effect snapshots, missing-input rejection, and testkit mutants for added/conditional/effect-first/swallowed/bypass handlers. The production wiring passes the immutable `gates.GATES` to policy validation and execution. A–D are all false; every registered tier >0 requires D, with A/B/C additionally attached to their features. The compiled full table contains only gated T1 `selftest.noop`; the t0 artifact has no op worker/effects and an empty table. Direct-socket gate tests exercise the root decision independently of agent checks. Root administration and bounded T0 diagnostics remain available as designed; they do not enable gated jobs.

Eight residuals checked

| Report residual | Privilege assessment |
|---|---|
| 1. Purge flag-clearing window / reopening an old fd | Can damage an old agent-log inode during root-authorized purge; cannot choose another inode or obtain root credentials/effects. Resealing precedes evidence hashing. |
| 2. Agent-writable shipping ack | Can suppress/repeat its own shipping. It is not authority for root purge; privctl purge is root guarded. |
| 3. Heal-own-log, agent flock/junk/disk exhaustion | Availability/own-log interference. Priv audit paths remain root controlled; audit failure prevents job effects. Observe-only status/selfcheck do not repair live logs. |
| 4. LOCAL_STOP appearing mid-switch | Race between root administrative actions. Agent cannot create LOCAL_STOP in the production root-controlled directory; restarting services does not bypass gates. |
| 5. Hub 5xx fails doctor/rollback | Availability failure ends stopped/disabled or explicitly reports an unsuccessful stop. No new privileged action authority. |
| 6. Absent ledger/policy or schema-0 empty ledger accepted | Bootstrap ambiguity requires root-controlled state to be removed/replaced; non-root cannot manufacture it at production paths. Installed policy/execution validation and gates still apply. |
| 7. Doctor timeout leaves descendant | Doctor runs as forgenode; surviving code has the same closed socket guards and cannot enable a gated op. Process lifetime remains an availability concern. |
| 8. Round-3 fixes not independently reviewed | This verification independently reads the named fixes and exercises their tests/mutants. No new privileged-effect path found. |

None of the eight gives a non-root uid an unauthorized privileged effect. Availability and operational limitations remain named; they are not silently treated as resolved.

Execution evidence

`timeout 1200 scripts/run-tests.sh -q`: exit 0; **1216 passed, 0 failed, 0 skipped**, 391 warnings, 425.42 s (7m05s). Warnings include Python deprecation warnings about forking multithreaded test processes.

Tests run in throw-away containers with real Postgres, ssh-keygen, filesystem flags and processes. No host installation, sudo, service enable/start, deployment, or external messaging was performed. The suite and mutants use disposable filesystem trees only.

Ten selected mutants from `scripts/mutation_spotcheck.py` were applied individually to copies of a frozen git archive of the reviewed SHA. **10 applied, 10 killed by assertion failures, 0 survivors, 0 not applied**. Infrastructure startup failures were discarded and retried; only actual pytest assertion failures count as kills. Temporary runner instrumentation saved stdout/stderr and used a separate mutation work directory; reviewed source/tests were unchanged.

| Mutant | Observed rejecting regression |
|---|---|
| n3-audit-no-flock | Concurrent appends lose uniqueness/chain serialization. |
| n3-audit-torn-tail-newline-in-the-record-write | Damaged-tail continuation/rotation regression rejects the missing separate newline. |
| n3-audit-scan-minimum-too-high | Cold scan loses valid chain records. |
| n3-audit-recovery-readds-only-a | Flagless-live recovery fails the seal-and-rotate old-descriptor regression. |
| n3-switch-window-closes-way-back-silently | Wider-window switch fails to refuse before changes. |
| n3-switch-indeterminate-ok | Parameterized non-final ledger-state test catches indeterminate. |
| n3-switch-rollback-restarts-failed-release | Failed rollback stop incorrectly starts units after doctor failure. |
| n3-resolver-onfailure | OnSuccess closure rejection fails (same removed check covers OnFailure). |
| n3-resolver-isolate-job-mode | Requested isolate is accepted. |
| n3-resolver-unneeded-below-conflicts | Unneeded dependency below a stopped conflict disappears from the transaction. |

N3-1..N3-16 were mapped to the design's acceptance names and the suite. N3-15's unavailable historical round-2 review documents/counts cannot be reconstructed by this verification; the final code and regression evidence were reviewed instead. Real installed systemd sandbox behavior, other filesystem types, power loss and N4+ remain outside this review's execution scope. No MAJOR blocker was found for this gated N3 slice.
