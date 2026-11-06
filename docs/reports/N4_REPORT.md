# forge-node Slice N4 — Report

Head: see `git -C /srv/forge/work/forge-node-n4 rev-parse n4` (the chat report carries it). Branch `n4` (worktree `/srv/forge/work/forge-node-n4`), base `main` e4b9efa. Scope: `docs/reports/N4_SCOPE.md`.
**Nothing installed, enabled or started on any host** (no unit, sudoers, key, firewall or `/etc` change; no real-host contact except what N3 already documented). Only tier T0 is released: gates A–D are still `met=False` (`gates.py` untouched), every op above T0 is denied, workload volumes / VM start / units with `OnSuccess=`/`OnFailure=`/`isolate` stay locked in code and policy (resolver untouched). The only new root commands are `privctl selftest-bypass` (sends a hub-signed **dry-run** envelope, refuses anything else locally) and `forge-node-release clear-hold`.

## SPEC-QUESTION (answered with reading A, please confirm)
The design has no N4 acceptance list (§16.1–16.3 exist for N1–N3; §15 has one line for N4). Reading A (built): list derived from §13.C, §14.1 T0 acceptance and the N3 hand-over, now `docs/design/FORGE_NODE.md` §16.4 (proposal). Consequence: T0 acceptance (1)(4)(5)(6)(9 in real units)(10) are host/observation steps and are **not claimed**; (8) "one inbox escalation for a cert with 10 days left" needs the hub→`core.escalations` forwarding, which the design assigns to N7.

## What was built
| Item | Change |
|---|---|
| M-108 | `doctor`: hub 5xx ⇒ up to 3 retries (2/5/10 s backoff) ⇒ check state `indeterminate`; verdict `INDETERMINATE`, exit **4** (0 OK, 1 FAILED; a real failure wins). Not downgraded after a switch. Switcher: rc 4 **plus** doctor's own verdict line = indeterminate; new release is not kept, the known-good release is restored and **started** (also when the rollback's doctor is indeterminate — previously a quiet, disabled node), `RELEASE_HOLD` (root, next to LOCAL_STOP) refuses every further `switch` until `forge-node-release clear-hold`; the hold file is the escalation record (`escalate_to: betriebsleiter`, printed too), exit **5**. Forwarding that record into the hub inbox is N7's (hub is the thing that is down). |
| M-109 | `Ledger(path)` never creates; `create=True` only from `privctl audit-init` on a fresh node (no log CURRENT yet). Missing / schema-less ledger ⇒ `LedgerMissing` in privd start, privctl, workers; `audit-init` on an installed node refuses instead of re-creating; switcher: missing/zero-byte ledger once a release is `current` ⇒ `Refused` (only before install-first it still reads (0,0)). |
| T0 acc. (3) | `privctl selftest-bypass <envelope> [REASON]` (N3 report deviation 6). |
| T0 acc. (11) | consolidated test with the production gate table (policy.apply rejects each gated feature; direct privd request denied). |
| M-112 | see below. |
| harness | `scripts/run-tests.sh`: `FN_REPEAT=n` (n consecutive pytest processes in one container, stop at first failure). |

## M-110 — the eight residuals of N3_REPORT "Round 3" (none gives a non-root uid a privileged effect; fixed where a fix was possible)
| # | Residual | Outcome | Evidence (test) |
|---|---|---|---|
| 1 | A4 purge window (`/proc/self/fd` re-open between flag clear and `unlinkat`) | **Confirmed, not closable in code.** Only the agent log (0660) is writable; the uid can write into the inode that is deleted one instruction later (hub-acked, ≥ 90 d). Lasting effects: none — the inode has no name (`st_nlink == 0`), the log directory is root-owned/not agent-writable so it cannot be re-linked, chain verifies. The priv log is 0640: not writable at all. | `test_a4_a_descriptor_reopened_for_writing_in_the_purge_window_…` (real ext4, forked child as agent uid, probe runs inside the window) |
| 2 | A7 ack file agent-writable | **Confirmed.** No root-side code (privd, audit, release, privctl) names or imports the ack file/shipper; `audit-purge` takes its acked seqs as arguments (owner reads them from the hub). A compromised agent can only stop shipping; hub `audit_heads` cross-check is the alarm. | `test_a7_no_privileged_component_reads_the_agent_writable_ack_file` (AST/text scan) |
| 3 | A8 (a) observe paths heal priv log (b) hostile flock holder blocks `status`/agent log (c) disk fill | **Confirmed (availability only, fail closed).** (a) by design: privd is the priv log's only writer. (b) agent-uid flock on the agent log ⇒ `AuditDown`, nothing written; the priv log (own root-only lock in a root-only dir) is unaffected; chain intact afterwards. (c) disk-full ⇒ `AuditDown` ⇒ mutating ops denied (`test_audit_down_denies_mutating`, N3); capacity monitoring stays out of scope (open item). | `test_a8_a_hostile_flock_holder_makes_the_agent_log_fail_closed_and_does_not_touch_the_priv_log` |
| 4 | B7 lockdown during a switch is undone by `_start_rest` | **Fixed.** LOCAL_STOP is re-checked before the socket start, before `_start_rest` and in the best-effort start; `LockedDown` ⇒ rollback path ⇒ everything stopped+disabled, state `LOCKDOWN…`, nothing started. | `test_b7_a_lockdown_during_the_switch_is_not_undone_by_the_switch`, `test_b7_a_lockdown_that_appears_while_the_way_back_is_taken_also_wins` |
| 5 | B8 hub 5xx in doctor | **Decided = M-108** (neither pass nor fail; B8's "quiet node, exit 3" no longer happens). | `tests/test_n4.py` N4-1/N4-2 |
| 6 | B9 missing input read as "nothing there" (ledger absent, zero-byte, no schema) | **Fixed = M-109** for the ledger (the decision asked in the report: the *install* creates it, `audit-init`). The policy directory absent is the same refusal once a release is `current` (before install-first it still reads "no policy"; present-but-empty stays "no policy yet" until `policy-apply`). | `tests/test_n4.py` N4-3 + `test_a_missing_policy_directory_is_a_refusal_…` |
| 7 | B10 doctor timeout kills `runuser` only; 900 s too short | **Fixed.** `run_process` starts its own session and kills the process group on timeout; `DOCTOR_TIMEOUT_S = 1800` (≥ 10× the paced-request + hub-retry budget, asserted). | `test_b10_a_timeout_kills_the_whole_process_group_…`, `test_b10_the_doctor_timeout_covers_the_worst_case_…` |
| 8 | Round-3 fixes unreviewed | **Reviewed** by two fresh read-only agents on e4b9efa (audit: `LineScan`, `_repair_tail_locked`, seal-and-rotate; switcher: `cmd_switch`, doctor). No BLOCKER; no non-root privileged effect in either. Fixed: switcher MAJOR 1 (refusal restarted *all* units, incl. the failed release on a quiet node → now only what was active), MAJOR 2 (`disable` removes links so the next `stop` fails "not loaded" → recovery impossible; now tolerated only when every unit says inactive/failed/unknown), MINOR 4/5 (OSError in stop/start helpers; dead stdout turned rc 3 into rc 1), B7 (above), audit MINOR off-by-one in tail repair. **Open, not fixed** (named): switcher "`privctl resolve` does not exist" (message corrected; the privd `reconcile`+`resolve` request exists, wrapper is N5 because only mutating ops make `indeterminate` rows); doctor selfcheck rate bucket per uid (a forgenode process outside the agent cgroup can exhaust it → doctor fails closed: availability only); audit MINOR `scanned_to` stale after an over-long line (wasted work only) and crafted ≥ 160-byte JSON-looking lines cost 4–13 MB/s under the log's flock (availability only, same class as residual 7 of N3). | `test_r8_a_refused_switch_restarts_only_what_was_running_before`, `test_r8_a_node_left_quiet_…_can_be_switched_again`, `test_r8_a_dead_stdout_…`, `test_r8_tail_repair_…` |

## M-112 — flaky `test_concurrent_overlapping_batches_store_each_record_once`
**Root cause (concurrency):** the test started 8 threads with batches `recs[:25]`, `recs[10:]`, `recs[:40]`, `recs[20:35]` (×2). `ingest_audit` serialises per chain with `pg_advisory_xact_lock`, but *which* thread gets the lock first is the scheduler's choice. When a batch that starts at seq 11 or 21 wins it while the head is 0, the hub correctly reports `audit_gap: priv-gap-1` and **quarantines the node** — the final `not quarantine` assertion fails (reproduced: reply `{'ok': False, 'rejected': {'seq': 11, 'reason': 'priv-gap-1'}}`, `quarantine_reason 'audit_gap: priv-gap-1'`). The product is right (a batch beyond head+1 *is* a gap); the test's precondition depended on lock order. **Fix (test only):** seed seq 1–5, use batches starting at seq 1/6 (valid whatever the order, still overlapping differently), release all threads with a barrier, assert all 8 deliveries `ok`, exactly 35 records stored in total (each by one delivery), 40 rows, no quarantine, chains verify. Base (e4b9efa, test unchanged), 5 blocks of up to 50 consecutive runs: pass 50/50, **FAILED at run 46**, **FAILED at run 49**, pass, pass; plus a failure on run 1 of an earlier series and 1 in 6 in a short series with the quarantine reason printed. **Branch, fixed test: 50 of 50 consecutive runs passed** (`FN_REPEAT=50 scripts/run-tests.sh -q <test id>`; also repeated on the final tree, see below).

## Tests
Final tree (f88bc2d), `timeout 1800 scripts/run-tests.sh -q` started by host uid 994 (`forge`, non-root; the container runs the privileged tests as root, as in N1-N3): **1251 passed, 0 failed, 0 skipped in 7 min 14 s** (N3 final: 1216). An earlier run on the M-108/M-109 tree: 1234 passed, 2 failed = the two G27 entry-point counts (expected: new `cmd_selftest_bypass`, `cmd_clear_hold`; updated, `cmd_clear_hold` is an explicit, reasoned exemption).
Existing tests whose contract N4 changes (updated in the same commits): the two doctor tests that expected HTTP 500 = fail (500 is now `indeterminate`, 404 stays `fail`), `test_a_dead_stdout_after_a_good_switch_does_not_roll_it_back` (now rc 0 instead of a raised BrokenPipe), `test_release_switch_moves_agent_ops_units_together` (an `is-active` query precedes `stop`), switcher tests that need a ledger after install-first, `Ledger(..., create=True)` in fixtures, `privctl audit-init` tests with a real ledger path.

### New tests: base (e4b9efa + the new tests, without the product changes) vs branch
Base failures are partly structural (`Switcher(hold_path=...)`, `Ledger(create=...)`, `D.EXIT_*` do not exist there); the behavioural proof is the mutation run below. Rows that PASS on base are *evidence* tests of residuals that were confirmed rather than fixed (A4, A7, A8). `error` = fixture/setup error on base.

| test | base | branch |
|---|---|---|
| `test_a_failed_rollback_doctor_is_still_a_quiet_node_and_a_failed_new_release_is_still_rc_1` | failed | passed |
| `test_a_ledger_replaced_by_an_empty_file_is_a_refusal_not_a_fresh_start` | failed | passed |
| `test_a_missing_ledger_refuses_the_switch_before_any_change` | failed | passed |
| `test_a_plain_failure_is_unchanged_rollback_rc_1_and_no_hold` | failed | passed |
| `test_a_real_failure_of_the_new_release_with_an_indeterminate_rollback_doctor_stays_on_the_known_good_release` | failed | passed |
| `test_after_an_indeterminate_switch_no_further_switch_until_the_hold_is_cleared` | failed | passed |
| `test_doctor_hub_5xx_retries_three_times_with_backoff_then_indeterminate[500]` | error | passed |
| `test_doctor_hub_5xx_retries_three_times_with_backoff_then_indeterminate[502]` | error | passed |
| `test_doctor_hub_5xx_retries_three_times_with_backoff_then_indeterminate[503]` | error | passed |
| `test_doctor_hub_5xx_retries_three_times_with_backoff_then_indeterminate[504]` | error | passed |
| `test_doctor_hub_5xx_retries_three_times_with_backoff_then_indeterminate[599]` | error | passed |
| `test_doctor_hub_5xx_that_clears_during_the_retries_is_a_pass_and_other_statuses_are_not_retried` | error | passed |
| `test_doctor_indeterminate_is_neither_ok_nor_failed_in_the_verdict_and_a_real_failure_wins` | error | passed |
| `test_doctor_main_exit_status_is_0_1_or_4` | failed | passed |
| `test_every_gated_feature_is_verified_disabled_policy_apply_and_direct_privd_request` | failed | passed |
| `test_install_creates_the_ledger_and_a_missing_ledger_afterwards_is_a_refusal` | failed | passed |
| `test_selftest_bypass_fails_when_privd_does_not_refuse_and_sends_only_signed_dry_runs` | error | passed |
| `test_selftest_bypass_sends_a_signed_t1_dry_run_straight_to_the_socket_and_stop_denies_it_while_t0_answers` | error | passed |
| `test_switch_with_indeterminate_doctor_keeps_the_known_good_release_holds_and_escalates` | failed | passed |
| `test_the_hold_survives_in_status_and_an_unreadable_hold_counts_as_a_hold` | failed | passed |
| `test_the_switcher_only_believes_exit_status_4_together_with_doctors_own_verdict_line` | failed | passed |
| `test_the_switcher_parses_what_doctor_really_prints_for_an_indeterminate_hub` | error | passed |
| `test_the_switcher_refuses_a_missing_ledger_on_an_installed_node_but_not_before_the_install` | failed | passed |
| `test_a4_a_descriptor_reopened_for_writing_in_the_purge_window_has_no_lasting_or_path_visible_effect` | passed | passed |
| `test_a7_no_privileged_component_reads_the_agent_writable_ack_file` | passed | passed |
| `test_a8_a_hostile_flock_holder_makes_the_agent_log_fail_closed_and_does_not_touch_the_priv_log` | passed | passed |
| `test_b10_a_timeout_kills_the_whole_process_group_not_only_the_direct_child` | failed | passed |
| `test_b10_the_doctor_timeout_covers_the_worst_case_of_paced_requests_and_hub_retries` | failed | passed |
| `test_b7_a_lockdown_during_the_switch_is_not_undone_by_the_switch` | failed | passed |
| `test_b7_a_lockdown_that_appears_while_the_way_back_is_taken_also_wins` | failed | passed |
| `test_r8_a_dead_stdout_does_not_change_the_verdict_and_an_oserror_in_the_stop_path_is_reported` | failed | passed |
| `test_r8_a_node_left_quiet_by_an_earlier_rollback_failure_can_be_switched_again` | failed | passed |
| `test_r8_a_refused_switch_restarts_only_what_was_running_before` | failed | passed |
| `test_r8_tail_repair_terminates_a_tail_that_a_hostile_writer_extended_three_times` | failed | passed |

## Mutation spot checks (N4)
21 new mutants in `scripts/mutation_spotcheck.py` (`n4-*`: doctor retry/verdict/exit code, hold written/checked, rc 4 needs the verdict line, ledger created implicitly / schema-less accepted / missing-on-installed passes / audit-init re-creates, lockdown re-check, process-group kill, restart-only-what-ran, not-loaded stop, dead stdout, doctor timeout, tail-repair off by one, selftest-bypass dry-run check and expected code), each against a `git archive` of HEAD: **21 killed, 0 survived, 0 not applied.** One survivor was found on the way and fixed: `n4-timeout-kills-only-the-child` (the first test passed after 5 minutes, when the orphaned grandchild ended; the test is now bounded by a 20 s thread join). N1-N3 mutants were not re-run (N4 touched switcher.py, doctor.py, ledger.py, privctl.py, audit/log.py; their tests are in the green full suite).

## Open items / decisions for the Betriebsleiter
1. Confirm section 16.4 (reading A) and that T0 acceptance (1)(4)(5)(6)(9)(10) are the owner's install/observation steps; (8) needs N7's inbox forwarding.
2. The hold/escalation record is a root file + console output; forwarding it into the hub inbox is N7. Is `clear-hold` by root alone acceptable, or should it require a green `doctor`?
3. Open review items (residual 8): privctl wrapper for `resolve` (N5), doctor selfcheck rate bucket per uid, `scanned_to` after an over-long line, crafted-line scan cost under the agent log's flock, disk-capacity monitoring.
4. A node that already runs the N3 switcher needs `forge-node-release self-update` to get `clear-hold`, the hold and the ledger guard (switcher API unchanged).

## Commits (branch n4, base e4b9efa)

f88bc2d forge-node N4: timeout test bounded by a thread join
d8b1643 forge-node N4: timeout test must return promptly (mutant survivor n4-timeout-kills-only-the-child)
d7f3ccb forge-node N4: policy directory missing on an installed node is a refusal, report draft, design §16.4
33c2a80 forge-node N4: gated-features test, tail-repair test, 20 N4 mutants
a49f1e2 forge-node N4: residuals B7 (lockdown during switch), B10 (process-group kill, doctor timeout), review findings (restart only what ran, not-loaded stop, dead stdout, tail-repair off by one), privctl selftest-bypass, residual evidence tests
23217b0 forge-node N4 M-108/M-109: doctor hub 5xx = indeterminate (rc 4) + switcher hold/escalation; ledger created by the install, missing ledger = refusal
ffb86c4 forge-node N4 M-112: fix flaky test_concurrent_overlapping_batches_store_each_record_once (test precondition depended on advisory-lock order), FN_REPEAT runner option
563337e docs(n4): scope - N4 section of the design quoted, M-108/M-109/M-110/M-112, spec question (no N4 list in §16)
