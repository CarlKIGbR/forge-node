# forge-node Slice N4 — scope (STEP 0)

Branch `n4`, base `main` e4b9efa. Hard limits ADR-025/ADR-028: only tier T0 is released; N4 enables, unlocks and exercises no T1/T2/T3 capability, opens no gate A–D, touches no real host, `/etc`, systemd or sudoers. Workload volumes, VM start and units with `OnSuccess=`/`OnFailure=`/`isolate` stay locked in code and policy.

## 1. The N4 section of the design (`docs/design/FORGE_NODE.md`, quoted verbatim)

### 1.1 §15 line 955 (slice list, N4 entry)
> **N4** install on g2 + round 0 + M1 — 1 d + observation 

### 1.2 §15 line 956 (mandatory acceptance) and line 958 (tripwire)
> **No mutating op is enabled before gate D.** N1–N4 are the T0 path.
> Tripwire (§2): after N4 + 3 months without a T1/T2 request, stop at T0.

### 1.3 §14.1 T0 acceptance ("closes N4 / round 0")
> - **T0 acceptance (closes N4 / round 0; no workload and no mutating op involved):** (1) all four nodes `active`, certs and policy serial as signed; (2) audit chains verify on node and hub; `priv.jsonl` on g1/g4 holds only read-only probe intent/result pairs; (3) STOP test: `forge-stop` ⇒ within ≤ 100 s every node's lease shows `stop`, a test T1 dry-run is `DENY_STOP` **also when sent directly to the privd socket** (`privctl selftest-bypass`), T0 still answers; `forge-release` ⇒ resumes; (4) before/after hash comparison of KMU/Trading evidence (§13.E) shows no change; (5) agent footprint within limits on every host over 24 h; (6) no new listener on g1/g3/g4 (`ss` diff); (7) redaction canaries injected into a test unit's log never reach the hub DB; (8) one deliberate anomaly (test cert with 10 days left) raises exactly one inbox escalation; (9) `doctor` selfcheck passes for every **enabled** op (the T0 ops) in its real unit on g2 and g3; (10) the gate-D tests (real rotation, descriptors, crash recovery) pass on g2, and a hostile rotation drill — while rotation runs, a process as `forgenode` attempts rename/unlink/symlink/hard link/truncate in both log directories and on the lock files — fails everywhere and the chains verify; (11) every gated feature is verified **disabled**: the policy validator rejects `tiers_enabled` > 0, `workloads_enabled:true`, `vm_pool`, `t2.ops` and `t3` flags while the gates are unmet, and a direct privd request for a gated op is denied.

### 1.4 §13.C install body (C1–C7, owner commands that N4 makes executable; abridged to the lines N4 code must implement or verify)
```
# audit/priv log directories are ROOT-owned: the agent must have no write permission on any directory in the privileged path (files are created by 'privctl audit-init' in C4)
sudo install -d -m 0750 -o root -g forgenode /var/log/forge-node-priv
sudo mkdir -p /opt/forge-node/releases/$VER
sudo tar -xf /tmp/forge-node-$VER-$PROFILE.tar -C /opt/forge-node/releases/$VER --strip-components=1 --no-same-owner
sudo chown -R root:root /opt/forge-node/releases/$VER
sudo install -m 0755 -o root -g root /opt/forge-node/releases/$VER/sbin/forge-node-release /usr/local/sbin/forge-node-release
sudo /usr/local/sbin/forge-node-release install-first $VER     # verifies the signed manifest, sets 'current', links units, daemon-reload
sudo /opt/forge-node/current/bin/privctl audit-init             # proves the seal protocol on the log filesystem (canary file: +a, +i, descriptors held across), creates privd's root-only state dirs, then the first log generations + CURRENT + lock files with the owners/modes of section 8.2 (+a)
ls -l /opt/forge-node/current /var/log/forge-node-priv /var/log/forge-node-agent; ls -l /etc/systemd/system | grep forge-node
sudo install -m 0644 -o forgenode -g forgenode /tmp/ca.crt   /etc/forge-node/pki/ca.crt
sudo systemctl enable --now forge-node-privd.socket
sudo /opt/forge-node/current/bin/privctl policy-apply /tmp/policy-$NID.json /tmp/policy-$NID.json.sig
sudo /opt/forge-node/current/bin/privctl status                          # policy serial 1, mode observe, lease: none yet

# C7 doctor (selfcheck of every enabled op inside its real transient unit), then the agent
sudo -u forgenode env FORGE_NODE_NODE_ID=$NID /usr/bin/python3 -I /opt/forge-node/current/forge-node.pyz doctor          # clock, certs, hub reachability+pin, policy, privd, forge root volume mounted, per-op selfcheck; expect OK (hub: 'unregistered')
```

### 1.5 What N3 left to N4 (design §16.3 "Not in N3", N3_REPORT deviation 6 and residual 6)
> the install and the real-unit proof of the hardening on a node (`doctor`, N4).
> N3_REPORT dev. 6: "`privctl selftest-bypass` (the N4 STOP test sends a hub-signed T1 dry-run straight to the socket) — a root command that sends a given signed envelope to the socket; trivial on top of `PrivClient`, but N4's, not N3's."
> N3_REPORT residual 6 (B9): "… N4 (install) decides whether `doctor` creates the ledger so that \"absent\" can become a refusal."

## 2. The four M-items (task text, verbatim)
- **M-108:** `doctor` treats hub 5xx neither as PASS nor FAIL: up to 3 retries with backoff, then state `indeterminate`; node stays on the known-good release, no further switch, escalation record to the Betriebsleiter.
- **M-109:** install creates the ledger; a missing ledger afterwards is a refusal (fail closed).
- **M-110:** the 8 named residuals in N3_REPORT: for each either fix with a test or confirm with evidence that no non-root uid gains a privileged effect. Table.
- **M-112:** flake `tests/test_hub_audit.py::test_concurrent_overlapping_batches_store_each_record_once` — find the root cause (concurrency), fix product or test with justification; prove with 50 consecutive runs of that test.

## 3. SPEC-QUESTION: the design has no N4 acceptance list
`FORGE_NODE.md` §16 has acceptance lists for N1 (§16.1), N2 (§16.2) and N3 (§16.3) but **no §16.4**; the N4 entry in §15 (line 955) is one line ("install on g2 + round 0 + M1 — 1 d + observation"). The task says "the N4 section's test list".
- **Reading A (adopted, built on):** the N4 list is derived (as N3 did for its own list) from the places the design assigns to N4: §14.1 T0 acceptance (1)–(11), §13.C install body, §16.3 "Not in N3" (install + real-unit proof of `doctor`) and N3_REPORT dev. 6 / residual 6. Of the 11 acceptance items those that a slice can prove **without a real host** become named tests (3 `selftest-bypass`, 7 canaries, 8 one escalation for an expiring cert, 11 gated features disabled, 2 chains verify); items that need the four real servers (1, 4, 5, 6, 9 on real units, 10 on g2's real filesystem) are NOT claimed — they are the install/observation half of N4 which the hard limits forbid here ("nothing installed on any host").
- **Reading B:** N4 = only the owner's install on g2 plus 24 h observation; there is nothing to build or test in the repository. Rejected: the task itself lists install/doctor/ledger as scope and the M-items are code.
The derived list is in `docs/reports/N4_REPORT.md` (§16.4 text proposed there, for the Betriebsleiter to confirm).

## 4. Out of scope / locked (not touched by N4)
T1/T2/T3 ops and their policies, gates A–D (`gates.py` stays `met=False`), `volume.*` / workload start, VM start/define, units with `OnSuccess=`/`OnFailure=`/`isolate` (resolver rejection stays), any real-host contact, any install, any service outside throw-away test containers.
