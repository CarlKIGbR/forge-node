# PROBEFIX step 0 — diagnosis (base 24189d3, forge-node 0.5.0 t0, first install on carlgpu2, 2026-11-08)

## Verdict (proven by reproduction, see below)

**Neither probe is denied by a sandbox.** There is no Landlock ruleset, no seccomp rule and no unit property involved. Both failures are bugs in forge-node's own selfcheck
(`src/forge_node/t0/selfcheck.py`, run by `probe_main --selfcheck <probe>`), and each reproduces as plain uid `forge` **outside any unit** on this kernel (7.0.0-31-generic):

| probe | selfcheck read | what actually happens | cause |
|---|---|---|---|
| `net` | `fs.read_text("/proc/net/dev", 1024)` | `FsError too_large: /proc/<pid>/net/dev` | selfcheck passes `limit=1024`; /proc files report size 0, so `Fs.read_text` reads `limit+1` bytes and raises `too_large` if the file is longer. `/proc/net/dev` is **7644 bytes** on g2 (docker0, br-*, ~20 veth) — it would pass only on a host with ≤ ~6 interfaces |
| `container_net` | `fs.read_text("/proc/self/net/dev", 1024)` | `FsError not_allowed: /proc/self/net/dev` | `Fs.READ_ALLOW` knows `/proc/net/dev` and `/proc/<digits>/net/dev`, never the literal `self`; the check is on the REQUESTED path, so the file is refused before it is opened. Would fail on **every** host |

`doctor` prints both as "denied inside the real unit: [path]" because it renders every non-ok `missing` entry that way (doctor.py:222); the text is a label, not a finding, and `missing` carries
no reason code — that hid the real error.

Two further defects in the declaration (`PROBE_NEEDS`), same class:
* `net` declares `/proc/net/dev`, but the `net` probe (`probes._probe_net`) only runs `ss -p`; it never reads that file. (The agent's T0 metrics read it, in the agent unit, with a 1 MiB limit.)
* `container_net` declares `/proc/self/net/dev`, but the probe really reads `/proc/<container pid>/net/dev` (probes.py:177, default 1 MiB limit). Reading a container's file as an unprivileged user works on
  this host (checked as uid 994 against three running containers), so no PTRACE/capability is needed — consistent with `container_net` having `caps=()`.

## Where "inside the real unit" runs

privd (root) starts `python -I forge-node.pyz probe --selfcheck <name>` in a transient `ro-probe` unit (`privd/main.py:68`, properties `hardening.ro_probe_properties`) and relays the JSON.
The check itself is `probe_main.main` → `selfcheck.probe_selfcheck(name, env)` using the same `Fs` allowlist the probe uses. Unit properties that touch /proc (`ProtectKernelTunables`: read-only
/proc/sys, /proc/acpi, /proc/fs, ...) do not cover /proc/net, `ProcSubset=` is not set, and the other 10 probes (same `_COMMON` base properties) pass in the same unit on g2, so the unit is not the denier.

## Reproduction (fails on 24189d3, this kernel, no unit, no sandbox) — `docs/reports/PROBEFIX_REPRO.py`

```
PYTHONPATH=src python3 docs/reports/PROBEFIX_REPRO.py
7.0.0-31-generic uid 994 wc -c /proc/net/dev = 7644
net            paths={'/proc/net/dev': False} <-- DENIED
firewall       (no paths) 
containers     (no paths) 
container_net  paths={'/proc/self/net/dev': False} <-- DENIED
vms            (no paths) 
certs          (no paths) 
git            (no paths) 
access         paths={'/etc/group': True, '/etc/passwd': True} 
models         (no paths) 
journal        (no paths) 
activity       (no paths) 
uulog          paths={'/var/log/unattended-upgrades/unattended-upgrades.log': False} <-- DENIED
read /proc/net/dev 1024 -> too_large: /proc/1867849/net/dev
read /proc/net/dev 1048576 OK
read /proc/self/net/dev 1048576 -> not_allowed: /proc/self/net/dev
read /proc/1867849/net/dev 1048576 OK
```
(`uulog` is `False` here only because uid forge cannot read the root:adm 0750 log; the probe runs as root, and it passed on g2.)

## Why the tests and the owner-guide dry run did not catch it

* No test ever runs `probe_selfcheck` for `net` / `container_net` against the real /proc: `test_doctor` only asserts statuses of `probe:access` and `probe:vms` (the `served` fixture), and the
  all-probes test (`test_doctor_paces_every_selfcheck…`) asserts only "no DENY_RATE" — the 12 statuses are never compared with `ok`.
* `PROBE_NEEDS` is a free-standing list, not connected to what the probe code reads and not to the `Fs` allowlist; nothing compares them.
* Test trees (`FN_TEST_FS_ROOT`) have small fake files; a 1024-byte limit only bites on a real /proc with many interfaces.
* The owner-guide dry run stubs `doctor` ("permission check as forgenode + injected verdict", run_guide.py:17) — it executes the guide blocks, not the probes.
* The design's "validation inside the real unit" was therefore only ever exercised with the test double (LocalProcessBackend), never on a real kernel with a real /proc.
