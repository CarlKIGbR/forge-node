# PROBEFIX report (forge-node 0.5.1, branch probefix off 24189d3)

Root cause, fix and tests: see PROBEFIX_DIAG.md. Owner steps: PROBEFIX_OWNER_UPGRADE.md (g2: `forge-node-release switch 0.5.1`, no policy re-apply).

* Root cause: forge-node's own selfcheck (limit=1024 on /proc/net/dev = 7644 bytes on g2; `/proc/self/net/dev` never in `Fs.READ_ALLOW`). No Landlock/seccomp/unit property involved; the unit could not be exercised here (no root, no user bus, userns blocked).
* Fix class: `t0/needs.py` declares per probe commands + reads (+limit) + Fs metadata methods; probe Fs and selfcheck are generated from it; undeclared = `not_declared`.
* Suite on the final tree: 1331 passed, 5 skipped (docker-only: 5 harness tests incl. the new upgrade run). Harness: g2 g3 g1 g4 16/16, `--doctor-rc 1` 12/12, `--doctor-rc 1 --upgrade` 16/16.
* Mutants killed: 8/8 (old /proc/self path, 1024 limit, extra read in net, dropped /etc/group, dropped list_meta, no enforcement, any-pid regex, selfcheck sample "self").
* Not proven here: the systemd transient unit itself (doctor on g2 is the proof), zsh behaviour of the Mac blocks (no zsh here; blocks are heredoc scripts run by bash), `switch` against real systemd (stub systemctl/doctor in the harness; real switcher code).
* Gates A–D unchanged (met=False); T0 read-only; unit properties, capabilities, policy untouched.
