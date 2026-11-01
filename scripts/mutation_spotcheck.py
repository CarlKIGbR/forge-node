"""Mutation spot checks for the T0 layer / agent (class kritisch: every critical branch). Each mutant is ONE textual replacement applied to a throw-away COPY of the repo; the named
test files are run with scripts/run-tests.sh and must fail ("KILLED"). A survivor is a missing or too weak test - or an equivalent mutant, which must be named in the slice report.

    python3 scripts/mutation_spotcheck.py                # all mutants (~12 min)
    python3 scripts/mutation_spotcheck.py pin-check ...  # selected ids
Patterns are exact source text: when the code changes, a mutant reports NOT-APPLIED and its pattern must be updated (that is deliberate - a silently skipped mutant proves nothing)."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SRC = str(Path(__file__).resolve().parents[1])
WORK = os.path.join(tempfile.gettempdir(), "fn-mutation-work")
IMAGES_LOCK = os.path.join(SRC, "..", "forge-core", "images.lock")
PG = os.environ.get("FN_PG_IMAGE") or subprocess.run(["sed", "-n", "s/^IMG_PGVECTOR=//p", IMAGES_LOCK], capture_output=True, text=True).stdout.split()[0]
M = [
 # id, file, old, new, tests
 ("engine-gates", "t0/engine.py", "        if not d.allowed:\n            return Outcome(\"denied\", d.code, d.detail)", "        if False:\n            return Outcome(\"denied\", d.code, d.detail)", "tests/test_t0_engine.py"),
 ("engine-window", "t0/engine.py", "if heavy and env.policy.window.in_blackout(env.now()):", "if False and env.policy.window.in_blackout(env.now()):", "tests/test_t0_engine.py"),
 ("engine-rate", "t0/engine.py", "            if not self.limiter.take(op, heavy):", "            if False:", "tests/test_t0_engine.py"),
 ("engine-logs-allow", "t0/engine.py", "if op == \"logs.unit\" and env.policy.log_unit(params[\"unit\"]) is None:", "if False:", "tests/test_t0_engine.py"),
 ("engine-tier0-policy", "t0/engine.py", "if 0 not in env.policy.tiers_enabled:", "if False:", "tests/test_t0_engine.py"),
 ("engine-params", "t0/engine.py", "            params_mod.validate_t0(op, params)", "            pass", "tests/test_t0_engine.py"),
 ("client-pin", "agent/client.py", "        if not pin_matches(der, self._pins):", "        if False:", "tests/test_agent_client.py"),
 ("client-tls13", "agent/client.py", "    ctx.minimum_version = ssl.TLSVersion.TLSv1_3\n", "", "tests/test_agent_client.py"),
 ("client-hostname", "agent/client.py", "    ctx.check_hostname = True", "    ctx.check_hostname = False", "tests/test_agent_client.py"),
 ("policy-signature", "t0/policy.py", "        sshsig.verify(raw, sig.decode(\"ascii\"), sshsig.NS_POLICY, OWNER_PRINCIPAL, signers, ssh_keygen)", "        pass", "tests/test_t0_policy.py"),
 ("policy-gates", "t0/policy.py", "    if viol:", "    if False:", "tests/test_t0_policy.py"),
 ("policy-serial-name", "t0/policy.py", "serial != file_serial", "False", "tests/test_t0_policy.py"),
 ("policy-node", "t0/policy.py", "    if doc.get(\"node\") != expect_node:", "    if False:", "tests/test_t0_policy.py"),
 ("policy-notbefore", "t0/policy.py", "if protocol.parse_ts(doc.get(\"not_before\")) > now:", "if False:", "tests/test_t0_policy.py"),
 ("policy-perms", "t0/policy.py", "or st.st_mode & 0o022 or st.st_size > limit:", "or st.st_size > limit:", "tests/test_t0_policy.py"),
 ("policy-customer", "t0/policy.py", "if lu.sensitivity != \"customer\" and any(", "if False and any(", "tests/test_t0_policy.py"),
 ("runner-trust", "t0/runner.py", "        return s.st_uid == 0 and stat.S_ISREG(s.st_mode) and not (s.st_mode & 0o022) and _dirs_trusted(os.path.dirname(p))", "        return True", "tests/test_t0_runner.py"),
 ("runner-slot", "t0/runner.py", "if not isinstance(v, str) or not pat.match(v) or", "if not isinstance(v, str) or False or", "tests/test_t0_runner.py"),
 ("runner-dash", "t0/runner.py", "(v.startswith(\"-\") and tok in (f\"<{name}>\", f\"<{name}...>\"))", "False", "tests/test_t0_runner.py"),
 ("runner-shell", "t0/runner.py", "shell=False", "shell=True", "tests/test_t0_runner.py"),
 ("runner-env", "t0/runner.py", "    env = {**_ENV_BASE, **dict(cmd.env)}", "    env = {**os.environ, **dict(cmd.env)}", "tests/test_t0_runner.py"),
 ("runner-killpg", "t0/runner.py", "        os.killpg(p.pid, signal.SIGKILL)", "        p.kill()", "tests/test_t0_runner.py"),
 ("fs-protected", "t0/fsread.py", "        if self.protected.hit(logical) or self.protected.hit(real):", "        if False:", "tests/test_t0_fs_window_limits.py"),
 ("fs-allowlist", "t0/fsread.py", "        if not any(rx.match(logical) for rx in READ_ALLOW):", "        if False:", "tests/test_t0_fs_window_limits.py"),
 ("fs-nofollow", "t0/fsread.py", "flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK", "flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK", "tests/test_t0_fs_window_limits.py"),
 ("fs-sys-escape", "t0/fsread.py", "            if not real.startswith(\"/sys/\"):\n                raise FsError(\"escape\", logical)", "            if False:\n                raise FsError(\"escape\", logical)", "tests/test_t0_fs_window_limits.py"),
 ("fs-exception-pattern", "t0/fsread.py", "        if not allowed_names.match(logical):", "        if False:", "tests/test_t0_fs_window_limits.py"),
 ("probe-journal-allow", "t0/probes.py", "    if lu is None:\n        raise ProbeError(\"DENY_NOT_ALLOWLISTED\"", "    if False:\n        raise ProbeError(\"DENY_NOT_ALLOWLISTED\"", "tests/test_t0_probes.py"),
 ("probe-heavy-window", "t0/probes.py", "    if name in HEAVY_PROBES and env.policy.window.in_blackout(env.now()):", "    if False:", "tests/test_t0_probes.py"),
 ("probe-ionice", "t0/probes.py", "sizes_ok = env.runner.available(\"du_ionice\")", "sizes_ok = True", "tests/test_t0_probes.py"),
 ("probe-cert-keyfiles", "t0/probes.py", "(?!.*(?i:priv|key|secret))", "", "tests/test_t0_probes.py"),
 ("probe-authkeys-options", "t0/parse.py", "\"has_options\": idx > 0}", "\"has_options\": idx > 0, \"options\": toks[:idx]}", "tests/test_t0_parse.py"),
 ("wire-peer", "t0/wire.py", "            if uid != self.expect_uid:", "            if False:", "tests/test_t0_probes.py"),
 ("wire-strict-request", "t0/wire.py", "set(req) != {\"req\", \"probe\", \"params\"} or ", "", "tests/test_t0_probes.py"),
 ("spool-excl", "t0/spool.py", "os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL", "os.O_RDWR | os.O_APPEND | os.O_CREAT", "tests/test_t0_spool_metrics.py"),
 ("spool-hardcap", "t0/spool.py", "self.max_bytes = min(int(max_bytes), HARD_MAX_BYTES)", "self.max_bytes = int(max_bytes)", "tests/test_t0_spool_metrics.py"),
 ("spool-evict", "t0/spool.py", "        while len(self._segs) > 1 and sum(s for _, _, s in self._segs) > self.max_bytes:", "        while False:", "tests/test_t0_spool_metrics.py"),
 ("spool-owner", "t0/spool.py", "        if st.st_uid != self.uid:", "        if False:", "tests/test_t0_spool_metrics.py"),
 ("sanitize-redact", "t0/sanitize.py", "body = redact.redact_obj(clean_tree(body), full=full_redaction)", "body = clean_tree(body)", "tests/test_t0_sanitize.py tests/test_t0_engine.py"),
 ("sanitize-names", "t0/sanitize.py", "    t = _NAME_BAD.sub(\"?\", clean_text(s, maxlen * 2))", "    t = clean_text(s, maxlen * 2)", "tests/test_t0_sanitize.py"),
 ("sanitize-fit", "t0/sanitize.py", "        if _size(body) <= limit:\n            return body, truncated", "        if True:\n            return body, truncated", "tests/test_t0_sanitize.py tests/test_t0_engine.py"),
 ("limits-take", "t0/limits.py", "            ok = tokens >= 1.0", "            ok = True", "tests/test_t0_fs_window_limits.py"),
 ("limits-persist", "t0/limits.py", "            os.replace(tmp, self.state_file)", "            pass", "tests/test_t0_fs_window_limits.py"),
 ("window-sunday", "t0/window.py", "        return local.weekday() == 6 and t < self.sunday_open", "        return False", "tests/test_t0_fs_window_limits.py"),
 ("window-builtin-floor", "t0/window.py", "        ranges = [BUILTIN_BLACKOUT]", "        ranges = []", "tests/test_t0_fs_window_limits.py"),
 ("window-tz", "t0/window.py", "        local = now.astimezone(BERLIN)", "        local = now", "tests/test_t0_fs_window_limits.py"),
 ("loop-lease", "agent/loop.py", "            lease = protocol.verify_lease(resp[\"lease\"], rt.policy.hub_gate_keys, self.cfg.node_id, now, self._last_lease_seq, self.ssh_keygen)\n            self._last_lease_seq = lease[\"seq\"]", "            pass", "tests/test_agent_e2e.py"),
 ("loop-job-verify", "agent/loop.py", "            job = protocol.verify_job(env, rt.policy.hub_gate_keys, self.cfg.node_id, now, self.ssh_keygen)", "            job = __import__('json').loads(env['payload'])", "tests/test_agent_e2e.py"),
 ("loop-tier", "agent/loop.py", "        if job[\"tier\"] != 0:", "        if False:", "tests/test_agent_e2e.py"),
 ("loop-policy-stage-verify", "agent/loop.py", "            verify_blob(doc[\"policy\"].encode(\"utf-8\"), doc[\"sig\"], signers, self.cfg.node_id, serial, self.clock(), self.ssh_keygen)", "            pass", "tests/test_agent_e2e.py"),
 ("loop-no-policy", "agent/loop.py", "        if view is None:\n            if self.rt is not None:", "        if False:\n            if self.rt is not None:", "tests/test_agent_e2e.py"),
 ("metrics-cadence", "t0/engine.py", "abs((now - self._last_sample).total_seconds()) < metrics.MIN_INTERVAL_S", "False", "tests/test_t0_spool_metrics.py"),
 ("config-ip", "agent/config.py", "            ipaddress.ip_address(self.hub_host)", "            pass", "tests/test_n2_scope.py"),
 ("collect-protected-role", "t0/collect.py", "hit = prot.hit(norm_abs(t)) if t.startswith(\"/\") else None", "hit = None", "tests/test_t0_collect.py"),
 ("collect-statvfs", "t0/collect.py", "    t.join(timeout)", "    t.join()", "tests/test_t0_collect.py"),
 ("hardening-nnp", "t0/hardening.py", "\"NoNewPrivileges\": \"yes\", \"ProtectSystem\": \"strict\", \"PrivateTmp\"", "\"NoNewPrivileges\": \"no\", \"ProtectSystem\": \"strict\", \"PrivateTmp\"", "tests/test_n2_scope.py"),
 ("gates-unmet", "gates.py", "        GATE_D, \"audit sealing protocol for append-only logs\", \"N3\", False,", "        GATE_D, \"audit sealing protocol for append-only logs\", \"N3\", True,", "tests/test_gates.py tests/test_n2_scope.py"),
 ("fs-resolved-target", "t0/fsread.py", "        elif not any(rx.match(real) for rx in READ_ALLOW):\n            raise FsError(\"escape\"", "        elif False:\n            raise FsError(\"escape\"", "tests/test_t0_fs_window_limits.py"),
 ("runner-extra-binaries", "t0/runner.py", "if not all(_trusted(p) for p in (path, *cmd.extra_binaries)):", "if not _trusted(path):", "tests/test_t0_runner.py"),
 ("runner-trust-chain", "t0/runner.py", "            if ds.st_uid != 0 or (ds.st_mode & 0o022 and not (ds.st_mode & stat.S_ISVTX)):", "            if False:", "tests/test_t0_runner.py"),
 ("holder-any-exception", "agent/loop.py", "        except Exception as e:  # noqa: BLE001 - ANY failure to establish the policy means no policy: never keep serving the previous one", "        except PolicyError as e:", "tests/test_n2_branches.py"),
 ("holder-signers-in-signature", "agent/loop.py", "            signers = (\"allowed_signers\", *self._stat_key(os.stat(self.cfg.allowed_signers, follow_symlinks=False)))", "            signers = ()", "tests/test_n2_branches.py"),
 ("sample-tier", "t0/engine.py", "or 0 not in env.policy.tiers_enabled:\n            return None", "or False:\n            return None", "tests/test_t0_spool_metrics.py"),
 ("sample-bucket", "t0/engine.py", "            if not self.limiter.take(\"metrics.collect\", False):\n                return None", "            if False:\n                return None", "tests/test_t0_spool_metrics.py"),
 ("containers-json-mounts", "t0/probes.py", "    mj = _json_field(mounts)", "    mj = []", "tests/test_t0_probes.py"),
 ("sanitize-clamp", "t0/sanitize.py", "        return max(-canon.MAX_INT, min(canon.MAX_INT, o))          # canonical", "        return o          # canonical", "tests/test_n2_branches.py"),
 ("sanitize-key-redact", "t0/sanitize.py", "            key = redact.redact_light(clean_name(k, 96))", "            key = clean_name(k, 96)", "tests/test_n2_branches.py"),
 ("agent-keygen-passed", "agent/loop.py", "job = protocol.verify_job(env, rt.policy.hub_gate_keys, self.cfg.node_id, now, self.ssh_keygen)", "job = protocol.verify_job(env, rt.policy.hub_gate_keys, self.cfg.node_id, now)", "tests/test_agent_e2e.py"),
 ("agent-keygen-lease", "agent/loop.py", "self._last_lease_seq, self.ssh_keygen)", "self._last_lease_seq)", "tests/test_agent_e2e.py"),
 ("hardening-split-net", "t0/hardening.py", "\"net\": MappingProxyType({\"caps\": (\"CAP_SYS_PTRACE\", \"CAP_DAC_READ_SEARCH\")", "\"net\": MappingProxyType({\"caps\": (\"CAP_SYS_PTRACE\", \"CAP_NET_ADMIN\", \"CAP_DAC_READ_SEARCH\")", "tests/test_n2_scope.py"),
 ("hardening-inaccessible", "t0/hardening.py", "    p[\"InaccessiblePaths\"] = \" \".join(\"-\" + h for h in hidden)", "    p[\"InaccessiblePaths\"] = \"-/run/forge-node\"", "tests/test_n2_scope.py"),
 ("host-empty-ok", "t0/collect.py", "    if not data or all(v is None for v in data.values()):\n        return unavailable", "    if False:\n        return unavailable", "tests/test_t0_collect.py"),
 ("usage-stream", "t0/usage.py", "    for rec in spool.iter_window(since):", "    for rec in spool.window(since):", "tests/test_t0_spool_metrics.py"),
 ("statvfs-hung-memory", "t0/collect.py", "    if time.monotonic() - _HUNG.get(path, -HUNG_MEMORY_S) < HUNG_MEMORY_S:", "    if False:", "tests/test_n2_branches.py"),
 ("models-du-deadline", "t0/probes.py", "min(120.0, left))", "120.0)", "tests/test_n2_branches.py"),
 ("cert-target-rule", "t0/probes.py", "                if not _CERT_FILE.match(f_real.rsplit(\"/\", 1)[-1]) or env.fs.protected.hit(f_real):", "                if False:", "tests/test_n2_branches.py"),
 ("listmeta-nofollow", "t0/fsread.py", "        dfd = self._walk_open(base, want_dir=True)\n        try:\n            with os.scandir(dfd) as it:", "        dfd = os.open(self._actual(base), os.O_RDONLY | os.O_DIRECTORY)\n        try:\n            with os.scandir(dfd) as it:", "tests/test_n2_branches.py"),
 ("policy-keygen-required", "t0/policy.py", "owner_uid: int, ssh_keygen: str) -> PolicyView:", "owner_uid: int, ssh_keygen: str = \"ssh-keygen\") -> PolicyView:", "tests/test_t0_engine.py"),

 ("proc-mounts-regex", "t0/fsread.py", "cgroup|net/dev|comm|mounts)", "cgroup|net/dev|comm)", "tests/test_t0_fs_window_limits.py"),
 ("wire-safe", "t0/wire.py", "sanitize.wire_safe(data)", "data", "tests/test_t0_probes.py"),
 ("docker-splitlines", "t0/probes.py", "r.text.split(\"\\n\"):", "r.text.splitlines():", "tests/test_t0_probes.py"),
 ("docker-budget", "t0/probes.py", "        if left < 5:\n            return rows, None", "        if False:\n            return rows, None", "tests/test_t0_probes.py"),
 ("activity-budget", "t0/probes.py", "        if env.now().timestamp() >= t_end:\n            rows.append", "        if False:\n            rows.append", "tests/test_t0_probes.py"),
 ("runner-link-dir", "t0/runner.py", "            if hops > 8 or not _dirs_trusted(os.path.dirname(os.path.abspath(p))):", "            if hops > 8:", "tests/test_t0_runner.py"),
 ("hardening-container-net-ptrace", "t0/hardening.py", "\"container_net\": MappingProxyType({\"caps\": ()", "\"container_net\": MappingProxyType({\"caps\": (\"CAP_SYS_PTRACE\",)", "tests/test_n2_scope.py"),
 ("hardening-sockets", "t0/hardening.py", "\"/run/containerd\", \"/run/dbus\", ", "", "tests/test_n2_scope.py"),
 ("sanitize-collide", "t0/sanitize.py", "            while key in out:", "            while False:", "tests/test_n2_branches.py"),
 ("fetched-bound", "t0/../agent/loop.py", "        while len(self._fetched) > 32:", "        while False:", "tests/test_n2_branches.py"),
 ("selfcheck-limit", "t0/selfcheck.py", "env.fs.read_text(p)", "env.fs.read_text(p, 4096)", "tests/test_t0_fs_window_limits.py"),
 ("nfs-unavailable", "t0/collect.py", "if mt else unavailable(\"/proc/mounts unreadable\")", "if True else unavailable(\"/proc/mounts unreadable\")", "tests/test_t0_collect.py"),
 ("git-dir-is-the-repo", "t0/runner.py", "(\"GIT_DIR\", \"snap\", \"\")", "(\"GIT_DIR\", \"repo\", \"/.git\")", "tests/test_t0_real_tools.py tests/test_t0_runner.py"),
 ("git-common-dir-is-the-repo", "t0/runner.py", "(\"GIT_COMMON_DIR\", \"snap\", \"\")", "(\"GIT_COMMON_DIR\", \"repo\", \"/.git\")", "tests/test_t0_real_tools.py tests/test_t0_runner.py"),
 ("git-ignore-submodules", "t0/runner.py", ", \"--ignore-submodules=all\"),\n                                  slots", "),\n                                  slots", "tests/test_t0_real_tools.py tests/test_t0_runner.py"),
 ("git-inert-core-widened", "t0/probes.py", "_INERT_CORE = frozenset({\"filemode\",", "_INERT_CORE = frozenset({\"fsmonitor\", \"filemode\",", "tests/test_t0_probes.py tests/test_t0_fuzz.py"),
 ("git-snapshot-copies-config", "t0/probes.py", "            snap = _git_snapshot(info, cfg_text)", "            snap = _git_snapshot(info, env.fs.read_exception(f\"{real}/.git/config\", _SAFE_GIT_FILES))", "tests/test_t0_probes.py tests/test_t0_real_tools.py"),
 ("git-snapshot-cleanup", "t0/probes.py", "                shutil.rmtree(snap, ignore_errors=True)", "                pass", "tests/test_t0_probes.py"),
 ("git-value-check", "t0/probes.py", "and _INERT_VALUE.match(k.group(2)):", ":", "tests/test_t0_probes.py"),
 ("policy-key-mode", "agent/loop.py", "return (st.st_ino, st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_mode, st.st_uid, st.st_gid, st.st_nlink)", "return (st.st_ino, st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_uid, st.st_gid, st.st_nlink)", "tests/test_n2_branches.py"),
 ("policy-key-nlink", "agent/loop.py", "st.st_mode, st.st_uid, st.st_gid, st.st_nlink)", "st.st_mode, st.st_uid, st.st_gid)", "tests/test_n2_branches.py"),
 ("policy-key-dirchain", "agent/loop.py", "return (files, signers, self._chain_key(self.cfg.policy_dir), self._chain_key(os.path.dirname(self.cfg.allowed_signers)))", "return (files, signers)", "tests/test_n2_branches.py"),
 ("policy-signers-nlink", "t0/policy.py", " or st.st_nlink != 1 or st.st_size > 64 * 1024", " or st.st_size > 64 * 1024", "tests/test_n2_branches.py"),
 ("policy-chain-trust", "t0/policy.py", " or not _chain_trusted(os.path.dirname(os.path.abspath(policy_dir)), owner_uid):", ":", "tests/test_n2_branches.py"),
 ("sampler-protect", "t0/engine.py", "self.spool.append(sanitize.protect(metrics.take_sample(env)))", "self.spool.append(metrics.take_sample(env))", "tests/test_t0_engine.py"),
 ("redact-by-key", "redact.py", "return {k: (_blank(v) if secret_key(k) else redact_obj(v, full)) for k, v in obj.items()}", "return {k: redact_obj(v, full) for k, v in obj.items()}", "tests/test_t0_engine.py tests/test_redact.py"),
 ("redact-key-normalisation", "redact.py", "re.sub(r\"[^a-z0-9]\", \"\", key.lower())", "key.lower()", "tests/test_t0_engine.py"),
 ("limits-timestamp-backwards", "t0/limits.py", "            last = max(last, now)", "            last = now", "tests/test_t0_fs_window_limits.py"),
 ("net-hostns-detection", "t0/metrics.py", "        if _host_has_container_bridges(host_ifs) and set(nd) >= host_ifs:", "        if False:", "tests/test_t0_spool_metrics.py"),
 ("net-counter-reset", "t0/usage.py", "    return cur - prev if cur >= prev else cur", "    return max(0, cur - prev)", "tests/test_t0_spool_metrics.py"),
 ("net-ip-accounting-off", "t0/metrics.py", " and a < 2**53 and c < 2**53 and len(net) < 2 * MAX_CG", "", "tests/test_t0_spool_metrics.py"),
 ("net-window-not-aggregated", "t0/usage.py", "            e[\"rx\"] += _grow(e[\"prev\"][0], v[0])", "            e[\"rx\"] += 0", "tests/test_t0_spool_metrics.py"),
 ("ref-validation-in-git-rev", "t0/probes.py", "    if not valid_branch(branch):\n        return {\"rev\": None, \"branch\": None, \"detached\": False, \"ref_error\": \"malformed_ref\"}", "    if False:\n        return {\"rev\": None, \"branch\": None, \"detached\": False, \"ref_error\": \"malformed_ref\"}", "tests/test_t0_probes.py tests/test_t0_real_tools.py"),
 ("ref-validation-in-snapshot", "t0/probes.py", "    if not info.get(\"detached\") and not valid_branch(info.get(\"branch\")):", "    if False:", "tests/test_t0_probes.py"),
 ("branch-charset", "t0/probes.py", "re.fullmatch(r\"[A-Za-z0-9._/-]+\", name)", "re.fullmatch(r\".+\", name)", "tests/test_t0_probes.py"),
 ("branch-leading-slash", "t0/probes.py", "    if name.startswith((\"/\", \"-\")) or", "    if name.startswith((\"-\",)) or", "tests/test_t0_probes.py"),
 ("confined-component-rule", "t0/confined.py", "COMPONENT = re.compile(r\"^[A-Za-z0-9_][A-Za-z0-9._-]{0,99}\\Z\")", "COMPONENT = re.compile(r\"^.+\\Z\")", "tests/test_t0_probes.py"),
 ("confined-nofollow", "t0/confined.py", "nfd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)", "nfd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=fd)", "tests/test_t0_probes.py"),
 ("confined-excl", "t0/confined.py", "os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent", "os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent", "tests/test_t0_probes.py"),
 ("confined-open-dir-nofollow", "t0/confined.py", "return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)", "return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)", "tests/test_t0_probes.py"),
 ("staging-serial-range", "agent/loop.py", "if isinstance(serial, bool) or not isinstance(serial, int) or not 1 <= serial <= 999_999_999:", "if False:", "tests/test_t0_probes.py"),
 ("staging-through-descriptor", "agent/loop.py", "dfd = confined.mkdirs_at(sfd, [\"staging\"])", "os.makedirs(os.path.join(self.cfg.state_dir, \"staging\"), exist_ok=True); dfd = os.open(os.path.join(self.cfg.state_dir, \"staging\"), os.O_RDONLY | os.O_DIRECTORY)", "tests/test_t0_probes.py"),
]
# Survivors that are equivalent by construction (the same fact is covered by a second, independent element of the cache key); named here so the verdict says so.
EQUIVALENT = {
    "engine-logs-allow": "engine step 5 and T0Engine._logs both enforce the logs.unit allowlist (defence in depth); the inner one has its own test",
    "ref-validation-in-snapshot": "valid_branch is also enforced upstream in _git_rev and by confined.py's component rule inside the writer (three independent layers; each has its own test)",
    "branch-leading-slash": "a leading '/' also yields an empty first component, refused by the per-component rule of valid_branch itself",
    "policy-key-mode": "st_ctime_ns is in the cache key and changes on every chmod",
    "policy-key-nlink": "st_ctime_ns is in the cache key and changes on every link/unlink",
}
only = sys.argv[1:]
res = []
for mid, f, old, new, tests in M:
    if only and mid not in only:
        continue
    if os.path.exists(WORK):
        shutil.rmtree(WORK)
    shutil.copytree(SRC, WORK, ignore=shutil.ignore_patterns(".git", "__pycache__", ".hypothesis"))
    path = os.path.join(WORK, "src/forge_node", f)
    s = open(path).read()
    if old not in s:
        res.append((mid, "NOT-APPLIED")); print(mid, "NOT-APPLIED", flush=True); continue
    open(path, "w").write(s.replace(old, new, 1))
    p = subprocess.run([f"{WORK}/scripts/run-tests.sh", "-x", "-q", *tests.split()], capture_output=True, text=True, env={**os.environ, "FN_PG_IMAGE": PG}, timeout=900)
    tail = [l for l in p.stdout.splitlines() if l.startswith(("FAILED", "ERROR")) or " passed" in l or " failed" in l][-2:]
    verdict = "KILLED" if p.returncode != 0 else ("EQUIVALENT" if mid in EQUIVALENT else "SURVIVED")
    res.append((mid, verdict)); print(mid, verdict, " | ".join(tail)[:200], flush=True)
print(json.dumps({v: sum(1 for _, x in res if x == v) for v in ("KILLED", "EQUIVALENT", "SURVIVED", "NOT-APPLIED")}))
print("SURVIVORS:", [m for m, v in res if v not in ("KILLED", "EQUIVALENT")])
