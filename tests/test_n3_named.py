"""The design's named acceptance tests (§16: T-GATE, T-PRIV, T-REL, T-APT, T-STORE, T-AUDIT, carried-over) that need a test of their own. Each one is small and checks one behaviour; the
big scenarios live in the topic files. N3's list (§16.3) refers to these by name."""
import ast
import dataclasses
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from audit_helpers import AGENT_UID
from privd_helpers import NODE, SRC, PrivdEnv, gates_with, policy_doc

from forge_node import gates, protocol, sshsig
from forge_node.privd import classes, optable
from forge_node.privd.gate import owner_binding
from forge_node.t0 import hardening

ROOT = Path(SRC).parent
PRIVD = Path(SRC) / "forge_node" / "privd"


def result(r):
    assert r["ok"] is True and "result" in r, r
    return r["result"]


@pytest.fixture
def e(privd_env):
    return privd_env.ready()


EARLY = {"DENY_STOP", "DENY_LOCAL_STOP", "DENY_STALE_LEASE", "DENY_CLOCK"}          # denied at steps 3-5, before the intent record: a `denial` record only


def denied(e, code, dry_run=True, **kw):
    r, job = e.exec(dry_run=dry_run, **kw)
    res = result(r)
    assert res["status"] == "denied" and res["reason_code"] == code, res
    trail = [x["type"] for x in e.priv_records() if x.get("job_id") == job["job_id"]]
    assert trail == (["denial"] if code in EARLY else ["intent", "result"]), (code, trail)
    assert not os.path.exists(f"{e.paths.work}/{job['job_id']}-1/effect.mark")
    assert not [u for u in e.backend.list_op_units() if job["job_id"] in u], "a unit was started for a denied job"
    return res, job


# ============================================================================================================================ T-GATE
def test_privd_direct_denied_on_stop(e):
    e.put_lease(seq=2, stop=True)
    denied(e, "DENY_STOP")
    e.put_lease(seq=3, projects=("p",))
    denied(e, "DENY_STOP", project="p")


def test_privd_direct_denied_on_local_stop(e):
    open(e.paths.local_stop, "w").close()
    res, job = denied(e, "DENY_LOCAL_STOP")
    assert e.ledger.get(job["job_id"]).state == "denied_retryable"


def test_privd_direct_denied_on_stale_lease(e):
    e.clock.advance(seconds=61)
    denied(e, "DENY_STALE_LEASE")


def test_privd_direct_denied_on_lease_seq_replay(e):
    assert e.put_lease(seq=5)["ok"] and e.put_lease(seq=6, stop=True)["ok"]
    r = e.put_lease(seq=5)                                                                   # replaying the older, permissive lease must not lift the stop
    assert r["ok"] is False and r["code"] == "DENY_STALE_LEASE"
    denied(e, "DENY_STOP")


def test_privd_direct_observe_forces_dry_run(privd_env):
    e = privd_env.ready(mode="observe", serial=2)
    r, job = e.exec(params={"note": "x"})
    assert result(r)["status"] == "dry_run" and not os.path.exists(f"{e.paths.work}/{job['job_id']}-1/effect.mark")


def test_privd_direct_denied_on_rate_limit(privd_env):
    e = privd_env.ready(t1_ops=[{"op": "selftest.noop", "mode": "enforce", "rate": [[1, 600]]}], serial=2)
    assert result(e.exec(dry_run=True)[0])["status"] == "dry_run"
    denied(e, "DENY_RATE")


def test_privd_direct_denied_on_circuit_open(e):
    for _ in range(3):
        e.ledger.circuit_record("selftest.noop", False, 3, e.clock())
    plan = result(e.exec(dry_run=True)[0])
    assert plan["status"] == "dry_run"                                                         # dry runs continue
    denied(e, "DENY_CIRCUIT_OPEN", dry_run=False, plan_hash=plan["plan_hash"])


def test_privd_direct_denied_on_plan_hash_mismatch(e):
    plan = result(e.exec(dry_run=True)[0])
    denied(e, "DENY_STALE_PLAN", dry_run=False, plan_hash="0" * 64)
    assert plan["plan_hash"] != "0" * 64


def test_privd_direct_denied_on_window(e):
    e.clock.t = datetime(2026, 11, 3, 3, 30, tzinfo=__import__("zoneinfo").ZoneInfo("Europe/Berlin")).astimezone(timezone.utc)      # Tuesday 03:30 Berlin
    e.put_lease(seq=7)
    denied(e, "DENY_WINDOW")
    e.clock.t = datetime(2026, 11, 8, 5, 30, tzinfo=__import__("zoneinfo").ZoneInfo("Europe/Berlin")).astimezone(timezone.utc)      # Sunday before 06:00 Berlin
    e.put_lease(seq=8)
    denied(e, "DENY_WINDOW")


def protected_table(e):
    entry = e.table.get("selftest.noop")
    return optable.OpTable([dataclasses.replace(entry, params=lambda p: {"note": "", "target": p["target"]}, effect_key=lambda p: "selftest.noop",
                                                 protected=optable.path_not_protected("target"), allowlist=optable.target_allowed("target"))])


def test_privd_direct_denied_on_protected_target(privd_env, tmp_path):
    e = privd_env.ready(t1_ops=[{"op": "selftest.noop", "mode": "enforce", "targets": [{"name": "/srv/forge/node/x"}, {"name": str(tmp_path / "evil")}, {"name": "/opt/kmu-ai/data"}]}], serial=2)
    e.ctx.optable = protected_table(e)
    (tmp_path / "evil").symlink_to("/opt/kmu-ai")
    for target in ("/opt/kmu-ai/data", "/opt/kmu-ai/../kmu-ai/data", str(tmp_path / "evil")):          # direct, via .., via a symlink into the protected tree
        e.clock.advance(seconds=61)
        e.put_lease(seq=10 + e.clock().second + len(target))
        denied(e, "DENY_PROTECTED", params={"target": target})
    e.clock.advance(seconds=61)
    e.put_lease(seq=900)
    r = result(e.exec(dry_run=True, params={"target": "/srv/forge/node/x"})[0])
    assert r["status"] == "dry_run"
    # not on the policy's target list => DENY_NOT_ALLOWLISTED
    e.clock.advance(seconds=61)
    e.put_lease(seq=901)
    denied(e, "DENY_NOT_ALLOWLISTED", params={"target": "/srv/forge/node/other"})


def test_protected_realpath_symlink_escape_denied(tmp_path):
    check = optable.path_not_protected("p")
    pol = type("P", (), {"protected_paths": ("/srv/models",)})()
    (tmp_path / "models").mkdir()
    link = tmp_path / "forge-link"
    link.symlink_to("/srv/models")
    for bad in ("/srv/models", "/srv/models/x", "/srv/models/../models/x", str(link), str(link / "sub")):
        with pytest.raises(protocol.ProtoError) as ex:
            check(pol, {"p": bad})
        assert ex.value.code == "DENY_PROTECTED", bad
    check(pol, {"p": "/srv/forge/node/x"})
    check(pol, {"p": "/srv/modelsX/x"})                                                         # a prefix of the string is not a prefix of the path


def test_privd_direct_denied_on_unsigned_or_wrong_node_job(e):
    env, job = e.job_env()
    for bad in (dict(env, sig=env["sig"][:-40] + "A" * 40), env["payload"], dict(env, key_id="nobody")):
        r = e.call("exec", {"job": bad})
        assert r["ok"] is False and r["code"] == "DENY_JOB_SIGNATURE"
    r = e.call("exec", {"job": e.job_env(node="g3")[0]})
    assert r["ok"] is False and r["code"] == "DENY_JOB_SIGNATURE" and not e.ledger.open_rows()


def test_privd_direct_denied_on_expired_job(e):
    env, _ = e.job_env(ttl=10)
    e.clock.advance(seconds=11)
    assert e.call("exec", {"job": env})["code"] == "DENY_JOB_EXPIRED"


def test_privd_direct_denied_on_missing_owner_signature(privd_env):
    e = privd_env.ready(t1_ops=[{"op": "selftest.noop", "mode": "enforce", "requires": "owner_signature"}], serial=2)
    denied(e, "DENY_NEEDS_OWNER_SIG")


def test_rate_state_survives_agent_restart(privd_env):
    e = privd_env.ready(t1_ops=[{"op": "selftest.noop", "mode": "enforce", "rate": [[1, 600]]}], serial=2)
    assert result(e.exec(dry_run=True)[0])["status"] == "dry_run"
    e2 = e.restart()                                                                          # a new privd on the same state: the agent restarting changes nothing either
    denied(e2, "DENY_RATE")


def test_t0_root_probe_allowed_during_stop_but_never_mutates(privd_env):
    e = privd_env
    e.install(tiers=(0,))
    e.put_lease(seq=2, stop=True)
    open(e.paths.local_stop, "w").close()
    before = (sorted(os.listdir(e.paths.work)), sorted(os.listdir(e.paths.policy_dir)), e.ledger.open_rows(), open(e.paths.serial_file).read())
    r = e.call("t0", {"probe": "access", "params": {}})
    assert r["ok"] is True and r["probe"]["ok"] is True
    assert (sorted(os.listdir(e.paths.work)), sorted(os.listdir(e.paths.policy_dir)), e.ledger.open_rows(), open(e.paths.serial_file).read()) == before
    for probe, spec in hardening.RO_PROBES.items():                                           # and no probe unit has a writable path at all
        assert "ReadWritePaths" not in hardening.ro_probe_properties(probe) and hardening.ro_probe_properties(probe)["ProtectSystem"] == "strict", probe


def test_every_denial_is_audited(e):
    open(e.paths.local_stop, "w").close()
    n = len(e.priv_records())
    for _ in range(3):
        denied(e, "DENY_LOCAL_STOP")
    recs = e.priv_records()[n:]
    assert [r["type"] for r in recs] == ["denial"] * 3 and all(r["reason_code"] == "DENY_LOCAL_STOP" and r["attempt"] == 1 for r in recs)


def test_audit_down_denies_mutating(e):
    from forge_node.audit import fsflags
    fd = os.open(f"{e.specs['priv'].dir}/priv.000001/priv.000001.jsonl", os.O_RDONLY)
    fsflags.add_flags(fd, fsflags.IMMUTABLE)
    os.close(fd)
    e.priv_log._drop()
    e.priv_log._heal_depth = 99
    r, job = e.exec(dry_run=True)
    assert (r.get("code") or result(r)["reason_code"]) == "DENY_AUDIT_DOWN"
    assert not e.backend.list_op_units()
    t0 = e.call("t0", {"probe": "access", "params": {}})
    assert t0["ok"] is False and t0["code"] == "DENY_AUDIT_DOWN"                               # privd refuses to act when it cannot record - reads included


def test_clock_skew_denies(e):
    e.clock.advance(seconds=-62)
    denied(e, "DENY_CLOCK")


def test_policy_serial_rollback_rejected(privd_env):
    e = privd_env
    assert e.install(tiers=(0,), serial=3)["ok"]
    e.clock.advance(seconds=61)
    for serial in (3, 2, 1):
        r = e.install(tiers=(0,), serial=serial)
        assert r["ok"] is False and r["code"] == "DENY_POLICY_INVALID" and "not newer" in r["detail"]
    assert e.ctx.policies.current().serial == 3


# ============================================================================================================================ T-PRIV
def test_no_sudoers_entry_for_forgenode():
    from forge_node.release import build, units
    texts = "\n".join(units.all_units().values())
    assert "sudo" not in texts and "NOPASSWD" not in texts
    man_files = {"forge-node.pyz", "bin/privctl", "sbin/forge-node-release", *[f"units/{u}" for u in units.all_units()]}
    assert not [f for f in man_files if "sudoers" in f]
    for p in (ROOT / "src").rglob("*.py"):
        t = p.read_text()
        assert "/etc/sudoers" not in t.replace('"/etc/sudoers", "/etc/sudoers.d"', "").replace("/etc/sudoers.d", "").replace('"/etc/sudoers"', "") or p.name in ("policies.py", "policy_full.py"), p
    assert not [p for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts and "sudoers" in p.name and p.suffix not in (".md", ".py")]


def test_dir_ops_rw_paths_derived_from_policy_only():
    p = classes.op_unit_properties("dir-ops", work_dir="/w/job-1", priv_state="/p", forge_roots=("/srv/forge/node", "/var/lib/forge-node/data"), timeout_s=30)
    assert p["ReadWritePaths"] == "/w/job-1 /p/locks /srv/forge/node /var/lib/forge-node/data"
    assert classes.op_unit_properties("dir-ops", work_dir="/w/job-1", priv_state="/p", timeout_s=30)["ReadWritePaths"] == "/w/job-1 /p/locks"      # no roots in the policy => none
    for cls in classes.CLASSES:
        if cls != "dir-ops" and cls not in classes.NO_FILESYSTEM_SANDBOX:
            assert "/srv/forge" not in classes.op_unit_properties(cls, work_dir="/w", priv_state="/p", forge_roots=("/srv/forge/node",), timeout_s=30)["ReadWritePaths"], cls
    import inspect
    assert [n for n in inspect.signature(classes.op_unit_properties).parameters] == ["cls", "work_dir", "priv_state", "forge_roots", "timeout_s"]       # no free-form property argument


def test_privd_unit_writes_only_state_log_policy():
    from forge_node.release import units
    props = units.PRIVD_SERVICE
    assert set(props["ReadWritePaths"].split()) == {"/var/lib/forge-node-priv", "/var/log/forge-node-priv", "/var/log/forge-node-agent", "/run/forge-node", "/etc/forge-node"}
    assert props["ProtectSystem"] == "strict" and props["ProtectHome"] == "yes" and props["NoNewPrivileges"] == "yes" and props["RestrictAddressFamilies"] == "AF_UNIX"
    # privd performs no effect itself: nothing in privd starts a program other than through the backend / the trusted command wrapper
    assert "docker" not in (PRIVD / "gate.py").read_text().replace("docker-ctl", "")


def test_ops_run_in_real_transient_units_selfcheck(e):
    """privd runs each op's and each probe's side-effect-free selfcheck in a unit of the op's class. (The test double starts real processes; the sandbox properties themselves are only
    in force in a real systemd unit - `doctor` proves that on the install.)"""
    seen = []
    real = e.backend.run_pipe
    e.backend.run_pipe = lambda name, props, argv, stdin, timeout: seen.append((name, dict(props), list(argv))) or real(name, props, argv, stdin, timeout)
    r = e.call("selfcheck", {"target": "op:selftest.noop"}, uid=AGENT_UID)
    assert r["ok"] and r["selfcheck"]["ok"] is True, r
    name, props, argv = seen[0]
    assert props["ProtectSystem"] == "strict" and "ReadWritePaths" in props and props["User"] == "root" and argv[-2] == "selfcheck"
    assert e.call("selfcheck", {"target": "op:nonexistent"})["code"] == "DENY_OP_UNKNOWN"          # (the probe selfchecks run in test_doctor with a tier-0 policy)


def test_op_units_do_not_write_priv_log_directly():
    """Op units never write priv.jsonl: the modules that run inside an op unit (worker, ops, opworker) do not import the audit package, and no unit class makes a log directory writable."""
    for f in ("worker.py", "ops.py", "opworker.py"):
        tree = ast.parse((PRIVD / f).read_text())
        for n in ast.walk(tree):
            if isinstance(n, ast.ImportFrom) and n.module:
                assert not n.module.startswith(("audit", "..audit")), (f, n.module)
            if isinstance(n, ast.Import):
                assert not any("audit" in a.name for a in n.names), f
    for cls in classes.CLASSES:
        props = classes.op_unit_properties(cls, work_dir="/var/lib/forge-node-priv/work/j-1", priv_state="/var/lib/forge-node-priv", forge_roots=("/srv/forge/node",), timeout_s=30)
        assert "/var/log" not in props.get("ReadWritePaths", ""), cls


def test_privd_never_reads_agent_supplied_paths():
    """Every place in privd (except the root CLI) that opens or creates a path: its path expression is built from the context's fixed paths, constants, names validated as uuid/int,
    or a descriptor - never from a request body. Reviewed list; a new one fails this test until it has been reviewed."""
    fixed = "fixed path of the install layout (core.Paths / constructor argument), no request field"
    reviewed = {
        ("core.py", "FileLock.__enter__"): "lock path from core.job_lock_path (canonical uuid) or worker.lock_path (sha256 hex)",
        ("gate.py", "_local_stop_active"): fixed, ("gate.py", "s_lockdown"): fixed + " (LOCAL_STOP)",
        ("gate.py", "s_selfcheck_run"): "wd = ctx.paths.work + 8 random bytes hex; constant file name",
        ("gate.py", "s_started"): "work dir name = uuid + int attempt (core.work_dir_path validates both); constant 'request.json'",
        ("maintenance.py", "prune"): "job ids / attempts read from OUR ledger rows (uuid, int); fixed work/locks directories",
        ("lease.py", "LeaseStore._load"): fixed, ("lease.py", "LeaseStore._store"): fixed + ", temp name constant",
        ("ledger.py", "Ledger.__init__"): fixed,
        ("ops.py", "_marker"): "priv_state + constant", ("ops.py", "noop_effect"): "work_dir (given by privd) + constant",
        ("opworker.py", "main"): "argv[1] = work dir privd created", ("opworker.py", "selfcheck"): "work_dir / lock_dir written by privd into selfcheck.json",
        ("policy_store.py", "PolicyStore._install"): "policy_dir / serial dir (fixed) + 'policy-<int>.json' (serial validated 1..999999999), constant temp names",
        ("policy_store.py", "PolicyStore._key"): fixed, ("policy_store.py", "PolicyStore.installed_serial"): fixed, ("policy_store.py", "_chain_key"): "walks up from a fixed path",
        ("policy_store.py", "_stat_key"): fixed,
        ("units.py", "LocalProcessBackend.__init__"): "registry dir (test double)", ("units.py", "LocalProcessBackend._alive"): "/proc/<pid> of a registered unit",
        ("units.py", "LocalProcessBackend._entry"): "unit name validated by UNIT_RE", ("units.py", "LocalProcessBackend.forget"): "unit name validated by UNIT_RE", ("units.py", "LocalProcessBackend._group_alive"): "/proc",
        ("units.py", "LocalProcessBackend.list_op_units"): "registry dir listing", ("units.py", "LocalProcessBackend.start"): "unit name validated by UNIT_RE",
        ("units.py", "SystemdBackend.cgroup_empty"): "/sys/fs/cgroup + ControlGroup reported by systemd for a unit we started", ("units.py", "_proc_start"): "/proc/<pid>",
        ("worker.py", "read_status"): "work_dir taken from the ledger row", ("worker.py", "run"): "argv[1] = the work dir privd created; request fields come from privd-written request.json",
        ("worker.py", "write_status"): "work_dir given by privd",
    }
    found = {}
    for f in sorted(PRIVD.glob("*.py")):
        if f.name in ("privctl.py", "main.py", "classes.py", "client.py", "policy_full.py", "optable.py", "resolver.py", "server.py", "__main__.py", "__init__.py"):
            continue
        tree = ast.parse(f.read_text())

        def walk(body, prefix=""):
            for node in body:
                if isinstance(node, ast.ClassDef):
                    walk(node.body, node.name + ".")
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for c in ast.walk(node):
                        if isinstance(c, ast.Call) and ast.unparse(c.func) in ("open", "os.open", "os.mkdir", "os.makedirs", "os.unlink", "os.rename", "os.listdir", "os.rmdir", "sqlite3.connect",
                                                                              "os.symlink", "os.lstat", "os.stat", "shutil.rmtree") and c.args:
                            found.setdefault((f.name, prefix + node.name), []).append(ast.unparse(c.args[0]))
        walk(tree.body)
    unreviewed = {k: v for k, v in found.items() if k not in reviewed}
    assert not unreviewed, unreviewed
    # and no handler/pipeline step feeds a request field into a path-opening call: the request body is only ever read through .get() and passed to validators / signature checks
    gate_src = (PRIVD / "gate.py").read_text()
    assert not re.search(r"os\.(open|mkdir|unlink|rename)\([^)]*req\.body", gate_src) and "open(st.req" not in gate_src and "open(b[" not in gate_src


# ============================================================================================================================ T-REL
SEGMENT_RE = re.compile(r"On the server \(\*\*segment (\d)\*\*[^\n]*\n```bash\n(.*?)```", re.S)


def test_install_blocks_source_env_file_in_every_remote_segment():
    """Static lint of §13.C: shell variables do not survive ssh, so every server-side segment must start by sourcing the env file and checking every variable it uses."""
    doc = (ROOT / "docs" / "design" / "FORGE_NODE.md").read_text()
    sec = doc[doc.index("### 13.C"):doc.index("### 13.D")]
    segs = SEGMENT_RE.findall(sec)
    assert [n for n, _ in segs] == ["1", "2"], [n for n, _ in segs]
    for n, body in segs:
        first = next(l for l in body.splitlines() if l.strip())
        assert first.startswith("set -a; . /tmp/fn.env; set +a;"), f"segment {n}: does not source the env file first"
        used = set(re.findall(r"\$\{?(NID|IP|VER|PROFILE|FORGE_ROOT|FORGE_ROOT_BYTES|MIN_FREE_BYTES)\b", body))
        checked = set(re.findall(r'"\$\{(\w+):\?\}"', first))
        assert used <= checked, f"segment {n} uses {sorted(used - checked)} without checking it"
        pre = body.split(first, 1)[0]
        assert not re.search(r"\$\{?(NID|IP|VER|PROFILE|FORGE_ROOT)", pre)
    mac = sec[sec.index("On the Mac:"):sec.index("On the server (**segment 1**")]
    assert "set -a; . ./fn.env; set +a" in mac                                                  # the Mac blocks source theirs as well


def test_install_aborts_on_missing_variable(tmp_path):
    """The very first line of each remote segment, executed for real with /tmp/fn.env pointing at a test file: a missing variable aborts with a message and a non-zero status."""
    doc = (ROOT / "docs" / "design" / "FORGE_NODE.md").read_text()
    sec = doc[doc.index("### 13.C"):doc.index("### 13.D")]
    full = {"NID": "g2", "IP": "192.168.10.4", "VER": "0.3.0", "PROFILE": "full", "FORGE_ROOT": "/srv/forge/node", "FORGE_ROOT_BYTES": "1", "MIN_FREE_BYTES": "2"}
    for n, body in SEGMENT_RE.findall(sec):
        first = next(l for l in body.splitlines() if l.strip())
        for missing in [None, *sorted(full)]:
            env = tmp_path / f"fn-{n}-{missing}.env"
            env.write_text("".join(f"{k}={v}\n" for k, v in full.items() if k != missing))
            script = first.replace("/tmp/fn.env", str(env)) + "\necho PASSED\n"
            r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
            if missing is None:
                assert r.returncode == 0 and "PASSED" in r.stdout, (n, r.stderr)
            else:
                assert r.returncode != 0 and "PASSED" not in r.stdout and missing in r.stderr, (n, missing, r.stderr)


def test_install_forge_volume_checks_target_fstype_and_backing_dev():
    doc = (ROOT / "docs" / "design" / "FORGE_NODE.md").read_text()
    c3 = doc[doc.index("# C3 user, directories"):doc.index("# C4 release tree")]
    assert 'sudo chattr +i "$FORGE_ROOT"' in c3 and "findmnt -no TARGET,FSTYPE,SOURCE,OPTIONS" in c3 and "stat -c %d /var/lib/forge-node-img/forge-root.img" in c3
    assert "Options=loop,nodev,nosuid" in c3 and "Never /srv/models or /srv/kmu-ai" in c3 and "fallocate" in c3 and "mkfs.ext4" in c3


# ============================================================================================================================ T-APT / T-STORE
def test_op_table_has_no_apt_apply_in_any_profile():
    from forge_node.privd.policy_full import APT_RE
    for profile in ("full", "t0"):
        assert not [n for n in optable.build_optable(profile).names(profile) if APT_RE.search(n)]
    assert not [n for n in gates.OPS if APT_RE.search(n)] and not [k for k in gates.MANIFEST_KINDS if APT_RE.search(k)]


def test_no_apt_window_field_in_policy(privd_env):
    from forge_node.privd.policy_full import parse_full
    from forge_node.t0.policy import PolicyError
    import json
    for patch in ({"windows": {"blackout": "02:00-05:45", "apt_window": "03:00-04:00"}}, {"apt_window": "03:00-04:00"}, {"windows": {"apt": "x"}}, {"upgrade_window": "x"}):
        doc = policy_doc(gate_keys=privd_env.gate_keys(), tiers=(0,), **patch)
        with pytest.raises(PolicyError):
            parse_full(json.dumps(doc).encode(), expect_node=NODE, file_serial=1, now=__import__("privd_helpers").NOW, gates_map=gates.GATES, table_ops=lambda p: frozenset(),
                       devof=lambda p: 1, protected_devs=lambda: set())


def forge_root_doc(**kw):
    root = {"path": "/srv/forge/node", "quota_backend": "loop_fs", "backing_image": "/var/lib/forge-node-img/forge-root.img", "size_bytes": 1 << 30, "log_budget_bytes": 1 << 20, "min_free_bytes": 1 << 30}
    root.update(kw)
    return root


def parse_roots(privd_env, roots, devof=lambda p: 1, pdevs=frozenset()):
    import json
    from forge_node.privd.policy_full import parse_full
    doc = policy_doc(gate_keys=privd_env.gate_keys(), tiers=(0,), forge_roots=roots)
    return parse_full(json.dumps(doc).encode(), expect_node=NODE, file_serial=1, now=__import__("privd_helpers").NOW, gates_map=gates.GATES, table_ops=lambda p: frozenset({"selftest.noop"}),
                      devof=devof, protected_devs=lambda: set(pdevs))


def test_models_mount_fully_protected_no_forge_exception(privd_env):
    from forge_node.t0.policy import PolicyError
    for path in ("/srv/models", "/srv/models/forge", "/srv/kmu-ai/x", "/srv", "/opt/kmu-ai/forge"):
        with pytest.raises(PolicyError, match="no forge subtree exception"):
            parse_roots(privd_env, [forge_root_doc(path=path)])


def test_policy_rejects_forge_root_without_loop_fs_backend_or_on_protected_device(privd_env):
    from forge_node.t0.policy import PolicyError
    for bad in (forge_root_doc(quota_backend="project_quota"), {k: v for k, v in forge_root_doc().items() if k != "quota_backend"}, forge_root_doc(quota_backend="none")):
        with pytest.raises(PolicyError, match="loop_fs"):
            parse_roots(privd_env, [bad])
    with pytest.raises(PolicyError, match="protected device"):
        parse_roots(privd_env, [forge_root_doc()], devof=lambda p: 9, pdevs={9})


def test_backing_image_must_be_on_root_filesystem(privd_env):
    from forge_node.t0.policy import PolicyError
    with pytest.raises(PolicyError, match="root filesystem"):
        parse_roots(privd_env, [forge_root_doc()], devof=lambda p: 7 if p == "/" else 8)
    with pytest.raises(PolicyError, match="root filesystem"):
        parse_roots(privd_env, [forge_root_doc()], devof=lambda p: None if p != "/" else 1)             # image does not exist
    assert parse_roots(privd_env, [forge_root_doc()]).forge_roots[0].backing_image.endswith("forge-root.img")


def test_volume_device_differs_from_every_protected_mount(privd_env):
    from forge_node.t0.policy import PolicyError
    for protected in ({6}, {6, 9}, {1, 6, 9}):                                                  # the image's device (6) is one of the protected mounts' devices
        with pytest.raises(PolicyError, match="protected device"):
            parse_roots(privd_env, [forge_root_doc()], devof=lambda p: 6, pdevs=protected)
    assert parse_roots(privd_env, [forge_root_doc()], devof=lambda p: 6, pdevs={1, 2}).forge_roots


# ====================================================================================================================== T-REVOKE (node half)
def test_ca_bundle_overlap_rotation_is_an_agent_file_replacement_not_a_policy_change():
    """§13.F: the CA bundle is replaced on disk (old+new first) and the agent restarted; nothing in privd or the policy is involved. The agent side is tested in test_agent_client."""
    doc = (ROOT / "docs" / "design" / "FORGE_NODE.md").read_text()
    assert "cat ca/ca.crt ca_new/ca.crt > ca_bundle.crt" in doc and "systemctl restart forge-node-agent.service" in doc
