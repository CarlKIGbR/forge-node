"""The complete policy schema (Design 7.1) and `policy.apply` (7.3): rules, signature/node/serial/not_before, atomic install, fail-closed loading."""
import base64
import json
import os
from datetime import datetime, timezone

import pytest
from privd_helpers import NODE, NOW, PrivdEnv, gates_with, policy_doc

from forge_node import canon, gates, sshsig
from forge_node.privd import optable as optable_mod
from forge_node.privd.policy_full import parse_full
from forge_node.t0.policy import PolicyError

PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOCnQJdkGAnqC9RpKFPyX3e4R8Y5v0QG9hJmFqQqkG8E"
KEYS = [{"id": "hub-gate-1", "pub": PUB, "not_after": "2099-12-31"}]
ALL_GATES = gates_with("A", "B", "C", "D")


def raw_of(**kw):
    return json.dumps(policy_doc(gate_keys=KEYS, **kw), sort_keys=True).encode()


def parse(raw=None, *, ops=frozenset({"selftest.noop"}), gates_map=None, devof=None, pdevs=frozenset(), **kw):
    raw = raw if raw is not None else raw_of(**kw)
    return parse_full(raw, expect_node=NODE, file_serial=json.loads(raw)["serial"], now=NOW, gates_map=gates_map or gates_with("D"), table_ops=lambda p: ops,
                      devof=devof or (lambda p: 1), protected_devs=lambda: set(pdevs))


def bad(match, **kw):
    with pytest.raises(PolicyError) as e:
        parse(**kw)
    assert match in e.value.detail, e.value.detail
    assert e.value.code == "DENY_POLICY_INVALID"


def test_valid_policy_is_normalised_with_builtin_protected_floor():
    p = parse(t1_ops=[{"op": "selftest.noop", "mode": "dry_run_only", "rate": [[3, 60]]}])
    assert p.serial == 1 and p.profile == "full" and p.tiers == (0, 1) and p.global_mode == "enforce"
    assert p.ops["selftest.noop"].mode == "dry_run_only" and p.ops["selftest.noop"].rate == ((3, 60),) and p.ops["selftest.noop"].requires == "none"
    assert "/srv/models" in p.protected_paths and "/opt/kmu-ai" in p.protected_paths           # builtin floor + policy
    assert "ollama.service" in p.protected_units and "forge-node-*" in p.protected_units
    assert p.circuit_threshold == 3 and p.workloads_enabled is False and not p.forge_roots


def test_unknown_keys_are_rejected_at_every_level():
    for extra in ({"surprise": 1}, ):
        bad("unknown keys", **extra)
    bad("unknown keys", t1={"workloads_enabled": False, "ops": [], "sudo": True})
    bad("unknown keys", t2={"ops": [], "x": 1})
    bad("unknown keys", t3={"manifests_enabled": [], "opaque_enabled": False, "extra": 1})
    bad("unknown keys", protected={"paths": [], "wat": []})
    bad("unknown keys", circuit={"fail_threshold": 3, "x": 1})
    bad("unknown keys", t1_ops=[{"op": "selftest.noop", "sudo": True}])
    bad("unknown keys", t0={"units_for_logs": [], "bogus": []})                                  # review: t0 and windows were open
    bad("unknown keys", windows={"blackout": "02:00-05:45", "sunday_open": "06:00", "bogus": "x"})


def test_t1_workload_fields_are_typed_and_bounded_even_before_they_mean_anything():
    ok = {"workloads_enabled": False, "ops": [], "label_selector": "forge.managed", "stack_roots": ["/srv/forge/stacks"], "vram_budget_mib": 0, "lint": {"allow_root": False, "max_pids": 512}}
    parse(t1=ok)
    for patch in ({"label_selector": "has space"}, {"label_selector": 5}, {"stack_roots": ["rel/path"]}, {"stack_roots": "x"}, {"vram_budget_mib": -1}, {"vram_budget_mib": True},
                  {"lint": {"bogus": {"nested": 1}}}, {"lint": {"bad key": 1}}, {"lint": []}, {"lint": {"a": 1.5}}, {"lint": {f"k{i}": 1 for i in range(40)}}):
        with pytest.raises(PolicyError):
            parse(t1={**ok, **patch})


def test_policy_schema_rejects_apt_apply_op_or_flag():
    for patch in ({"apt_apply": True}, {"t1": {"workloads_enabled": False, "ops": [], "apt.upgrade": 1}}, {"t3": {"manifests_enabled": ["apt.upgrade"], "opaque_enabled": False}}):
        with pytest.raises(PolicyError) as e:
            parse(**patch)
        assert "apt" in e.value.detail or "unknown" in e.value.detail
    for op in ("apt.upgrade", "apt.install_apply", "apt-get.apply", "upgrade", "dist-upgrade"):
        with pytest.raises(PolicyError):
            parse(t2_ops=[{"op": op}], tiers=(0, 2))
    # names that merely CONTAIN the words are fine: forge-node reports on unattended-upgrades, and docker.prune_apply / policy.apply are real ops
    p = parse(t0={"units_for_logs": ["unattended-upgrades.service"]})
    assert p.view.t0.units_for_logs[0].unit == "unattended-upgrades.service"
    assert not [o for o in gates.OPS if __import__("re").search(r"^(apt|upgrade)", o)]


def test_ops_must_be_in_the_release_op_table_for_the_profile():
    bad("not in this release's op table", t1_ops=[{"op": "container.stop"}], ops=frozenset({"selftest.noop"}), gates_map=ALL_GATES)
    bad("unknown op", t1_ops=[{"op": "made.up"}])
    bad("is a tier 1 op", tiers=(0, 2), t2_ops=[{"op": "selftest.noop"}])
    p = parse(t1_ops=[{"op": "container.stop"}], ops=frozenset({"selftest.noop", "container.stop"}), gates_map=ALL_GATES)
    assert "container.stop" in p.ops
    bad("duplicate op", t1_ops=[{"op": "selftest.noop"}, {"op": "selftest.noop"}])


def test_gated_features_cannot_be_switched_on_by_policy():
    bad("gate D", tiers=(0, 1), gates_map=gates.GATES, t1_ops=[])
    bad("gate A", t1={"workloads_enabled": True, "ops": []}, gates_map=gates_with("D"))
    bad("gate C", tiers=(0, 2), t2_ops=[{"op": "unit.restart", "targets": [{"name": "forge-edge.service", "closure_sha256": "a" * 64}]}], ops=frozenset({"unit.restart"}), gates_map=gates_with("D"))
    bad("gate B", t1={"workloads_enabled": False, "ops": [], "vm_pool": {"x": 1}}, gates_map=gates_with("D"))
    # with every gate met the same documents are acceptable (the gate table is the only switch)
    parse(tiers=(0, 2), t2_ops=[{"op": "unit.restart", "targets": [{"name": "forge-edge.service", "closure_sha256": "a" * 64}]}], ops=frozenset({"unit.restart"}), gates_map=ALL_GATES)


def test_unit_targets_need_closure_sha256():
    bad("closure_sha256", tiers=(0, 2), t2_ops=[{"op": "unit.restart", "targets": [{"name": "forge-edge.service"}]}], ops=frozenset({"unit.restart"}), gates_map=ALL_GATES)
    bad("closure_sha256", tiers=(0, 2), t2_ops=[{"op": "unit.restart", "targets": [{"name": "forge-edge.service", "closure_sha256": "zz"}]}], ops=frozenset({"unit.restart"}), gates_map=ALL_GATES)


def root(path="/srv/forge/node", **kw):
    d = {"path": path, "quota_backend": "loop_fs", "backing_image": "/var/lib/forge-node-img/forge-root.img", "size_bytes": 1 << 30, "log_budget_bytes": 1 << 20, "min_free_bytes": 1 << 30}
    d.update(kw)
    return d


def test_forge_roots_rules():
    p = parse(forge_roots=[root()], devof=lambda path: 5)
    assert p.forge_roots[0].path == "/srv/forge/node" and p.forge_roots[0].size_bytes == 1 << 30
    bad("loop_fs", forge_roots=[root(quota_backend="project_quota")])
    bad("loop_fs", forge_roots=[{k: v for k, v in root().items() if k != "quota_backend"}])
    bad("no forge subtree exception", forge_roots=[root(path="/srv/models/forge")])                    # test_models_mount_fully_protected_no_forge_exception
    bad("no forge subtree exception", forge_roots=[root(path="/srv/kmu-ai")])
    bad("no forge subtree exception", forge_roots=[root(path="/srv")])                                  # a root that CONTAINS a protected mount
    bad("no forge subtree exception", forge_roots=[root(backing_image="/srv/models/forge-root.img")])
    bad("root filesystem", forge_roots=[root()], devof=lambda path: 7 if path == "/" else 8)            # test_backing_image_must_be_on_root_filesystem
    bad("root filesystem", forge_roots=[root()], devof=lambda path: None if path != "/" else 1)
    bad("protected device", forge_roots=[root()], devof=lambda path: 9, pdevs={9})                      # test_volume_device_differs_from_every_protected_mount
    bad("normalized absolute path", forge_roots=[root(path="srv/forge")])
    bad("normalized absolute path", forge_roots=[root(path="/srv/forge/../models")])
    bad("normalized absolute path", forge_roots=[root(backing_image="/var//img")])
    bad("size_bytes", forge_roots=[root(size_bytes=0)])
    bad("overlap", forge_roots=[root("/srv/a"), root("/srv/a/b")], devof=lambda p: 5)
    bad("at most 4", forge_roots=[root(f"/srv/x{i}") for i in range(5)])


def test_policy_schema_rejects_workloads_enabled_without_loop_fs():
    bad("needs a forge root", t1={"workloads_enabled": True, "ops": []}, gates_map=ALL_GATES)
    parse(t1={"workloads_enabled": True, "ops": []}, forge_roots=[root()], devof=lambda p: 5, gates_map=ALL_GATES)


def test_profile_t0_enables_tier_zero_only_and_no_opaque_t3():
    p = parse(profile="t0", tiers=(0,), ops=frozenset())
    assert p.tiers == (0,)
    bad("tier 0 only", profile="t0", tiers=(0, 1), ops=frozenset({"selftest.noop"}))
    bad("tier 0 only", profile="t0", tiers=(0,), t3={"manifests_enabled": [], "opaque_enabled": True}, gates_map=ALL_GATES, ops=frozenset())
    bad("no forge roots", profile="t0", tiers=(0,), forge_roots=[root()], devof=lambda p: 5, ops=frozenset())
    bad("not in this release's op table", profile="t0", tiers=(0, 1), t1_ops=[{"op": "selftest.noop"}], ops=frozenset())


def test_op_configuration_values():
    bad("mode/requires", t1_ops=[{"op": "selftest.noop", "mode": "yolo"}])
    bad("mode/requires", t1_ops=[{"op": "selftest.noop", "requires": "nobody"}])
    bad("rate entries", t1_ops=[{"op": "selftest.noop", "rate": [[0, 60]]}])
    bad("at most 4", t1_ops=[{"op": "selftest.noop", "rate": [[1, 60]] * 5}])
    bad("must be a list of at most 64", t1_ops=[{"op": "selftest.noop"}] * 65)
    bad("circuit.fail_threshold", circuit={"fail_threshold": 0})
    bad("tiers_enabled", tiers=(1,))
    bad("not in tiers_enabled", tiers=(0,), t1_ops=[{"op": "selftest.noop"}])


# --------------------------------------------------------------------------------------------------------------------------------- apply
def body(raw, sig):
    return {"policy_b64": base64.b64encode(raw).decode(), "sig": sig}


def test_apply_installs_atomically_with_root_modes_and_records_audit(privd_env):
    e = privd_env
    r = e.install(tiers=(0,), serial=1)
    assert r["ok"] and r["policy"]["serial"] == 1 and r["audit_seq"] > 0
    for n in ("policy-1.json", "policy-1.json.sig"):
        st = os.stat(f"{e.paths.policy_dir}/{n}")
        assert (st.st_uid, st.st_mode & 0o777, st.st_nlink) == (0, 0o644, 1)
    assert open(e.paths.serial_file).read().strip() == "1" and not [n for n in os.listdir(e.paths.policy_dir) if n.startswith(".tmp")]
    assert e.ctx.policies.current().serial == 1
    rec = [x for x in e.priv_records() if x["type"] == "policy"][-1]
    assert rec["action"] == "apply" and rec["serial"] == 1 and rec["previous_serial"] == 0 and len(rec["sha256"]) == 64


def test_apply_failures_leave_the_previous_policy_in_force(privd_env, keys):
    e = privd_env
    e.install(tiers=(0,), serial=1)
    before = sorted(os.listdir(e.paths.policy_dir))
    raw2, sig2 = e.sign(e.doc(tiers=(0,), serial=2))
    other_priv, _ = keys.make("other-owner")
    forged = sshsig.sign(raw2, other_priv, sshsig.NS_POLICY)
    cases = {
        "bad signature": (raw2, forged),
        "wrong namespace": (raw2, sshsig.sign(raw2, e.owner["priv"], sshsig.NS_APPROVAL)),
        "tampered content": (raw2.replace(b'"serial":2', b'"serial":3'), sig2),
        "wrong node": e.sign(e.doc(tiers=(0,), serial=2, node="g3")),
        "serial equal": e.sign(e.doc(tiers=(0,), serial=1)),
        "same serial, different content": e.sign(e.doc(tiers=(0,), serial=1, mode="observe")),
        "not_before in the future": e.sign(e.doc(tiers=(0,), serial=2, not_before="2027-01-01T00:00:00Z")),
        "not valid json": (b"{nope", sshsig.sign(b"{nope", e.owner["priv"], sshsig.NS_POLICY)),
        "float": e.sign(b'{"schema":1,"serial":2,"x":1.5}'),
        "duplicate key": e.sign(b'{"schema":1,"serial":2,"serial":2}'),
        "gated feature": e.sign(e.doc(tiers=(0,), serial=2, t1={"workloads_enabled": True, "ops": []})),
    }
    for i, (name, (raw, sig)) in enumerate(cases.items()):
        if i % 5 == 4:
            e.clock.advance(seconds=61)                                                     # policy.apply is rate limited (10/min): the table is longer than that
        r = e.call("policy.apply", body(raw, sig))
        assert r["ok"] is False and r["code"] == "DENY_POLICY_INVALID", (name, r)
    assert sorted(os.listdir(e.paths.policy_dir)) == before and e.ctx.policies.current().serial == 1
    e.clock.advance(seconds=61)
    assert e.call("policy.apply", {"policy_b64": "!!!", "sig": "x"})["code"] == "DENY_PARAM"
    assert e.call("policy.apply", {"policy_b64": "AAAA"})["code"] == "DENY_PARAM"
    # the rollback story: sign the OLD content with serial+1
    raw3, sig3 = e.sign(e.doc(tiers=(0,), serial=3))
    assert e.call("policy.apply", body(raw3, sig3))["ok"] and e.ctx.policies.current().serial == 3


def test_apply_refused_when_audit_is_down_and_pending_record_is_kept(privd_env):
    from forge_node.audit import fsflags
    e = privd_env
    e.install(tiers=(0,), serial=1)
    spec = e.specs["priv"]
    fd = os.open(f"{spec.dir}/priv.000001/priv.000001.jsonl", os.O_RDONLY)
    fsflags.add_flags(fd, fsflags.IMMUTABLE)
    os.close(fd)
    e.priv_log._drop()
    e.priv_log._heal_depth = 99
    r = e.install(tiers=(0,), serial=2)
    assert r["ok"] is False and r["code"] == "DENY_AUDIT_DOWN" and e.ctx.policies.installed_serial() == 1


def test_policy_signature_not_valid_as_approval_and_fail_closed_loading(privd_env):
    e = privd_env
    e.install(tiers=(0,), serial=1)
    assert e.ctx.policies.current().serial == 1
    # chmod 0666 on the verified file: the policy is gone (no cache, no fallback)
    p = f"{e.paths.policy_dir}/policy-1.json"
    os.chmod(p, 0o666)
    with pytest.raises(PolicyError):
        e.ctx.policies.current()
    os.chmod(p, 0o644)
    assert e.ctx.policies.current().serial == 1
    # the highest serial is broken: NO policy, not the older one
    raw2, sig2 = e.sign(e.doc(tiers=(0,), serial=2))
    open(f"{e.paths.policy_dir}/policy-2.json", "wb").write(raw2 + b" ")
    open(f"{e.paths.policy_dir}/policy-2.json.sig", "w").write(sig2)
    os.chmod(f"{e.paths.policy_dir}/policy-2.json", 0o644)
    os.chmod(f"{e.paths.policy_dir}/policy-2.json.sig", 0o644)
    with pytest.raises(PolicyError):
        e.ctx.policies.current()
    # a symlink in place of the file is not followed
    os.unlink(f"{e.paths.policy_dir}/policy-2.json")
    os.symlink(p, f"{e.paths.policy_dir}/policy-2.json")
    with pytest.raises(PolicyError):
        e.ctx.policies.current()
    # a signers file anyone can write is no trust anchor
    os.unlink(f"{e.paths.policy_dir}/policy-2.json")
    os.unlink(f"{e.paths.policy_dir}/policy-2.json.sig")
    os.chmod(e.paths.allowed_signers, 0o666)
    with pytest.raises(PolicyError):
        e.ctx.policies.current()
    os.chmod(e.paths.allowed_signers, 0o644)
    assert e.ctx.policies.current().serial == 1


def test_old_gate_key_signatures_rejected_after_policy_serial_plus_one(privd_env):
    e = privd_env
    e.ready()
    assert e.call("exec", {"job": e.job_env(dry_run=True)[0]})["result"]["status"] == "dry_run"
    e.install(e.doc(serial=2, t1_ops=[{"op": "selftest.noop"}], gate_keys=[{"id": "hub-gate-2", "pub": PUB, "not_after": "2099-12-31"}]))
    r = e.call("exec", {"job": e.job_env(dry_run=True)[0]})
    assert r["ok"] is False and r["code"] == "DENY_JOB_SIGNATURE"
