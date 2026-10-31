"""Feature-Gates a)-d) (Betriebsleiter-Entscheid nach REPORT_BRIEF_forge-nodedesignverify3): in N1 sind alle vier UNERFUELLT; was sie sperren, ist in Code und Policy aus."""
import re
from dataclasses import replace
from pathlib import Path

import pytest

from forge_node import gates, protocol

ROOT = Path(__file__).resolve().parents[1]
ALL_MET = {k: replace(v, met=True) for k, v in gates.GATES.items()}


def test_all_four_gates_exist_and_are_unmet_in_n1():
    assert set(gates.GATES) == {"A", "B", "C", "D"}
    assert all(g.met is False for g in gates.GATES.values())
    for g in gates.GATES.values():
        assert g.acceptance and g.required_tests and g.slice


def test_gates_cannot_be_opened_by_environment_policy_or_mutation(monkeypatch):
    src = (ROOT / "src" / "forge_node" / "gates.py").read_text()
    assert "environ" not in src and "getenv" not in src
    for k in "ABCD":
        monkeypatch.setenv(f"FORGE_NODE_GATE_{k}", "1")
    assert not any(g.met for g in gates.GATES.values())
    with pytest.raises(TypeError):
        gates.GATES["A"] = replace(gates.GATES["A"], met=True)
    with pytest.raises(Exception):
        gates.GATES["A"].met = True
    # eine signierte Policy kann Gates nur nicht einschalten, nie oeffnen
    assert gates.policy_gate_violations({"tiers_enabled": [0], "gates": {"A": True}}) == []
    assert not any(g.met for g in gates.GATES.values())


def test_production_hub_wiring_uses_the_real_gates():
    import inspect

    from forge_node.hub import core

    assert inspect.signature(core.Hub.__init__).parameters["gate_set"].default is gates.GATES
    main_src = (ROOT / "src" / "forge_node" / "hub" / "__main__.py").read_text()
    assert "gate_set" not in main_src and "gates" not in main_src      # __main__ baut Hub(cfg, db, signer) ohne Gate-Override


def test_every_op_above_t0_is_denied_in_n1_for_both_profiles():
    for op, spec in gates.OPS.items():
        for profile in ("full", "t0"):
            d = gates.decide(op, spec.tier, profile, {"kind": "unit_action"} if op == "t3.exec" else {})
            if spec.tier == 0 and profile == "full":
                assert d.allowed, op
            elif spec.tier == 0:
                assert d.allowed, op           # T0-Ops gibt es auch im t0-Profil
            else:
                assert not d.allowed and d.code == "DENY_TIER_DISABLED", (op, profile, d)


@pytest.mark.parametrize("op,gate", [
    ("volume.create", "A"), ("volume.grow", "A"), ("volume.destroy", "A"), ("container.start", "A"), ("container.restart", "A"), ("container.recreate", "A"), ("stack.up", "A"),
    ("selftest.fill", "A"), ("vm.start", "B"), ("vm.define", "B"), ("unit.start", "C"), ("unit.stop", "C"), ("unit.restart", "C"), ("scene.switch", "C"), ("agent.restart", "C"),
])
def test_each_affected_operation_requires_its_gate_beyond_gate_d(op, gate):
    """Selbst wenn D (Audit-Siegel) erfuellt waere, bleibt die Operation durch ihr eigenes Gate gesperrt."""
    only_d = {**gates.GATES, "D": ALL_MET["D"]}
    d = gates.decide(op, gates.OPS[op].tier, "full", {}, only_d)
    assert not d.allowed and f"gate {gate} unmet" in d.detail
    others_met = {**ALL_MET, gate: gates.GATES[gate]}
    d = gates.decide(op, gates.OPS[op].tier, "full", {}, others_met)
    assert not d.allowed and f"gate {gate} unmet" in d.detail
    assert gates.decide(op, gates.OPS[op].tier, "full", {}, ALL_MET).allowed


def test_no_mutating_op_without_gate_d():
    only_abc = {**ALL_MET, "D": gates.GATES["D"]}
    for op, spec in gates.OPS.items():
        if spec.tier >= 1:
            d = gates.decide(op, spec.tier, "full", {"kind": "firewall_apply"} if op == "t3.exec" else {}, only_abc)
            assert not d.allowed and "gate D unmet" in d.detail, op


def test_t3_unit_action_needs_gate_c_other_kinds_only_d():
    only_d = {**gates.GATES, "D": ALL_MET["D"]}
    assert "gate C unmet" in gates.decide("t3.exec", 3, "full", {"kind": "unit_action"}, only_d).detail
    assert gates.decide("t3.exec", 3, "full", {"kind": "file_replace"}, only_d).allowed
    assert gates.decide("t3.exec", 3, "full", {"kind": "nope"}, only_d).code == "DENY_PARAM"
    assert gates.decide("t3.exec", 3, "full", {}, only_d).code == "DENY_PARAM"


def test_unknown_op_tier_mismatch_and_profile_rules():
    assert gates.decide("rm.rf", 0, "full").code == "DENY_OP_UNKNOWN"
    assert gates.decide("inv.host", 1, "full").code == "DENY_PARAM"
    assert gates.decide("inv.host", 0, "weird").code == "DENY_POLICY_INVALID"
    assert gates.decide("selftest.noop", 1, "t0", gates=ALL_MET).code == "DENY_TIER_DISABLED"
    assert gates.decide("dir.ensure", 1, "t0", gates=ALL_MET).code == "DENY_TIER_DISABLED"
    assert gates.decide("selftest.noop", 1, "full", gates=ALL_MET).allowed


def test_no_apt_apply_op_exists():
    assert not any(re.search(r"apt|upgrade", op) for op in gates.OPS)


def test_every_design_t1_t2_op_is_registered():
    design = (ROOT / "docs" / "design" / "FORGE_NODE.md").read_text()
    for op in ("container.start", "container.stop", "container.restart", "container.recreate", "stack.put", "stack.up", "stack.down", "volume.create", "volume.grow", "volume.destroy",
               "dir.ensure", "dir.du", "dir.trash", "dir.purge_trash", "file.put", "file.get", "vm.shutdown", "vm.destroy", "unit.restart", "scene.switch", "docker.prune_plan",
               "docker.prune_apply", "image.pin", "policy.apply", "agent.restart", "ledger.resolve"):
        assert op in gates.OPS, op
    for n in ("inv.host", "inv.disks", "inv.gpu", "inv.net", "inv.units", "inv.containers", "inv.vms", "inv.pkgs", "inv.certs", "inv.backups", "inv.git", "inv.access", "inv.usage",
              "inv.models", "metrics.sample", "logs.unit"):
        assert n in gates.OPS and gates.OPS[n].tier == 0 and f"`{n}`" in design


# ------------------------------------------------------------------------------------------------------ policy-side rules
def test_policy_gate_violations_flags_each_disabled_feature():
    v = gates.policy_gate_violations({"tiers_enabled": [0, 1, 2],
                                      "t1": {"workloads_enabled": True, "vm_pool": "forge", "ops": ["volume.create"]},
                                      "t2": {"ops": [{"op": "unit.restart", "targets": []}]},
                                      "t3": {"manifests_enabled": ["unit_action", "file_replace"], "opaque_enabled": True}})
    text = "\n".join(v)
    for needle in ("tiers_enabled contains 1", "tiers_enabled contains 2", "workloads_enabled=true", "vm_pool", "op volume.create", "op unit.restart", "unit_action", "opaque_enabled"):
        assert needle in text, needle


def test_policy_for_t0_path_passes():
    assert gates.policy_gate_violations({"tiers_enabled": [0], "t1": {"workloads_enabled": False}, "t2": {"ops": []}, "t3": {"manifests_enabled": [], "opaque_enabled": False}}) == []
    assert gates.policy_gate_violations({"tiers_enabled": [0]}) == []


def test_policy_violations_clear_only_with_met_gates():
    pol = {"tiers_enabled": [0, 1], "t1": {"workloads_enabled": True}}
    assert gates.policy_gate_violations(pol)
    assert gates.policy_gate_violations(pol, ALL_MET) == []
    assert gates.policy_gate_violations(pol, {**ALL_MET, "A": gates.GATES["A"]}) != []


def test_policy_unknown_op_and_malformed_inputs():
    assert any("unknown op" in x for x in gates.policy_gate_violations({"t2": {"ops": [{"op": "apt.upgrade_apply"}]}}))
    assert gates.policy_gate_violations([]) == ["policy is not an object"]
    assert gates.policy_gate_violations({"tiers_enabled": "0"})


def test_design_records_the_four_acceptance_criteria_per_slice():
    design = (ROOT / "docs" / "design" / "FORGE_NODE.md").read_text()
    for g in gates.GATES.values():
        for t in g.required_tests:
            assert t in design, f"required test {t} of gate {g.id} must be named in the design"
