"""N3 scope pins: the acceptance list in the design names only tests that exist, gate D has its evidence but is still unmet, and nothing above T0 is reachable in production."""
import re
from pathlib import Path

from forge_node import gates

ROOT = Path(__file__).resolve().parents[1]


def all_test_names():
    out = set()
    for f in (ROOT / "tests").glob("test_*.py"):
        out |= set(re.findall(r"^def (test_[a-z0-9_]+)\(", f.read_text(), re.M))
    return out


def test_design_n3_list_names_existing_tests():
    design = (ROOT / "docs" / "design" / "FORGE_NODE.md").read_text()
    sec = design[design.index("### 16.3 Slice N3 acceptance list"):design.index("## 17. Open questions")]
    named = set(re.findall(r"`(test_[a-z0-9_]+)`", sec.split("**Not in N3")[0]))
    assert not sorted(named - all_test_names()), sorted(named - all_test_names())
    assert len(named) >= 150


def test_gate_d_evidence_tests_exist_and_gate_d_is_still_unmet():
    """Gate D's required tests are all present; `met` stays False in the N3 commits (the flip is the commit after the independent review). Every op above T0 is therefore disabled."""
    names = all_test_names()
    assert set(gates.GATES["D"].required_tests) <= names, set(gates.GATES["D"].required_tests) - names
    assert not any(g.met for g in gates.GATES.values())
    assert all(gates.required_gates(op) & {"D"} for op, spec in gates.OPS.items() if spec.tier > 0)


def test_gate_c_resolver_half_tests_exist_and_gate_c_is_still_unmet():
    names = all_test_names()
    done = {"test_t2_unit_with_onsuccess_in_closure_denied", "test_t2_unit_with_onfailure_in_closure_denied", "test_t2_unit_isolate_job_mode_denied"}
    assert done <= names and gates.GATES["C"].met is False
    pending = set(gates.GATES["C"].required_tests) - done
    assert pending == {"test_resolver_follows_onsuccess_onfailure_recursively_and_binds_closure_sha256", "test_t3_unit_with_onfailure_requires_frozen_ack_and_bound_closure",
                       "test_t3_unit_isolate_requires_frozen_ack_and_bound_closure"}
    assert not (pending & names), "N6/N7's tests must not exist yet: they belong to the slice that opens gate C"


def test_the_op_table_of_this_release_contains_only_the_selftest_op():
    from forge_node.privd.optable import build_optable
    assert sorted(e.name for e in build_optable("full")) == ["selftest.noop"] and len(build_optable("t0")) == 0
