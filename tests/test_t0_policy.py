import json
import os

import pytest

from forge_node import sshsig
from forge_node.t0 import policy as P

from n2_helpers import NOW, PIN, install_policy, policy_doc, signers_text, view


@pytest.fixture
def signers(tmp_path, owner):
    p = tmp_path / "allowed_signers"
    p.write_text(signers_text(owner["pub"]))
    os.chmod(p, 0o644)
    return str(p)


def load(tmp_path, signers, node="g2", now=NOW):
    return P.load_installed(str(tmp_path / "policy"), signers, node, now, owner_uid=os.getuid())


def test_installed_signed_policy_loads_and_exposes_what_the_agent_uses(tmp_path, owner, signers):
    install_policy(tmp_path / "policy", policy_doc(), owner["priv"])
    v = load(tmp_path, signers)
    assert v.serial == 1 and v.node == "g2" and v.profile == "full" and v.tiers_enabled == (0,) and v.hub_tls_pins == (PIN,)
    assert [u.unit for u in v.t0.units_for_logs] == ["forge-postbote.service", "forge-edge.service"] and "hub-gate-1" in v.hub_gate_keys
    assert len(v.sha256) == 64 and v.window.in_blackout


def test_policy_bad_signature_rejected(tmp_path, owner, signers, gate):
    raw = json.dumps(policy_doc()).encode()
    sig = sshsig.sign(raw, gate["priv"], sshsig.NS_POLICY)               # signed by the hub gate key, not the owner
    install_policy(tmp_path / "policy", policy_doc(), owner["priv"], raw=raw, sig=sig)
    with pytest.raises(P.PolicyError) as e:
        load(tmp_path, signers)
    assert e.value.code == "DENY_POLICY_INVALID" and "signature" in e.value.detail


def test_tampered_content_after_signing_rejected(tmp_path, owner, signers):
    raw = install_policy(tmp_path / "policy", policy_doc(), owner["priv"])
    (tmp_path / "policy" / "policy-1.json").write_bytes(raw.replace(b'"observe"', b'"enforce"'))
    with pytest.raises(P.PolicyError):
        load(tmp_path, signers)


def test_policy_signature_not_valid_as_approval(tmp_path, owner, signers):
    raw = json.dumps(policy_doc()).encode()
    sig = sshsig.sign(raw, owner["priv"], sshsig.NS_APPROVAL)
    install_policy(tmp_path / "policy", policy_doc(), owner["priv"], raw=raw, sig=sig)
    with pytest.raises(P.PolicyError):
        load(tmp_path, signers)


def test_policy_wrong_node_rejected(tmp_path, owner, signers):
    install_policy(tmp_path / "policy", policy_doc(node="g3"), owner["priv"])
    with pytest.raises(P.PolicyError) as e:
        load(tmp_path, signers, node="g2")
    assert "another node" in e.value.detail


def test_serial_must_match_file_name(tmp_path, owner, signers):
    install_policy(tmp_path / "policy", policy_doc(serial=5), owner["priv"], serial=2)
    with pytest.raises(P.PolicyError) as e:
        load(tmp_path, signers)
    assert "serial" in e.value.detail


def test_highest_serial_wins_and_a_broken_newest_means_no_policy_not_the_older_one(tmp_path, owner, signers):
    install_policy(tmp_path / "policy", policy_doc(serial=1), owner["priv"])
    install_policy(tmp_path / "policy", policy_doc(serial=2), owner["priv"], raw=b'{"serial": 2}', sig=sshsig.sign(b'{"serial": 3}', owner["priv"], sshsig.NS_POLICY))
    with pytest.raises(P.PolicyError):
        load(tmp_path, signers)
    install_policy(tmp_path / "policy", policy_doc(serial=3), owner["priv"])
    assert load(tmp_path, signers).serial == 3


def test_not_before_in_the_future_rejected(tmp_path, owner, signers):
    install_policy(tmp_path / "policy", policy_doc(not_before="2026-11-01T00:00:00Z"), owner["priv"])
    with pytest.raises(P.PolicyError) as e:
        load(tmp_path, signers)
    assert "not_before" in e.value.detail


@pytest.mark.parametrize("over,needle", [
    ({"tiers_enabled": [0, 1]}, "gated"), ({"tiers_enabled": [1]}, "tier 0"), ({"tiers_enabled": [0], "t1": {"workloads_enabled": True}}, "gated"),
    ({"t1": {"vm_pool": "forge"}}, "gated"), ({"t2": {"ops": [{"op": "unit.restart", "targets": []}]}}, "gated"), ({"t3": {"opaque_enabled": True}}, "gated"),
    ({"t3": {"manifests_enabled": ["unit_action"]}}, "gated"), ({"schema": 2}, "schema"), ({"profile": "x"}, "profile"), ({"global_mode": "off"}, "global_mode"),
    ({"hub_tls_pins": []}, "pins"), ({"hub_tls_pins": ["zz"]}, "pins"), ({"hub_tls_pins": [PIN, PIN]}, "pins"), ({"hub_gate_keys": []}, "hub_gate_keys"),
    ({"protected": {"paths": ["relative"]}}, "protected.paths"), ({"t0": {"repos": ["/a/../b"]}}, "normalized"), ({"t0": {"model_dirs": ["/"]}}, "normalized"),
    ({"t0": {"units_for_logs": ["not a unit"]}}, "unit"), ({"t0": {"units_for_logs": [{"unit": "x.service", "sensitivity": "public"}]}}, "sensitivity"),
    ({"windows": {"blackout": "bad"}}, "windows"), ({"windows": "x"}, "windows"), ({"t0": "x"}, "t0"), ({"protected": []}, "protected"),
])
def test_invalid_or_gate_violating_policy_rejected(tmp_path, owner, signers, over, needle):
    install_policy(tmp_path / "policy", policy_doc(**over), owner["priv"])
    with pytest.raises(P.PolicyError) as e:
        load(tmp_path, signers)
    assert e.value.code == "DENY_POLICY_INVALID" and needle in e.value.detail


def test_kmu_log_units_need_customer_sensitivity(tmp_path, owner, signers):
    install_policy(tmp_path / "policy", policy_doc(t0={"units_for_logs": ["kmu-s2-backup.service"]}), owner["priv"])
    with pytest.raises(P.PolicyError) as e:
        load(tmp_path, signers)
    assert "customer" in e.value.detail
    install_policy(tmp_path / "policy", policy_doc(serial=2, t0={"units_for_logs": [{"unit": "kmu-s2-backup.service", "sensitivity": "customer"}]}), owner["priv"])
    v = load(tmp_path, signers)
    assert v.log_unit("kmu-s2-backup.service").sensitivity == "customer" and v.log_unit("other.service") is None


def test_files_must_be_root_owned_regular_unshared(tmp_path, owner, signers):
    d = tmp_path / "policy"
    install_policy(d, policy_doc(), owner["priv"])
    os.chmod(d / "policy-1.json", 0o666)
    with pytest.raises(P.PolicyError):
        load(tmp_path, signers)
    os.chmod(d / "policy-1.json", 0o644)
    os.link(d / "policy-1.json", tmp_path / "hardlink")
    with pytest.raises(P.PolicyError):
        load(tmp_path, signers)
    os.unlink(tmp_path / "hardlink")
    os.chown(d / "policy-1.json", 1000, 1000)
    with pytest.raises(P.PolicyError):
        load(tmp_path, signers)
    os.chown(d / "policy-1.json", 0, 0)
    os.chmod(d, 0o775)
    with pytest.raises(P.PolicyError):
        load(tmp_path, signers)


def test_symlinked_policy_file_or_directory_not_followed(tmp_path, owner, signers):
    d = tmp_path / "policy"
    install_policy(tmp_path / "real", policy_doc(), owner["priv"])
    os.symlink(tmp_path / "real", d)
    with pytest.raises(P.PolicyError):
        load(tmp_path, signers)
    os.unlink(d)
    d.mkdir()
    os.symlink(tmp_path / "real" / "policy-1.json", d / "policy-1.json")
    os.symlink(tmp_path / "real" / "policy-1.json.sig", d / "policy-1.json.sig")
    with pytest.raises(P.PolicyError):
        load(tmp_path, signers)


def test_empty_missing_directory_and_unsafe_allowed_signers(tmp_path, owner, signers):
    (tmp_path / "policy").mkdir()
    with pytest.raises(P.PolicyError) as e:
        load(tmp_path, signers)
    assert "no policy" in e.value.detail
    with pytest.raises(P.PolicyError):
        P.load_installed(str(tmp_path / "nope"), signers, "g2", NOW, owner_uid=os.getuid())
    install_policy(tmp_path / "policy", policy_doc(), owner["priv"])
    os.chmod(signers, 0o666)
    with pytest.raises(P.PolicyError):
        load(tmp_path, signers)


def test_duplicate_keys_and_floats_rejected_by_strict_parser(tmp_path, owner, signers):
    raw = json.dumps(policy_doc()).encode().replace(b'"serial": 1', b'"serial": 1, "serial": 1')
    install_policy(tmp_path / "policy", policy_doc(), owner["priv"], raw=raw)
    with pytest.raises(P.PolicyError):
        load(tmp_path, signers)
    raw = json.dumps(policy_doc()).encode().replace(b'"schema": 1', b'"schema": 1.0')
    install_policy(tmp_path / "policy", policy_doc(serial=2), owner["priv"], raw=raw, serial=2)
    with pytest.raises(P.PolicyError):
        load(tmp_path, signers)


def test_verify_blob_for_hub_delivered_policy(owner, signers):
    raw = json.dumps(policy_doc(serial=7)).encode()
    sig = sshsig.sign(raw, owner["priv"], sshsig.NS_POLICY)
    text = open(signers).read()
    assert P.verify_blob(raw, sig, text, "g2", 7, NOW).serial == 7
    with pytest.raises(P.PolicyError):
        P.verify_blob(raw + b" ", sig, text, "g2", 7, NOW)
    with pytest.raises(P.PolicyError):
        P.verify_blob(raw, sig, text, "g2", 8, NOW)
    with pytest.raises(P.PolicyError):
        P.verify_blob(b"x" * (P.MAX_POLICY_BYTES + 1), sig, text, "g2", 7, NOW)


def test_old_gate_key_signatures_rejected_after_policy_serial_plus_one(gate, gate2):
    """T-REVOKE: the key list of the *installed* policy decides. A policy without the old key makes its leases/jobs unverifiable (verified in test_agent_e2e with real envelopes)."""
    v1 = view(policy_doc(serial=1, gate_keys=gate["keys"]))
    v2 = view(policy_doc(serial=2, gate_keys=gate2["keys"]))
    assert set(v1.hub_gate_keys) == {"hub-gate-1"} and set(v2.hub_gate_keys) == {"hub-gate-2"}
