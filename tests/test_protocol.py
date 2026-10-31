"""Signaturen (ssh-keygen -Y), Namespaces, Lease/Job-Huellen und ihre Pruefung (privd-Seite). Echte Schluessel, fluechtig im tmp."""
import copy
import json
from datetime import timedelta

import pytest

from conftest import NOW, job_payload, lease_payload
from forge_node import canon, protocol, sshsig
from forge_node.protocol import ProtoError


def _seal(gate, payload):
    return protocol.seal(payload, gate["priv"], gate["id"])


# -------------------------------------------------------------------------------------------------------------- namespaces
def test_sign_verify_roundtrip_and_tamper(gate):
    allowed = sshsig.allowed_signers_text([(gate["id"], gate["pub"], sshsig.NS_HUB)])
    sig = sshsig.sign(b"data", gate["priv"], sshsig.NS_HUB)
    assert sshsig.verify(b"data", sig, sshsig.NS_HUB, gate["id"], allowed).startswith("SHA256:")
    with pytest.raises(sshsig.SigError):
        sshsig.verify(b"datA", sig, sshsig.NS_HUB, gate["id"], allowed)


def test_policy_signature_not_valid_as_approval(gate, owner):      # test_policy_signature_not_valid_as_approval (Namespaces)
    pol = sshsig.sign(b"blob", owner["priv"], sshsig.NS_POLICY)
    for ns in (sshsig.NS_APPROVAL, sshsig.NS_RELEASE, sshsig.NS_HUB):
        allowed = sshsig.allowed_signers_text([("owner", owner["pub"], ns)])
        with pytest.raises(sshsig.SigError):
            sshsig.verify(b"blob", pol, ns, "owner", allowed)
    # selbst wenn allowed_signers alle Namespaces zulaesst, bindet die Signatur ihren Namespace
    allowed_all = f'owner namespaces="{sshsig.NS_POLICY},{sshsig.NS_APPROVAL}" {owner["pub"]}\n'
    with pytest.raises(sshsig.SigError):
        sshsig.verify(b"blob", pol, sshsig.NS_APPROVAL, "owner", allowed_all)
    sshsig.verify(b"blob", pol, sshsig.NS_POLICY, "owner", allowed_all)


def test_unknown_namespace_and_bad_principal_and_bad_keys(gate):
    with pytest.raises(sshsig.SigError):
        sshsig.sign(b"x", gate["priv"], "forge-node-other")
    for p in ("a b", "a\nb", "", "-x", 'a"b', "x" * 65):
        with pytest.raises(sshsig.SigError):
            sshsig.check_principal(p)
    for pub in (gate["pub"] + "\nssh-ed25519 AAAA", 'command="x" ' + gate["pub"], "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC", "", gate["pub"].replace("ssh-ed25519", "ssh-ed25519\t")):
        with pytest.raises(sshsig.SigError):
            sshsig.normalize_pub(pub)
    assert sshsig.normalize_pub(gate["pub"] + " comment") == gate["pub"]


def test_signing_key_must_be_private_to_owner(gate, tmp_path):
    k = tmp_path / "k"
    k.write_bytes(gate["priv"].read_bytes())
    k.chmod(0o644)
    with pytest.raises(sshsig.SigError):
        sshsig.sign(b"x", k, sshsig.NS_HUB)
    with pytest.raises(sshsig.SigError):
        sshsig.sign(b"x", tmp_path / "missing", sshsig.NS_HUB)


def test_malformed_signature_inputs(gate):
    allowed = sshsig.allowed_signers_text([(gate["id"], gate["pub"], sshsig.NS_HUB)])
    for sig in ("", "garbage", None, "-----BEGIN SSH SIGNATURE-----\n", "x" * 5000):
        with pytest.raises(sshsig.SigError):
            sshsig.verify(b"d", sig, sshsig.NS_HUB, gate["id"], allowed)


# -------------------------------------------------------------------------------------------------------- lease verification
def test_lease_roundtrip(gate, gate_keys):
    env = _seal(gate, lease_payload(seq=5))
    p = protocol.verify_lease(env, gate_keys, "g2", NOW + timedelta(seconds=3), last_seq=4)
    assert p["seq"] == 5 and p["stop"] is False and set(env) == {"payload", "sig", "key_id"}
    assert canon.is_canonical(env["payload"])


def test_lease_replay_and_old_seq_rejected(gate, gate_keys):
    env = _seal(gate, lease_payload(seq=5))
    for last in (5, 6, 100):
        with pytest.raises(ProtoError) as e:
            protocol.verify_lease(env, gate_keys, "g2", NOW, last_seq=last)
        assert e.value.code == "DENY_STALE_LEASE"


def test_lease_expired_wrong_node_and_skew(gate, gate_keys):
    env = _seal(gate, lease_payload())
    with pytest.raises(ProtoError) as e:
        protocol.verify_lease(env, gate_keys, "g2", NOW + timedelta(seconds=61), 0)
    assert e.value.code == "DENY_STALE_LEASE"
    with pytest.raises(ProtoError) as e:
        protocol.verify_lease(env, gate_keys, "g3", NOW, 0)
    assert e.value.code == "DENY_STALE_LEASE"
    with pytest.raises(ProtoError) as e:
        protocol.verify_lease(env, gate_keys, "g2", NOW - timedelta(seconds=90), 0)
    assert e.value.code == "DENY_CLOCK"


def test_lease_validity_over_60s_cannot_even_be_sealed_or_verified(gate, gate_keys):
    with pytest.raises(ProtoError):
        _seal(gate, lease_payload(valid=61))
    # ein boeswilliger Hub (oder ein Fehler) signiert 61 s ausserhalb von seal(): der Pruefer lehnt ab
    p = lease_payload(valid=61)
    text = canon.canonical_text(p)
    sig = sshsig.sign(text.encode(), gate["priv"], sshsig.NS_HUB)
    with pytest.raises(ProtoError):
        protocol.verify_lease({"payload": text, "sig": sig, "key_id": gate["id"]}, gate_keys, "g2", NOW, 0)


def test_stop_flag_and_projects_carried(gate, gate_keys):
    env = _seal(gate, lease_payload(stop=True, projects=["b-proj", "a-proj"], quarantine=True))
    p = protocol.verify_lease(env, gate_keys, "g2", NOW, 0)
    assert p["stop"] and p["quarantine"] and p["stopped_projects"] == ["a-proj", "b-proj"]
    with pytest.raises(ProtoError):
        protocol.seal(lease_payload(projects=["b", "a"]) | {"stopped_projects": ["b", "a"]}, gate["priv"], gate["id"])     # unsortiert => ungueltig


# ---------------------------------------------------------------------------------------------------------- job verification
def test_job_roundtrip(gate, gate_keys):
    env = _seal(gate, job_payload(op="inv.host"))
    p = protocol.verify_job(env, gate_keys, "g2", NOW + timedelta(seconds=10))
    assert p["op"] == "inv.host" and p["delivery_seq"] == 1


def test_expired_and_wrong_node_and_future_job(gate, gate_keys):
    env = _seal(gate, job_payload())
    with pytest.raises(ProtoError) as e:
        protocol.verify_job(env, gate_keys, "g2", NOW + timedelta(seconds=121))
    assert e.value.code == "DENY_JOB_EXPIRED"
    with pytest.raises(ProtoError) as e:
        protocol.verify_job(env, gate_keys, "g3", NOW)
    assert e.value.code == "DENY_JOB_SIGNATURE"
    with pytest.raises(ProtoError) as e:
        protocol.verify_job(env, gate_keys, "g2", NOW - timedelta(seconds=120))
    assert e.value.code == "DENY_CLOCK"


def test_job_ttl_over_120s_rejected(gate, gate_keys):
    with pytest.raises(ProtoError):
        _seal(gate, job_payload(ttl=121))


@pytest.mark.parametrize("field,val", [("tier", 4), ("tier", True), ("op", "Bad Op"), ("job_id", "XYZ"), ("dry_run", "no"), ("plan_hash", "abc"), ("delivery_seq", 0), ("params", [])])
def test_job_schema_rejects(gate, field, val):
    with pytest.raises(ProtoError):
        _seal(gate, job_payload(**{field: val}))


def test_job_unknown_and_missing_fields_rejected(gate):
    p = job_payload()
    with pytest.raises(ProtoError):
        _seal(gate, p | {"extra": 1})
    q = dict(p)
    del q["owner_sig"]
    with pytest.raises(ProtoError):
        _seal(gate, q)


def test_lease_is_not_valid_as_job_and_vice_versa(gate, gate_keys):
    lease = _seal(gate, lease_payload())
    job = _seal(gate, job_payload())
    with pytest.raises(ProtoError):
        protocol.verify_job(lease, gate_keys, "g2", NOW)
    with pytest.raises(ProtoError):
        protocol.verify_lease(job, gate_keys, "g2", NOW, 0)


def test_tampered_payload_signature_and_key_id(gate, gate_keys):
    env = _seal(gate, job_payload(op="inv.host"))
    bad = dict(env, payload=env["payload"].replace("inv.host", "inv.disks"))
    with pytest.raises(ProtoError) as e:
        protocol.verify_job(bad, gate_keys, "g2", NOW)
    assert e.value.code == "DENY_JOB_SIGNATURE"
    with pytest.raises(ProtoError):
        protocol.verify_job(dict(env, key_id="hub-gate-9"), gate_keys, "g2", NOW)
    with pytest.raises(ProtoError):
        protocol.verify_job({**env, "extra": 1}, gate_keys, "g2", NOW)
    with pytest.raises(ProtoError):
        protocol.verify_job("not-an-envelope", gate_keys, "g2", NOW)


def test_non_canonical_payload_with_valid_signature_rejected(gate, gate_keys):
    text = json.dumps(job_payload(), indent=1)          # gueltige Signatur ueber nicht-kanonischen Text
    sig = sshsig.sign(text.encode(), gate["priv"], sshsig.NS_HUB)
    with pytest.raises(ProtoError):
        protocol.verify_job({"payload": text, "sig": sig, "key_id": gate["id"]}, gate_keys, "g2", NOW)


def test_signature_in_other_namespace_rejected(gate, gate_keys):
    text = canon.canonical_text(job_payload())
    for ns in (sshsig.NS_POLICY, sshsig.NS_APPROVAL, sshsig.NS_RELEASE):
        sig = sshsig.sign(text.encode(), gate["priv"], ns)
        with pytest.raises(ProtoError):
            protocol.verify_job({"payload": text, "sig": sig, "key_id": gate["id"]}, gate_keys, "g2", NOW)


# --------------------------------------------------------------------------------------------- revocation (T-REVOKE, Bibliothek)
def test_old_gate_key_signatures_rejected_after_policy_serial_plus_one(gate, gate2):   # test_old_gate_key_signatures_rejected_after_policy_serial_plus_one
    old = protocol.parse_gate_keys(gate["keys"])
    new = protocol.parse_gate_keys(gate2["keys"])                     # Policy serial+1: alter Schluessel entfernt, neuer eingetragen
    env_old = _seal(gate, job_payload())
    protocol.verify_job(env_old, old, "g2", NOW)
    with pytest.raises(ProtoError) as e:
        protocol.verify_job(env_old, new, "g2", NOW)
    assert e.value.code == "DENY_JOB_SIGNATURE"
    protocol.verify_job(_seal(gate2, job_payload()), new, "g2", NOW)
    both = protocol.parse_gate_keys(gate["keys"] + gate2["keys"])
    protocol.verify_job(env_old, both, "g2", NOW)                     # Uebergangsphase: beide gelistet
    with pytest.raises(ProtoError):
        protocol.verify_lease(_seal(gate, lease_payload()), new, "g2", NOW, 0)


def test_key_signed_under_a_different_key_id_is_rejected(gate, gate2):
    """Ein gelisteter Schluessel darf nicht unter der ID eines anderen signieren."""
    keys = protocol.parse_gate_keys(gate["keys"] + gate2["keys"])
    env = protocol.seal(job_payload(), gate2["priv"], gate["id"])     # Signatur von gate2, behauptet hub-gate-1
    with pytest.raises(ProtoError):
        protocol.verify_job(env, keys, "g2", NOW)


def test_gate_key_not_after_expiry(gate):
    keys = protocol.parse_gate_keys([{"id": gate["id"], "pub": gate["pub"], "not_after": "2026-10-30"}])
    env = _seal(gate, job_payload())
    with pytest.raises(ProtoError):
        protocol.verify_job(env, keys, "g2", NOW)                      # NOW = 31.10.
    keys_ok = protocol.parse_gate_keys([{"id": gate["id"], "pub": gate["pub"], "not_after": "2026-10-31"}])
    protocol.verify_job(env, keys_ok, "g2", NOW)                      # not_after gilt bis Tagesende UTC


def test_parse_gate_keys_validation(gate):
    for raw in ([], None, [{"id": "a", "pub": gate["pub"]}], [{"id": "a b", "pub": gate["pub"], "not_after": "2027-01-01"}],
                [{"id": "a", "pub": "ssh-rsa AAAA", "not_after": "2027-01-01"}], [{"id": "a", "pub": gate["pub"], "not_after": "tomorrow"}],
                [{"id": "a", "pub": gate["pub"], "not_after": "2027-01-01"}, {"id": "a", "pub": gate["pub"], "not_after": "2027-01-01"}]):
        with pytest.raises(ProtoError) as e:
            protocol.parse_gate_keys(raw)
        assert e.value.code == "DENY_POLICY_INVALID"


# ------------------------------------------------------------------------------------------------------ reason codes / bodies
def test_retryable_denials_match_design():
    assert protocol.RETRYABLE_DENIALS == {f"DENY_{x}" for x in "STOP LOCAL_STOP QUARANTINE STALE_LEASE CLOCK AUDIT_DOWN WINDOW RATE CIRCUIT_OPEN TARGET_LOCKED".split()}
    assert protocol.RETRYABLE_DENIALS < protocol.REASON_CODES
    assert protocol.result_to_state("denied", "DENY_STOP") == "denied_retryable"
    assert protocol.result_to_state("denied", "DENY_PROTECTED") == "denied"
    assert protocol.result_to_state("committed", None) == "committed"


def _result(**kw):
    b = {"attempt": 1, "status": "committed", "reason_code": None, "output": "", "audit_seq_range": None, "plan_hash": None}
    b.update(kw)
    return b


@pytest.mark.parametrize("kw", [{"status": "bogus"}, {"status": "denied"}, {"status": "denied", "reason_code": "FAIL_EXEC"}, {"status": "committed", "reason_code": "DENY_STOP"},
                                {"status": "failed", "reason_code": "BOGUS"}, {"status": "indeterminate", "reason_code": "FAIL_EXEC"}, {"attempt": 0}, {"output": "x" * 70000},
                                {"audit_seq_range": [5, 3]}, {"audit_seq_range": [1]}, {"plan_hash": "short"}])
def test_result_validation_rejects(kw):
    with pytest.raises(ProtoError):
        protocol.validate_result(_result(**kw))


def test_result_validation_accepts():
    protocol.validate_result(_result())
    protocol.validate_result(_result(status="denied", reason_code="DENY_STOP"))
    protocol.validate_result(_result(status="indeterminate", reason_code="INDETERMINATE", audit_seq_range=[3, 9]))
    protocol.validate_result(_result(status="failed", reason_code="FAIL_FENCED"))


def _poll(**kw):
    b = {"v": 1, "version": "0.1.0", "policy": {"serial": 1, "sha256": ""}, "clock": "2026-10-31T13:40:10Z", "spool_depth": 0, "audit_heads": {}, "open_jobs": []}
    b.update(kw)
    return b


def test_poll_validation():
    protocol.validate_poll_request(_poll(wait_s=30, audit_heads={"agent": {"seq": 0, "hash": "0" * 64}}))
    for kw in ({"wait_s": 31}, {"v": 2}, {"clock": "yesterday"}, {"audit_heads": {"hub": {"seq": 0, "hash": "0" * 64}}}, {"open_jobs": [{"job_id": "x", "state": "started", "attempt": 1}]},
               {"open_jobs": [{"job_id": "11111111-1111-4111-8111-111111111111", "state": "committed", "attempt": 1}]}, {"extra": 1}, {"spool_depth": -1}):
        with pytest.raises(ProtoError):
            protocol.validate_poll_request(_poll(**kw))


def test_trailing_newline_is_not_accepted_anywhere():
    """re '$' trifft vor einem abschliessenden Newline - Eingaben mit '\\n' am Ende duerfen nie als gueltig durchgehen (allowed_signers-Zeileninjektion u. a.)."""
    from forge_node import chain

    with pytest.raises(sshsig.SigError):
        sshsig.check_principal("hub-gate-1\n")
    assert not protocol.is_node_id("g2\n") and not protocol.is_slug("proj\n") and not protocol.is_hex64("a" * 64 + "\n") and not protocol.is_version("0.1.0\n")
    with pytest.raises(ProtoError):
        protocol.parse_ts("2026-10-31T13:40:10Z\n")
    with pytest.raises(ProtoError):
        protocol.check_uuid("11111111-1111-4111-8111-111111111111\n")
    with pytest.raises(chain.RecordError):
        chain.validate_record({"fmt": 1, "ts": "2026-10-31T13:40:10Z\n", "node": "g2", "seq": 1, "type": "t0", "prev_hash": "0" * 64, "hash": "0" * 64}, None, None)
    with pytest.raises(sshsig.SigError):
        sshsig.normalize_pub("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + "A" * 43 + "\nssh-ed25519 AAAA")
