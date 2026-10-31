import pytest

from forge_node import redact

CANARIES = {
    "sk": "sk-CANARYabcdef123456", "ghp": "ghp_CANARYabcdef123456", "pat": "github_pat_11CANARY_abcdef", "slack": "xoxb-CANARY-123456-abcdef", "aws": "AKIACANARY1234567890",
    "hf": "hf_CANARYabcdef123456", "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.CANARYsig_abc-123",
    "pem": "-----BEGIN OPENSSH PRIVATE KEY-----\nCANARYb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----",
    "url": "https://alice:CANARYpw@example.org/x", "kv": "password=CANARYhunter2", "kvq": '"api_key": "CANARYkey123"', "auth": "Authorization: Bearer CANARYtoken123456",
    "bearer": "bearer CANARYabcdefgh12",
}


@pytest.mark.parametrize("name", sorted(CANARIES))
def test_light_redacts_canary(name):
    out = redact.redact_light(f"before {CANARIES[name]} after")
    assert "CANARY" not in out and redact.MARK in out and "before" in out and "after" in out


def test_full_redacts_long_hex_and_base64_but_keeps_digests_and_paths():
    s = "rev " + "0123456789abcdef" * 3 + " digest sha256:" + "ab12" * 16 + " path /usr/lib/python3/dist-packages key QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY3ODkw"
    out = redact.redact_full(s)
    assert "0123456789abcdef0123456789abcdef" not in out and "QUJDREVGR0hJSktMTU5PUFFSU1RV" not in out
    assert "sha256:" + "ab12" * 16 in out and "/usr/lib/python3/dist-packages" in out


def test_light_keeps_inventory_digests_and_git_revs():
    s = "image sha256:" + "ab12" * 16 + " rev " + "0123456789abcdef" * 2 + "01234567"
    assert redact.redact_light(s) == s


def test_redact_obj_recurses_values_not_keys():
    o = {"password": "x", "a": ["token=CANARYxyz12345", {"b": "sk-CANARYabcdef123456"}], "n": 3}
    out = redact.redact_obj(o)
    assert "CANARY" not in repr(out) and out["n"] == 3 and "password" in out


def test_idempotent():
    s = "token=CANARYxyz12345 and sk-CANARYabcdef123456"
    once = redact.redact_light(s)
    assert redact.redact_light(once) == once
