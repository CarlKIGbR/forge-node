"""Signaturen ueber `ssh-keygen -Y` (Design 3.1): die Python-stdlib kann kein Ed25519; OpenSSH ist auf allen vier Hosts vorhanden.

Vier getrennte Namespaces; eine Signatur fuer einen Namespace ist in keinem anderen gueltig (Policy-Signatur != Approval).
Der Aufrufer reicht Daten als Bytes; Schluessel- und allowed_signers-Dateien liegen nur in einem 0700-Temp-Verzeichnis. Es wird hier nie ein Schluessel erzeugt."""
import os
import re
import subprocess
import tempfile
from pathlib import Path

NS_POLICY = "forge-node-policy"
NS_RELEASE = "forge-node-release"
NS_APPROVAL = "forge-node-approval"
NS_HUB = "forge-node-hub"
NAMESPACES = frozenset({NS_POLICY, NS_RELEASE, NS_APPROVAL, NS_HUB})

MAX_SIG_BYTES = 4096
MAX_DATA_BYTES = 300 * 1024 * 1024
_PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}\Z")
_PUB_RE = re.compile(r"^ssh-ed25519 (AAAAC3NzaC1lZDI1NTE5[A-Za-z0-9+/]{48})( [^\r\n]{0,64})?\Z")
_SIG_BEGIN = "-----BEGIN SSH SIGNATURE-----"
_SIG_END = "-----END SSH SIGNATURE-----"
TIMEOUT_S = 20


class SigError(Exception):
    """Signatur ungueltig, Namespace falsch oder ssh-keygen nicht nutzbar - immer fail-closed."""


def _clean_env() -> dict:
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "HOME": "/nonexistent"}


def check_namespace(ns: str) -> str:
    if ns not in NAMESPACES:
        raise SigError(f"unknown namespace {ns!r}")
    return ns


def check_principal(p: str) -> str:
    if not isinstance(p, str) or not _PRINCIPAL_RE.match(p):
        raise SigError("invalid principal / key id")
    return p


def normalize_pub(pub: str) -> str:
    """Nur `ssh-ed25519 <base64>` (optional kurzer Kommentar). Optionen, Mehrzeiler, andere Schluesseltypen => Fehler (kein Einschleusen in allowed_signers)."""
    if not isinstance(pub, str) or not _PUB_RE.match(pub.strip()):
        raise SigError("public key must be a single-line ssh-ed25519 key")
    m = _PUB_RE.match(pub.strip())
    return f"ssh-ed25519 {m.group(1)}"


def allowed_signers_text(keys: list[tuple[str, str, str]]) -> str:
    """keys: (principal, pub, namespace) -> allowed_signers-Zeilen mit namespaces="…" (Signatur nur in diesem Namespace)."""
    lines = []
    for principal, pub, ns in keys:
        lines.append(f'{check_principal(principal)} namespaces="{check_namespace(ns)}" {normalize_pub(pub)}')
    return "\n".join(lines) + "\n"


def _run(argv: list[str], data: bytes | None = None, cwd: str | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, input=data if data is not None else b"", capture_output=True, timeout=TIMEOUT_S, cwd=cwd, env=_clean_env(), check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise SigError(f"ssh-keygen unusable: {type(e).__name__}") from e


def sign(data: bytes, key_path: str | Path, namespace: str, ssh_keygen: str = "ssh-keygen") -> str:
    """Detached armored signature. Der Schluessel darf nicht fuer Gruppe/Andere lesbar sein (kein Passphrase-Prompt: stdin ist leer)."""
    check_namespace(namespace)
    key_path = Path(key_path)
    try:
        st = key_path.stat()
    except OSError as e:
        raise SigError("signing key not readable") from e
    if st.st_mode & 0o077:
        raise SigError("signing key must not be accessible by group/others")
    if len(data) > MAX_DATA_BYTES:
        raise SigError("data too large")
    with tempfile.TemporaryDirectory(prefix="fn-sign-") as d:
        os.chmod(d, 0o700)
        f = Path(d) / "msg"
        f.write_bytes(data)
        r = _run([ssh_keygen, "-q", "-Y", "sign", "-f", str(key_path), "-n", namespace, str(f)])
        sig = Path(d) / "msg.sig"
        if r.returncode != 0 or not sig.exists():
            raise SigError("signing failed")
        text = sig.read_text(encoding="ascii")
    if not text.startswith(_SIG_BEGIN):
        raise SigError("signing produced no signature")
    return text


def verify(data: bytes, sig: str, namespace: str, principal: str, allowed_signers: str, ssh_keygen: str = "ssh-keygen") -> str:
    """True-Pfad liefert den Fingerprint des Signierschluessels; jeder andere Ausgang wirft SigError."""
    check_namespace(namespace)
    check_principal(principal)
    if not isinstance(sig, str) or len(sig) > MAX_SIG_BYTES or not sig.startswith(_SIG_BEGIN) or _SIG_END not in sig:
        raise SigError("malformed signature")
    if not sig.isascii():
        raise SigError("malformed signature")
    if len(data) > MAX_DATA_BYTES:
        raise SigError("data too large")
    with tempfile.TemporaryDirectory(prefix="fn-verify-") as d:
        os.chmod(d, 0o700)
        sf, af = Path(d) / "sig", Path(d) / "allowed"
        sf.write_text(sig, encoding="ascii")
        af.write_text(allowed_signers, encoding="ascii")
        r = _run([ssh_keygen, "-Y", "verify", "-f", str(af), "-I", principal, "-n", namespace, "-s", str(sf)], data=data)
    out = r.stdout.decode("utf-8", "replace")
    m = re.match(r'^Good "([^"]+)" signature for (\S+) with ED25519 key (SHA256:[A-Za-z0-9+/]{43})\s*$', out)
    if r.returncode != 0 or not m or m.group(1) != namespace or m.group(2) != principal:
        raise SigError("signature verification failed")
    return m.group(3)


def fingerprint_of_pub(pub: str, ssh_keygen: str = "ssh-keygen") -> str:
    with tempfile.TemporaryDirectory(prefix="fn-fp-") as d:
        os.chmod(d, 0o700)
        f = Path(d) / "k.pub"
        f.write_text(normalize_pub(pub) + "\n", encoding="ascii")
        r = _run([ssh_keygen, "-lf", str(f)])
    m = re.match(r"^\d+ (SHA256:[A-Za-z0-9+/]{43}) ", r.stdout.decode("utf-8", "replace"))
    if r.returncode != 0 or not m:
        raise SigError("cannot fingerprint key")
    return m.group(1)
