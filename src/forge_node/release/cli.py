"""Owner-side release commands (Design 13.A/13.C): `release build` and `release sign`. They run on the owner's Mac from a source checkout, never from the installed zipapp (the `release` package is
not part of any artifact):

    PYTHONPATH=src python3 -m forge_node.cli release build <VER> <t0|full> --out DIR --key ~/forge-node-owner/owner_ed25519
    PYTHONPATH=src python3 -m forge_node.cli release sign FILE --key KEY [--namespace forge-node-release]

Signing is `ssh-keygen -Y sign -n <namespace>` with the owner's passphrase-protected key, run INTERACTIVELY: the child inherits the terminal (stdin/stdout/stderr and the environment, so the
passphrase prompt on /dev/tty or via SSH_ASKPASS and a running ssh-agent all work). Nothing is captured, nothing is piped in, no passphrase passes through this program. A build asks for the
passphrase twice (the manifest and the tarball are two signatures); with `ssh-add KEY` once and `--key KEY.pub` the agent signs without a prompt. After signing, both signatures are verified
against the public key the way 13.C C2 does on the server, so a wrong key or namespace is found on the Mac, before anything is copied."""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .. import sshsig
from ..t0.policy import OWNER_PRINCIPAL
from . import build

MIN_PYTHON = (3, 12)


class CliError(Exception):
    pass


def _find_ssh_keygen() -> str:
    p = shutil.which("ssh-keygen")
    if not p:
        raise CliError("ssh-keygen not found in PATH")
    return p


def _check_key(key: Path) -> Path:
    """A private key must be a regular file nobody else can read; a `.pub` file means 'let ssh-agent sign' (the private key must be loaded with ssh-add)."""
    try:
        st = key.stat()
    except OSError as e:
        raise CliError(f"key not readable: {key}") from e
    if not key.is_file():
        raise CliError(f"key is not a regular file: {key}")
    if not key.name.endswith(".pub") and st.st_mode & 0o077:
        raise CliError(f"{key}: private key must not be accessible by group/others (chmod 600)")
    return key


def pub_for(key: Path, pub: Path | None) -> str:
    """The single-line `ssh-ed25519 AAAA...` the signatures are checked against."""
    cand = pub or (key if key.name.endswith(".pub") else key.with_name(key.name + ".pub"))
    try:
        return sshsig.normalize_pub(" ".join(cand.read_text().split()[:2]))
    except (OSError, sshsig.SigError) as e:
        raise CliError(f"public key {cand} missing or not a single ssh-ed25519 key (use --pub)") from e


def interactive_sign(data: bytes, key: Path, namespace: str, ssh_keygen: str, what: str = "data") -> str:
    """Armored detached signature of `data`. The terminal belongs to ssh-keygen for the duration (passphrase prompt); the data goes through a file in a private temp directory."""
    sshsig.check_namespace(namespace)
    with tempfile.TemporaryDirectory(prefix="fn-sign-") as d:
        os.chmod(d, 0o700)
        f = Path(d) / "msg"
        f.write_bytes(data)
        how = "ssh-agent signs" if key.name.endswith(".pub") else "enter the key's passphrase when asked"
        sys.stderr.write(f"signing {what} (namespace {namespace}) with {key} - {how}\n")
        sys.stderr.flush()
        try:
            rc = subprocess.run([ssh_keygen, "-Y", "sign", "-f", str(key), "-n", namespace, str(f)], check=False).returncode      # inherits stdin/stdout/stderr/env: NO capture_output
        except OSError as e:
            raise CliError(f"cannot run ssh-keygen: {e}") from e
        sig = Path(d) / "msg.sig"
        if rc != 0 or not sig.exists():
            raise CliError(f"ssh-keygen -Y sign failed (exit {rc}) - wrong passphrase, or the key cannot sign")
        text = sig.read_text(encoding="ascii")
    if not text.startswith("-----BEGIN SSH SIGNATURE-----"):
        raise CliError("ssh-keygen produced no signature")
    return text


def _verify(data: bytes, sig: str, namespace: str, pub: str, ssh_keygen: str) -> str:
    signers = sshsig.allowed_signers_text([(OWNER_PRINCIPAL, pub, namespace)])
    try:
        return sshsig.verify(data, sig, namespace, OWNER_PRINCIPAL, signers, ssh_keygen)
    except sshsig.SigError as e:
        raise CliError(f"the new signature does not verify against {pub[:30]}... - is that the owner key whose public half is in allowed_signers?") from e


def cmd_build(a) -> int:
    ssh_keygen = _find_ssh_keygen()
    key = _check_key(Path(a.key).expanduser())
    pub = pub_for(key, Path(a.pub).expanduser() if a.pub else None)
    out = Path(a.out).expanduser()
    src = Path(a.src).expanduser() if a.src else Path(__file__).resolve().parents[2]
    if not (src / "forge_node").is_dir():
        raise CliError(f"{src} has no forge_node/ package (--src)")
    if a.profile == "full":
        sys.stderr.write("note: profile full is not the install profile of the current decision (all hosts install t0)\n")
    tar, sig = out / f"forge-node-{a.version}-{a.profile}.tar", out / f"forge-node-{a.version}-{a.profile}.tar.sig"
    if not a.force and (tar.exists() or sig.exists()):
        raise CliError(f"{tar} already exists (--force to replace; a release version is built once)")
    seen = {}

    def sign(raw: bytes) -> str:
        what = "RELEASE.json (the manifest)" if "manifest" not in seen else f"{tar.name}"
        seen["manifest"] = True
        text = interactive_sign(raw, key, sshsig.NS_RELEASE, ssh_keygen, what)
        seen["fp"] = _verify(raw, text, sshsig.NS_RELEASE, pub, ssh_keygen)
        return text

    try:
        res = build.build_release(a.version, a.profile, out, src_root=src, sign=sign)
    except build.BuildError as e:
        raise CliError(f"build refused: {e}") from e
    except BaseException:                                                          # a failed or interrupted signature must not leave a tarball without (or with a stale) .sig behind
        for leftover in (tar, sig):
            leftover.unlink(missing_ok=True)
        raise
    print(f"tar:     {res['tar']}")
    print(f"sig:     {res['sig']}")
    print(f"sha256:  {res['sha256']}")
    print(f"signer:  {seen.get('fp', '?')}   (both signatures verified locally, namespace {sshsig.NS_RELEASE})")
    print(f"policy templates: {sorted(k for k in res['manifest']['files'] if k.startswith('policy/'))}")
    return 0


def cmd_sign(a) -> int:
    ssh_keygen = _find_ssh_keygen()
    key = _check_key(Path(a.key).expanduser())
    pub = pub_for(key, Path(a.pub).expanduser() if a.pub else None)
    f = Path(a.file).expanduser()
    try:
        data = f.read_bytes()
    except OSError as e:
        raise CliError(f"cannot read {f}") from e
    dest = Path(a.sig).expanduser() if a.sig else f.with_name(f.name + ".sig")
    if dest.exists() and not a.force:
        raise CliError(f"{dest} already exists (--force to replace)")
    text = interactive_sign(data, key, a.namespace, ssh_keygen, f.name)
    fp = _verify(data, text, a.namespace, pub, ssh_keygen)
    dest.write_text(text, encoding="ascii")
    print(f"sig:     {dest}")
    print(f"signer:  {fp}   (verified locally, namespace {a.namespace})")
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="forge-node release", description="owner-side release build and signing (run on the Mac from a source checkout)")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="build forge-node-<VER>-<profile>.tar + .tar.sig (two interactive signatures)")
    b.add_argument("version")
    b.add_argument("profile", choices=("t0", "full"))
    b.add_argument("--out", required=True, help="output directory (e.g. ~/forge-node-owner/release)")
    b.add_argument("--key", required=True, help="owner private key (passphrase asked), or its .pub when the key is loaded in ssh-agent")
    b.add_argument("--pub", help="public key to verify against (default: KEY.pub)")
    b.add_argument("--src", help="directory that contains forge_node/ (default: the tree this program runs from)")
    b.add_argument("--force", action="store_true", help="replace an existing artifact")
    b.set_defaults(fn=cmd_build)
    s = sub.add_parser("sign", help="sign one file (detached .sig next to it)")
    s.add_argument("file")
    s.add_argument("--key", required=True)
    s.add_argument("--pub")
    s.add_argument("--namespace", default=sshsig.NS_RELEASE, choices=(sshsig.NS_RELEASE, sshsig.NS_POLICY, sshsig.NS_APPROVAL))
    s.add_argument("--sig", help="signature file to write (default: FILE.sig)")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_sign)
    return p


def main(argv=None) -> int:
    if sys.version_info < MIN_PYTHON:
        sys.stderr.write(f"python >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]} needed (this is {sys.version.split()[0]})\n")
        return 2
    args = parser().parse_args(sys.argv[1:] if argv is None else argv)
    try:
        return args.fn(args)
    except CliError as e:
        sys.stderr.write(f"release: {e}\n")
        return 1
