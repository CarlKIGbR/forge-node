"""Per-profile release artifact (Design 13.C C2/C4, 13.E): `forge-node-<VER>-<profile>.tar` (+ `.tar.sig`) containing

    forge-node-<VER>/RELEASE.json            manifest: release, profile, switcher_api, state window, policy schema, units, sha256 of EVERY file
    forge-node-<VER>/RELEASE.json.sig        the owner's signature over RELEASE.json (namespace forge-node-release)
    forge-node-<VER>/forge-node.pyz          agent, privd, privctl, probes, doctor (zipapp). Profile t0: no op code (privd/ops.py, opworker.py) at all
    forge-node-<VER>/bin/privctl             /sbin-style wrapper around the zipapp
    forge-node-<VER>/sbin/forge-node-release the switcher (also installed OUTSIDE the tree by the owner, once)
    forge-node-<VER>/units/*                 the unit files (linked by the switcher, never copied)
    forge-node-<VER>/policy/policy-<nid>.json  templates for the nodes of this profile

The builder never holds a key: `sign` is a function the caller provides (the owner's `ssh-keygen -Y sign` on the Mac). The output is deterministic for a given source tree, version and
profile (fixed mtimes, owners and modes, sorted entries). Nothing here installs anything."""
import hashlib
import io
import json
import re
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Callable

from . import policies, units

VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}\Z")
SWITCHER_API = 1
STATE_MIN, STATE_MAX = 1, 1
POLICY_SCHEMA = 1
EPOCH = 1_762_000_000                                       # fixed mtime (2025-11-01): reproducible archives
ZIP_DATE = time.gmtime(EPOCH)[:6]                           # the same instant as the zip's DOS date (UTC, never the builder's local time)
EXCLUDE_DIRS = {"hub", "release", "__pycache__"}
# A t0 artifact (g1/g4: no workloads, no mutating op) carries only the privd modules LISTED here; anything else - op code today, `ops_*.py` of N5-N7 tomorrow - is not in it unless a reviewer
# adds it to this list. test_t0_artifacts_contain_only_listed_privd_modules_and_every_module_is_classified fails on a module that is in neither list.
T0_PRIVD_ALLOWED = ("__init__.py", "__main__.py", "classes.py", "client.py", "core.py", "gate.py", "lease.py", "ledger.py", "main.py", "maintenance.py", "optable.py", "policy_full.py",
                    "policy_store.py", "privctl.py", "reconcile.py", "resolver.py", "server.py", "units.py", "worker.py")
T0_PRIVD_EXCLUDED = ("ops.py", "opworker.py")


class BuildError(Exception):
    pass


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def package_files(src_root: Path, profile: str) -> list[Path]:
    """The forge_node source files that go into the zipapp of a profile."""
    pkg = src_root / "forge_node"
    out = []
    for p in sorted(pkg.rglob("*.py")):
        rel = p.relative_to(pkg)
        if any(part in EXCLUDE_DIRS for part in rel.parts) or str(rel) == "profile.py":
            continue
        if profile == "t0" and rel.parts[0] == "privd" and len(rel.parts) == 2 and rel.parts[1] not in T0_PRIVD_ALLOWED:
            continue
        out.append(p)
    return out


def build_zipapp(src_root: Path, profile: str, release: str, target: Path) -> None:
    """The release zipapp, written entry by entry with a fixed timestamp, fixed modes and a sorted order: the bytes depend on the source tree only - not on the builder's umask, time zone
    (zipapp/zipfile store LOCAL time), file mtimes or directory order. A zipapp is a zip with a `__main__.py`; `python3 -I forge-node.pyz` needs no header."""
    entries: dict[str, bytes] = {}
    for p in package_files(src_root, profile):
        entries["forge_node/" + p.relative_to(src_root / "forge_node").as_posix()] = p.read_bytes()
    entries["forge_node/profile.py"] = f'"""Build profile and release name (written by the release builder)."""\nPROFILE = "{profile}"\nRELEASE = "{release}"\n'.encode()
    # zipapp's own `main=` spec would call main() and DROP its return value (exit status 0 always): write the entry ourselves
    entries["__main__.py"] = b"import sys\nfrom forge_node.cli import main\n\nsys.exit(main())\n"
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as z:
        for name in sorted(entries):
            zi = zipfile.ZipInfo(name, date_time=ZIP_DATE)
            zi.compress_type = zipfile.ZIP_STORED
            zi.create_system = 3
            zi.external_attr = 0o100644 << 16
            z.writestr(zi, entries[name])


def _wrapper() -> bytes:
    return (b"#!/bin/sh\n# forge-node privctl: always runs the artifact that is `current`\n"
            b"exec /usr/bin/python3 -I /opt/forge-node/current/forge-node.pyz privctl \"$@\"\n")


def build_release(version: str, profile: str, out_dir: Path, *, src_root: Path, sign: Callable[[bytes], str], switcher_api: int = SWITCHER_API, state_window: tuple = (STATE_MIN, STATE_MAX),
                  policy_schema: int = POLICY_SCHEMA) -> dict:
    """Returns {tar, sig, sha256, manifest}. `sign(bytes) -> armored ssh signature text` is the owner's signature function (namespace forge-node-release)."""
    if not VERSION_RE.match(version) or profile not in ("full", "t0"):
        raise BuildError("bad version or profile")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    top = f"forge-node-{version}"
    files: dict[str, tuple[bytes, int]] = {}                                    # relative path -> (content, mode)
    with tempfile.TemporaryDirectory(prefix="fn-build-") as t:
        pyz = Path(t) / "forge-node.pyz"
        build_zipapp(Path(src_root), profile, version, pyz)
        files["forge-node.pyz"] = (pyz.read_bytes(), 0o644)
    files["bin/privctl"] = (_wrapper(), 0o755)
    switcher = (Path(src_root) / "forge_node" / "release" / "switcher.py").read_bytes()
    files["sbin/forge-node-release"] = (switcher, 0o755)
    unit_texts = units.all_units()
    for name, text in sorted(unit_texts.items()):
        files[f"units/{name}"] = (text.encode(), 0o644)
    for nid in policies.nodes_for(profile):
        files[f"policy/policy-{nid}.json"] = (json.dumps(policies.template(nid), indent=1, sort_keys=True).encode() + b"\n", 0o644)
    manifest = {"fmt": 1, "release": version, "profile": profile, "switcher_api": switcher_api, "state_min": state_window[0], "state_max": state_window[1], "policy_schema": policy_schema,
                "units": sorted(unit_texts), "files": {k: _sha(v[0]) for k, v in sorted(files.items())}}
    manifest_raw = json.dumps(manifest, indent=1, sort_keys=True).encode() + b"\n"
    sig = sign(manifest_raw)
    files["RELEASE.json"] = (manifest_raw, 0o644)
    files["RELEASE.json.sig"] = (sig.encode("ascii"), 0o644)
    tar_path = out_dir / f"forge-node-{version}-{profile}.tar"
    with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as tf:
        for d in ("", "bin", "sbin", "units", "policy"):
            ti = tarfile.TarInfo(f"{top}/{d}".rstrip("/"))
            ti.type, ti.mode, ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = tarfile.DIRTYPE, 0o755, EPOCH, 0, 0, "root", "root"
            if d != "policy" or any(k.startswith("policy/") for k in files):
                tf.addfile(ti)
        for name in sorted(files):
            data, mode = files[name]
            ti = tarfile.TarInfo(f"{top}/{name}")
            ti.size, ti.mode, ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = len(data), mode, EPOCH, 0, 0, "root", "root"
            tf.addfile(ti, io.BytesIO(data))
    tar_bytes = tar_path.read_bytes()
    sig_path = Path(str(tar_path) + ".sig")
    sig_path.write_text(sign(tar_bytes))
    return {"tar": tar_path, "sig": sig_path, "sha256": _sha(tar_bytes), "manifest": manifest}
