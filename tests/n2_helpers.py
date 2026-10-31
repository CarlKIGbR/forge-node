"""Shared builders for the N2 tests: signed policies, a fake command runner, a fake /proc tree. (Not a test module.)"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from forge_node import protocol, sshsig
from forge_node.t0 import runner as runner_mod
from forge_node.t0.env import Env
from forge_node.t0.fsread import Fs, ProtectedSet
from forge_node.t0.policy import OWNER_PRINCIPAL, parse_policy

NOW = datetime(2026, 10, 31, 13, 40, 10, tzinfo=timezone.utc)      # Saturday 14:40 Berlin: outside every window
PIN = "ab" * 32


def policy_doc(node="g2", serial=1, pins=(PIN,), gate_keys=None, **over) -> dict:
    d = {"schema": 1, "serial": serial, "not_before": "2026-10-31T00:00:00Z", "node": node, "profile": "full", "global_mode": "observe", "tiers_enabled": [0],
         "hub_tls_pins": list(pins), "hub_gate_keys": gate_keys or [{"id": "hub-gate-1", "pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOCnQJdkGAnqC9RpKFPyX3e4R8Y5v0QG9hJmFqQqkG8E", "not_after": "2099-12-31"}],
         "protected": {"paths": ["/opt/kmu-ai", "/srv/models", "/srv/kmu-ai"], "units": ["kmu-*", "ollama.service"]},
         "t0": {"units_for_logs": ["forge-postbote.service", "forge-edge.service"], "cert_paths": [], "backup_units": ["kmu-sicherung-*"], "backup_dirs": [], "repos": [], "model_dirs": []},
         "t1": {"workloads_enabled": False}, "t2": {"ops": []}, "t3": {"manifests_enabled": [], "opaque_enabled": False}, "windows": {"blackout": "02:00-05:45", "sunday_open": "06:00"}}
    d.update(over)
    return d


def signers_text(owner_pub: str) -> str:
    return sshsig.allowed_signers_text([(OWNER_PRINCIPAL, owner_pub, sshsig.NS_POLICY)])


def install_policy(directory: Path, doc: dict, owner_priv, serial: int | None = None, raw: bytes | None = None, sig: str | None = None) -> bytes:
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o755)
    serial = serial if serial is not None else doc["serial"]
    raw = raw if raw is not None else json.dumps(doc, indent=1, sort_keys=True).encode()
    sig = sig if sig is not None else sshsig.sign(raw, owner_priv, sshsig.NS_POLICY)
    for name, data in ((f"policy-{serial}.json", raw), (f"policy-{serial}.json.sig", sig.encode())):
        p = directory / name
        p.write_bytes(data)
        os.chmod(p, 0o644)
    return raw


def view(doc=None, **over):
    doc = doc or policy_doc(**over)
    return parse_policy(json.dumps(doc).encode(), doc["node"], doc["serial"], NOW)


class FakeRunner:
    """Scripted stand-in for runner.ReadOnlyRunner: results by command id (a Run, a bytes/str stdout, or a callable(slots, stdin) -> Run). Unknown ids are 'missing'."""

    def __init__(self, script=None, available=None):
        self.script = dict(script or {})
        self.avail = available
        self.calls: list[tuple[str, dict]] = []

    def run(self, cmd_id, slots=None, stdin=None, max_wait_s=None):
        assert cmd_id in runner_mod.CMDS, f"unknown command id {cmd_id}"
        self.calls.append((cmd_id, dict(slots or {})))
        r = self.script.get(cmd_id)
        if callable(r):
            r = r(slots or {}, stdin)
        if r is None:
            return runner_mod.Run(False, "missing", argv=(cmd_id,))
        if isinstance(r, (str, bytes)):
            return runner_mod.Run(True, "ok", 0, r.encode() if isinstance(r, str) else r, argv=(cmd_id,))
        return r

    def available(self, cmd_id):
        if self.avail is not None:
            return cmd_id in self.avail
        return self.script.get(cmd_id) is not None

    def called(self, cmd_id) -> int:
        return sum(1 for c, _ in self.calls if c == cmd_id)


def write_tree(root: Path, files: dict[str, str]):
    for rel, content in files.items():
        p = root / rel.lstrip("/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)


PROC = {
    "/proc/meminfo": "MemTotal:       65856000 kB\nMemFree:         1000000 kB\nMemAvailable:   30000000 kB\nSwapTotal:       2097148 kB\nSwapFree:        1900000 kB\n",
    "/proc/cpuinfo": "processor\t: 0\nmodel name\t: AMD Ryzen 9 7950X\n\nprocessor\t: 1\nmodel name\t: AMD Ryzen 9 7950X\n",
    "/proc/loadavg": "0.52 0.40 0.30 1/500 12345\n",
    "/proc/uptime": "123456.78 654321.00\n",
    "/proc/stat": "cpu  1000 0 500 8000 100 0 0 0 0 0\ncpu0 500 0 250 4000 50 0 0 0 0 0\n",
    "/proc/diskstats": "259 0 nvme0n1 100 0 2000 50 200 0 4000 80 3 130 0 0 0 0 0 0 0\n259 1 nvme0n1p1 10 0 20 5 20 0 40 8 0 13 0 0 0 0 0 0 0\n   7 0 loop0 1 0 2 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
    "/proc/net/dev": "Inter-|   Receive\n face |bytes\n    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0\n  eth0: 5000 50 0 0 0 0 0 0 7000 70 0 0 0 0 0 0\n",
    "/proc/mounts": "server:/export /mnt/nas nfs4 rw,relatime 0 0\n/dev/nvme0n1p2 / ext4 rw 0 0\n",
    "/proc/sys/kernel/osrelease": "6.8.0-48-generic\n",
    "/proc/sys/kernel/hostname": "carlgpu2\n",
    "/etc/os-release": 'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nVERSION_ID="24.04"\nID=ubuntu\nVERSION_CODENAME=noble\n',
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\ncarl:x:1000:1000::/home/carl:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n",
    "/etc/group": "root:x:0:\nsudo:x:27:carl\ndocker:x:984:carl,forge\nadm:x:4:syslog\n",
}


def make_env(tmp: Path, runner=None, policy=None, files=None, now=NOW, protected=("/srv/models",)) -> Env:
    write_tree(tmp, {**PROC, **(files or {})})
    pol = policy or view()
    return Env(Fs(ProtectedSet.from_policy(list(protected) + list(pol.protected_paths)), str(tmp)), runner or FakeRunner(), lambda: now, pol)
