"""Transient-unit property classes of the op units (Design 4.4 table). The property set of an op unit comes from here and from the op table entry's class name - NEVER from request
parameters. The only inputs besides the class are values privd derives itself: the per-attempt work directory (it created it) and, for `dir-ops`, the forge roots of the verified policy.

`ro-probe` (the T0 probes) is hardening.ro_probe_properties(); this module adds the classes of the mutating ops. Data only: nothing here writes a unit file."""
from types import MappingProxyType

from ..t0 import hardening

_BASE = {
    "NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes", "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectKernelLogs": "yes",
    "ProtectControlGroups": "yes", "ProtectClock": "yes", "ProtectHostname": "yes", "LockPersonality": "yes", "RestrictRealtime": "yes", "RestrictSUIDSGID": "yes", "RestrictNamespaces": "yes",
    "SystemCallArchitectures": "native", "SystemCallFilter": "@system-service", "SystemCallErrorNumber": "EPERM", "UMask": "0077", "IPAddressDeny": "any",
    "KillMode": "control-group", "SendSIGKILL": "yes", "TimeoutStopSec": "30", "User": "root", "RestrictAddressFamilies": "AF_UNIX", "MemoryMax": "512M", "TasksMax": "128",
    "MemoryDenyWriteExecute": "yes", "PrivateDevices": "yes",
}

# class -> (extra fixed properties, needs the per-attempt work directory writable)
CLASSES = MappingProxyType({
    # the `selftest.*` ops and `doctor`'s selfcheck: they may write their own work directory and take the effect lock, nothing else
    "selftest": MappingProxyType({"CapabilityBoundingSet": ""}),
    "unit-ctl": MappingProxyType({"CapabilityBoundingSet": ""}),                                  # connects to the D-Bus/systemd sockets, which needs no write access
    "docker-ctl": MappingProxyType({"CapabilityBoundingSet": "", "InaccessiblePaths": "-/run/forge-node"}),
    "dir-ops": MappingProxyType({"CapabilityBoundingSet": "CAP_DAC_OVERRIDE CAP_CHOWN CAP_FOWNER"}),
    "volume-ops": MappingProxyType({"CapabilityBoundingSet": "CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_MKNOD", "PrivateDevices": "no"}),    # gate A: mounts are made by PID 1, never in this unit
    "scene": MappingProxyType({"CapabilityBoundingSet": ""}),
    "t3-manifest": MappingProxyType({"CapabilityBoundingSet": ""}),
    "t3-opaque": MappingProxyType({}),                                                            # cannot be sandboxed (effects unknown): caps below, no filesystem sandbox
})
NO_FILESYSTEM_SANDBOX = frozenset({"t3-opaque"})


class ClassError(Exception):
    pass


def op_unit_properties(cls: str, *, work_dir: str, priv_state: str, forge_roots: tuple[str, ...] = (), timeout_s: int) -> dict:
    """Property set of an op unit. `work_dir` is the per-attempt directory privd created (root-only); `forge_roots` come from the verified policy and only matter for `dir-ops`."""
    if cls not in CLASSES:
        raise ClassError(f"unknown unit class {cls!r}")
    if not isinstance(timeout_s, int) or isinstance(timeout_s, bool) or not 1 <= timeout_s <= 3600:
        raise ClassError("timeout out of range")
    p = {**_BASE, **CLASSES[cls]}
    if cls == "t3-opaque":
        for k in ("ProtectSystem", "ProtectHome", "PrivateTmp", "MemoryDenyWriteExecute", "SystemCallFilter", "RestrictNamespaces", "RestrictAddressFamilies", "PrivateDevices"):
            p.pop(k, None)
        p.update({"MemoryMax": "1G", "CPUQuota": "200%", "TasksMax": "256"})
    p["RuntimeMaxSec"] = str(timeout_s)
    rw = [work_dir, f"{priv_state}/locks"]
    if cls == "dir-ops":
        rw += list(forge_roots)
    if cls not in NO_FILESYSTEM_SANDBOX:
        p["ReadWritePaths"] = " ".join(rw)
    return p


def probe_unit_properties(probe: str, node_id: str) -> dict:
    """ro-probe class for one probe + the only environment it gets: the node id (probe_main loads and re-verifies the policy itself)."""
    p = hardening.ro_probe_properties(probe)
    p["Environment"] = f"FORGE_NODE_NODE_ID={node_id}"
    return p
