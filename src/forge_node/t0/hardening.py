"""Hardening data (Design 4.4, 4.5) as code, so the properties are tested and N3 renders them into unit files / `systemd-run` arguments. This is data only: no unit file is shipped,
nothing is installed. Properties come from these tables, never from request parameters; the functions take no parameters from outside.

Deviation from design 4.5 (reported): `RestrictAddressFamilies` for the agent lists AF_NETLINK in addition to AF_UNIX/AF_INET/AF_INET6, because `ss` and `ip route` (T0 inv.net) talk
netlink. It is harmless without capabilities (CapabilityBoundingSet is empty). `doctor` (N3/N4) proves the whole set inside the real unit."""
from types import MappingProxyType

AGENT_UNIT = MappingProxyType({
    "User": "forgenode", "NoNewPrivileges": "yes", "ProtectSystem": "strict", "ReadWritePaths": "/var/lib/forge-node /var/log/forge-node-agent", "ProtectHome": "yes", "PrivateTmp": "yes",
    "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectControlGroups": "yes", "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6 AF_NETLINK",
    "IPAddressDeny": "any", "IPAddressAllow": "192.168.10.4/32 127.0.0.0/8", "SystemCallFilter": "@system-service", "CapabilityBoundingSet": "", "MemoryMax": "128M",
    "CPUQuota": "15%", "Nice": "19", "IOWeight": "10", "Restart": "on-failure", "RestartSec": "10",
})
AGENT_UNIT_OVERRIDES = MappingProxyType({"g4": MappingProxyType({"MemoryMax": "96M"})})          # swap-bound host (Design 4.5)

RO_PROBE_BASE = MappingProxyType({
    "User": "root", "NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "read-only", "PrivateTmp": "yes", "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes",
    "ProtectControlGroups": "yes", "IPAddressDeny": "any", "MemoryMax": "256M", "TasksMax": "64", "Nice": "19", "KillMode": "control-group", "SendSIGKILL": "yes", "TimeoutStopSec": "30",
})
# per probe: extra capabilities, address families, wall-clock limit, idle I/O class. No probe gets a ReadWritePaths entry.
RO_PROBES = MappingProxyType({
    "net": MappingProxyType({"caps": ("CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_DAC_READ_SEARCH"), "families": "AF_UNIX AF_NETLINK AF_INET", "runtime_s": 60, "idle_io": False}),
    "containers": MappingProxyType({"caps": ("CAP_SYS_PTRACE", "CAP_DAC_READ_SEARCH"), "families": "AF_UNIX", "runtime_s": 120, "idle_io": False}),
    "vms": MappingProxyType({"caps": (), "families": "AF_UNIX", "runtime_s": 60, "idle_io": False}),
    "certs": MappingProxyType({"caps": ("CAP_DAC_READ_SEARCH",), "families": "AF_UNIX", "runtime_s": 120, "idle_io": False}),
    "git": MappingProxyType({"caps": ("CAP_DAC_READ_SEARCH",), "families": "AF_UNIX", "runtime_s": 240, "idle_io": True}),
    "access": MappingProxyType({"caps": ("CAP_DAC_READ_SEARCH",), "families": "AF_UNIX", "runtime_s": 60, "idle_io": False}),
    "models": MappingProxyType({"caps": ("CAP_DAC_READ_SEARCH",), "families": "AF_UNIX", "runtime_s": 240, "idle_io": True}),
    "journal": MappingProxyType({"caps": ("CAP_DAC_READ_SEARCH",), "families": "AF_UNIX", "runtime_s": 60, "idle_io": False}),
    "activity": MappingProxyType({"caps": ("CAP_DAC_READ_SEARCH",), "families": "AF_UNIX", "runtime_s": 60, "idle_io": False}),
    "uulog": MappingProxyType({"caps": ("CAP_DAC_READ_SEARCH",), "families": "AF_UNIX", "runtime_s": 30, "idle_io": False}),
})


def agent_properties(node_id: str) -> dict:
    return {**AGENT_UNIT, **AGENT_UNIT_OVERRIDES.get(node_id, {})}


def ro_probe_properties(probe: str) -> dict:
    spec = RO_PROBES[probe]
    p = dict(RO_PROBE_BASE)
    p["CapabilityBoundingSet"] = " ".join(spec["caps"])
    p["RestrictAddressFamilies"] = spec["families"]
    p["RuntimeMaxSec"] = str(spec["runtime_s"])
    if spec["idle_io"]:
        p["IOSchedulingClass"] = "idle"
    return p
