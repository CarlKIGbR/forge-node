"""Hardening data (Design 4.4, 4.5) as code, so the properties are tested and N3 renders them into unit files / `systemd-run` arguments. This is data only: no unit file is shipped,
nothing is installed. Properties come from these tables, never from request parameters; the functions take no parameters from outside.

Checked offline in N2 (no install): every directive name and value parses (`systemd-analyze verify` on a rendered copy outside the repo reports nothing), exposure scores are in the N2 report.
NOT checked: that the commands still work inside the sandbox - `doctor` (N3/N4) runs each op's `--selfcheck` in the real unit.

Deviations from the design text (reported):
  * agent `RestrictAddressFamilies` lists AF_NETLINK (`ss`, `ip route` of inv.net use netlink; revision 3 omitted it; harmless without capabilities);
  * the design's single `ro-probe` class is a base plus a per-probe row: `net` (ss -p) needs CAP_SYS_PTRACE, `firewall` (iptables -S) CAP_NET_ADMIN, so they are separate probes and no
    probe holds both; `container_net` (reads /proc/<pid>/net/dev of container processes) is separate from the plain `containers` inventory so that one has no PTRACE;
  * probes cannot reach privd's socket, nor the sockets of daemons they have no business with (Docker, containerd, libvirt, D-Bus, systemd's private socket): `InaccessiblePaths`,
    although they are root and have AF_UNIX."""
from types import MappingProxyType

_COMMON = {
    "NoNewPrivileges": "yes", "ProtectSystem": "strict", "PrivateTmp": "yes", "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectKernelLogs": "yes",
    "ProtectControlGroups": "yes", "ProtectClock": "yes", "ProtectHostname": "yes", "LockPersonality": "yes", "RestrictRealtime": "yes", "RestrictSUIDSGID": "yes",
    "RestrictNamespaces": "yes", "SystemCallArchitectures": "native", "SystemCallFilter": "@system-service", "SystemCallErrorNumber": "EPERM", "UMask": "0077", "IPAddressDeny": "any",
}

AGENT_UNIT = MappingProxyType({
    **_COMMON, "User": "forgenode", "ReadWritePaths": "/var/lib/forge-node /var/log/forge-node-agent", "ProtectHome": "yes", "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6 AF_NETLINK",
    "IPAddressAllow": "192.168.10.4/32 127.0.0.0/8", "CapabilityBoundingSet": "", "MemoryMax": "128M", "CPUQuota": "15%", "Nice": "19", "IOWeight": "10", "Restart": "on-failure", "RestartSec": "10",
    # no PrivateDevices (nvidia-smi needs /dev/nvidia*) and no MemoryDenyWriteExecute (the NVIDIA driver library maps writable+executable memory)
})
AGENT_UNIT_OVERRIDES = MappingProxyType({"g4": MappingProxyType({"MemoryMax": "96M"})})          # swap-bound host (Design 4.5)

RO_PROBE_BASE = MappingProxyType({
    **_COMMON, "User": "root", "ProtectHome": "read-only", "PrivateDevices": "yes", "MemoryDenyWriteExecute": "yes", "MemoryMax": "256M", "TasksMax": "64", "Nice": "19",
    "KillMode": "control-group", "SendSIGKILL": "yes", "TimeoutStopSec": "30",
})
# Per probe: extra capabilities, address families, wall-clock limit, idle I/O class, whether it may talk to Docker. No probe gets a ReadWritePaths entry.
RO_PROBES = MappingProxyType({
    "net": MappingProxyType({"caps": ("CAP_SYS_PTRACE", "CAP_DAC_READ_SEARCH"), "families": "AF_UNIX AF_NETLINK", "runtime_s": 60, "idle_io": False, "docker": False}),
    "firewall": MappingProxyType({"caps": ("CAP_NET_ADMIN",), "families": "AF_UNIX AF_NETLINK AF_INET", "runtime_s": 60, "idle_io": False, "docker": False}),
    "containers": MappingProxyType({"caps": ("CAP_DAC_READ_SEARCH",), "families": "AF_UNIX", "runtime_s": 120, "idle_io": False, "docker": True}),
    "container_net": MappingProxyType({"caps": (), "families": "AF_UNIX", "runtime_s": 120, "idle_io": False, "docker": True}),            # /proc/<pid>/net/dev is world-readable (hidepid=0)
    "vms": MappingProxyType({"caps": (), "families": "AF_UNIX", "runtime_s": 60, "idle_io": False, "docker": False}),
    "certs": MappingProxyType({"caps": ("CAP_DAC_READ_SEARCH",), "families": "AF_UNIX", "runtime_s": 120, "idle_io": False, "docker": False}),
    "git": MappingProxyType({"caps": ("CAP_DAC_READ_SEARCH",), "families": "AF_UNIX", "runtime_s": 240, "idle_io": True, "docker": False}),
    "access": MappingProxyType({"caps": ("CAP_DAC_READ_SEARCH",), "families": "AF_UNIX", "runtime_s": 60, "idle_io": False, "docker": False}),
    "models": MappingProxyType({"caps": ("CAP_DAC_READ_SEARCH",), "families": "AF_UNIX", "runtime_s": 240, "idle_io": True, "docker": False}),
    "journal": MappingProxyType({"caps": ("CAP_DAC_READ_SEARCH",), "families": "AF_UNIX", "runtime_s": 60, "idle_io": False, "docker": False}),
    "activity": MappingProxyType({"caps": ("CAP_DAC_READ_SEARCH",), "families": "AF_UNIX", "runtime_s": 60, "idle_io": False, "docker": False}),
    "uulog": MappingProxyType({"caps": ("CAP_DAC_READ_SEARCH",), "families": "AF_UNIX", "runtime_s": 30, "idle_io": False, "docker": False}),
})


def agent_properties(node_id: str) -> dict:
    return {**AGENT_UNIT, **AGENT_UNIT_OVERRIDES.get(node_id, {})}


def ro_probe_properties(probe: str) -> dict:
    spec = RO_PROBES[probe]
    p = dict(RO_PROBE_BASE)
    p["CapabilityBoundingSet"] = " ".join(spec["caps"])
    p["RestrictAddressFamilies"] = spec["families"]
    p["RuntimeMaxSec"] = str(spec["runtime_s"])
    # privd's socket is never reachable from a probe; Docker's only for the probes that inventory containers, libvirt's only for `vms` ('-' = ignore if absent)
    hidden = ["/run/forge-node", "/run/containerd", "/run/dbus", "/run/systemd/private", "/run/systemd/io.systemd.ManagedOOM"]
    if not spec["docker"]:
        hidden.append("/run/docker.sock")
    if probe != "vms":
        hidden.append("/run/libvirt")
    p["InaccessiblePaths"] = " ".join("-" + h for h in hidden)
    if spec["idle_io"]:
        p["IOSchedulingClass"] = "idle"
    return p
