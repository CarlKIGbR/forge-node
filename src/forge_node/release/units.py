"""Unit files of the node (Design 4.4, 4.5, 8.3, 13.C), rendered from DATA. Nothing is written to /etc/systemd here; the release artifact carries these texts under units/ and
`forge-node-release` links them (`systemctl link /opt/forge-node/current/units/<unit>`), so one `current` switch moves agent, privd and timers together.

The agent unit comes from t0/hardening.AGENT_UNIT (checked offline in N2); privd, its socket and the rotation timer are defined here. Properties are fixed; the node id is the only
per-host value and comes from /etc/forge-node/node.env (EnvironmentFile), never from the artifact."""
from types import MappingProxyType

from ..t0 import hardening

PYZ = "/opt/forge-node/current/forge-node.pyz"
PYTHON = "/usr/bin/python3"
NODE_ENV = "/etc/forge-node/node.env"

# privd (root): the only privileged process. It performs no effect itself (op units do), writes only its state, the logs and the installed policy (Design 4.4), and may flag inodes.
PRIVD_SERVICE = MappingProxyType({
    "Type": "simple", "User": "root", "NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes",
    "ReadWritePaths": "/var/lib/forge-node-priv /var/log/forge-node-priv /var/log/forge-node-agent /run/forge-node /etc/forge-node",
    "ProtectKernelTunables": "yes", "ProtectKernelModules": "yes", "ProtectKernelLogs": "yes", "ProtectControlGroups": "yes", "ProtectClock": "yes", "ProtectHostname": "yes",
    "LockPersonality": "yes", "RestrictRealtime": "yes", "RestrictSUIDSGID": "yes", "RestrictNamespaces": "yes", "SystemCallArchitectures": "native", "SystemCallFilter": "@system-service",
    "SystemCallErrorNumber": "EPERM", "MemoryDenyWriteExecute": "yes", "PrivateDevices": "yes", "UMask": "0077", "RestrictAddressFamilies": "AF_UNIX", "IPAddressDeny": "any",
    "CapabilityBoundingSet": "CAP_LINUX_IMMUTABLE CAP_CHOWN", "MemoryMax": "256M", "TasksMax": "64", "Restart": "on-failure", "RestartSec": "5",
    "KillMode": "process",                       # op units are separate transient units, not children: killing privd never kills a worker, and a stop of privd must not either
})
PRIVD_SOCKET = MappingProxyType({"ListenStream": "/run/forge-node/priv.sock", "SocketMode": "0660", "SocketUser": "root", "SocketGroup": "forgenode", "DirectoryMode": "0755",
                                 "Accept": "no", "RemoveOnStop": "yes"})
ROTATE_SERVICE = MappingProxyType({"Type": "oneshot", "User": "root", "NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes",
                                   "ReadWritePaths": "/run/forge-node", "RestrictAddressFamilies": "AF_UNIX", "IPAddressDeny": "any", "CapabilityBoundingSet": "", "UMask": "0077",
                                   "SystemCallFilter": "@system-service", "MemoryMax": "64M"})
ROTATE_TIMER = MappingProxyType({"OnCalendar": "hourly", "RandomizedDelaySec": "300", "Persistent": "yes", "AccuracySec": "1min"})


def _render(sections: list[tuple[str, list[tuple[str, str]]]]) -> str:
    out = []
    for name, items in sections:
        out.append(f"[{name}]")
        for k, v in items:
            if "\n" in v or "\x00" in v:
                raise ValueError(f"unit value for {k} contains a line break")
            out.append(f"{k}={v}")
        out.append("")
    return "\n".join(out)


def _props(d) -> list[tuple[str, str]]:
    return [(k, v) for k, v in d.items()]


def agent_service(node_id: str | None = None) -> str:
    """The agent's unit. `node_id` None = the shipped artifact (node id from node.env); a value adds the g4 MemoryMax override only for the offline check."""
    props = hardening.agent_properties(node_id) if node_id else dict(hardening.AGENT_UNIT)
    props.pop("User", None)
    return _render([
        ("Unit", [("Description", "forge-node agent (T0 reads, relay to privd)"), ("Requires", "forge-node-privd.socket"), ("After", "network-online.target forge-node-privd.socket"), ("Wants", "network-online.target")]),
        ("Service", [("User", "forgenode"), ("EnvironmentFile", NODE_ENV), ("ExecStart", f"{PYTHON} -I {PYZ} agent run"), *_props(props)]),
        ("Install", [("WantedBy", "multi-user.target")]),
    ])


def privd_service() -> str:
    return _render([
        ("Unit", [("Description", "forge-node privd (the one root entry point; no effect of its own)"), ("Requires", "forge-node-privd.socket"), ("After", "forge-node-privd.socket local-fs.target")]),
        ("Service", [("EnvironmentFile", NODE_ENV), ("ExecStart", f"{PYTHON} -I {PYZ} privd"), *_props(PRIVD_SERVICE)]),
    ])


def privd_socket() -> str:
    return _render([("Unit", [("Description", "forge-node privd socket (root:forgenode 0660)")]), ("Socket", _props(PRIVD_SOCKET)), ("Install", [("WantedBy", "sockets.target")])])


def rotate_service() -> str:
    return _render([("Unit", [("Description", "forge-node audit rotation (size/age, sealed by privd)"), ("After", "forge-node-privd.socket"), ("Requires", "forge-node-privd.socket")]),
                    ("Service", [("EnvironmentFile", NODE_ENV), ("ExecStart", f"{PYTHON} -I {PYZ} privctl audit-rotate due"), *_props(ROTATE_SERVICE)])])


def rotate_timer() -> str:
    return _render([("Unit", [("Description", "forge-node audit rotation timer")]), ("Timer", _props(ROTATE_TIMER)), ("Install", [("WantedBy", "timers.target")])])


def all_units() -> dict[str, str]:
    return {"forge-node-agent.service": agent_service(), "forge-node-privd.service": privd_service(), "forge-node-privd.socket": privd_socket(),
            "forge-node-audit-rotate.service": rotate_service(), "forge-node-audit-rotate.timer": rotate_timer()}
