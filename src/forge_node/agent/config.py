"""Agent configuration: environment variables set by the (N3) unit, validated once at start. Paths default to the layout of Design 13.C; the hub address is an IP literal (no DNS,
so a resolver cannot redirect the agent) and is only ever dialled over mTLS with the pins from the signed policy."""
import ipaddress
import os
import re
from dataclasses import dataclass

NODE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}\Z")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class AgentConfig:
    node_id: str
    hub_host: str
    hub_port: int
    node_cert: str
    node_key: str
    ca_file: str
    policy_dir: str
    allowed_signers: str
    state_dir: str
    priv_socket: str
    owner_uid: int            # uid that must own root-protected inputs (policy dir, allowed_signers, privd socket peer): 0 in production
    agent_uid: int            # uid the agent runs as (owner of the state directory)
    fs_root: str = "/"        # relocation of the logical filesystem; production is always "/"

    @classmethod
    def from_environ(cls, environ=None) -> "AgentConfig":
        e = os.environ if environ is None else environ

        def get(name, default=None):
            v = e.get("FORGE_NODE_" + name, default)
            if v is None:
                raise ConfigError(f"FORGE_NODE_{name} is required")
            return v
        node = get("NODE_ID")
        host = get("HUB_HOST", "192.168.10.4")
        try:
            port = int(get("HUB_PORT", "8094"))
        except ValueError as ex:
            raise ConfigError("FORGE_NODE_HUB_PORT must be an integer") from ex
        cfg = cls(node, host, port, get("NODE_CERT", "/etc/forge-node/pki/node.crt"), get("NODE_KEY", "/etc/forge-node/pki/node.key"), get("CA_FILE", "/etc/forge-node/pki/ca.crt"),
                  get("POLICY_DIR", "/etc/forge-node/policy"), get("ALLOWED_SIGNERS", "/etc/forge-node/allowed_signers"), get("STATE_DIR", "/var/lib/forge-node"),
                  get("PRIV_SOCKET", "/run/forge-node/priv.sock"), 0, os.getuid())
        cfg.validate()
        return cfg

    def validate(self):
        if not NODE_RE.match(self.node_id):
            raise ConfigError("node id")
        try:
            ipaddress.ip_address(self.hub_host)
        except ValueError as ex:
            raise ConfigError("hub host must be an IP address literal") from ex
        if not 1 <= self.hub_port <= 65535:
            raise ConfigError("hub port")
        for name in ("node_cert", "node_key", "ca_file", "policy_dir", "allowed_signers", "state_dir", "priv_socket"):
            if not os.path.isabs(getattr(self, name)):
                raise ConfigError(f"{name} must be an absolute path")
