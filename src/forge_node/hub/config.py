"""Hub-Konfiguration aus der Umgebung (FORGE_NODEHUB_*). Geheimnisse nur aus Dateien (NAME_FILE), nie als Wert in Env/argv."""
import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

from ..protocol import LEASE_MAX_VALID_S, LONG_POLL_MAX_S


class ConfigError(ValueError):
    pass


def _path(env, name, default=None) -> Path | None:
    v = env.get(name, default)
    return Path(v) if v else None


def check_bind_host(host: str, in_container: bool = False) -> str:
    """Der Hub lauscht nur auf einer konkreten Adresse (Design 5.1: LAN-IP 192.168.10.4) - nie auf einem Hostnamen oder leer, und Wildcards (0.0.0.0, ::) nur im Container
    (FORGE_NODEHUB_CONTAINER=1): dort ist das Netz privat, die Erreichbarkeit regelt allein das Publish `192.168.10.4:8094` (deploy/compose.nodehub.yaml, per Test gesichert)."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError as e:
        raise ConfigError(f"listen host must be a literal IP address, got {host!r}") from e
    if ip.is_multicast:
        raise ConfigError("listen host must not be a multicast address")
    if ip.is_unspecified and not in_container:
        raise ConfigError("listen host must be a concrete interface address; 0.0.0.0/:: only inside the container (FORGE_NODEHUB_CONTAINER=1)")
    return str(ip)


@dataclass(frozen=True)
class HubConfig:
    db_dsn: str
    db_password_file: Path | None
    listen_host: str
    listen_port: int
    tls_cert: Path
    tls_key: Path
    tls_ca: Path
    gate_key: Path
    gate_key_id: str
    control_dir: Path
    policy_dir: Path
    release_dir: Path
    ssh_keygen: str = "ssh-keygen"
    lease_valid_s: int = LEASE_MAX_VALID_S
    long_poll_max_s: int = LONG_POLL_MAX_S
    queue_ttl_s: int = 3600
    reconcile_after_s: int = 300
    crosscheck_grace_s: int = 300
    lock_timeout_s: float = 10.0

    @classmethod
    def from_env(cls, env=None) -> "HubConfig":
        env = os.environ if env is None else env

        def need(name):
            v = env.get(name)
            if not v:
                raise ConfigError(f"{name} is required")
            return v

        port = int(env.get("FORGE_NODEHUB_PORT", "8094"))
        lease = int(env.get("FORGE_NODEHUB_LEASE_VALID_S", str(LEASE_MAX_VALID_S)))
        if not 10 <= lease <= LEASE_MAX_VALID_S:
            raise ConfigError(f"lease validity must be 10..{LEASE_MAX_VALID_S} s")
        return cls(
            db_dsn=need("FORGE_NODEHUB_DB_DSN"), db_password_file=_path(env, "FORGE_NODEHUB_DB_PASSWORD_FILE"),
            listen_host=check_bind_host(need("FORGE_NODEHUB_LISTEN_HOST"), env.get("FORGE_NODEHUB_CONTAINER") == "1"), listen_port=port,
            tls_cert=Path(need("FORGE_NODEHUB_TLS_CERT")), tls_key=Path(need("FORGE_NODEHUB_TLS_KEY")), tls_ca=Path(need("FORGE_NODEHUB_TLS_CA")),
            gate_key=Path(need("FORGE_NODEHUB_GATE_KEY")), gate_key_id=need("FORGE_NODEHUB_GATE_KEY_ID"),
            control_dir=Path(need("FORGE_NODEHUB_CONTROL_DIR")), policy_dir=Path(need("FORGE_NODEHUB_POLICY_DIR")), release_dir=Path(need("FORGE_NODEHUB_RELEASE_DIR")),
            ssh_keygen=env.get("FORGE_NODEHUB_SSH_KEYGEN", "ssh-keygen"), lease_valid_s=lease,
            long_poll_max_s=min(int(env.get("FORGE_NODEHUB_LONG_POLL_S", str(LONG_POLL_MAX_S))), LONG_POLL_MAX_S),
            queue_ttl_s=int(env.get("FORGE_NODEHUB_QUEUE_TTL_S", "3600")), reconcile_after_s=int(env.get("FORGE_NODEHUB_RECONCILE_AFTER_S", "300")),
            crosscheck_grace_s=int(env.get("FORGE_NODEHUB_CROSSCHECK_GRACE_S", "300")), lock_timeout_s=float(env.get("FORGE_NODEHUB_LOCK_TIMEOUT_S", "10")),
        )
