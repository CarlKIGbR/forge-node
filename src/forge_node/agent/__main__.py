"""Entry point: `python -m forge_node.agent` (or the zipapp). Wiring only; every decision lives in the modules it builds. The privileged probe transport is the root-owned
socket - the agent has no other way to run a root read."""
import signal
import sys
from datetime import datetime, timezone

from .. import __version__
from ..redact import redact_light
from ..t0 import metrics
from ..t0.env import Env
from ..t0.engine import T0Engine
from ..t0.fsread import Fs, ProtectedSet
from ..t0.limits import RateLimiter
from ..t0.runner import ReadOnlyRunner, RunnerError, trusted_binary
from ..t0.spool import Spool
from ..t0.wire import SocketProbeClient
from .client import HubClient
from .config import AgentConfig, ConfigError
from .loop import Agent, PolicyHolder, Runtime


def _log(msg: str):
    sys.stderr.write(redact_light(msg)[:400] + "\n")
    sys.stderr.flush()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def build(cfg: AgentConfig, *, runner, clock, log, probe, ssh_keygen: str, priv=None, shipper=None) -> Agent:
    """Wire the agent. runner/clock/log/probe are required: main() passes the real ones; the tests pass fakes of the same two-method interfaces. Everything that guards is built here
    from the policy view and the config, never taken from a caller."""
    import os
    state = cfg.state_dir
    os.makedirs(os.path.join(state, "spool"), mode=0o700, exist_ok=True)
    spool = Spool(os.path.join(state, "spool"), cfg.agent_uid)
    limiter = RateLimiter(os.path.join(state, "ratelimit.json"), clock)

    def build_runtime(view) -> Runtime:
        env = Env(Fs(ProtectedSet.from_policy(view.protected_paths), cfg.fs_root), runner, clock, view)
        client = HubClient(cfg.hub_host, cfg.hub_port, cfg.node_cert, cfg.node_key, cfg.ca_file, view.hub_tls_pins)
        engine = T0Engine(node=cfg.node_id, env=env, limiter=limiter, probe=probe, spool=spool, node_cert_path=cfg.node_cert, hub_cert_der=client.hub_certificate_der)
        return Runtime(view, client, engine)

    return Agent(cfg, PolicyHolder(cfg, clock, log, ssh_keygen), build_runtime, spool, lambda rt: metrics.Sampler(rt.engine), clock, ssh_keygen, log=log, priv=priv, shipper=shipper)


def _priv_link(cfg: AgentConfig):
    """The agent's link to privd and its own audit log. The log is optional at start (a node that has not run `privctl audit-init` yet is T0-only): without it nothing above T0 is
    relayed."""
    import os
    from ..audit.log import Appender
    from ..audit.spec import AuditDown, agent_spec
    from ..privd.client import PrivClient
    from .privlink import PrivLink
    audit = None
    try:
        audit = Appender(agent_spec(gid=os.getegid(), trust_anchor="/"), cfg.node_id, _now)
    except AuditDown as e:
        _log(f"audit log not available ({e}): relaying nothing above T0")
    return PrivLink(client=PrivClient(cfg.priv_socket, cfg.owner_uid, 150), audit=audit, log=_log)


def _shipper(cfg: AgentConfig):
    import os
    from ..audit.spec import agent_spec, priv_spec
    from .shipper import AuditShipper
    gid = os.getegid()
    return AuditShipper(specs={"agent": agent_spec(gid=gid, trust_anchor="/"), "priv": priv_spec(gid=gid, trust_anchor="/")}, node=cfg.node_id, state_dir=cfg.state_dir, log=_log)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--version"]:
        print(__version__)
        return 0
    if argv not in ([], ["run"]):
        sys.stderr.write("usage: python -m forge_node.agent [run | --version]\n")
        return 2
    try:
        cfg = AgentConfig.from_environ()
    except ConfigError as e:
        sys.stderr.write(f"configuration error: {e}\n")
        return 2
    try:
        ssh_keygen = trusted_binary("ssh-keygen")
    except RunnerError as e:
        sys.stderr.write(f"cannot start: {e}\n")
        return 2
    agent = build(cfg, runner=ReadOnlyRunner(), clock=_now, log=_log, probe=SocketProbeClient(cfg.priv_socket, expect_uid=cfg.owner_uid), ssh_keygen=ssh_keygen, priv=_priv_link(cfg), shipper=_shipper(cfg))
    signal.signal(signal.SIGTERM, lambda *_: agent.stop())
    signal.signal(signal.SIGINT, lambda *_: agent.stop())
    agent.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
