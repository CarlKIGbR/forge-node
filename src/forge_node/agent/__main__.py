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
from ..t0.runner import ReadOnlyRunner
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


def build(cfg: AgentConfig, *, runner, clock, log, probe) -> Agent:
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

    return Agent(cfg, PolicyHolder(cfg, clock, log), build_runtime, spool, lambda rt: metrics.Sampler(rt.engine.env, spool), clock, log=log)


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
    agent = build(cfg, runner=ReadOnlyRunner(), clock=_now, log=_log, probe=SocketProbeClient(cfg.priv_socket, expect_uid=cfg.owner_uid))
    signal.signal(signal.SIGTERM, lambda *_: agent.stop())
    signal.signal(signal.SIGINT, lambda *_: agent.stop())
    agent.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
