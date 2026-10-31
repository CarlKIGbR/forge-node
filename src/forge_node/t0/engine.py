"""The single guarded path for T0 (Design 3.3 reduced pipeline for `t0`): every T0 read the node performs - from a hub job or from a local call - goes through
T0Engine.execute(), in this fixed order, and the first failing step ends it:

  1 gates.decide (op known, tier 0, profile)        5 op allowlist from the signed policy (logs.unit unit)
  2 policy enables tier 0                           6 blackout window for heavy ops (re-checked by the probe at execution)
  3 op registered in this layer                     7 rate bucket (light 2/min, heavy 1/10 min, per op, persisted)
  4 parameter schema (same code the hub uses)       8 collect -> filter -> redact -> size-bound -> untrusted envelope

There is no flag, argument or environment setting that skips a step. The limiter, the probe transport and the environment are required constructor arguments."""
import threading
from dataclasses import dataclass
from typing import Callable

from .. import gates, protocol
from ..protocol import ProtoError
from . import collect, metrics, params as params_mod, probes, sanitize, usage as usage_mod
from .env import Env, failed, unavailable
from .limits import RateLimiter
from .spool import Spool
from .wire import ProbeDenied, ProbeUnavailable

# section names each probe answers with (an unreachable or failing probe turns each of them into a status section)
PROBE_SECTIONS = {"net": ("listeners", "docker_user"), "containers": ("containers",), "vms": ("domains", "pools"), "certs": ("certs",), "git": ("repos",),
                  "access": ("sshd", "groups", "authorized_keys"), "models": ("models",), "journal": ("log",), "activity": ("activity",), "uulog": ("uulog",)}
RETRYABLE_PROBE_CODES = frozenset({"DENY_WINDOW", "DENY_RATE", "DENY_STOP", "DENY_LOCAL_STOP", "DENY_STALE_LEASE", "DENY_CLOCK", "DENY_AUDIT_DOWN", "DENY_QUARANTINE"})


@dataclass(frozen=True)
class Outcome:
    status: str                  # committed | denied | failed
    reason_code: str | None
    output: str                  # canonical JSON envelope (committed) or a short plain explanation (denied/failed)


class OpDenied(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


class T0Engine:
    def __init__(self, *, node: str, env: Env, limiter: RateLimiter, probe, spool: Spool, node_cert_path: str | None, hub_cert_der: Callable[[], bytes | None]):
        """`hub_cert_der` returns the DER of the hub certificate seen on the live connection (None before the first handshake): inv.certs reports its expiry (Design 4.1)."""
        self.node, self.env, self.limiter, self.probe, self.spool, self.node_cert_path, self.hub_cert_der = node, env, limiter, probe, spool, node_cert_path, hub_cert_der
        self._lock = threading.Lock()
        self._ops: dict[str, tuple[bool, Callable[[dict], tuple[dict, str]]]] = {
            "inv.host": (False, lambda p: (collect.host(env), "internal")),
            "inv.disks": (False, lambda p: (collect.disks(env), "internal")),
            "inv.gpu": (False, lambda p: (collect.gpu(env), "internal")),
            "inv.net": (False, lambda p: (self._net(), "internal")),
            "inv.units": (False, lambda p: (collect.units(env), "internal")),
            "inv.containers": (False, lambda p: (self._probe("containers", {}), "internal")),
            "inv.vms": (False, lambda p: (self._vms(), "internal")),
            "inv.pkgs": (False, lambda p: (collect.pkgs(env, self._probe("uulog", {})["uulog"]), "internal")),
            "inv.certs": (False, lambda p: (self._certs(), "internal")),
            "inv.backups": (False, lambda p: (collect.backups(env), "internal")),
            "inv.git": (True, lambda p: (self._probe("git", {}), "internal")),
            "inv.access": (False, lambda p: (self._probe("access", {}), "internal")),
            "inv.usage": (False, lambda p: (usage_mod.usage(env, spool, probe, p), "internal")),
            "inv.models": (True, lambda p: (self._probe("models", {}), "internal")),
            "metrics.sample": (False, lambda p: (metrics.read_op(spool, p), "internal")),
            "logs.unit": (False, self._logs),
        }

    # ----------------------------------------------------------------------------------------------------------------- probes
    def _probe(self, name: str, params: dict) -> dict:
        """Call a root probe. Unreachable privd -> the sections say so; a retryable denial (window, rate, stop...) denies the whole op so the hub redelivers it later."""
        try:
            return self.probe.call(name, params)
        except ProbeUnavailable as e:
            return {sec: unavailable(str(e)[:120]) for sec in PROBE_SECTIONS[name]}
        except ProbeDenied as e:
            if e.code in RETRYABLE_PROBE_CODES or e.code in ("DENY_PARAM", "DENY_NOT_ALLOWLISTED"):
                raise OpDenied(e.code, e.detail) from e
            return {sec: failed(e.code, e.detail) for sec in PROBE_SECTIONS[name]}

    def _net(self) -> dict:
        out = collect.net_local(self.env)
        p = self._probe("net", {})
        if "listeners" in p and p["listeners"].get("status") == "ok":
            out.update(p)
        else:
            out["listeners"] = collect.listeners_unprivileged(self.env)          # degraded: no process names
            out["docker_user"] = p.get("docker_user", unavailable("needs the privileged probe"))
        return out

    def _vms(self) -> dict:
        if not self.env.runner.available("virsh_list"):
            return {"domains": unavailable("virsh not installed"), "pools": unavailable("virsh not installed")}
        return self._probe("vms", {})

    def _certs(self) -> dict:
        out = {"node_certificate": collect.own_certs(self.env, self.node_cert_path, self.env.now()), "hub_certificate": collect.der_cert(self.env, self.hub_cert_der()),
               "local_tls": collect.local_tls(self.env)}
        out.update(self._probe("certs", {}))
        return out

    def _logs(self, params: dict) -> tuple[dict, str]:
        lu = self.env.policy.log_unit(params["unit"])
        if lu is None:
            raise OpDenied("DENY_NOT_ALLOWLISTED", "unit is not in policy t0.units_for_logs")
        probe_params = {k: params[k] for k in ("unit", "since_s", "lines") if k in params}
        return self._probe("journal", probe_params), lu.sensitivity

    # ----------------------------------------------------------------------------------------------------------- the one path
    def execute(self, op: str, tier: int, params: dict) -> Outcome:
        env = self.env
        d = gates.decide(op, tier, env.policy.profile, params)                                   # 1
        if not d.allowed:
            return Outcome("denied", d.code, d.detail)
        if 0 not in env.policy.tiers_enabled:                                                    # 2
            return Outcome("denied", "DENY_TIER_DISABLED", "policy does not enable tier 0")
        entry = self._ops.get(op)                                                                # 3
        if entry is None:
            return Outcome("denied", "DENY_OP_UNKNOWN", f"{op} is not a T0 op of this node")
        heavy, handler = entry
        try:
            params_mod.validate_t0(op, params)                                                   # 4
        except ProtoError as e:
            return Outcome("denied", e.code, e.detail)
        if op == "logs.unit" and env.policy.log_unit(params["unit"]) is None:                    # 5
            return Outcome("denied", "DENY_NOT_ALLOWLISTED", "unit is not in policy t0.units_for_logs")
        if heavy and env.policy.window.in_blackout(env.now()):                                   # 6
            return Outcome("denied", "DENY_WINDOW", "heavy read inside the blackout window")
        with self._lock:
            if not self.limiter.take(op, heavy):                                                 # 7
                return Outcome("denied", "DENY_RATE", f"{op} rate limit")
            try:
                body, sensitivity = handler(params)                                              # 8
                text = sanitize.finalize(self.node, op, protocol.fmt_ts(env.now()), sensitivity, body, full_redaction=(op == "logs.unit"))
            except OpDenied as e:
                return Outcome("denied", e.code, e.detail)
            except Exception as e:  # noqa: BLE001 - a collector bug is a failed op, never a crash of the agent loop
                return Outcome("failed", "FAIL_EXEC", f"{type(e).__name__}")
        return Outcome("committed", None, text)


T0_OPS = tuple(k for k in gates.OPS if gates.OPS[k].tier == 0)
__all__ = ["T0Engine", "Outcome", "OpDenied", "T0_OPS", "probes"]
