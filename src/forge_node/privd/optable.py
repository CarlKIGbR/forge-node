"""The compiled-in op table (Design 4.3, 4.4): ONE entry per operation this release can execute. The signed policy can only enable/disable entries and bind them to targets; it cannot add
ops. 'No entry => no code path': an op that gates.OPS knows but this table lacks (everything from N5 on) is DENY_OP_UNKNOWN at the node regardless of what the hub signed.

An entry fixes: name, tier, mutating, profiles, transient-unit class (classes.py), parameter schema, effect key, idempotency class and probe (Design 9.4), settle hook (delegated
effects), timeout, abort_on_stop, whether apply needs a stored plan, default rate. All of it is code in the release; none of it comes from a request."""
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable

from .. import gates
from ..protocol import ProtoError

IDEMPOTENCY = ("natural", "probe", "resume_same_plan", "opaque")
VERDICTS = ("applied", "not_applied", "partial", "unknown")
_NOTE = re.compile(r"^[A-Za-z0-9 ._-]{0,64}\Z")


@dataclass(frozen=True)
class OpEntry:
    name: str
    tier: int
    mutating: bool
    profiles: frozenset
    unit_class: str                                        # classes.CLASSES key
    params: Callable[[dict], dict]                         # validate + normalise; raises ProtoError('DENY_PARAM')
    effect_key: Callable[[dict], str]
    idempotency: str
    probe: Callable[[str], str] | None                     # (work_dir) -> verdict; required for idempotency 'probe'
    settle: Callable[[str], bool] | None                   # (work_dir) -> True once delegated effects have settled
    worker_cmd: str | None                                 # sub-command of the release's op worker; None = performed inside privd (policy.apply, ledger.resolve)
    timeout_s: int
    abort_on_stop: bool
    requires_plan: bool
    default_rate: tuple[tuple[int, int], ...]
    protected: Callable | None = None                      # (policy, params) -> raises ProtoError('DENY_PROTECTED')
    allowlist: Callable | None = None                      # (op_policy, params) -> raises ProtoError('DENY_NOT_ALLOWLISTED')

    def __post_init__(self):
        if self.name not in gates.OPS or gates.OPS[self.name].tier != self.tier or gates.OPS[self.name].mutating != self.mutating:
            raise ValueError(f"op table entry {self.name} disagrees with gates.OPS")
        if self.idempotency not in IDEMPOTENCY or (self.idempotency == "probe" and self.probe is None):
            raise ValueError(f"{self.name}: bad idempotency/probe")
        if not self.profiles <= {"full", "t0"} or (self.profiles & {"t0"} and self.tier > 0):
            raise ValueError(f"{self.name}: profiles")


class OpTable:
    def __init__(self, entries):
        d = {}
        for e in entries:
            if e.name in d:
                raise ValueError(f"duplicate op {e.name}")
            d[e.name] = e
        self._d = MappingProxyType(d)

    def get(self, name: str) -> OpEntry | None:
        return self._d.get(name)

    def names(self, profile: str) -> frozenset:
        return frozenset(n for n, e in self._d.items() if profile in e.profiles)

    def __iter__(self):
        return iter(self._d.values())

    def __len__(self):
        return len(self._d)


def noop_params(p: dict) -> dict:
    if not isinstance(p, dict) or set(p) - {"note"}:
        raise ProtoError("DENY_PARAM", "selftest.noop takes only {note}")
    note = p.get("note", "")
    if not isinstance(note, str) or not _NOTE.match(note):
        raise ProtoError("DENY_PARAM", "note must be up to 64 characters of [A-Za-z0-9 ._-]")
    return {"note": note}


def build_optable() -> OpTable:
    """The table of this release. N3 delivers the machinery and ONE executable op, `selftest.noop` (T1, full profile only, gated by D): it touches nothing but its own work directory.
    Every other op of gates.OPS arrives with its slice (N5 T1, N6 T2, N7 T3) and is DENY_OP_UNKNOWN until then."""
    from .ops import noop_probe
    return OpTable([
        OpEntry("selftest.noop", 1, True, frozenset({"full"}), "selftest", noop_params, lambda p: "selftest.noop", "probe", noop_probe, None, "selftest.noop", 30, True, True, ((6, 60),)),
    ])
