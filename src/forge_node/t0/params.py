"""Parameter schemas of the T0 ops. One definition, used by the hub (first line, before signing) and by the node engine (pipeline step 9, independent re-check)."""
import re

from ..protocol import ProtoError

UNIT_RE = re.compile(r"^[A-Za-z0-9:_.@\\-]{1,128}\.(service|timer|socket|mount|target|path)\Z")
MAX_PARAMS_BYTES = 16 * 1024
SAMPLE_MAX = 400


def _int(v, lo, hi, what):
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise ProtoError("DENY_PARAM", f"{what} must be an integer in {lo}..{hi}")


def _only(params: dict, allowed: set, required: set = frozenset()):
    extra, missing = params.keys() - allowed, required - params.keys()
    if extra or missing:
        raise ProtoError("DENY_PARAM", f"unexpected {sorted(extra)} / missing {sorted(missing)}")


def validate_t0(op: str, params) -> dict:
    if not isinstance(params, dict):
        raise ProtoError("DENY_PARAM", "params must be an object")
    if op == "logs.unit":
        _only(params, {"unit", "since_s", "lines"}, {"unit"})
        if not isinstance(params["unit"], str) or not UNIT_RE.match(params["unit"]):
            raise ProtoError("DENY_PARAM", "unit must be a plain systemd unit name")
        if "since_s" in params:
            _int(params["since_s"], 1, 7 * 86400, "since_s")          # <= 7 d
        if "lines" in params:
            _int(params["lines"], 1, 500, "lines")                    # <= 500 lines
    elif op == "inv.usage":
        _only(params, {"window_h"})
        if "window_h" in params:
            _int(params["window_h"], 1, 72, "window_h")
    elif op == "metrics.sample":
        _only(params, {"after_seq", "max_samples"})
        if "after_seq" in params:
            _int(params["after_seq"], 0, 2**53 - 1, "after_seq")
        if "max_samples" in params:
            _int(params["max_samples"], 1, SAMPLE_MAX, "max_samples")
    else:
        _only(params, set())
    return params
