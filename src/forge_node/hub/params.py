"""Parameter-Schemas der T0-Ops auf dem Hub (erste Linie; der Node prueft in Pipeline-Schritt 9 unabhaengig noch einmal). Ops ab T1 haben in N1 kein Hub-Schema,
weil sie per Gate gesperrt sind; ihre Schemas liefern N5-N7 zusammen mit dem Gate-Wechsel."""
import re

from ..protocol import ProtoError

_UNIT_RE = re.compile(r"^[A-Za-z0-9:_.@\\-]{1,128}\.(service|timer|socket|mount|target|path)\Z")
MAX_PARAMS_BYTES = 16 * 1024


def _int(v, lo, hi, what):
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise ProtoError("DENY_PARAM", f"{what} must be an integer in {lo}..{hi}")


def _only(params: dict, allowed: set, required: set = frozenset()):
    extra, missing = params.keys() - allowed, required - params.keys()
    if extra or missing:
        raise ProtoError("DENY_PARAM", f"unexpected {sorted(extra)} / missing {sorted(missing)}")


def validate(op: str, tier: int, params) -> dict:
    if not isinstance(params, dict):
        raise ProtoError("DENY_PARAM", "params must be an object")
    if tier > 0:
        return params
    if op == "logs.unit":
        _only(params, {"unit", "since_s", "lines"}, {"unit"})
        if not isinstance(params["unit"], str) or not _UNIT_RE.match(params["unit"]):
            raise ProtoError("DENY_PARAM", "unit must be a plain systemd unit name")
        if "since_s" in params:
            _int(params["since_s"], 1, 7 * 86400, "since_s")          # <= 7 d
        if "lines" in params:
            _int(params["lines"], 1, 500, "lines")                    # <= 500 Zeilen
    elif op == "inv.usage":
        _only(params, {"window_h"})
        if "window_h" in params:
            _int(params["window_h"], 1, 72, "window_h")
    else:
        _only(params, set())
    return params
