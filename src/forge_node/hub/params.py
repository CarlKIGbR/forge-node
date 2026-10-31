"""Parameter-Schemas der T0-Ops auf dem Hub (erste Linie; der Node prueft in Pipeline-Schritt 9 unabhaengig noch einmal). Seit N2 liegt die Definition in
forge_node.t0.params (eine Quelle fuer Hub und Node). Ops ab T1 haben in N1 kein Hub-Schema, weil sie per Gate gesperrt sind; ihre Schemas liefern N5-N7 zusammen mit dem Gate-Wechsel."""
from ..protocol import ProtoError
from ..t0 import params as t0_params

MAX_PARAMS_BYTES = t0_params.MAX_PARAMS_BYTES
_UNIT_RE = t0_params.UNIT_RE


def validate(op: str, tier: int, params) -> dict:
    if not isinstance(params, dict):
        raise ProtoError("DENY_PARAM", "params must be an object")
    if tier > 0:
        return params
    return t0_params.validate_t0(op, params)
