"""inv.usage (Design 4.1, 14.1): per container and unit - CPU, RSS, block I/O, GPU VRAM per process, network bytes, restarts, last-activity, compose/label attribution with an
`unattributed` flag - over a window (72 h at most) aggregated from the spool plus a live snapshot. Names and labels come from the privileged `containers` probe; without it the
snapshot reports short ids only (section marked degraded)."""
from datetime import timedelta

from .. import protocol
from . import metrics
from .env import Env, failed, ok, unavailable
from .spool import Spool
from .wire import ProbeDenied, ProbeUnavailable


def _agg(samples: list[dict]) -> dict:
    keys: dict[str, dict] = {}
    for s in samples:
        for k, v in (s.get("cg") or {}).items():
            e = keys.setdefault(k, {"first": v, "last": v, "mem_max": 0, "n": 0})
            e["last"] = v
            e["mem_max"] = max(e["mem_max"], v[1])
            e["n"] += 1
    out = {}
    for k, e in keys.items():
        f, l = e["first"], e["last"]
        out[k] = {"samples": e["n"], "cpu_seconds": max(0, (l[0] - f[0]) // 1_000_000), "rss_max": e["mem_max"], "io_read_bytes": max(0, l[2] - f[2]), "io_write_bytes": max(0, l[3] - f[3])}
    return out


def _gpu(samples: list[dict]) -> dict:
    cards: dict[int, dict] = {}
    for s in samples:
        for g in s.get("gpu") or []:
            c = cards.setdefault(g["i"], {"mem_used_max": 0, "mem_free_min": None, "util_max": 0, "temp_max": 0, "total": g["tot"]})
            c["mem_used_max"] = max(c["mem_used_max"], g["mem"] or 0)
            free = (g["tot"] or 0) - (g["mem"] or 0)
            c["mem_free_min"] = free if c["mem_free_min"] is None else min(c["mem_free_min"], free)
            c["util_max"] = max(c["util_max"], g["util"] or 0)
            c["temp_max"] = max(c["temp_max"], g["temp"] or 0)
    return {str(k): v for k, v in sorted(cards.items())}


def _gpu_by_owner(samples: list[dict]) -> dict:
    out: dict[str, int] = {}
    for s in samples:
        for a in s.get("gpu_apps") or []:
            key = a.get("cg") or f"pid-proc:{a.get('proc')}"
            out[key] = max(out.get(key, 0), a.get("mib") or 0)
    return dict(sorted(out.items(), key=lambda kv: -kv[1])[:40])


def usage(env: Env, spool: Spool, probe, params: dict) -> dict:
    window_h = params.get("window_h", 72)
    now = env.now()
    since = protocol.fmt_ts(now - timedelta(hours=window_h))
    samples = spool.window(since)
    out: dict = {"window": ok(hours=window_h, samples=len(samples), first=samples[0]["ts"] if samples else None, last=samples[-1]["ts"] if samples else None,
                              covered_hours=(round_hours(samples)), per_cgroup=_agg(samples), gpu=_gpu(samples), gpu_vram_by_owner_mib=_gpu_by_owner(samples),
                              swap_used_max=max((((s.get("mem") or {}).get("swap_total") or 0) - ((s.get("mem") or {}).get("swap_free") or 0) for s in samples), default=None),
                              load1_milli_max=max((s.get("load1_milli") or 0 for s in samples), default=None))}
    live = metrics.cgroup_counters(env)
    out["now"] = ok(cgroups={k: {"cpu_usec": v[0], "rss": v[1], "io_read_bytes": v[2], "io_write_bytes": v[3]} for k, v in live.items()})
    try:
        c = probe.call("containers", {"with_usage": True})["containers"]
        act = probe.call("activity", {})["activity"]
        out["containers"] = c
        out["unit_activity"] = act
    except ProbeUnavailable as e:
        out["containers"] = unavailable(f"names/labels need the privileged probe: {e}")
    except ProbeDenied as e:
        out["containers"] = failed(e.code)
    return out


def round_hours(samples: list[dict]) -> int:
    """Whole hours between first and last sample (integer: canonical JSON has no floats)."""
    if len(samples) < 2:
        return 0
    a, b = protocol.parse_ts(samples[0]["ts"]), protocol.parse_ts(samples[-1]["ts"])
    return int((b - a).total_seconds() // 3600)
