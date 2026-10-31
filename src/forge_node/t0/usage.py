"""inv.usage (Design 4.1, 14.1): per container and unit - CPU, RSS, block I/O, GPU VRAM per process, network bytes, restarts, last-activity, compose/label attribution with an
`unattributed` flag - over a window (72 h at most) aggregated from the spool plus a live snapshot. Names and labels come from the privileged `containers` probe; without it the
snapshot reports short ids only (section marked degraded)."""
from datetime import timedelta

from .. import protocol
from . import metrics
from .env import Env, failed, ok, unavailable
from .spool import Spool
from .wire import ProbeDenied, ProbeUnavailable


class _Acc:
    """Single-pass aggregation over the spool window: memory is O(cgroups + cards), independent of the number of samples."""

    def __init__(self):
        self.n = 0
        self.first_ts = self.last_ts = None
        self.cg: dict[str, dict] = {}
        self.cards: dict[int, dict] = {}
        self.by_owner: dict[str, int] = {}
        self.swap_used_max = None
        self.load_max = None

    def add(self, s: dict):
        self.n += 1
        self.first_ts = self.first_ts or s["ts"]
        self.last_ts = s["ts"]
        for k, v in (s.get("cg") or {}).items():
            e = self.cg.setdefault(k, {"first": v, "last": v, "mem_max": 0, "n": 0})
            e["last"] = v
            e["mem_max"] = max(e["mem_max"], v[1])
            e["n"] += 1
        for g in s.get("gpu") or []:
            c = self.cards.setdefault(g["i"], {"mem_used_max": 0, "mem_free_min": None, "util_max": 0, "temp_max": 0, "total": g["tot"]})
            c["mem_used_max"] = max(c["mem_used_max"], g["mem"] or 0)
            free = (g["tot"] or 0) - (g["mem"] or 0)
            c["mem_free_min"] = free if c["mem_free_min"] is None else min(c["mem_free_min"], free)
            c["util_max"] = max(c["util_max"], g["util"] or 0)
            c["temp_max"] = max(c["temp_max"], g["temp"] or 0)
        for a in s.get("gpu_apps") or []:
            key = a.get("cg") or f"pid-proc:{a.get('proc')}"
            self.by_owner[key] = max(self.by_owner.get(key, 0), a.get("mib") or 0)
        m = s.get("mem") or {}
        if m.get("swap_total") is not None and m.get("swap_free") is not None:
            used = m["swap_total"] - m["swap_free"]
            self.swap_used_max = used if self.swap_used_max is None else max(self.swap_used_max, used)
        if s.get("load1_milli") is not None:
            self.load_max = s["load1_milli"] if self.load_max is None else max(self.load_max, s["load1_milli"])

    def per_cgroup(self) -> dict:
        out = {}
        for k, e in self.cg.items():
            f, l = e["first"], e["last"]
            out[k] = {"samples": e["n"], "cpu_seconds": max(0, (l[0] - f[0]) // 1_000_000), "rss_max": e["mem_max"], "io_read_bytes": max(0, l[2] - f[2]), "io_write_bytes": max(0, l[3] - f[3])}
        return out

    def hours(self) -> int:
        if self.n < 2:
            return 0
        return int((protocol.parse_ts(self.last_ts) - protocol.parse_ts(self.first_ts)).total_seconds() // 3600)


def usage(env: Env, spool: Spool, probe, params: dict) -> dict:
    window_h = params.get("window_h", 72)
    now = env.now()
    since = protocol.fmt_ts(now - timedelta(hours=window_h))
    acc = _Acc()
    skipped = 0
    for rec in spool.iter_window(since):
        try:
            acc.add(rec)
        except (TypeError, KeyError, IndexError, ValueError, AttributeError):
            skipped += 1                       # a record of the wrong shape (the spool is a file on disk): skip it, report it, keep the rest
    out_skipped = skipped
    out: dict = {"window": ok(hours=window_h, samples=acc.n, first=acc.first_ts, last=acc.last_ts, covered_hours=acc.hours(), per_cgroup=acc.per_cgroup(),
                              gpu={str(k): v for k, v in sorted(acc.cards.items())}, gpu_vram_by_owner_mib=dict(sorted(acc.by_owner.items(), key=lambda kv: -kv[1])[:40]),
                              swap_used_max=acc.swap_used_max, load1_milli_max=acc.load_max, skipped_records=out_skipped)}
    live = metrics.cgroup_counters(env)
    out["now"] = ok(cgroups={k: {"cpu_usec": v[0], "rss": v[1], "io_read_bytes": v[2], "io_write_bytes": v[3]} for k, v in live.items()})
    try:
        out["containers"] = probe.call("containers", {})["containers"]
        out["unit_activity"] = probe.call("activity", {})["activity"]
        try:
            out["container_net"] = probe.call("container_net", {})["container_net"]
        except (ProbeUnavailable, ProbeDenied) as e:
            out["container_net"] = unavailable(f"needs the privileged probe: {e}")
    except ProbeUnavailable as e:
        out["containers"] = unavailable(f"names/labels need the privileged probe: {e}")
    except ProbeDenied as e:
        out["containers"] = failed(e.code)
    return out
