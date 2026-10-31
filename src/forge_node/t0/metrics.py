"""metrics.sample (Design 4.1, 14.2 M1): one compact sample every >= 30 s into the spool - CPU/RAM/swap/load, disk I/O counters per whole device (system disk vs the KMU model SSD, read
from /proc/diskstats, never by touching /srv/models), network bytes, GPU per card and per compute process, and cgroup counters of containers and services. Counters are CUMULATIVE
(raw); rates are derived from consecutive samples by the consumer. Reading the spool back (the `metrics.sample` op) returns samples after a cursor."""
import re
from datetime import datetime

from .. import protocol
from . import parse
from .env import Env
from .fsread import FsError
from .spool import Spool

MIN_INTERVAL_S = 30
CG_BASE = "/sys/fs/cgroup/system.slice"
MAX_CG = 40
_DOCKER_SCOPE = re.compile(r"^docker-([0-9a-f]{64})\.scope\Z")
_SERVICE = re.compile(r"^[A-Za-z0-9:_.@\\-]{1,100}\.service\Z")


def cgroup_counters(env: Env) -> dict[str, list[int]]:
    """{'d:<12hex>' | 'u:<unit>': [cpu_usec, mem_current, io_rbytes, io_wbytes]} for the MAX_CG biggest consumers of memory."""
    try:
        entries, _ = env.fs.list_meta(CG_BASE, 3000)
    except FsError:
        return {}
    rows = []
    for e in entries:
        if e["kind"] != "dir":
            continue
        m = _DOCKER_SCOPE.match(e["name"])
        if m:
            key = "d:" + m.group(1)[:12]
        elif _SERVICE.match(e["name"]):
            key = "u:" + e["name"]
        else:
            continue
        base = f"{CG_BASE}/{e['name']}"
        try:
            mem = int(env.fs.read_text(f"{base}/memory.current", 64).strip())
        except (FsError, ValueError):
            continue
        try:
            cpu = parse.kv_file(env.fs.read_text(f"{base}/cpu.stat", 4096)).get("usage_usec", 0)
        except FsError:
            cpu = 0
        try:
            io = parse.io_stat(env.fs.read_text(f"{base}/io.stat", 16384))
        except FsError:
            io = {"rbytes": 0, "wbytes": 0}
        rows.append((mem, key, [cpu, mem, io["rbytes"], io["wbytes"]]))
    rows.sort(reverse=True)
    return {k: v for _, k, v in rows[:MAX_CG]}


def take_sample(env: Env) -> dict:
    def rd(p, limit=1024 * 1024):
        try:
            return env.fs.read_text(p, limit)
        except FsError:
            return ""
    mem = parse.meminfo(rd("/proc/meminfo"))
    cpu = parse.cpu_times(rd("/proc/stat")) or {}
    load = parse.loadavg(rd("/proc/loadavg"))
    net_text = rd("/proc/net/dev")
    nd = parse.net_dev(net_text)
    s: dict = {"ts": protocol.fmt_ts(env.now()), "up": parse.uptime(rd("/proc/uptime")), "cpu": cpu, "load1_milli": load.get("load1_milli"),
               "mem": {"total": mem.get("MemTotal"), "avail": mem.get("MemAvailable"), "swap_total": mem.get("SwapTotal"), "swap_free": mem.get("SwapFree")},
               "disk": {k: [v["rd_sectors"], v["wr_sectors"], v["io_ms"], v["inflight"]] for k, v in parse.diskstats(rd("/proc/diskstats")).items()}}
    if nd:                                        # absent when /proc/net/dev was unreadable or empty: a zero would be a false measurement
        s["net"] = {"rx": sum(v["rx_bytes"] for v in nd.values()), "tx": sum(v["tx_bytes"] for v in nd.values())}
    g = env.runner.run("nvidia_gpus")
    if g.ok:
        gpus = parse.nvidia_gpus(g.text)
        s["gpu"] = [{"i": x["index"], "mem": x["mem_used_mib"], "tot": x["mem_total_mib"], "util": x["util_pct"], "temp": x["temp_c"], "pw": x["power_mw"], "clk": x["clock_sm_mhz"],
                     "pcie": [x["pcie_gen"], x["pcie_width"]], "thr": x["throttle"]} for x in gpus]
        a = env.runner.run("nvidia_apps")
        if a.ok:
            by = {x["uuid"]: x["index"] for x in gpus}
            s["gpu_apps"] = [{"gi": by.get(x["gpu_uuid"]), "pid": x["pid"], "proc": x["process"][:40], "mib": x["used_mib"], "cg": _pid_cgroup_key(env, x["pid"])} for x in parse.nvidia_apps(a.text)[:40]]
    s["cg"] = cgroup_counters(env)
    return s


def _pid_cgroup_key(env: Env, pid) -> str | None:
    if not isinstance(pid, int):
        return None
    try:
        path = parse.cgroup_v2_path(env.fs.read_text(f"/proc/{pid}/cgroup", 4096))
    except FsError:
        return None
    if not path:
        return None
    for part in path.split("/"):
        m = _DOCKER_SCOPE.match(part)
        if m:
            return "d:" + m.group(1)[:12]
        if _SERVICE.match(part):
            return "u:" + part
    return None


class Sampler:
    """Schedules the engine's continuous collection. Holds no cadence, no guard and no reader of its own: `engine.sample()` is the only caller of take_sample()."""

    def __init__(self, engine):
        self.engine = engine

    def tick(self) -> int | None:
        return self.engine.sample()


def read_op(spool: Spool, params: dict) -> dict:
    """The `metrics.sample` op: samples after the cursor from the spool."""
    r = spool.read_after(params.get("after_seq", 0), params.get("max_samples", 100))
    return {"samples": {"status": "ok", "samples": r["samples"], "next_seq": r["next_seq"], "more": r["more"], "gap": r["gap"], "newest_seq": r["newest_seq"], "interval_min_s": MIN_INTERVAL_S}}
