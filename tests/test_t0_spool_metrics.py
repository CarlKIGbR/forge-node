import json
import os
import stat
import threading
from datetime import timedelta

import pytest
from hypothesis import given, settings, strategies as st

from forge_node import canon, protocol
from forge_node.t0 import metrics, usage as usage_mod
from forge_node.t0.runner import Run
from forge_node.t0.spool import HARD_MAX_BYTES, MAX_LINE, Spool, SpoolError

from n2_helpers import FakeRunner, NOW, make_env


def mk(tmp_path, max_bytes=16384):
    d = tmp_path / "spool"
    d.mkdir(exist_ok=True)
    return Spool(str(d), os.getuid(), max_bytes), d


def ts(i):
    return protocol.fmt_ts(NOW + timedelta(seconds=30 * i))


# ---------------------------------------------------------------------------------------------------------------------------------- spool
def test_append_assigns_increasing_seq_and_reads_back_after_a_cursor(tmp_path):
    s, _ = mk(tmp_path)
    assert [s.append({"ts": ts(i), "v": i}) for i in range(5)] == [1, 2, 3, 4, 5]
    r = s.read_after(2, 10)
    assert [x["seq"] for x in r["samples"]] == [3, 4, 5] and r["next_seq"] == 5 and not r["more"] and not r["gap"] and r["newest_seq"] == 5
    r = s.read_after(0, 2)
    assert [x["seq"] for x in r["samples"]] == [1, 2] and r["more"] and s.read_after(5, 10)["samples"] == []
    assert s.depth() == 5


def test_ring_drops_the_oldest_segment_and_reports_a_gap(tmp_path):
    s, d = mk(tmp_path, 8192)
    for i in range(500):
        s.append({"ts": ts(i), "pad": "x" * 40})
    assert s.bytes_used() <= 8192 + s.seg_bytes and len(os.listdir(d)) < 12
    r = s.read_after(0, 1000, 10**9)
    assert r["gap"] is True and r["samples"][0]["seq"] == s.oldest_seq() > 1 and r["samples"][-1]["seq"] == 500
    assert s.read_after(r["samples"][0]["seq"] - 1, 1)["gap"] is False


def test_hard_cap_cannot_be_raised(tmp_path):
    s, _ = mk(tmp_path, 10**12)
    assert s.max_bytes == HARD_MAX_BYTES == 50 * 1024 * 1024


def test_restart_continues_the_sequence_and_survives_a_torn_tail(tmp_path):
    s, d = mk(tmp_path)
    for i in range(3):
        s.append({"ts": ts(i)})
    s.close()
    seg = next(iter(sorted(d.iterdir())))
    with open(seg, "ab") as f:
        f.write(b'{"seq":4,"ts":"2026-10')                                 # power loss mid-write
    s2 = Spool(str(d), os.getuid(), 16384)
    assert s2.append({"ts": ts(9)}) == 4                                      # the torn line never counted; its seq is reused by the next sample
    got = s2.read_after(0, 10)["samples"]
    assert [x["seq"] for x in got] == [1, 2, 3, 4] and got[-1]["ts"] == ts(9)


def test_a_torn_segment_is_never_reopened_a_new_segment_takes_over(tmp_path):
    s, d = mk(tmp_path)
    s.append({"ts": ts(0)})
    s.close()
    seg = next(iter(d.iterdir()))
    with open(seg, "ab") as f:
        f.write(b'{"seq":2,"ts"')
    s2 = Spool(str(d), os.getuid(), 16384)
    s2.append({"ts": ts(1)})
    assert seg.read_bytes().endswith(b'{"seq":2,"ts"') and len(os.listdir(d)) == 2
    assert [x["seq"] for x in s2.read_after(0, 10)["samples"]] == [1, 2]


def test_symlinks_hardlinks_and_foreign_files_in_the_spool_dir_are_ignored_and_never_deleted(tmp_path):
    s, d = mk(tmp_path, 4096)
    outside = tmp_path / "precious"
    outside.write_text("keep me")
    os.symlink(outside, d / "seg-000000000001.jsonl")
    os.link(outside, d / "seg-000000000002.jsonl")
    (d / "notes.txt").write_text("x")
    s2 = Spool(str(d), os.getuid(), 4096)
    for i in range(200):
        s2.append({"ts": ts(i), "pad": "y" * 60})
    assert outside.read_text() == "keep me" and (d / "notes.txt").exists()
    assert s2.read_after(0, 10**6, 10**9)["samples"][-1]["seq"] >= 200


def test_spool_dir_must_be_ours_not_a_symlink_and_is_tightened(tmp_path):
    d = tmp_path / "spool"
    d.mkdir(mode=0o755)
    Spool(str(d), os.getuid())
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
    os.symlink(d, tmp_path / "link")
    with pytest.raises(SpoolError):
        Spool(str(tmp_path / "link"), os.getuid())
    with pytest.raises(SpoolError):
        Spool(str(d), os.getuid() + 7)
    with pytest.raises(SpoolError):
        Spool(str(tmp_path / "missing"), os.getuid())


def test_oversized_sample_is_refused(tmp_path):
    s, _ = mk(tmp_path)
    with pytest.raises(SpoolError):
        s.append({"ts": ts(0), "blob": "x" * (MAX_LINE + 1)})
    assert s.depth() == 0


def test_window_selects_by_timestamp(tmp_path):
    s, _ = mk(tmp_path, 1 << 20)
    for i in range(10):
        s.append({"ts": ts(i), "i": i})
    assert [x["i"] for x in s.window(ts(7))] == [7, 8, 9]


def test_concurrent_appends_keep_unique_seq_and_all_lines(tmp_path):
    s, _ = mk(tmp_path, 1 << 22)
    seqs = []

    def work():
        for i in range(100):
            seqs.append(s.append({"ts": ts(0), "t": threading.get_ident()}))
    ts_ = [threading.Thread(target=work) for _ in range(8)]
    [t.start() for t in ts_]
    [t.join() for t in ts_]
    assert sorted(seqs) == list(range(1, 801)) and len(s.read_after(0, 10**6, 10**9)["samples"]) == 800


@settings(max_examples=30, deadline=None)
@given(st.lists(st.integers(0, 300), min_size=1, max_size=80), st.integers(0, 40))
def test_property_reads_are_contiguous_ascending_and_bounded(pads, after):
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        d = os.path.join(td, "s")
        os.mkdir(d)
        s = Spool(d, os.getuid(), 6000)
        for i, p in enumerate(pads):
            s.append({"ts": ts(i % 50), "pad": "z" * p})
        r = s.read_after(after, 25, 4000)
        seqs = [x["seq"] for x in r["samples"]]
        assert seqs == sorted(set(seqs)) and all(q > after for q in seqs) and len(seqs) <= 25
        assert all(b - a == 1 for a, b in zip(seqs, seqs[1:])) and sum(len(canon.canonical(x)) + 1 for x in r["samples"]) <= 4000 + MAX_LINE


# --------------------------------------------------------------------------------------------------------------------------------- metrics
CG = {
    "/sys/fs/cgroup/system.slice/docker-" + "a" * 64 + ".scope/memory.current": "1048576\n",
    "/sys/fs/cgroup/system.slice/docker-" + "a" * 64 + ".scope/cpu.stat": "usage_usec 5000000\nuser_usec 1\n",
    "/sys/fs/cgroup/system.slice/docker-" + "a" * 64 + ".scope/io.stat": "259:0 rbytes=100 wbytes=50 rios=1\n",
    "/sys/fs/cgroup/system.slice/forge-postbote.service/memory.current": "52428800\n",
    "/sys/fs/cgroup/system.slice/forge-postbote.service/cpu.stat": "usage_usec 9000000\n",
    "/sys/fs/cgroup/system.slice/not-a-unit.slice/memory.current": "1\n",
    "/proc/4242/cgroup": "0::/system.slice/docker-" + "a" * 64 + ".scope\n",
}
GPU = "0, GPU-aaaa, RTX 4090, 1024, 24564, 3, 41, 70.12, 450.00, 210, 2520, 4, 16, 0x0\n"


def menv(tmp_path, **kw):
    return make_env(tmp_path, FakeRunner({"nvidia_gpus": GPU, "nvidia_apps": "GPU-aaaa, 4242, /usr/bin/python3, 512\n", **kw}), files=CG)


def test_sample_contains_counters_gpu_and_cgroups_without_floats(tmp_path):
    s = metrics.take_sample(menv(tmp_path))
    canon.canonical(s)                                                           # no floats anywhere
    assert s["up"] == 123456 and s["cpu"] == {"total": 9600, "idle": 8100} and s["load1_milli"] == 520 and s["mem"]["swap_total"] == 2097148 * 1024
    assert s["disk"] == {"nvme0n1": [2000, 4000, 130, 3]} and s["net"] == {"rx": 5000, "tx": 7000}
    assert s["gpu"][0]["mem"] == 1024 and s["gpu"][0]["pw"] == 70120 and s["gpu_apps"][0] == {"gi": 0, "pid": 4242, "proc": "python3", "mib": 512, "cg": "d:" + "a" * 12}
    assert s["cg"]["d:" + "a" * 12] == [5000000, 1048576, 100, 50] and s["cg"]["u:forge-postbote.service"][1] == 52428800 and len(s["cg"]) == 2
    assert len(canon.canonical(s)) < MAX_LINE


def test_sample_without_gpu_and_cgroups(tmp_path):
    s = metrics.take_sample(make_env(tmp_path, FakeRunner({})))
    assert "gpu" not in s and s["cg"] == {}


def test_cgroup_scan_keeps_the_biggest_consumers_only(tmp_path):
    files = {f"/sys/fs/cgroup/system.slice/u{i}.service/memory.current": f"{i + 1}\n" for i in range(80)}
    cg = metrics.cgroup_counters(make_env(tmp_path, FakeRunner({}), files=files))
    assert len(cg) == metrics.MAX_CG and "u:u79.service" in cg and "u:u0.service" not in cg


def sampler_for(tmp_path, runner=None):
    from forge_node.t0 import engine as E
    from forge_node.t0.limits import RateLimiter
    env = make_env(tmp_path, runner or FakeRunner({}))
    clock = {"t": NOW}
    env.now = lambda: clock["t"]
    spool, _ = mk(tmp_path)
    eng = E.T0Engine(node="g2", env=env, limiter=RateLimiter(str(tmp_path / "rl.json"), lambda: clock["t"]), probe=None, spool=spool, node_cert_path=None, hub_cert_der=lambda: None)
    return metrics.Sampler(eng), clock, spool, eng


def test_sampler_cadence_is_at_least_30_seconds_whoever_calls(tmp_path):
    sm, clock, spool, eng = sampler_for(tmp_path)
    assert sm.tick() == 1
    for dt in (0, 1, 15, 29):
        clock["t"] = NOW + timedelta(seconds=dt)
        assert sm.tick() is None
    clock["t"] = NOW + timedelta(seconds=30)
    assert sm.tick() == 2 and spool.depth() == 2
    clock["t"] = NOW - timedelta(hours=1)                   # clock stepped back: the interval counts from the last tick, so no flood and no negative gap
    assert sm.tick() == 3
    clock["t"] = NOW - timedelta(hours=1) + timedelta(seconds=10)
    assert sm.tick() is None
    clock["t"] = NOW - timedelta(hours=1) - timedelta(seconds=10)         # small backwards jitter after the step: still too early
    assert sm.tick() is None


def test_metrics_cadence_is_a_constant_not_a_parameter():
    import inspect
    from forge_node.t0 import engine as E
    assert metrics.MIN_INTERVAL_S == 30 and "interval" not in inspect.signature(metrics.Sampler.__init__).parameters and "interval" not in inspect.signature(E.T0Engine.sample).parameters


def test_sampling_goes_through_the_engine_guards(tmp_path):
    """Review finding: the sampler was a second read path. Now it is T0Engine.sample(): policy tier, gate registry, its own rate bucket, cadence."""
    sm, clock, spool, eng = sampler_for(tmp_path)
    object.__setattr__(eng.env.policy, "tiers_enabled", ())
    assert sm.tick() is None and spool.depth() == 0
    object.__setattr__(eng.env.policy, "tiers_enabled", (0,))
    assert sm.tick() == 1
    # the engine's own persisted bucket bounds restart flapping: a fresh engine has no cadence memory, the bucket (2 tokens, 2/min, stored on disk) still remembers
    from forge_node.t0 import engine as E
    from forge_node.t0.limits import RateLimiter
    (tmp_path / "flap").mkdir()
    seqs = []
    for i in range(4):
        t = NOW + timedelta(seconds=i)
        env = make_env(tmp_path / "flap", FakeRunner({}))
        env.now = lambda t=t: t
        spool2 = Spool(str(tmp_path / "flap"), os.getuid(), 1 << 16)
        e2 = E.T0Engine(node="g2", env=env, limiter=RateLimiter(str(tmp_path / "flap" / "rl.json"), lambda t=t: t), probe=None, spool=spool2, node_cert_path=None, hub_cert_der=lambda: None)
        seqs.append(metrics.Sampler(e2).tick())
    assert [s is not None for s in seqs] == [True, True, False, False]
    import ast
    from pathlib import Path
    src = Path(__file__).resolve().parents[1] / "src" / "forge_node"
    callers = [p.name for p in (src / "t0").glob("*.py") for n in ast.walk(ast.parse(p.read_text())) if isinstance(n, ast.Call) and getattr(n.func, "attr", getattr(n.func, "id", "")) == "take_sample"]
    assert sorted(set(callers)) == ["engine.py"], callers          # defined in metrics.py, called only by the engine


def test_samples_with_absurd_integers_are_clamped_not_dropped(tmp_path):
    sm, clock, spool, eng = sampler_for(tmp_path, FakeRunner({"nvidia_gpus": "0, GPU-a, X, 1, 999999999999999999999, 1, 1, 1.0, 1.0, 1, 1, 4, 16, 0x0\n"}))
    assert sm.tick() == 1
    g = spool.read_after(0, 1)["samples"][0]["gpu"][0]
    assert g["tot"] == 2**53 - 1


# ---------------------------------------------------------------------------------------------------------------------------------- usage
class FakeProbe:
    def __init__(self, reply):
        self.reply = reply

    def call(self, name, params):
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply[name]


def test_usage_window_aggregates_samples_and_joins_probe_names(tmp_path):
    env = menv(tmp_path)
    spool, _ = mk(tmp_path, 1 << 20)
    key = "d:" + "a" * 12
    for i in range(5):
        spool.append({"ts": protocol.fmt_ts(NOW - timedelta(hours=4 - i)), "cg": {key: [1_000_000 * (i + 1) * 10, 1000 * (i + 1), 100 * i, 50 * i]},
                      "gpu": [{"i": 0, "mem": 1000 * (i + 1), "tot": 24564, "util": 10 * i, "temp": 40 + i, "pw": 1, "clk": 1, "pcie": [4, 16], "thr": []}],
                      "gpu_apps": [{"gi": 0, "pid": 1, "proc": "python3", "mib": 500 * (i + 1), "cg": key}], "mem": {"swap_total": 100, "swap_free": 100 - i}, "load1_milli": 100 * i})
    probe = FakeProbe({"containers": {"containers": {"status": "ok", "containers": [{"id": "a" * 12, "name": "pg", "attribution": {"unattributed": False}}]}},
                       "activity": {"activity": {"status": "ok", "units": []}}, "container_net": {"container_net": {"status": "ok", "containers": {"a" * 12: {"rx_bytes": 5, "tx_bytes": 6}}}}})
    u = usage_mod.usage(env, spool, probe, {"window_h": 72})
    w = u["window"]
    assert w["samples"] == 5 and w["covered_hours"] == 4 and w["per_cgroup"][key] == {"samples": 5, "cpu_seconds": 40, "rss_max": 5000, "io_read_bytes": 400, "io_write_bytes": 200}
    assert w["gpu"]["0"] == {"mem_used_max": 5000, "mem_free_min": 24564 - 5000, "util_max": 40, "temp_max": 44, "total": 24564} and w["gpu_vram_by_owner_mib"] == {key: 2500}
    assert w["swap_used_max"] == 4 and w["load1_milli_max"] == 400 and u["containers"]["containers"][0]["name"] == "pg" and u["container_net"]["containers"]["a" * 12]["rx_bytes"] == 5
    assert u["now"]["cgroups"][key]["rss"] == 1048576
    narrow = usage_mod.usage(env, spool, probe, {"window_h": 2})["window"]
    assert narrow["samples"] == 3


def test_usage_degrades_without_the_privileged_probe(tmp_path):
    from forge_node.t0.wire import ProbeDenied, ProbeUnavailable
    spool, _ = mk(tmp_path)
    u = usage_mod.usage(menv(tmp_path), spool, FakeProbe(ProbeUnavailable("down")), {})
    assert u["containers"]["status"] == "unavailable" and u["window"]["samples"] == 0 and u["window"]["swap_used_max"] is None
    assert usage_mod.usage(menv(tmp_path), spool, FakeProbe(ProbeDenied("DENY_RATE")), {})["containers"]["status"] == "error"


def test_usage_skips_malformed_spool_records_and_streams(tmp_path):
    env = menv(tmp_path)
    spool, _ = mk(tmp_path, 1 << 20)
    spool.append({"ts": protocol.fmt_ts(NOW - timedelta(hours=1)), "cg": {"d:aaa": [1_000_000, 10, 0, 0]}})
    spool.append({"ts": protocol.fmt_ts(NOW - timedelta(minutes=50)), "cg": "garbage", "gpu": [{"i": "x"}]})
    spool.append({"ts": protocol.fmt_ts(NOW - timedelta(minutes=40)), "cg": {"d:aaa": [3_000_000, 20, 0, 0]}})
    u = usage_mod.usage(env, spool, FakeProbe({"containers": {"containers": {"status": "ok"}}, "activity": {"activity": {"status": "ok"}}, "container_net": {"container_net": {"status": "ok"}}}), {"window_h": 2})["window"]
    assert u["samples"] == 3 and u["skipped_records"] >= 1 and u["per_cgroup"]["d:aaa"]["cpu_seconds"] == 2
    import types
    assert isinstance(spool.iter_window("0"), types.GeneratorType)


def test_usage_never_materialises_the_spool_window(tmp_path, monkeypatch):
    env = menv(tmp_path)
    spool, _ = mk(tmp_path, 1 << 20)
    spool.append({"ts": protocol.fmt_ts(NOW - timedelta(minutes=5)), "cg": {"d:aaa": [1_000_000, 10, 0, 0]}})
    monkeypatch.setattr(Spool, "window", lambda self, since: (_ for _ in ()).throw(AssertionError("the whole window was loaded into memory")))
    from forge_node.t0.wire import ProbeUnavailable
    u = usage_mod.usage(env, spool, FakeProbe(ProbeUnavailable("down")), {"window_h": 1})
    assert u["window"]["samples"] == 1

