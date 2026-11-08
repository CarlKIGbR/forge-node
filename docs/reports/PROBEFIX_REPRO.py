"""Repro on the real kernel, NO sandbox, NO unit: run each probe's own --selfcheck code (t0.selfcheck.probe_selfcheck) against the real Fs ('/'), as probe_main does."""
import os, sys
from forge_node.t0.env import Env
from forge_node.t0.fsread import Fs, ProtectedSet
from forge_node.t0.runner import ReadOnlyRunner
from forge_node.t0 import selfcheck
fs = Fs(ProtectedSet.from_policy([]), "/")
env = Env(fs, ReadOnlyRunner(), None, None)
print(os.uname().release, "uid", os.getuid(), "wc -c /proc/net/dev =", len(open("/proc/net/dev").read()))
for name in selfcheck.PROBE_NEEDS:
    r = selfcheck.probe_selfcheck(name, env)
    bad = [p for p, ok in r["paths"].items() if not ok]
    print(f"{name:14} paths={r['paths']}" if r["paths"] else f"{name:14} (no paths)", "<-- DENIED" if bad else "")
from forge_node.t0.fsread import FsError
for p, lim in (("/proc/net/dev", 1024), ("/proc/net/dev", 1<<20), ("/proc/self/net/dev", 1<<20), (f"/proc/{os.getpid()}/net/dev", 1<<20)):
    try: fs.read_text(p, lim); print("read", p, lim, "OK")
    except FsError as e: print("read", p, lim, "->", e)
