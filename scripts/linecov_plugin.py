"""Stdlib line coverage for the test run (the test image has no `coverage`): pytest plugin on sys.monitoring (PEP 669, Python >= 3.12). Enabled by FN_COV=1.
  FN_COV=1 scripts/run-tests.sh -p linecov_plugin -q            prints a table for src/forge_node/**.py with the missed line numbers
Counts every line that has code (code objects, recursively) and every line the monitor saw executed. Not a substitute for branch coverage - mutation checks cover that."""
import os
import sys

ROOT = os.environ.get("FN_COV_ROOT", "/w/src/forge_node/")
_hits: dict[str, set[int]] = {}


def pytest_configure(config):
    if not os.environ.get("FN_COV"):
        return
    mon = sys.monitoring
    mon.use_tool_id(mon.COVERAGE_ID, "fn-linecov")

    def on_line(code, line):
        if code.co_filename.startswith(ROOT):
            _hits.setdefault(code.co_filename, set()).add(line)
        return mon.DISABLE
    mon.register_callback(mon.COVERAGE_ID, mon.events.LINE, on_line)
    mon.set_events(mon.COVERAGE_ID, mon.events.LINE)


def _executable(path: str) -> set[int]:
    with open(path, "rb") as f:
        code = compile(f.read(), path, "exec")
    lines: set[int] = set()
    stack = [code]
    while stack:
        c = stack.pop()
        lines |= {ln for _, _, ln in c.co_lines() if ln}
        stack.extend(k for k in c.co_consts if hasattr(k, "co_lines"))
    return lines


def pytest_sessionfinish(session, exitstatus):
    if not os.environ.get("FN_COV"):
        return
    sys.monitoring.set_events(sys.monitoring.COVERAGE_ID, 0)
    rows, tot_e, tot_h = [], 0, 0
    for dp, _, fns in os.walk(ROOT):
        for fn in sorted(fns):
            if not fn.endswith(".py"):
                continue
            p = os.path.join(dp, fn)
            ex = _executable(p)
            hit = _hits.get(p, set()) & ex
            miss = sorted(ex - hit)
            tot_e += len(ex)
            tot_h += len(hit)
            rows.append((p[len(ROOT):], len(ex), len(hit), miss))
    print("\n--- line coverage (stdlib monitor) ---")
    for name, e, h, miss in sorted(rows):
        print(f"{name:34s} {h:5d}/{e:<5d} {100.0 * h / max(e, 1):6.1f}%  missed: {','.join(map(str, miss[:40]))}{' ...' if len(miss) > 40 else ''}")
    print(f"{'TOTAL':34s} {tot_h:5d}/{tot_e:<5d} {100.0 * tot_h / max(tot_e, 1):6.1f}%")
