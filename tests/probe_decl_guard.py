"""Runs probe code under the probe's own declaration (t0/needs.py) wherever a test drives `probes._probe_<name>`: while a probe function runs, every Fs read/metadata call is checked against
that probe's declaration, exactly like `needs.declared_fs` does in the unit. A probe (or a helper it calls) that reads something the table does not name fails the test that triggered it."""
import contextvars

from forge_node.t0 import fsread, needs, probes

CURRENT = contextvars.ContextVar("probe", default=None)
SEEN: list = []


def _check_read(logical):
    name = CURRENT.get()
    if name is None:
        return
    need = needs.PROBE_NEEDS[name]
    p = fsread.norm_abs(logical)
    SEEN.append((name, "read_text", p))
    if not any(r.regex.match(p) for r in need.reads):
        raise AssertionError(f"probe {name} reads {p!r}, which its declaration does not name")


def _check_meta(method):
    name = CURRENT.get()
    if name is not None:
        SEEN.append((name, method, ""))
        assert method in needs.PROBE_NEEDS[name].meta, f"probe {name} calls Fs.{method}, which its declaration does not name"


def install(monkeypatch):
    SEEN.clear()
    orig_resolve = fsread.Fs._resolve_for_read

    def resolve(self, logical):
        _check_read(logical)
        return orig_resolve(self, logical)
    monkeypatch.setattr(fsread.Fs, "_resolve_for_read", resolve)
    for m in sorted(needs.FS_METHODS):
        def wrap(orig, m=m):
            def f(self, *a, **kw):
                _check_meta(m)
                return orig(self, *a, **kw)
            return f
        monkeypatch.setattr(fsread.Fs, m, wrap(getattr(fsread.Fs, m)))
    for name in probes.PROBE_NAMES:
        def wrap_probe(orig, name=name):
            def f(params, env):
                tok = CURRENT.set(name)
                try:
                    return orig(params, env)
                finally:
                    CURRENT.reset(tok)
            return f
        monkeypatch.setattr(probes, "_probe_" + name, wrap_probe(getattr(probes, "_probe_" + name)))
