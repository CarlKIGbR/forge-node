"""G27 helper: enumerate every register/publish/execute/release entry point and check each goes through the one guarded function.

Dependency-free. Copy this file into the project's tests/ directory (or import it from a pinned forge-standards checkout).

    report = check_entry_points(
        Path("src/myapp"),
        verbs=("register", "publish", "execute", "release"),
        guarded=("guarded_dispatch",),            # the single protected path
        expected_count=7,                         # the counted entry points; a new one fails the test until counted
        exempt={"myapp.cli.release_notes": "renders text, releases nothing"},   # every exemption needs a reason
        guard_params=("customer_data", "model_locks", "session", "budget"),
        effect_calls=("send", "write_row"),       # calls that must not happen before the guard (may be empty, but must be stated)
    )
    assert report.ok, report.render()
    assert_guard_failures_rejected(CASES, report=report, rejects=(Rejected,), side_effects=lambda: len(db.rows))   # REQUIRED companion, see below

THE STATIC CHECK IS NECESSARY, NOT SUFFICIENT. G27 is met only with BOTH halves:
  1. static (`check_entry_points`): the guard call must *dominate* every `return` and the end of the entry function on every path through
     `if`/`try`/`with`/loops/`match` (a guard in only one branch, after an early return, after a swallowing `except`, behind `and`/`or`, in a lambda or
     comprehension does not count), and no listed effect call may precede it. Calls to intra-tree helpers count when the helper itself passes this test.
  2. behavioural (`assert_guard_failures_rejected`): every counted entry point is actually invoked with input that must fail each check (missing session,
     exhausted budget, locked model, customer data not cleared ...) and must reject with no side effect. This catches what static analysis cannot:
     dynamic dispatch, decorators, a guard that exists but is wired to the wrong value, effects hidden in unlisted calls, bypasses by data (`if trusted:` is
     caught statically only when the branch returns without the guard), and anything outside this tree.
Passing (1) alone proves nothing about runtime behaviour; a review must see both.

Other limits: resolution is by bare function name (`foo()` or `x.foo()`), so a same-named unrelated function can mask a bypass (guarded names must be
unique in the tree; a helper name with several definitions counts only if ALL definitions are guarded). Python only; no data-flow, no aliasing
(`g = guard; g()` is not recognised), no `raise`-before-effect analysis (a path that ends in `raise` is treated as a rejection).
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Mapping

BYPASS_PARAM = re.compile(r"^(skip|bypass|no_check|unsafe|force|disable)(_|$)|(^|_)(skip|bypass)$")


@dataclass(frozen=True)
class EntryPoint:
    qualname: str          # module.path.Class.func
    name: str
    path: str
    lineno: int


@dataclass
class Report:
    entry_points: list[EntryPoint] = field(default_factory=list)
    unguarded: list[EntryPoint] = field(default_factory=list)
    reasons: dict[str, list[str]] = field(default_factory=dict)      # qualname -> why it is unguarded
    exempt: list[str] = field(default_factory=list)
    optional_guard_params: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not (self.unguarded or self.optional_guard_params or self.problems)

    def render(self) -> str:
        out = [f"{len(self.entry_points)} entry point(s) counted"]
        for e in self.unguarded:
            out.append(f"UNGUARDED {e.qualname} ({e.path}:{e.lineno}): the guarded path is not on every path")
            out += [f"    {r}" for r in self.reasons.get(e.qualname, [])]
        out += [f"OPTIONAL-GUARD {x}" for x in self.optional_guard_params]
        out += [f"PROBLEM {x}" for x in self.problems]
        return "\n".join(out)


@dataclass
class _Fn:
    entry: EntryPoint
    node: ast.AST
    calls: set[str]


def _callee(node: ast.Call) -> str | None:
    f = node.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None


def _collect(root: Path) -> list[_Fn]:
    root = Path(root)
    fns: list[_Fn] = []
    for f in sorted(root.rglob("*.py")):
        if "__pycache__" in f.parts:
            continue
        rel = f.relative_to(root.parent)
        mod = ".".join(rel.with_suffix("").parts).removesuffix(".__init__")
        tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))

        def walk(body, prefix):
            for n in body:
                if isinstance(n, ast.ClassDef):
                    walk(n.body, f"{prefix}.{n.name}")
                elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    calls = {c for x in ast.walk(n) if isinstance(x, ast.Call) and (c := _callee(x))}
                    fns.append(_Fn(EntryPoint(f"{prefix}.{n.name}", n.name, rel.as_posix(), n.lineno), n, calls))
        walk(tree.body, mod)
    return fns


def _is_entry(name: str, verbs: Iterable[str], include_private: bool) -> bool:
    if name.startswith("_") and not include_private:
        return False
    return bool(set(name.strip("_").lower().split("_")) & set(verbs))


class _Dominance:
    """Does a call to the guarded function happen on EVERY path from function entry to every `return` (and to the end of the body)?

    Conservative control-flow over the AST: `if`/`else`, `try`/`except`/`else`/`finally`, `with`, `for`/`while` (body may run zero times), `match`.
    `raise` ends a path without a violation (it rejects). Evaluated-at-most-sometimes code does not count as a guard: the right side of `and`/`or`,
    both arms of a conditional expression, lambdas, comprehensions, nested defs. An exception handler is analysed as if the `try` body had not run.
    Optionally, a call to an `effect` function before the guard is a violation too. Anything not understood counts as 'guard not established'."""

    def __init__(self, fns: list[_Fn], guarded: set[str], effects: set[str]):
        self.guarded, self.effects = guarded, effects
        self.by_name: dict[str, list[_Fn]] = {}
        for f in fns:
            self.by_name.setdefault(f.entry.name, []).append(f)
        self.memo: dict[str, list[str]] = {}
        self.active: set[str] = set()

    def violations(self, fn: _Fn) -> list[str]:
        """[] = the guard dominates every return/end/effect of `fn` (the guarded function itself is trivially fine)."""
        q = fn.entry.qualname
        if fn.entry.name in self.guarded:
            return []
        if q in self.memo:
            return self.memo[q]
        if q in self.active:                                    # recursion cannot establish a guard
            return ["recursive call chain without a guard before it"]
        self.active.add(q)
        try:
            out, v = self.block(fn.node.body, False)
            if not out:
                v.append(f"line {getattr(fn.node, 'lineno', '?')}: the function can finish without passing the guard")
        finally:
            self.active.discard(q)
        self.memo[q] = v
        return v

    def _guard_name(self, name: str) -> bool:
        if name in self.guarded:
            return True
        defs = self.by_name.get(name)
        return bool(defs) and all(not self.violations(d) for d in defs)

    def expr(self, node: ast.AST | None) -> bool:
        """True when evaluating `node` certainly performs a guard call."""
        if node is None:
            return False
        if isinstance(node, ast.Call):
            c = _callee(node)
            if c and self._guard_name(c):
                return True
            return any(self.expr(x) for x in [node.func, *node.args, *[k.value for k in node.keywords]])
        if isinstance(node, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            return False
        if isinstance(node, ast.BoolOp):
            return self.expr(node.values[0])
        if isinstance(node, ast.IfExp):
            return self.expr(node.test)
        return any(self.expr(c) for c in ast.iter_child_nodes(node))

    def _effects_in(self, node: ast.AST) -> list[str]:
        if isinstance(node, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef)):
            return []
        found = [c for x in ast.walk(node) if isinstance(x, ast.Call) and (c := _callee(x)) in self.effects]
        return found

    def block(self, stmts: list[ast.stmt], g: bool) -> tuple[bool, list[str]]:
        v: list[str] = []
        for st in stmts:
            g, sv = self.stmt(st, g)
            v += sv
        return g, v

    def stmt(self, st: ast.stmt, g: bool) -> tuple[bool, list[str]]:
        ln = f"line {getattr(st, 'lineno', '?')}"
        if isinstance(st, ast.Return):
            ev = [f"{ln}: effect call {c}() before the guard" for c in self._effects_in(st)] if not g and not self.expr(st.value) else []
            return True, ev + ([] if g or self.expr(st.value) else [f"{ln}: return without a guard call on this path"])
        if isinstance(st, ast.Raise):
            return True, []
        if isinstance(st, ast.If):
            ev = self._pre_effects(st.test, g, ln)
            g1 = g or self.expr(st.test)
            gb, vb = self.block(st.body, g1)
            ge, ve = self.block(st.orelse, g1)
            return gb and ge, ev + vb + ve
        if isinstance(st, (ast.With, ast.AsyncWith)):
            ev, g1 = [], g
            for it in st.items:
                ev += self._pre_effects(it.context_expr, g1, ln)
                g1 = g1 or self.expr(it.context_expr)
            go, vb = self.block(st.body, g1)
            return go, ev + vb
        if isinstance(st, (ast.For, ast.AsyncFor, ast.While)):
            head = st.iter if not isinstance(st, ast.While) else st.test
            ev = self._pre_effects(head, g, ln)
            g1 = g or self.expr(head)
            _, vb = self.block(st.body, g1)                    # the body may run zero times: it cannot establish the guard
            go, ve = self.block(st.orelse, g1)
            return g1, ev + vb + ve
        if isinstance(st, ast.Try) or st.__class__.__name__ == "TryStar":
            gb, vb = self.block(st.body, g)
            ge, ve = self.block(st.orelse, gb)
            outs, vh = [ge], []
            for h in st.handlers:                              # the body may have failed before the guard
                gh, v1 = self.block(h.body, g)
                outs.append(gh)
                vh += v1
            gf, vf = self.block(st.finalbody, g)
            return all(outs) or gf, vb + ve + vh + vf
        if isinstance(st, ast.Match):
            outs, vs = [], []
            for case in st.cases:
                go, v1 = self.block(case.body, g or self.expr(st.subject))
                outs.append(go)
                vs += v1
            exhaustive = bool(st.cases) and isinstance(st.cases[-1].pattern, ast.MatchAs) and st.cases[-1].pattern.pattern is None and st.cases[-1].guard is None
            return (all(outs) and exhaustive) or g or self.expr(st.subject), vs
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return g, []
        ev = self._pre_effects(st, g, ln)
        return g or self.expr(st), ev

    def _pre_effects(self, node: ast.AST, g: bool, ln: str) -> list[str]:
        return [] if g else [f"{ln}: effect call {c}() before the guard" for c in self._effects_in(node)]


def find_entry_points(root: Path, verbs: Iterable[str], include_private: bool = False) -> list[EntryPoint]:
    return [f.entry for f in _collect(root) if _is_entry(f.entry.name, verbs, include_private)]


def check_entry_points(root: Path, *, verbs: Iterable[str], guarded: Iterable[str], expected_count: int, exempt: Mapping[str, str],
                       guard_params: Iterable[str], effect_calls: Iterable[str], include_private: bool = False) -> Report:
    """Every argument is required on purpose (G27: no optional parameter whose absence skips a check)."""
    guarded_set, verbs = set(guarded), tuple(verbs)
    rep = Report()
    if not guarded_set:
        rep.problems.append("no guarded function named: nothing to prove")
        return rep
    fns = _collect(root)
    for g in sorted(guarded_set):
        n = sum(1 for f in fns if f.entry.name == g)
        if n != 1:
            rep.problems.append(f"guarded function '{g}' is defined {n} times in the tree (must be exactly once)")
    for q, why in exempt.items():
        if not str(why).strip():
            rep.problems.append(f"exemption {q} has no reason")
    names = {f.entry.qualname for f in fns}
    rep.problems += [f"exemption {q} matches no function (stale)" for q in exempt if q not in names]
    gparams = set(guard_params)
    dom = _Dominance(fns, guarded_set, set(effect_calls))
    for fn in fns:
        if fn.entry.name in guarded_set:
            continue                                   # the guard itself is proven by assert_fail_closed
        if not _is_entry(fn.entry.name, verbs, include_private):
            continue
        rep.entry_points.append(fn.entry)
        if fn.entry.qualname in exempt:
            rep.exempt.append(fn.entry.qualname)
            continue
        why = dom.violations(fn)
        if why:
            rep.unguarded.append(fn.entry)
            rep.reasons[fn.entry.qualname] = why
    # optional parameters that can switch a check off: on every counted entry point and on the guarded functions
    for fn in fns:
        if fn.entry.name in guarded_set or fn.entry in rep.entry_points:
            a = fn.node.args
            pos = a.posonlyargs + a.args
            defaulted = {p.arg for p in pos[len(pos) - len(a.defaults):]} | {p.arg for p, d in zip(a.kwonlyargs, a.kw_defaults) if d is not None}
            for p in sorted(defaulted):
                if p in gparams or BYPASS_PARAM.search(p):
                    rep.optional_guard_params.append(f"{fn.entry.qualname}({p}=...) has a default; a missing check input must reject, not skip")
    if len(rep.entry_points) != expected_count:
        rep.problems.append(f"counted {len(rep.entry_points)} entry point(s), expected {expected_count}: "
                            f"{sorted(e.qualname for e in rep.entry_points)} (update expected_count only after reviewing the new entry point)")
    return rep


def assert_fail_closed(fn: Callable, valid_kwargs: Mapping, required_state: Iterable[str], *, rejects: tuple[type[BaseException], ...],
                       side_effects: Callable[[], int]) -> None:
    """Runtime half of G27: calling the guarded function with any required state missing (key absent, None) must raise one of `rejects`
    and must leave `side_effects()` unchanged. Also proves the call with all state present is accepted (else the test proves nothing)."""
    fn(**valid_kwargs)
    for key in required_state:
        for variant in ("absent", "none"):
            kw = {k: v for k, v in valid_kwargs.items() if k != key}
            if variant == "none":
                kw[key] = None
            before = side_effects()
            try:
                fn(**kw)
            except rejects:
                pass
            except TypeError as e:
                if variant == "none":
                    raise AssertionError(f"{key}=None raised TypeError instead of a clean rejection: {e}") from e
            else:
                raise AssertionError(f"missing state '{key}' ({variant}) was accepted: the check is skipped, not fail-closed")
            if side_effects() != before:
                raise AssertionError(f"missing state '{key}' ({variant}) was rejected only after a side effect happened")


@dataclass(frozen=True)
class EntryCase:
    """One entry point under behavioural test. `call(**kwargs)` invokes it; `valid` is an input that must be accepted;
    `failing` maps a label (which check fails) to the kwargs overrides that must make the call reject (a value of `_DROP` removes the key)."""
    call: Callable
    valid: Mapping
    failing: Mapping[str, Mapping]


DROP = object()          # in a failing override: remove this key from the call


def assert_guard_failures_rejected(cases: Mapping[str, EntryCase], *, report: Report, rejects: tuple[type[BaseException], ...],
                                   side_effects: Callable[[], int]) -> None:
    """Behavioural half of G27. For EVERY counted, non-exempt entry point in `report` there must be a case (key = qualname), and for each failing
    input the call must raise one of `rejects` with `side_effects()` unchanged. The valid input must be accepted first (otherwise the rejections prove nothing),
    each failing override must really differ from the valid input, and every case must define at least one failing input."""
    want = {e.qualname for e in report.entry_points} - set(report.exempt)
    missing, stale = sorted(want - set(cases)), sorted(set(cases) - want)
    if missing or stale:
        raise AssertionError(f"behavioural cases do not match the counted entry points: missing {missing}, unknown {stale}")
    for q, case in sorted(cases.items()):
        if not case.failing:
            raise AssertionError(f"{q}: no guard-failing input defined")
        case.call(**dict(case.valid))
        for label, override in case.failing.items():
            kw = dict(case.valid)
            for k, v in override.items():
                if v is DROP:
                    kw.pop(k, None)
                else:
                    kw[k] = v
            if kw == dict(case.valid):
                raise AssertionError(f"{q}[{label}]: the failing input equals the valid input")
            before = side_effects()
            try:
                case.call(**kw)
            except rejects:
                pass
            else:
                raise AssertionError(f"{q}[{label}]: guard-failing input was ACCEPTED (bypass)")
            if side_effects() != before:
                raise AssertionError(f"{q}[{label}]: rejected only after a side effect happened")
