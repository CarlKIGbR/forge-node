"""systemd transaction resolver (Design 4.3.1): the COMPLETE action-specific transaction of a unit operation, computed from the live unit graph BEFORE authorization.

Starting or restarting a unit does not only touch that unit: systemd also activates dependencies and STOPS units that conflict. The resolver therefore computes, for the requested action,
  F  forward activation closure (Requires, Requisite, BindsTo, Wants, Upholds; transitively) plus what sockets/timers trigger,
  C  every loaded unit named in Conflicts= of a member of F, or carrying a Conflicts= that names a member of F (ConflictedBy),
  S  the stop-closure of C (reverse edges RequiredBy, BoundBy, ConsistsOf, PropagatesStopTo),
  X  action extras (restart propagation, reload propagation, WantedBy/RequiredBy of enable/disable),
and reports a PROTECTED HIT if any member is in the protected unit set, has a FragmentPath in a protected path, or cannot be fully enumerated (provider error, missing property, a loaded
unit without a fragment): an incomplete resolution is a hit (fail closed). `closure_sha256` binds the resolved sets AND each member's fragment/drop-in paths, so a new drop-in or a new
Conflicts= changes the hash (DENY_CLOSURE_CHANGED until the owner re-signs).

GATE C (Betriebsleiter decision): this resolver does NOT follow OnSuccess=/OnFailure= edges or isolate-like job modes. Until it follows them recursively and binds them into the hash
(N6/N7), it REJECTS - as a hit, like an incomplete resolution - any unit in the closure that uses OnSuccess=/OnFailure= (or an isolate OnSuccessJobMode=/OnFailureJobMode=), and any
requested job mode other than replace/fail (isolate, replace-irreversibly, flush, ignore-dependencies, ignore-requirements, ...). gates.GATES['C'] stays unmet; all unit ops stay disabled.

Deliberate refinement of 'unit not loaded but referenced': a referenced unit whose LoadState is not-found cannot be part of a transaction when it is only WANTED / listed in Conflicts=
(weak edges: systemd ignores it), so it is skipped; for Requires/Requisite/BindsTo (strong edges) and for every unit the provider fails on it is a hit."""
import hashlib
import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Callable

from .. import canon

ACTIONS = ("start", "stop", "restart", "try-restart", "reload", "reload-or-restart", "enable", "disable", "mask", "unmask")
ALLOWED_JOB_MODES = ("replace", "fail")
STRONG = ("Requires", "Requisite", "BindsTo")
FORWARD = ("Requires", "Requisite", "BindsTo", "Wants", "Upholds")
REVERSE_STOP = ("RequiredBy", "BoundBy", "ConsistsOf", "PropagatesStopTo")
REL_PROPS = ("Requires", "Requisite", "BindsTo", "Wants", "Upholds", "Conflicts", "ConflictedBy", "RequiredBy", "BoundBy", "ConsistsOf", "PropagatesStopTo", "PropagatesReloadTo",
             "PartOf", "Triggers", "TriggeredBy", "WantedBy", "UpheldBy")
GATE_C_PROPS = ("OnSuccess", "OnFailure", "OnSuccessJobMode", "OnFailureJobMode")
META_PROPS = ("Id", "LoadState", "ActiveState", "FragmentPath", "DropInPaths", "Names")
ALL_PROPS = REL_PROPS + GATE_C_PROPS + META_PROPS
MAX_UNITS = 400


@dataclass(frozen=True)
class Hit:
    unit: str
    reason: str
    edge: str = ""

    def text(self) -> str:
        return f"{self.unit}: {self.reason}" + (f" (via {self.edge})" if self.edge else "")


@dataclass
class Resolution:
    unit: str
    action: str
    F: set = field(default_factory=set)
    C: set = field(default_factory=set)
    S: set = field(default_factory=set)
    X: set = field(default_factory=set)
    frag: dict = field(default_factory=dict)
    hits: list = field(default_factory=list)

    @property
    def denied(self) -> bool:
        return bool(self.hits)

    @property
    def members(self) -> set:
        return {self.unit} | self.F | self.C | self.S | self.X

    def closure_sha256(self) -> str:
        doc = {"v": 1, "unit": self.unit, "action": self.action, "F": sorted(self.F), "C": sorted(self.C), "S": sorted(self.S), "X": sorted(self.X),
               "frag": {u: self.frag[u] for u in sorted(self.frag)}}
        return hashlib.sha256(canon.canonical(doc)).hexdigest()


class Incomplete(Exception):
    pass


class _Walker:
    def __init__(self, provider: Callable[[str], dict | None], protected_units: tuple, protected_paths: tuple, res: Resolution):
        self.provider, self.pu, self.pp, self.res = provider, protected_units, protected_paths, res
        self.cache: dict[str, dict | None] = {}

    def props(self, name: str, edge: str, strong: bool = True) -> dict | None:
        """Properties of a unit (with its relation lists split). None = skip (weak edge to a not-found unit); a hit is recorded for anything incomplete."""
        if name not in self.cache:
            try:
                raw = self.provider(name)
            except Exception:  # noqa: BLE001 - a provider bug is an incomplete resolution too
                raw = None
            self.cache[name] = self._normalise(name, raw, edge)
        p = self.cache[name]
        if p is not None and p.get("_notfound"):
            if strong:
                self.res.hits.append(Hit(name, "referenced by a strong edge but not loaded", edge))
            return None
        return p

    def _normalise(self, name: str, raw: dict | None, edge: str) -> dict | None:
        if raw is None:
            self.res.hits.append(Hit(name, "cannot be enumerated (systemctl show failed)", edge))
            return {"_incomplete": True, **{k: [] for k in REL_PROPS}}
        if raw.get("LoadState") == "not-found":
            return {"_notfound": True}
        missing = [k for k in ALL_PROPS if k not in raw]
        if missing:
            self.res.hits.append(Hit(name, f"incomplete resolution: systemctl show lacks {missing[:3]}", edge))
            return {"_incomplete": True, **{k: [] for k in REL_PROPS}}
        p = {k: raw[k].split() for k in REL_PROPS}
        p.update({k: raw[k] for k in META_PROPS + GATE_C_PROPS if k not in ("Names",)})
        p["Names"] = raw["Names"].split()
        p["OnSuccess"], p["OnFailure"] = raw["OnSuccess"].split(), raw["OnFailure"].split()
        return p

    def check_member(self, name: str, p: dict, edge: str) -> None:
        """Hits that depend on the unit alone: protected name/path, no fragment, gate C."""
        if p.get("_incomplete"):
            return
        names = [name, *p.get("Names", [])]
        for n in names:
            for g in self.pu:
                if fnmatchcase(n, g):
                    self.res.hits.append(Hit(name, f"protected unit ({g})", edge))
                    break
            else:
                continue
            break
        frag = p.get("FragmentPath", "")
        drop = p.get("DropInPaths", "")
        if not frag and p.get("LoadState") == "loaded":
            self.res.hits.append(Hit(name, "loaded unit without a fragment file cannot be enumerated", edge))
        for path in [frag, *drop.split()]:
            if path and any(path == pp or path.startswith(pp.rstrip("/") + "/") for pp in self.pp):
                self.res.hits.append(Hit(name, f"fragment/drop-in in a protected path ({path})", edge))
        if p["OnSuccess"] or p["OnFailure"]:
            which = "OnFailure" if p["OnFailure"] else "OnSuccess"
            self.res.hits.append(Hit(name, f"uses {which}= ({' '.join(p[which])}): not followed by this resolver (gate C)", f"{name} —{which}→ {' '.join(p[which])}"))
        for k in ("OnSuccessJobMode", "OnFailureJobMode"):
            if p[k] == "isolate":
                self.res.hits.append(Hit(name, f"{k}=isolate: isolate job modes are not handled (gate C)", f"{name} —{k}→ isolate"))
        self.res.frag[name] = {"fragment": frag, "dropins": sorted(drop.split()), "onsuccess": sorted(p["OnSuccess"]), "onfailure": sorted(p["OnFailure"])}

    def closure(self, start: str, keys: tuple, strong_keys: tuple, edge_label: str) -> set:
        """Transitive closure over the given relation keys; every member is checked. Returns the members (without `start`)."""
        seen, todo = set(), [(start, "")]
        while todo:
            u, via = todo.pop()
            p = self.props(u, via, strong=True)
            if p is None:
                continue
            if u not in self.res.frag:
                self.check_member(u, p, via)
            for k in keys:
                for v in p.get(k, []):
                    if v in seen or v == start:
                        continue
                    q = self.props(v, f"{u} —{k}→ {v}", strong=k in strong_keys)
                    if q is None:
                        continue
                    seen.add(v)
                    if len(seen) + len(self.res.members) > MAX_UNITS:
                        self.res.hits.append(Hit(v, "closure too large to enumerate", f"{u} —{k}→ {v}"))
                        return seen
                    todo.append((v, f"{u} —{k}→ {v}"))
        return seen


def resolve(provider: Callable[[str], dict | None], unit: str, action: str, *, job_mode: str, protected_units: tuple, protected_paths: tuple) -> Resolution:
    """All arguments required. `provider(name)` returns the `systemctl show` properties of one unit as {Key: 'value'} (None on failure)."""
    res = Resolution(unit, action)
    if action not in ACTIONS:
        res.hits.append(Hit(unit, f"unknown action {action!r}"))
        return res
    if job_mode not in ALLOWED_JOB_MODES:
        res.hits.append(Hit(unit, f"job mode {job_mode!r} is not allowed (only replace/fail; isolate-like modes are rejected: gate C)"))
        return res
    w = _Walker(provider, tuple(protected_units), tuple(protected_paths), res)
    root = w.props(unit, "requested unit")
    if root is None:
        res.hits.append(Hit(unit, "requested unit is not loaded"))
        return res
    w.check_member(unit, root, "requested unit")

    def start_sets():
        F = w.closure(unit, FORWARD, STRONG, "forward")
        # sockets/timers: whatever they trigger is activated later
        for u in {unit} | F:
            p = w.props(u, "", strong=False)
            if p:
                for t in p.get("Triggers", []):
                    if w.props(t, f"{u} —Triggers→ {t}", strong=False) is not None:
                        F.add(t)
                        F |= w.closure(t, FORWARD, STRONG, "forward")
        members = {unit} | F
        C = set()
        for u in members:
            p = w.props(u, "", strong=False)
            if not p:
                continue
            for v in p.get("Conflicts", []) + p.get("ConflictedBy", []):
                q = w.props(v, f"{u} —Conflicts→ {v}", strong=False)
                if q is not None and q.get("LoadState") == "loaded":
                    C.add(v)
                    w.check_member(v, q, f"{u} —Conflicts→ {v}")
        S = set()
        for c in C:
            S |= w.closure(c, REVERSE_STOP, (), "stop")
        return F, C, S

    def stop_set(u):
        return w.closure(u, REVERSE_STOP, (), "stop")

    if action in ("start", "try-restart", "reload-or-restart"):
        res.F, res.C, res.S = start_sets()
    elif action == "stop":
        res.S = stop_set(unit)
    elif action == "restart":
        res.S = stop_set(unit)
        F, C, S = start_sets()
        res.F, res.C, res.S = F, C, res.S | S
        for u in {unit}:
            p = w.props(u, "", strong=False)
            for v in (p or {}).get("ConsistsOf", []):
                res.X.add(v)
    elif action == "reload":
        p = root
        for v in p.get("PropagatesReloadTo", []):
            if w.props(v, f"{unit} —PropagatesReloadTo→ {v}", strong=False) is not None:
                res.X.add(v)
                w.check_member(v, w.props(v, "", strong=False), f"{unit} —PropagatesReloadTo→ {v}")
    else:                                                         # enable disable mask unmask: boot-time effect + the stop-closure of a running unit
        for k in ("WantedBy", "RequiredBy", "UpheldBy"):
            for v in root.get(k, []):
                q = w.props(v, f"{unit} —{k}→ {v}", strong=False)
                if q is not None:
                    res.X.add(v)
                    w.check_member(v, q, f"{unit} —{k}→ {v}")
        if action in ("disable", "mask"):
            res.S = stop_set(unit)
    # every member found by a closure was checked when it was walked; sets that were filled directly are checked here too
    for name in sorted(res.members):
        if name not in res.frag:
            p = w.props(name, "", strong=False)
            if p:
                w.check_member(name, p, "")
    seen, uniq = set(), []
    for h in res.hits:
        if (h.unit, h.reason, h.edge) not in seen:
            seen.add((h.unit, h.reason, h.edge))
            uniq.append(h)
    res.hits = uniq
    return res


_UNIT = re.compile(r"^(?:-\.(?:mount|slice)|[A-Za-z0-9:_@\\][A-Za-z0-9:_.@\\-]{0,255}\.(?:service|socket|timer|target|mount|path|slice|scope|automount|swap|device))\Z")


def systemctl_provider(systemctl: str, run: Callable) -> Callable[[str], dict | None]:
    """Live provider: `systemctl show` on the live manager (drop-ins, templates and generated units are included). `run(argv, stdin, timeout_s) -> (rc, out, err)` is injected."""
    def provider(name: str):
        if not _UNIT.match(name):
            return None
        rc, out, _ = run([systemctl, "show", "--no-pager", "-p", ",".join(ALL_PROPS), "--", name], None, 20)
        if rc != 0:
            return None
        d = {}
        for line in out.decode("utf-8", "replace").splitlines():
            k, sep, v = line.partition("=")
            if sep:
                d[k] = v
        return d or None
    return provider
