"""systemd transaction resolver (Design 4.3.1): the COMPLETE action-specific transaction of a unit operation, computed from the live unit graph BEFORE authorization.

Starting or restarting a unit does not only touch that unit: systemd also activates dependencies and STOPS units that conflict. The resolver therefore computes, for the requested action,
  F  forward activation closure (Requires, Requisite, BindsTo, Wants, Upholds; transitively) plus what sockets/timers trigger,
  C  every loaded unit named in Conflicts= of a member of F, or carrying a Conflicts= that names a member of F (ConflictedBy),
  S  the stop-closure of C (reverse edges RequiredBy, BoundBy, ConsistsOf, PropagatesStopTo),
  X  action extras (restart propagation, reload propagation, WantedBy/RequiredBy of enable/disable),
and reports a PROTECTED HIT if a member the transaction would CHANGE is in the protected unit set, has a FragmentPath in a protected path, or cannot be fully enumerated (provider error,
missing property): an incomplete resolution is a hit (fail closed). `closure_sha256` binds the COMPLETE resolved sets AND each member's fragment/drop-in/On*= data, so a new drop-in or a new
Conflicts= changes the hash (DENY_CLOSURE_CHANGED until the owner re-signs).

STATE-AWARE EFFECT SET (refinement of the design text, found by the live check on carlgpu2 - see the N3 report): the literal rule 'any member of F is protected' denies EVERY real unit,
because the forward closure of a service reaches sysinit.target, local-fs.target, -.slice ... and even the design's own example forge-edge.service (it `Requires=docker.service`). Starting a
unit does nothing to a dependency that is already active; what a transaction changes is: the requested unit, forward members that are NOT active (they get started), conflicting units that ARE
active (they get stopped) and the active members of the stop-closure. Protected-name/path hits, the 'no fragment' rule and the gate-C rule are evaluated on that effect set; completeness is
required of the whole closure. A protected dependency that is INACTIVE (so the start would start it) is a hit.

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


def split_names(value: str) -> list[str]:
    """Whitespace-separated unit names/paths as `systemctl show` prints them: a name with special characters (every escaped mount unit: opt-kmu\\x2dai.mount) is wrapped in double quotes
    with backslash, double quote, dollar and backtick escaped by a backslash. Malformed quoting yields a token that no unit regex accepts (-> an incomplete resolution), never a guess."""
    out, i, n = [], 0, len(value)
    while i < n:
        if value[i].isspace():
            i += 1
            continue
        tok = []
        if value[i] == '"':
            i += 1
            while i < n and value[i] != '"':
                if value[i] == "\\" and i + 1 < n and value[i + 1] in '\\"$`':
                    tok.append(value[i + 1])
                    i += 2
                else:
                    tok.append(value[i])
                    i += 1
            if i >= n:
                out.append("\x00unterminated")
                break
            i += 1
        else:
            while i < n and not value[i].isspace():
                tok.append(value[i])
                i += 1
        out.append("".join(tok))
    return out


class Incomplete(Exception):
    pass


class _Walker:
    def __init__(self, provider: Callable[[str], dict | None], protected_units: tuple, protected_paths: tuple, res: Resolution):
        self.provider, self.pu, self.pp, self.res = provider, protected_units, protected_paths, res
        self.cache: dict[str, dict | None] = {}
        self.via: dict[str, str] = {}                              # how a unit was reached first (for the edge text of a hit)

    def props(self, name: str, edge: str, strong: bool = True) -> dict | None:
        """Properties of a unit (relation lists split). None = skip (weak edge to a not-found unit); a hit is recorded for anything incomplete."""
        if edge:
            self.via.setdefault(name, edge)
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
            return {"_incomplete": True, "ActiveState": "inactive", **{k: [] for k in REL_PROPS}, "OnSuccess": [], "OnFailure": [], "OnSuccessJobMode": "", "OnFailureJobMode": "",
                    "FragmentPath": "", "DropInPaths": "", "LoadState": "", "Names": [name]}
        if raw.get("LoadState") == "not-found":
            return {"_notfound": True}
        missing = [k for k in ALL_PROPS if k not in raw]
        if missing:
            self.res.hits.append(Hit(name, f"incomplete resolution: systemctl show lacks {missing[:3]}", edge))
            return {"_incomplete": True, "ActiveState": "inactive", **{k: [] for k in REL_PROPS}, "OnSuccess": [], "OnFailure": [], "OnSuccessJobMode": "", "OnFailureJobMode": "",
                    "FragmentPath": "", "DropInPaths": "", "LoadState": "", "Names": [name]}
        p = {k: split_names(raw[k]) for k in REL_PROPS}
        p.update({k: raw[k] for k in META_PROPS + GATE_C_PROPS if k not in ("Names",)})
        p["Names"] = split_names(raw["Names"])
        p["OnSuccess"], p["OnFailure"] = split_names(raw["OnSuccess"]), split_names(raw["OnFailure"])
        p["DropInPaths"] = " ".join(split_names(raw["DropInPaths"]))
        return p

    def is_active(self, name: str) -> bool:
        """Will the transaction leave this unit alone / is there something to stop? activating and reloading units count as active; anything unknown does not (fail closed)."""
        p = self.cache.get(name)
        return bool(p) and not p.get("_notfound") and not p.get("_incomplete") and p.get("ActiveState") in ("active", "activating", "reloading")

    def record(self, name: str, p: dict) -> None:
        """What goes into closure_sha256 for a member (whether or not the transaction changes it)."""
        if not p.get("_incomplete"):
            self.res.frag[name] = {"fragment": p.get("FragmentPath", ""), "dropins": sorted(p.get("DropInPaths", "").split()), "onsuccess": sorted(p["OnSuccess"]), "onfailure": sorted(p["OnFailure"])}

    def check_effect(self, name: str, why: str) -> None:
        """Hits for a member the transaction would CHANGE: protected name or path, a loaded unit without any fragment, gate C (On*= / isolate job modes)."""
        edge = f"{self.via[name]}; {why}" if name in self.via else why
        p = self.cache.get(name)
        if not p or p.get("_incomplete") or p.get("_notfound"):
            return
        for n in [name, *p.get("Names", [])]:
            g = next((g for g in self.pu if fnmatchcase(n, g)), None)
            if g:
                self.res.hits.append(Hit(name, f"protected unit ({g})", edge))
                break
        frag, drop = p.get("FragmentPath", ""), p.get("DropInPaths", "")
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

    def closure(self, start: str, keys: tuple, strong_keys: tuple) -> set:
        """Transitive closure over the given relation keys. Returns the members (without `start`); every member is loaded (completeness) and recorded for the hash."""
        seen, todo = set(), [(start, "")]
        while todo:
            u, via = todo.pop()
            p = self.props(u, via, strong=True)
            if p is None:
                continue
            self.record(u, p)
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
    w.record(unit, root)

    def start_sets():
        F = w.closure(unit, FORWARD, STRONG)
        for u in {unit} | F:                                       # sockets/timers: whatever they trigger is activated later
            p = w.props(u, "", strong=False)
            if p:
                for t in p.get("Triggers", []):
                    if w.props(t, f"{u} —Triggers→ {t}", strong=False) is not None:
                        F.add(t)
                        F |= w.closure(t, FORWARD, STRONG)
        C = set()
        for u in {unit} | F:
            p = w.props(u, "", strong=False)
            if not p:
                continue
            for v in p.get("Conflicts", []) + p.get("ConflictedBy", []):
                q = w.props(v, f"{u} —Conflicts→ {v}", strong=False)
                if q is not None and q.get("LoadState") == "loaded":
                    C.add(v)
                    w.record(v, q)
        S = set()
        for c in C:
            S |= w.closure(c, REVERSE_STOP, ())
        return F, C, S

    effect: dict[str, str] = {}                                    # member -> why the transaction changes it (the edge text of the hit)

    def mark(names, why, only_active=None):
        for n in names:
            if only_active is None or w.is_active(n) == only_active:
                effect.setdefault(n, why)

    if action in ("start", "try-restart", "reload-or-restart"):
        res.F, res.C, res.S = start_sets()
        mark({unit}, "requested unit")
        mark(res.F, "would be started (inactive dependency)", only_active=False)
        mark(res.C, "would be stopped (conflict)", only_active=True)
        mark(res.S, "would be stopped (stop-closure of a conflict)", only_active=True)
    elif action == "stop":
        res.S = w.closure(unit, REVERSE_STOP, ())
        mark({unit}, "requested unit")
        mark(res.S, "would be stopped (stop-closure)", only_active=True)
    elif action == "restart":
        stop = w.closure(unit, REVERSE_STOP, ())
        F, C, S = start_sets()
        res.F, res.C, res.S = F, C, stop | S
        res.X = set(root.get("ConsistsOf", []))
        for v in res.X:
            q = w.props(v, f"{unit} —ConsistsOf→ {v}", strong=False)
            if q is not None:
                w.record(v, q)
        mark({unit}, "requested unit")
        mark(F, "would be started (inactive dependency)", only_active=False)
        mark(C, "would be stopped (conflict)", only_active=True)
        mark(res.S, "would be stopped/restarted (stop-closure)", only_active=True)
        mark(res.X, "restarted with it (PartOf)", only_active=True)
    elif action == "reload":
        for v in root.get("PropagatesReloadTo", []):
            q = w.props(v, f"{unit} —PropagatesReloadTo→ {v}", strong=False)
            if q is not None:
                res.X.add(v)
                w.record(v, q)
        mark({unit}, "requested unit")
        mark(res.X, "reloaded with it", only_active=True)
    else:                                                          # enable disable mask unmask: boot-time effect + the stop-closure of a running unit
        for k in ("WantedBy", "RequiredBy", "UpheldBy"):
            for v in root.get(k, []):
                q = w.props(v, f"{unit} —{k}→ {v}", strong=False)
                if q is not None:
                    res.X.add(v)
                    w.record(v, q)
        mark({unit}, "requested unit")
        mark(res.X, "its boot-time start set changes", only_active=None)
        if action in ("disable", "mask"):
            res.S = w.closure(unit, REVERSE_STOP, ())
            mark(res.S, "would be stopped (stop-closure)", only_active=True)
    for name in sorted(effect):
        w.check_effect(name, effect[name])
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
