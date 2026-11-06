"""The complete policy schema (Design 7.1) as enforced by `privd policy.apply` and by every privd gate() call. The agent's view (t0/policy.py) reads only the fields it needs; this module
validates EVERYTHING and returns the normalized object privd works from. Rules enforced at apply time (7.1):

  * any op or key matching apt*apply*/apt_apply/upgrade* anywhere in the document: whole policy rejected (4.3, OQ-12);
  * ops that are not in this release's op table for the profile: rejected (the policy can only enable/disable compiled-in entries);
  * every forge_roots[] entry needs quota_backend "loop_fs", a backing_image on the ROOT filesystem and never on/under a protected path or mount, and a size; a forge root never
    lies on/under/over a protected path ("/srv/models and /srv/kmu-ai are protected as whole mounts; there is no forge subtree exception");
  * t1.workloads_enabled:true without such a root: rejected; gated features (gates.policy_gate_violations with THIS node's gates): rejected;
  * every unit.* target needs closure_sha256; t3.opaque_enabled:true is rejected for profile t0; profile t0 enables tier 0 only.
Unknown keys at any level are rejected: the schema is closed."""
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from .. import canon, gates
from ..t0.policy import PolicyError, PolicyView, parse_policy

BUILTIN_PROTECTED_PATHS = ("/srv/models", "/srv/kmu-ai", "/opt/kmu-ai", "/etc/forge-node", "/etc/ssh", "/etc/sudoers", "/etc/sudoers.d", "/root", "/var/lib/forge-node-priv",
                           "/var/log/forge-node-priv", "/var/log/forge-node-agent")
BUILTIN_PROTECTED_UNITS = ("kmu-*", "tradebot-*", "secmpro*", "nexus*", "ollama.service", "ssh.service", "sshd.service", "docker.service", "containerd.service", "forge-node-*")
APT_RE = re.compile(r"^(apt|apt-get|aptitude|dist-upgrade|upgrades?)([._-]|$)|apt[._-]?apply|[._-]upgrade(s|d)?\Z", re.I)
_TOP = {"schema", "serial", "not_before", "node", "profile", "global_mode", "tiers_enabled", "hub_tls_pins", "hub_gate_keys", "protected", "forge_roots", "t0", "t1", "t2", "t3", "windows",
        "redaction_version", "circuit"}
_PROT = {"paths", "units", "containers", "networks", "ports", "users", "gpu"}
_ROOT = {"path", "quota_backend", "backing_image", "size_bytes", "log_budget_bytes", "min_free_bytes"}
_T1 = {"label_selector", "stack_roots", "lint", "workloads_enabled", "vram_budget_mib", "vm_pool", "ops"}
_T0 = {"units_for_logs", "cert_paths", "backup_units", "backup_dirs", "repos", "model_dirs"}
_WINDOWS = {"blackout", "sunday_open"}
_T2 = {"ops"}
_T3 = {"manifests_enabled", "opaque_enabled"}
_OPCFG = {"op", "mode", "requires", "rate", "window", "targets"}
_TARGET = {"name", "action", "closure_sha256"}
_HEX64 = re.compile(r"^[0-9a-f]{64}\Z")
MODES = ("dry_run_only", "enforce")
REQUIRES = ("none", "owner_signature")
MAX_OPS = 64


@dataclass(frozen=True)
class OpPolicy:
    op: str
    tier: int
    mode: str
    requires: str
    rate: tuple[tuple[int, int], ...]          # (max events, window seconds); empty = the op table default
    targets: tuple[dict, ...]


@dataclass(frozen=True)
class ForgeRoot:
    path: str
    backing_image: str
    size_bytes: int
    log_budget_bytes: int
    min_free_bytes: int


@dataclass(frozen=True)
class FullPolicy:
    view: PolicyView
    raw_sha256: str
    ops: dict                                   # op name -> OpPolicy (T1 and T2 entries)
    forge_roots: tuple[ForgeRoot, ...]
    protected_paths: tuple[str, ...]            # builtin floor + policy
    protected_units: tuple[str, ...]
    workloads_enabled: bool
    t3_manifests: tuple[str, ...]
    opaque_enabled: bool
    circuit_threshold: int

    @property
    def serial(self) -> int:
        return self.view.serial

    @property
    def profile(self) -> str:
        return self.view.profile

    @property
    def global_mode(self) -> str:
        return self.view.global_mode

    @property
    def tiers(self) -> tuple[int, ...]:
        return self.view.tiers_enabled


def _bad(msg: str):
    raise PolicyError("DENY_POLICY_INVALID", msg)


def _scan_apt(o, path="policy", op_context=False):
    """Keys everywhere; string VALUES only where they name an op or a manifest kind (a log unit called unattended-upgrades.service is legitimate: inv.pkgs reports on it)."""
    if isinstance(o, dict):
        for k, v in o.items():
            if isinstance(k, str) and APT_RE.search(k):
                _bad(f"{path}.{k}: apt apply / upgrade is not available (OQ-12)")
            _scan_apt(v, f"{path}.{k}", op_context=(k == "op" and isinstance(v, str)) or k in ("ops", "manifests_enabled"))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            _scan_apt(v, f"{path}[{i}]", op_context)
    elif isinstance(o, str) and op_context and APT_RE.search(o):
        _bad(f"{path}: apt apply / upgrade is not available (OQ-12)")


def _closed(d, allowed: set, what: str):
    if not isinstance(d, dict):
        _bad(f"{what} must be an object")
    extra = set(d) - allowed
    if extra:
        _bad(f"{what}: unknown keys {sorted(extra)}")


def _t1_shapes(t1: dict) -> None:
    """The T1 workload fields have no executable meaning before N5; until then they are accepted only in a bounded, typed form (never an open-ended blob a later slice would have to
    guess the meaning of)."""
    if "label_selector" in t1 and (not isinstance(t1["label_selector"], str) or not re.match(r"^[A-Za-z0-9._/-]{1,128}\Z", t1["label_selector"])):
        _bad("t1.label_selector must be a label name")
    if "stack_roots" in t1:
        sr = t1["stack_roots"]
        if not isinstance(sr, list) or len(sr) > 16:
            _bad("t1.stack_roots must be a list of at most 16 paths")
        for i, p in enumerate(sr):
            _norm_abs(p, f"t1.stack_roots[{i}]")
    if "vram_budget_mib" in t1 and (isinstance(t1["vram_budget_mib"], bool) or not isinstance(t1["vram_budget_mib"], int) or not 0 <= t1["vram_budget_mib"] <= 1 << 20):
        _bad("t1.vram_budget_mib must be 0..1048576")
    for k in ("lint", "vm_pool"):
        if k in t1:
            o = t1[k]
            if not isinstance(o, dict) or len(o) > 32 or any(not isinstance(a, str) or not re.match(r"^[a-z][a-z0-9_]{0,63}\Z", a) or isinstance(b, (dict, list)) or isinstance(b, str) and len(b) > 256
                                                              or isinstance(b, float) for a, b in o.items()):
                _bad(f"t1.{k} must be a flat object of at most 32 scalar settings")


def _under(path: str, base: str) -> bool:
    return path == base or path.startswith(base.rstrip("/") + "/")


def _overlaps(a: str, b: str) -> bool:
    return _under(a, b) or _under(b, a)


def _norm_abs(p, what: str) -> str:
    if not isinstance(p, str) or not p.startswith("/") or "\x00" in p or p != re.sub(r"/+", "/", p) or p.endswith("/") and p != "/" or ".." in p.split("/") or "." in p.split("/") or p == "/":
        _bad(f"{what}: must be a normalized absolute path (not '/')")
    return p


def _rate(v, what):
    if v is None:
        return ()
    if not isinstance(v, list) or len(v) > 4:
        _bad(f"{what}: rate must be a list of at most 4 [max, window_s] pairs")
    out = []
    for x in v:
        if (not isinstance(x, list) or len(x) != 2 or any(isinstance(i, bool) or not isinstance(i, int) for i in x) or not 1 <= x[0] <= 10_000 or not 1 <= x[1] <= 7 * 86400):
            _bad(f"{what}: rate entries are [max 1..10000, window_s 1..604800]")
        out.append((x[0], x[1]))
    return tuple(out)


def _op_cfg(x, tier: int, table_ops: frozenset, g) -> OpPolicy:
    if isinstance(x, str):
        x = {"op": x}
    _closed(x, _OPCFG, f"t{tier}.ops[]")
    op = x.get("op")
    if not isinstance(op, str) or op not in gates.OPS:
        _bad(f"t{tier}.ops: unknown op {op!r}")
    if gates.OPS[op].tier != tier:
        _bad(f"t{tier}.ops: {op} is a tier {gates.OPS[op].tier} op")
    if op not in table_ops:
        _bad(f"t{tier}.ops: {op} is not in this release's op table for the profile")
    mode = x.get("mode", "dry_run_only")
    req = x.get("requires", "owner_signature" if tier >= 3 else "none")
    if mode not in MODES or req not in REQUIRES:
        _bad(f"t{tier}.ops[{op}]: mode/requires invalid")
    targets = x.get("targets", [])
    if not isinstance(targets, list) or len(targets) > 64:
        _bad(f"t{tier}.ops[{op}].targets must be a list")
    tt = []
    for t in targets:
        _closed(t, _TARGET, f"t{tier}.ops[{op}].targets[]")
        if not isinstance(t.get("name"), str) or not t["name"] or len(t["name"]) > 128:
            _bad(f"t{tier}.ops[{op}].targets: name required")
        if op.startswith("unit.") and not _HEX64.match(str(t.get("closure_sha256", ""))):
            _bad(f"t{tier}.ops[{op}].targets[{t['name']}]: every unit.* target needs closure_sha256 (privctl unit-closure)")
        tt.append(dict(t))
    return OpPolicy(op, tier, mode, req, _rate(x.get("rate"), f"{op}"), tuple(tt))


def parse_full(raw: bytes, *, expect_node: str, file_serial: int, now: datetime, gates_map, table_ops: Callable[[str], frozenset], devof: Callable[[str], int | None],
               protected_devs: Callable[[], set]) -> FullPolicy:
    """Strict parse + all apply-time rules. `table_ops(profile)` = op names in the release's op table; `devof(path)` = st_dev of an existing path (None if absent);
    `protected_devs()` = devices of the protected mounts. All required: there is no way to skip a rule by omitting an argument."""
    view = parse_policy(raw, expect_node, file_serial, now, gates_map)             # signature is checked by the caller; this validates the fields the agent also uses + gate rules
    doc = canon.loads(raw)
    _closed(doc, _TOP, "policy")
    _scan_apt(doc)
    profile = view.profile
    tops = table_ops(profile)
    prot = doc.get("protected", {})
    _closed(prot, _PROT, "protected")
    for k in ("containers", "networks", "users", "gpu"):
        v = prot.get(k, [])
        if not isinstance(v, list) or len(v) > 256 or any(not isinstance(i, str) or not i or len(i) > 128 for i in v):
            _bad(f"protected.{k} must be a list of strings")
    ports = prot.get("ports", [])
    if not isinstance(ports, list) or len(ports) > 256 or any(isinstance(p, bool) or not isinstance(p, int) or not 1 <= p <= 65535 for p in ports):
        _bad("protected.ports must be a list of port numbers")
    prot_paths = tuple(sorted(set(BUILTIN_PROTECTED_PATHS) | set(view.protected_paths)))
    prot_units = tuple(sorted(set(BUILTIN_PROTECTED_UNITS) | set(view.protected_units)))
    # forge roots
    roots_raw = doc.get("forge_roots", [])
    if not isinstance(roots_raw, list) or len(roots_raw) > 4:
        _bad("forge_roots must be a list of at most 4")
    roots = []
    rootdev = devof("/")
    pdevs = protected_devs()
    for r in roots_raw:
        _closed(r, _ROOT, "forge_roots[]")
        if r.get("quota_backend") != "loop_fs":
            _bad("forge_roots[]: quota_backend must be loop_fs (kernel-enforced allocation)")
        path = _norm_abs(r.get("path"), "forge_roots[].path")
        img = _norm_abs(r.get("backing_image"), "forge_roots[].backing_image")
        for k in ("size_bytes", "log_budget_bytes", "min_free_bytes"):
            v = r.get(k)
            if isinstance(v, bool) or not isinstance(v, int) or v < 0 or v > 2 ** 50 or (k == "size_bytes" and v < 1 << 20):
                _bad(f"forge_roots[].{k} invalid")
        for pp in prot_paths:
            if _overlaps(path, pp) or _under(img, pp):
                _bad(f"forge_roots: {path} / {img} touch the protected path {pp} (no forge subtree exception)")
        for other in roots:
            if _overlaps(path, other.path):
                _bad("forge_roots overlap")
        d = devof(img)
        if d is None or rootdev is None or d != rootdev:
            _bad("forge_roots[].backing_image must exist on the root filesystem")
        if d in pdevs:
            _bad("forge_roots[].backing_image is on a protected device")
        roots.append(ForgeRoot(path, img, r["size_bytes"], r["log_budget_bytes"], r["min_free_bytes"]))
    if profile == "t0" and roots:
        _bad("profile t0 has no forge roots")
    _closed(doc.get("t0", {}), _T0, "t0")
    _closed(doc.get("windows", {}), _WINDOWS, "windows")
    t1 = doc.get("t1", {})
    _closed(t1, _T1, "t1")
    _t1_shapes(t1)
    wl = t1.get("workloads_enabled", False)
    if not isinstance(wl, bool):
        _bad("t1.workloads_enabled must be a boolean")
    if wl and not roots:
        _bad("t1.workloads_enabled:true needs a forge root on a loop-backed filesystem")
    t2 = doc.get("t2", {})
    _closed(t2, _T2, "t2")
    t3 = doc.get("t3", {})
    _closed(t3, _T3, "t3")
    ops: dict[str, OpPolicy] = {}
    for tier, items in ((1, t1.get("ops", [])), (2, t2.get("ops", []))):
        if not isinstance(items, list) or len(items) > MAX_OPS:
            _bad(f"t{tier}.ops must be a list of at most {MAX_OPS}")
        for x in items:
            o = _op_cfg(x, tier, tops, gates_map)
            if o.op in ops:
                _bad(f"duplicate op {o.op}")
            ops[o.op] = o
    if profile == "t0" and (ops or view.tiers_enabled != (0,) or wl or t1.get("vm_pool") or t3.get("manifests_enabled") or t3.get("opaque_enabled")):
        _bad("profile t0 enables tier 0 only")
    if ops and not set(o.tier for o in ops.values()) <= set(view.tiers_enabled):
        _bad("an op is configured for a tier that is not in tiers_enabled")
    manifests = t3.get("manifests_enabled", [])
    if not isinstance(manifests, list) or any(m not in gates.MANIFEST_KINDS for m in manifests):
        _bad("t3.manifests_enabled: unknown manifest kind")
    if t3.get("opaque_enabled", False) not in (True, False):
        _bad("t3.opaque_enabled must be a boolean")
    circuit = doc.get("circuit", {})
    _closed(circuit, {"fail_threshold"}, "circuit")
    thr = circuit.get("fail_threshold", 3)
    if isinstance(thr, bool) or not isinstance(thr, int) or not 1 <= thr <= 10:
        _bad("circuit.fail_threshold must be 1..10")
    rv = doc.get("redaction_version", None)
    if rv is not None and (isinstance(rv, bool) or not isinstance(rv, int) or rv < 1):
        _bad("redaction_version invalid")
    return FullPolicy(view, view.sha256, ops, tuple(roots), prot_paths, prot_units, wl, tuple(manifests), bool(t3.get("opaque_enabled", False)), thr)
