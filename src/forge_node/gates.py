"""Feature-Gates a)-d) (Betriebsleiter-Entscheid zu ADR-016/026, Vermerk nach REPORT_BRIEF_forge-nodedesignverify3, d50f2b4).

Das Design ist fuer den T0-Pfad (nur lesen) freigegeben. Die vier offenen MAJOR sind verpflichtende Abnahmekriterien der Slices, die die betroffenen Funktionen freischalten;
bis dahin sind diese Funktionen in Code UND Policy ausgeschaltet. Dieses Modul ist die einzige Stelle, die das im Code festhaelt:

  * Der Hub signiert keinen Job fuer eine Operation mit nicht erfuelltem Gate (decide()).
  * Die Policy-Validierung (N3) ruft policy_gate_violations() und lehnt eine Policy ab, die ausgeschaltete Funktionen einschaltet.
  * `met` ist eine Code-Konstante: keine Umgebungsvariable, keine Policy, kein Hub-Endpunkt kann ein Gate oeffnen. Ein Gate wird nur in dem Commit geoeffnet, der
    die unter `required_tests` genannten Tests liefert und gruen hat (Review G6); test_gates.py haelt den Ist-Stand fest.
"""
from dataclasses import dataclass
from types import MappingProxyType

from .protocol import ProtoError


@dataclass(frozen=True)
class Gate:
    id: str
    title: str
    slice: str
    met: bool
    acceptance: str
    required_tests: tuple[str, ...]


GATE_A, GATE_B, GATE_C, GATE_D = "A", "B", "C", "D"

GATES = MappingProxyType({
    GATE_A: Gate(
        GATE_A, "workload volumes host-visible", "N5", False,
        "Per-workload (and the forge root) loop volumes are mounted by systemd mount units or an equivalent mechanism whose mounts live in the HOST mount namespace, not in the "
        "private namespace of a transient op unit; verified from the host and from Docker (bind source) after the worker unit has exited. volume.create and every workload-start op "
        "(container.start|restart|recreate, stack.up, selftest.fill) stay disabled until then. Mountpoint guard (chattr +i while unmounted) applies to EVERY registered target volume, not only the forge root.",
        ("test_volume_mount_visible_on_host_after_worker_exit", "test_volume_mount_visible_to_docker_after_worker_exit",
         "test_volume_mount_survives_worker_unit_and_privd_restart", "test_volumes_remounted_at_boot_before_stack_start",
         "test_unmounted_mountpoint_is_immutable_for_every_registered_volume", "test_workload_start_ops_denied_until_gate_a")),
    GATE_B: Gate(
        GATE_B, "VM logging hard-bounded", "N9", False,
        "VM log growth is bounded by a mechanism that is in force continuously (e.g. virtlogd max_size/max_backups), not by a periodic logrotate that leaves a window; proven by a "
        "continuous log-flood test against a running domain. vm.define and vm.start stay disabled until then.",
        ("test_vm_log_flood_continuous_stays_within_budget", "test_vm_start_denied_until_gate_b", "test_vm_log_budget_counted_in_log_budget_bytes")),
    GATE_C: Gate(
        GATE_C, "unit resolver handles OnSuccess=/OnFailure= and isolate job modes", "N3 (resolver) / N6 (T2 units) / N7 (T3 unit_action)", False,
        "The systemd transaction resolver rejects any unit (and any member of its closure) that uses OnSuccess=/OnFailure= or an isolate job mode until it follows those edges "
        "recursively and binds them into closure_sha256. All unit ops (unit.*, scene.switch, agent.restart, T3 unit_action) stay disabled until then.",
        ("test_t2_unit_with_onsuccess_in_closure_denied", "test_t2_unit_with_onfailure_in_closure_denied", "test_t2_unit_isolate_job_mode_denied",
         "test_resolver_follows_onsuccess_onfailure_recursively_and_binds_closure_sha256", "test_t3_unit_with_onfailure_requires_frozen_ack_and_bound_closure",
         "test_t3_unit_isolate_requires_frozen_ack_and_bound_closure")),
    GATE_D: Gate(
        GATE_D, "audit sealing protocol for append-only logs", "N3", False,
        "A workable seal/rotation protocol for chattr +a log files: no fchmod/chmod/chown on append-only inodes (the kernel refuses them with EPERM); open descriptors held by a writer "
        "across a rotation are handled (a sealed file cannot receive further appends through a descriptor opened earlier); verified with REAL rotation on ext4 with chattr +a and "
        "live writer processes, and with crash recovery (kill -9 at every rotation step). No mutating op (any tier >= 1) is enabled before this is met.",
        ("test_rotation_real_ext4_chattr_a_live_writer_descriptor_cannot_append_after_seal", "test_seal_never_calls_chmod_on_append_only_inode",
         "test_rotation_crash_recovery_kill_at_every_step", "test_rotation_has_no_writable_window_on_live_file", "test_mutating_ops_denied_until_gate_d")),
})
GATE_ORDER = (GATE_D, GATE_A, GATE_B, GATE_C)


@dataclass(frozen=True)
class OpSpec:
    tier: int
    mutating: bool
    gates: frozenset = frozenset()
    full_only: bool = False


def _ops():
    d: dict[str, OpSpec] = {}
    for n in "host disks gpu net units containers vms pkgs certs backups git access usage models".split():
        d[f"inv.{n}"] = OpSpec(0, False)
    d["metrics.sample"] = OpSpec(0, False)
    d["logs.unit"] = OpSpec(0, False)
    for n in "stop rm".split():
        d[f"container.{n}"] = OpSpec(1, True)
    for n in "start restart recreate".split():
        d[f"container.{n}"] = OpSpec(1, True, frozenset({GATE_A}))
    d["stack.put"] = OpSpec(1, True)
    d["stack.down"] = OpSpec(1, True)
    d["stack.up"] = OpSpec(1, True, frozenset({GATE_A}))
    for n in "create grow destroy".split():
        d[f"volume.{n}"] = OpSpec(1, True, frozenset({GATE_A}))
    for n, m in (("ensure", True), ("du", False), ("trash", True), ("purge_trash", True)):
        d[f"dir.{n}"] = OpSpec(1, m)
    d["file.put"] = OpSpec(1, True)
    d["file.get"] = OpSpec(1, False)
    for n in "define start".split():
        d[f"vm.{n}"] = OpSpec(1, True, frozenset({GATE_B}))
    for n in "shutdown destroy".split():
        d[f"vm.{n}"] = OpSpec(1, True)
    d["selftest.noop"] = OpSpec(1, True, full_only=True)
    d["selftest.fill"] = OpSpec(1, True, frozenset({GATE_A}), full_only=True)
    for n in "start stop restart".split():
        d[f"unit.{n}"] = OpSpec(2, True, frozenset({GATE_C}))
    d["scene.switch"] = OpSpec(2, True, frozenset({GATE_C}))
    d["agent.restart"] = OpSpec(2, True, frozenset({GATE_C}))
    for n in ("docker.prune_plan", "docker.prune_apply", "image.pin", "policy.apply", "ledger.resolve"):
        d[n] = OpSpec(2, True)
    d["t3.exec"] = OpSpec(3, True)
    return d


OPS = MappingProxyType(_ops())
# T3-Manifest-Arten (Design 4.6) -> zusaetzlich verlangte Gates. Unbekannte Arten werden abgelehnt.
MANIFEST_KINDS = MappingProxyType({
    "unit_action": frozenset({GATE_C}),
    "container_action": frozenset(),
    "file_replace": frozenset(),
    "dir_remove": frozenset(),
    "package_install": frozenset(),
    "firewall_apply": frozenset(),
    "policy_replace_trust": frozenset(),
    "opaque": frozenset(),
})
# Jede Operation ab T1 verlangt Gate D (kein veraendernder Op vor dem Audit-Siegel-Protokoll). Nicht-veraendernde T1-Lesezugriffe (dir.du, file.get) laufen mit,
# weil sie nur auf Forge-Root-Volumes arbeiten, die erst mit N5 existieren.
TIER_GATES = MappingProxyType({0: frozenset(), 1: frozenset({GATE_D}), 2: frozenset({GATE_D}), 3: frozenset({GATE_D})})


@dataclass(frozen=True)
class Decision:
    allowed: bool
    code: str | None = None      # Reason-Code aus Design 3.2
    detail: str = ""


def required_gates(op: str, params: dict | None = None) -> frozenset:
    spec = OPS[op]
    g = set(spec.gates) | set(TIER_GATES[spec.tier])
    if op == "t3.exec":
        kind = (params or {}).get("kind")
        g |= set(MANIFEST_KINDS.get(kind, ()))
    return frozenset(g)


def unmet(gates_needed, gates=GATES) -> list[str]:
    return [g for g in GATE_ORDER if g in gates_needed and not gates[g].met]


def decide(op: str, tier: int, profile: str, params: dict | None = None, gates=GATES) -> Decision:
    """Hub-Entscheid vor dem Signieren. Der Node entscheidet unabhaengig noch einmal (privd gate())."""
    spec = OPS.get(op)
    if spec is None:
        return Decision(False, "DENY_OP_UNKNOWN", f"unknown op {op!r}")
    if tier != spec.tier:
        return Decision(False, "DENY_PARAM", f"op {op} is tier {spec.tier}, job says {tier}")
    if profile not in ("full", "t0"):
        return Decision(False, "DENY_POLICY_INVALID", "unknown node profile")
    if profile == "t0" and (spec.tier > 0 or spec.full_only):
        return Decision(False, "DENY_TIER_DISABLED", f"op {op} is not part of the t0 profile")
    if spec.full_only and profile != "full":
        return Decision(False, "DENY_TIER_DISABLED", f"op {op} exists only in the full profile")
    if op == "t3.exec":
        kind = (params or {}).get("kind")
        if kind not in MANIFEST_KINDS:
            return Decision(False, "DENY_PARAM", "unknown T3 manifest kind")
    need = unmet(required_gates(op, params), gates)
    if need:
        g = gates[need[0]]
        return Decision(False, "DENY_TIER_DISABLED", f"gate {g.id} unmet ({g.title}); enabled by slice {g.slice}")
    return Decision(True)


def require(op: str, tier: int, profile: str, params: dict | None = None, gates=GATES) -> None:
    d = decide(op, tier, profile, params, gates)
    if not d.allowed:
        raise ProtoError(d.code, d.detail)


def _ops_in(policy: dict, *path) -> list[str]:
    cur = policy
    for p in path:
        cur = cur.get(p) if isinstance(cur, dict) else None
    out = []
    if isinstance(cur, list):
        for x in cur:
            if isinstance(x, str):
                out.append(x)
            elif isinstance(x, dict) and isinstance(x.get("op"), str):
                out.append(x["op"])
    return out


def policy_gate_violations(policy: dict, gates=GATES) -> list[str]:
    """Von der Policy-Validierung (N3, privd/privctl policy.apply) aufzurufen: Liste der Stellen, an denen eine signierte Policy eine noch gesperrte Funktion einschaltet.
    Leer = ok. Die Policy kann keine Gates oeffnen - sie kann nur Dinge nicht einschalten, die ein Gate sperrt."""
    v: list[str] = []
    if not isinstance(policy, dict):
        return ["policy is not an object"]
    tiers = policy.get("tiers_enabled", [])
    if not isinstance(tiers, list):
        return ["tiers_enabled is not a list"]
    for t in tiers:
        if t in TIER_GATES and unmet(TIER_GATES[t], gates):
            v.append(f"tiers_enabled contains {t} while gate {unmet(TIER_GATES[t], gates)[0]} is unmet")
    t1 = policy.get("t1") if isinstance(policy.get("t1"), dict) else {}
    if t1.get("workloads_enabled") is True and unmet({GATE_A}, gates):
        v.append("t1.workloads_enabled=true while gate A (workload volumes host-visible) is unmet")
    if t1.get("vm_pool") and unmet({GATE_B}, gates):
        v.append("t1.vm_pool set while gate B (VM logging bounded) is unmet")
    named = _ops_in(policy, "t1", "ops") + _ops_in(policy, "t2", "ops")
    for op in named:
        if op not in OPS:
            v.append(f"unknown op {op!r}")
            continue
        need = unmet(required_gates(op), gates)
        if need:
            v.append(f"op {op} enabled while gate {need[0]} is unmet")
    t3 = policy.get("t3") if isinstance(policy.get("t3"), dict) else {}
    for kind in t3.get("manifests_enabled", []) if isinstance(t3.get("manifests_enabled"), list) else []:
        if kind not in MANIFEST_KINDS:
            v.append(f"unknown T3 manifest kind {kind!r}")
        elif unmet(MANIFEST_KINDS[kind] | TIER_GATES[3], gates):
            v.append(f"t3.manifests_enabled contains {kind} while gate {unmet(MANIFEST_KINDS[kind] | TIER_GATES[3], gates)[0]} is unmet")
    if t3.get("opaque_enabled") is True and unmet(TIER_GATES[3], gates):
        v.append("t3.opaque_enabled=true while gate D is unmet")
    return v
