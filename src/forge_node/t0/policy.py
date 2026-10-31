"""The node's view of its installed, owner-signed policy (Design 7.1, 7.3, 5.3).

Installing a policy is `privd policy.apply` (N3). Everything that RUNS under a policy - the agent and the root `ro-probe` programs - re-verifies the installed file itself instead of
trusting its location: signature (namespace forge-node-policy, owner key from allowed_signers), node, serial = file name, not_before, and the gate rules. The agent uses the policy for
exactly three things: the hub trust values (pins, gate keys), the T0 allowlists, and the windows. The complete schema validation (forge_roots, t2 ops, apt rules, ...) belongs to the
installer in N3; this loader additionally refuses any policy that switches on a gated feature (gates.policy_gate_violations), so a policy the future validator would reject cannot start work here."""
import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime

from .. import canon, gates, protocol, sshsig
from ..protocol import ProtoError
from . import window as window_mod
from .fsread import FsError, norm_abs

OWNER_PRINCIPAL = "owner@forge"
MAX_POLICY_BYTES = 256 * 1024
_NAME = re.compile(r"^policy-([1-9][0-9]{0,8})\.json\Z")
_UNIT_NAME = re.compile(r"^[A-Za-z0-9:_.@\\-]{1,128}\.(?:service|timer|socket|mount|target|path)\Z")
_UNIT_GLOB = re.compile(r"^[A-Za-z0-9:_.@\\*?-]{1,128}\Z")
_CUSTOMER_UNITS = ("kmu-*", "tradebot-*", "secmpro*", "nexus*")
MAX_LIST = 64


class PolicyError(Exception):
    """code is a design reason code (DENY_POLICY_INVALID, DENY_CLOCK, ...)."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


@dataclass(frozen=True)
class LogUnit:
    unit: str
    sensitivity: str = "internal"


@dataclass(frozen=True)
class T0Policy:
    units_for_logs: tuple[LogUnit, ...] = ()
    cert_paths: tuple[str, ...] = ()
    backup_units: tuple[str, ...] = ()
    backup_dirs: tuple[str, ...] = ()
    repos: tuple[str, ...] = ()
    model_dirs: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyView:
    serial: int
    sha256: str
    node: str
    profile: str
    global_mode: str
    tiers_enabled: tuple[int, ...]
    hub_tls_pins: tuple[str, ...]
    hub_gate_keys: dict = field(compare=False)
    protected_paths: tuple[str, ...]
    protected_units: tuple[str, ...]
    t0: T0Policy
    window: window_mod.Window

    def log_unit(self, unit: str) -> LogUnit | None:
        for lu in self.t0.units_for_logs:
            if lu.unit == unit:
                return lu
        return None


def _bad(msg: str):
    raise PolicyError("DENY_POLICY_INVALID", msg)


def _str_list(v, what, rx=None, maxlen=256):
    if v is None:
        return ()
    if not isinstance(v, list) or len(v) > MAX_LIST:
        _bad(f"{what} must be a list of at most {MAX_LIST}")
    for x in v:
        if not isinstance(x, str) or not x or len(x) > maxlen or (rx is not None and not rx.match(x)):
            _bad(f"{what}: invalid entry")
    return tuple(v)


def _paths(v, what):
    out = _str_list(v, what, maxlen=4096)
    norm = []
    for p in out:
        try:
            n = norm_abs(p)
        except FsError:
            _bad(f"{what}: not an absolute path")
        if n != p or n == "/" or ".." in p.split("/"):
            _bad(f"{what}: path must be normalized and not the root: {p!r}")
        norm.append(n)
    return tuple(norm)


def _log_units(v, protected_units) -> tuple[LogUnit, ...]:
    if v is None:
        return ()
    if not isinstance(v, list) or len(v) > MAX_LIST:
        _bad("t0.units_for_logs must be a list")
    out = []
    from fnmatch import fnmatchcase
    for x in v:
        if isinstance(x, str):
            lu = LogUnit(x, "internal")
        elif isinstance(x, dict) and set(x) <= {"unit", "sensitivity"} and "unit" in x:
            lu = LogUnit(x["unit"], x.get("sensitivity", "internal"))
        else:
            _bad("t0.units_for_logs: entry must be a unit name or {unit, sensitivity}")
        if not isinstance(lu.unit, str) or not _UNIT_NAME.match(lu.unit):
            _bad("t0.units_for_logs: invalid unit name")
        if lu.sensitivity not in ("internal", "customer"):
            _bad("t0.units_for_logs: sensitivity must be internal or customer")
        # Design 4.1 / OQ-7: logs of customer systems are an explicit exception and always carry sensitivity: customer
        if lu.sensitivity != "customer" and any(fnmatchcase(lu.unit, g) for g in (*_CUSTOMER_UNITS, *protected_units)):
            _bad(f"t0.units_for_logs: {lu.unit} belongs to a protected/customer system and needs sensitivity: customer")
        out.append(lu)
    return tuple(out)


def parse_policy(raw: bytes, expect_node: str, file_serial: int, now: datetime) -> PolicyView:
    """Strict parse of the fields this layer uses. Raises PolicyError."""
    try:
        doc = canon.loads(raw)
    except canon.CanonError as e:
        _bad(f"not valid strict JSON: {e}")
    if not isinstance(doc, dict):
        _bad("policy must be an object")
    if doc.get("schema") != 1 or isinstance(doc.get("schema"), bool):
        _bad("unsupported schema")
    serial = doc.get("serial")
    if isinstance(serial, bool) or not isinstance(serial, int) or serial != file_serial:
        _bad("serial does not match the file name")
    if doc.get("node") != expect_node:
        _bad("policy is for another node")
    if doc.get("profile") not in ("full", "t0"):
        _bad("unknown profile")
    if doc.get("global_mode") not in ("observe", "enforce"):
        _bad("global_mode must be observe or enforce")
    try:
        if protocol.parse_ts(doc.get("not_before")) > now:
            raise PolicyError("DENY_POLICY_INVALID", "policy not valid yet (not_before)")
    except ProtoError as e:
        _bad(f"not_before: {e.detail}")
    tiers = doc.get("tiers_enabled")
    if not isinstance(tiers, list) or any(isinstance(t, bool) or t not in protocol.TIERS for t in tiers) or 0 not in tiers:
        _bad("tiers_enabled must list tier 0")
    viol = gates.policy_gate_violations(doc)
    if viol:
        _bad("gated feature switched on: " + "; ".join(viol[:3]))
    pins = doc.get("hub_tls_pins")
    if not isinstance(pins, list) or not 1 <= len(pins) <= 4 or not all(protocol.is_hex64(p) for p in pins) or len(set(pins)) != len(pins):
        _bad("hub_tls_pins must be 1..4 distinct sha256 hex digests")
    try:
        keys = protocol.parse_gate_keys(doc.get("hub_gate_keys"))
    except ProtoError as e:
        _bad(e.detail)
    prot = doc.get("protected", {})
    if not isinstance(prot, dict):
        _bad("protected must be an object")
    prot_paths = _paths(prot.get("paths"), "protected.paths")
    prot_units = _str_list(prot.get("units"), "protected.units", _UNIT_GLOB)
    t0 = doc.get("t0", {})
    if not isinstance(t0, dict):
        _bad("t0 must be an object")
    t0p = T0Policy(
        units_for_logs=_log_units(t0.get("units_for_logs"), prot_units),
        cert_paths=_paths(t0.get("cert_paths"), "t0.cert_paths"),
        backup_units=_str_list(t0.get("backup_units"), "t0.backup_units", _UNIT_GLOB),
        backup_dirs=_paths(t0.get("backup_dirs"), "t0.backup_dirs"),
        repos=_paths(t0.get("repos"), "t0.repos"),
        model_dirs=_paths(t0.get("model_dirs"), "t0.model_dirs"))
    wins = doc.get("windows")
    try:
        win = window_mod.Window.from_policy(wins if isinstance(wins, dict) else None)
    except window_mod.WindowError as e:
        _bad(f"windows: {e}")
    if wins is not None and not isinstance(wins, dict):
        _bad("windows must be an object")
    return PolicyView(serial, canon.sha256_hex(raw), doc["node"], doc["profile"], doc["global_mode"], tuple(sorted(tiers)), tuple(pins), keys, prot_paths, prot_units, t0p, win)


def _read_root_file(dirfd: int, name: str, limit: int, owner_uid: int) -> bytes:
    """One policy file: O_NOFOLLOW, regular, nlink 1, owned by `owner_uid`, not writable by group/others - all re-observed on the open descriptor."""
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dirfd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != owner_uid or st.st_mode & 0o022 or st.st_size > limit:
            raise PolicyError("DENY_POLICY_INVALID", f"{name}: not a regular root-owned, non-writable file")
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            raise PolicyError("DENY_POLICY_INVALID", f"{name}: too large")
        return data
    finally:
        os.close(fd)


def load_installed(policy_dir: str, allowed_signers_path: str, node: str, now: datetime, *, owner_uid: int, ssh_keygen: str) -> PolicyView:
    """The installed policy is the highest serial in `policy_dir`. If that one does not verify there is NO policy (fail closed): falling back to an older file would be the
    downgrade the monotonic serial exists to prevent. Raises PolicyError."""
    try:
        dfd = os.open(policy_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as e:
        raise PolicyError("DENY_POLICY_INVALID", f"policy directory unreadable ({type(e).__name__})") from e
    try:
        ds = os.fstat(dfd)
        if ds.st_uid != owner_uid or ds.st_mode & 0o022:
            raise PolicyError("DENY_POLICY_INVALID", "policy directory must be root-owned and not writable by others")
        serials = sorted((int(m.group(1)) for n in os.listdir(dfd) if (m := _NAME.match(n))), reverse=True)
        if not serials:
            raise PolicyError("DENY_POLICY_INVALID", "no policy installed")
        serial = serials[0]
        raw = _read_root_file(dfd, f"policy-{serial}.json", MAX_POLICY_BYTES, owner_uid)
        sig = _read_root_file(dfd, f"policy-{serial}.json.sig", 16 * 1024, owner_uid)
    except OSError as e:
        raise PolicyError("DENY_POLICY_INVALID", f"policy unreadable ({type(e).__name__})") from e
    finally:
        os.close(dfd)
    try:
        signers = read_signers(allowed_signers_path, owner_uid)
        sshsig.verify(raw, sig.decode("ascii"), sshsig.NS_POLICY, OWNER_PRINCIPAL, signers, ssh_keygen)
    except (sshsig.SigError, UnicodeDecodeError, OSError) as e:
        raise PolicyError("DENY_POLICY_INVALID", f"policy signature invalid ({type(e).__name__})") from e
    return parse_policy(raw, node, serial, now)


def read_signers(path: str, owner_uid: int) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != owner_uid or st.st_mode & 0o022 or st.st_size > 64 * 1024:
            raise OSError("allowed_signers must be a root-owned regular file that others cannot write")
        return os.read(fd, 64 * 1024 + 1).decode("ascii")
    finally:
        os.close(fd)


def verify_blob(raw: bytes, sig: str, allowed_signers: str, node: str, serial: int, now: datetime, ssh_keygen: str) -> PolicyView:
    """For a policy blob downloaded from the hub (staging): same checks as for the installed file, applied to the bytes in memory."""
    if len(raw) > MAX_POLICY_BYTES:
        _bad("policy blob too large")
    try:
        sshsig.verify(raw, sig, sshsig.NS_POLICY, OWNER_PRINCIPAL, allowed_signers, ssh_keygen)
    except sshsig.SigError as e:
        raise PolicyError("DENY_POLICY_INVALID", "policy signature invalid") from e
    return parse_policy(raw, node, serial, now)
