"""Production wiring of privd and privctl: constants of the install layout (Design 13.C), trusted binaries, the REAL gate table (gates.GATES), the systemd backend. Nothing here is
configurable from a request; the environment supplies only the node id (set by the unit). Tests build Context themselves with the same constructor - this module is what the units run."""
import os
import pwd
import re
import socket
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone

from .. import __version__, gates, protocol
from ..audit.log import AuditAdmin
from ..audit.spec import AuditCorrupt, AuditDown, agent_spec, priv_spec
from ..profile import PROFILE, RELEASE
from ..t0.runner import FIXED_PATH, RunnerError, trusted_binary
from . import resolver
from .client import PrivClient
from .core import Context, Paths
from .gate import flush_pending_policy_audit, record_release_switch
from .ledger import Ledger, LedgerError
from .lease import LeaseStore
from .optable import build_optable
from .policy_full import BUILTIN_PROTECTED_PATHS, BUILTIN_PROTECTED_UNITS
from .policy_store import PolicyStore, release_table_ops
from .privctl import Ctl
from .privctl import main as ctl_main
from .reconcile import recover_all
from .server import Server
from .units import SystemdBackend

PAGE = "/opt/forge-node/current"
PYTHON = "/usr/bin/python3"
PYZ = f"{PAGE}/forge-node.pyz"
PROTECTED_MOUNTS = ("/srv/models", "/srv/kmu-ai")
PRIV_STATE = "/var/lib/forge-node-priv"
RUN_DIR = "/run/forge-node"
PATHS = Paths(PRIV_STATE, RUN_DIR, "/etc/forge-node/policy", "/etc/forge-node/allowed_signers", "/etc/forge-node/LOCAL_STOP")


def full_version() -> str:
    """`__version__` is a constant of the source tree; the release name written by the builder tells two releases of the same tree apart (the audit `release_switch` record compares this string)."""
    return f"{__version__}+{RELEASE}"


def now() -> datetime:
    return datetime.now(timezone.utc)


def run_process(argv, stdin, timeout_s):
    """Trusted subprocess wrapper for the systemd backend and the live resolver: argv list, no shell, fixed PATH, bounded time."""
    try:
        r = subprocess.run(argv, input=stdin if stdin is not None else b"", capture_output=True, timeout=timeout_s, env={"PATH": ":".join(FIXED_PATH), "LC_ALL": "C"}, check=False)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, b"", b"timeout"


def argv_for(role: str, name: str, work_dir: str | None) -> list:
    base = [PYTHON, "-I", PYZ]
    if role == "op":
        return [*base, "opworker", "run", work_dir]
    if role == "op-selfcheck":
        return [*base, "opworker", "selfcheck", work_dir]
    if role == "probe":
        return [*base, "probe", name]
    if role == "probe-selfcheck":
        return [*base, "probe", "--selfcheck", name]
    raise ValueError(role)


def devof(path: str):
    try:
        return os.stat(path).st_dev
    except OSError:
        return None


def protected_devs() -> set:
    return {d for d in (devof(p) for p in PROTECTED_MOUNTS) if d is not None}


def build_policy_store(node: str, table, ssh_keygen: str) -> PolicyStore:
    """The production PolicyStore. `table_ops` is release_table_ops(table, PROFILE): a t0 release refuses every policy that is not profile t0 (its own function so that a test pins this wiring)."""
    return PolicyStore(policy_dir=PATHS.policy_dir, allowed_signers=PATHS.allowed_signers, serial_file=PATHS.serial_file, node=node, owner_uid=0, ssh_keygen=ssh_keygen, clock=now,
                       gates_map=gates.GATES, table_ops=release_table_ops(table, PROFILE), devof=devof, protected_devs=protected_devs)


def build_context(node: str, agent_user: str = "forgenode") -> Context:
    ssh_keygen = trusted_binary("ssh-keygen")
    pw = pwd.getpwnam(agent_user)
    table = build_optable(PROFILE)
    ledger = Ledger(PATHS.ledger)
    priv_log = AuditAdmin(priv_spec(gid=pw.pw_gid, trust_anchor="/"), node, now)
    agent_log = AuditAdmin(agent_spec(gid=pw.pw_gid, trust_anchor="/"), node, now)
    backend = SystemdBackend(systemd_run=trusted_binary("systemd-run"), systemctl=trusted_binary("systemctl"), run=run_process, sleep=time.sleep, monotonic=time.monotonic)
    policies = build_policy_store(node, table, ssh_keygen)
    leases = LeaseStore(path=PATHS.lease_file, ledger=ledger, node=node, ssh_keygen=ssh_keygen, clock=now, owner_uid=0)
    return Context(node=node, paths=PATHS, clock=now, ledger=ledger, priv_log=priv_log, agent_log=agent_log, backend=backend, optable=table, gates=gates.GATES, ssh_keygen=ssh_keygen,
                   owner_uid=0, agent_uid=pw.pw_uid, policies=policies, leases=leases, argv_for=argv_for, version=full_version(), sleep=time.sleep, monotonic=time.monotonic)


def listener_from_systemd() -> socket.socket:
    """Socket activation: forge-node-privd.socket hands over fd 3 (mode 0660 root:forgenode, set by the unit). No fallback bind: without the socket unit privd does not run."""
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        raise SystemExit("privd must be started by forge-node-privd.socket (LISTEN_FDS=1)")
    return socket.socket(fileno=3)


def run_privd() -> int:
    node = os.environ.get("FORGE_NODE_NODE_ID", "")
    if not protocol.is_node_id(node):
        sys.stderr.write("FORGE_NODE_NODE_ID missing or invalid\n")
        return 2
    try:
        ctx = build_context(node)
    except (RunnerError, KeyError, OSError, AuditDown, AuditCorrupt, LedgerError) as e:
        sys.stderr.write(f"cannot start: {type(e).__name__}: {e}\n")
        return 2
    recover_all(ctx)
    flush_pending_policy_audit(ctx)
    record_release_switch(ctx)
    Server(ctx).serve(listener_from_systemd())
    return 0


def ensure_state_dirs() -> None:
    """The root-only state directories of privd (13.C creates only /var/lib/forge-node-priv itself)."""
    for d in (PATHS.priv_state, PATHS.locks, PATHS.work):
        os.makedirs(d, mode=0o700, exist_ok=True)
        os.chown(d, 0, 0)
        os.chmod(d, 0o700)


NODE_ENV = "/etc/forge-node/node.env"


def node_id_from_file(path: str, owner_uid: int) -> str:
    """FORGE_NODE_NODE_ID from node.env (the file the units use as EnvironmentFile): `sudo privctl …` runs with a scrubbed environment, so the wrapper cannot rely on it. The file must be a
    regular root-owned file that others cannot write (it decides which node this is). '' when it is missing, unsafe or has no valid id."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError:
        return ""
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != owner_uid or st.st_mode & 0o022 or st.st_size > 64 * 1024:
            return ""
        text = os.read(fd, 64 * 1024 + 1).decode("utf-8", "replace")
    finally:
        os.close(fd)
    found = ""
    for line in text.splitlines():                                 # the LAST assignment wins - as for systemd's EnvironmentFile= and for the switcher's `env` call (round 3: privctl took the first)
        m = re.match(r"^FORGE_NODE_NODE_ID=(?:\"([^\"]*)\"|'([^']*)'|(\S+))\s*$", line.strip())
        if m:
            v = next(g for g in m.groups() if g is not None)
            found = v if protocol.is_node_id(v) else ""
    return found


def run_privctl(argv: list) -> int:
    node = os.environ.get("FORGE_NODE_NODE_ID", "")
    if not protocol.is_node_id(node):
        node = node_id_from_file(NODE_ENV, 0)
    if not protocol.is_node_id(node):
        sys.stderr.write("FORGE_NODE_NODE_ID missing or invalid\n")
        return 2
    gid = pwd.getpwnam("forgenode").pw_gid
    sysctl = trusted_binary("systemctl")
    ctl = Ctl(euid=os.geteuid(), client=PrivClient(PATHS.socket, 0, 60), state_setup=ensure_state_dirs,
              admin_factory=lambda: (AuditAdmin(priv_spec(gid=gid, trust_anchor="/"), node, now), AuditAdmin(agent_spec(gid=gid, trust_anchor="/"), node, now)), ledger_path=PATHS.ledger, local_stop=PATHS.local_stop,
              systemctl_provider=resolver.systemctl_provider(sysctl, run_process), systemctl_text_provider=resolver.systemctl_text_provider(sysctl, run_process), protected_units=BUILTIN_PROTECTED_UNITS, protected_paths=BUILTIN_PROTECTED_PATHS,
              run_systemctl=lambda a: run_process([sysctl, *a], None, 60), clock=now, out=sys.stdout)
    return ctl_main(argv, ctl)
