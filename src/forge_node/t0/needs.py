"""What each root probe needs from the host, declared in ONE place (probefix 0.5.1). Everything that gates a probe is generated from this table:

  * the probe's `Fs` (`fsread.DeclaredFs`, built in probe_main): a content read whose requested path matches no `reads` entry, or a metadata method not in `meta`, is refused ('not_declared');
  * the probe's `--selfcheck` (selfcheck.probe_selfcheck): opens every declared read with the REAL limit and reports the reason per path;
  * the tests (test_probe_reads): run every probe against the real /proc and fail on a declared read that is denied or a read that is not declared.

A new read in probes.py without an entry here fails closed (the probe reports an error) and in the tests. `reads` are paths as REQUESTED (before symlink resolution; `Fs` still checks the resolved
path against its global allowlist and the protected set). They are read-only, no capability is implied: the unit properties (hardening.py) are untouched by this table."""
import os
import re
from dataclasses import dataclass

DEFAULT_LIMIT = 1024 * 1024
UULOG_LIMIT = 256 * 1024
FS_METHODS = frozenset({"stat_meta", "list_meta", "resolve_dir", "read_exception", "read_user_file"})          # policy-named / user-controlled locations: metadata or one named file


@dataclass(frozen=True)
class Read:
    """One kernel/system file read with `Fs.read_text`. `path` may contain `{pid}` (digits only); `limit` is what the probe passes to read_text (selfcheck uses the same)."""
    path: str
    limit: int = DEFAULT_LIMIT

    @property
    def regex(self) -> re.Pattern:
        return re.compile("^" + re.escape(self.path).replace(re.escape("{pid}"), "[0-9]{1,9}") + r"\Z")

    def sample(self) -> str:
        """The concrete path the selfcheck opens: for `{pid}` this process (a container's init is not guaranteed to exist while the install is checked)."""
        return self.path.replace("{pid}", str(os.getpid()))


@dataclass(frozen=True)
class Need:
    commands: tuple = ()                 # allowlisted commands (runner.CMDS ids) that must exist
    optional: tuple = ()                 # reported, not required (sshd / virsh are not on every host)
    reads: tuple = ()                    # Read(...) entries
    meta: frozenset = frozenset()        # Fs methods from FS_METHODS the probe may call


PROBE_NEEDS = {
    "net": Need(commands=("ss_listen_procs",)),                                          # ss -p only; it does not read /proc/net/dev (the agent's metrics do, in the agent unit)
    "firewall": Need(commands=("iptables_docker_user",)),
    "containers": Need(commands=("docker_ps_ids", "docker_inspect", "docker_image_inspect"), meta=frozenset({"stat_meta", "resolve_dir"})),
    # /proc/<pid>/net/dev of a container's init process: world-readable (hidepid=0), no PTRACE; verified as an unprivileged user against running containers
    "container_net": Need(commands=("docker_ps_ids", "docker_inspect"), reads=(Read("/proc/{pid}/net/dev"),)),
    "vms": Need(optional=("virsh_list", "virsh_pools")),
    "certs": Need(commands=("openssl_x509_file",), meta=frozenset({"resolve_dir", "stat_meta", "list_meta"})),
    "git": Need(commands=("git_status_tracked",), meta=frozenset({"resolve_dir", "stat_meta", "read_exception"})),
    "access": Need(optional=("sshd_effective",), reads=(Read("/etc/group"), Read("/etc/passwd")), meta=frozenset({"read_user_file"})),
    "models": Need(commands=("du_ionice",), meta=frozenset({"resolve_dir", "list_meta"})),
    "journal": Need(commands=("journal_unit",)),
    "activity": Need(commands=("journal_last",)),
    "uulog": Need(reads=(Read("/var/log/unattended-upgrades/unattended-upgrades.log", UULOG_LIMIT),)),
}


def declared_fs(name: str, protected, root: str = "/"):
    """The `Fs` a probe runs with, generated from its declaration. An unknown name gets an Fs that can do nothing (the dispatcher answers DENY_OP_UNKNOWN before any read)."""
    from .fsread import DeclaredFs
    need = PROBE_NEEDS.get(name)
    return DeclaredFs(protected, root, [r.regex for r in need.reads] if need else (), need.meta if need else frozenset())
