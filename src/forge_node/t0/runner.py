"""The ONLY place in the T0 layer that starts a process (Design 4.1: "read-only commands", 12: closed op table, no free-form execution).

Commands are a fixed table (`CMDS`): binary name + argv template + typed slots. A caller names a command id and supplies slot values; each value must match its slot's pattern, and the
rest of the argv is constant. There is no way to pass an extra flag, a different binary, a shell string or an environment variable. Binaries resolve only from a fixed PATH and must be
root-owned and not writable by group/others at exec time (re-observed on every call). No shell, stdin closed unless the command declares input, output size and wall time are capped,
the process group is killed on timeout."""
import os
import re
import select
import signal
import stat
import subprocess
import time
from dataclasses import dataclass, field
from types import MappingProxyType

FIXED_PATH = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")
_ENV_BASE = {"PATH": ":".join(FIXED_PATH), "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8", "HOME": "/nonexistent", "TERM": "dumb"}

SLOT_PATTERNS = {
    "unit": re.compile(r"^[A-Za-z0-9:_.@\\-]{1,128}\.(?:service|timer|socket|mount|target|path)\Z"),
    "unit_glob": re.compile(r"^[A-Za-z0-9:_.@\\*?-]{1,128}\Z"),
    "hex64": re.compile(r"^[0-9a-f]{64}\Z"),
    "image_id": re.compile(r"^sha256:[0-9a-f]{64}\Z"),
    "int": re.compile(r"^[0-9]{1,9}\Z"),
    "seconds": re.compile(r"^-?[0-9]{1,8}s\Z"),
    "abs_path": re.compile(r"^/[A-Za-z0-9_.@:+,=%~/ -]{1,4095}\Z"),
    "pkg_pattern": re.compile(r"^[a-z0-9][a-z0-9+.*-]{0,63}\Z"),
}


@dataclass(frozen=True)
class Cmd:
    binary: str
    argv: tuple[str, ...]                       # constant tokens; "<name>" = a single slot, "<name...>" = a list slot
    slots: tuple[tuple[str, str], ...] = ()     # (slot name, SLOT_PATTERNS key)
    timeout_s: int = 20
    max_out: int = 1024 * 1024
    ok_rc: tuple[int, ...] = (0,)
    stdin: bool = False
    max_list: int = 64
    env: tuple[tuple[str, str], ...] = ()       # extra constant environment (git hardening)


def _cmds() -> dict[str, Cmd]:
    d: dict[str, Cmd] = {}
    d["lsblk"] = Cmd("lsblk", ("-J", "-b", "-o", "NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,RO,ROTA,MODEL,PKNAME"))
    d["findmnt"] = Cmd("findmnt", ("-J", "-b", "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"))
    d["timedatectl"] = Cmd("timedatectl", ("show", "--property=Timezone", "--property=NTPSynchronized", "--property=NTP", "--property=TimeUSec"))
    d["nvidia_gpus"] = Cmd("nvidia-smi", ("--query-gpu=index,uuid,name,memory.used,memory.total,utilization.gpu,temperature.gpu,power.draw,power.limit,clocks.sm,clocks.max.sm,"
                                          "pcie.link.gen.current,pcie.link.width.current,clocks_throttle_reasons.active", "--format=csv,noheader,nounits"), timeout_s=15)
    d["nvidia_apps"] = Cmd("nvidia-smi", ("--query-compute-apps=gpu_uuid,pid,process_name,used_gpu_memory", "--format=csv,noheader,nounits"), timeout_s=15)
    d["systemctl_show_all"] = Cmd("systemctl", ("show", "--no-pager", "-p", "Id", "-p", "LoadState", "-p", "ActiveState", "-p", "SubState", "-p", "Result", "-p", "FragmentPath",
                                                "-p", "Description", "-p", "NRestarts", "-p", "ActiveEnterTimestamp", "*.service", "*.timer", "*.socket", "*.mount"), max_out=4 * 1024 * 1024, timeout_s=30)
    d["systemctl_show_unit"] = Cmd("systemctl", ("show", "--no-pager", "-p", "Id", "-p", "LoadState", "-p", "ActiveState", "-p", "SubState", "-p", "Result", "-p", "FragmentPath",
                                                 "-p", "ExecMainStatus", "-p", "ExecMainExitTimestamp", "-p", "ActiveEnterTimestamp", "-p", "InactiveEnterTimestamp", "<unit...>"),
                                   slots=(("unit", "unit"),), max_list=32)
    d["systemctl_list_units"] = Cmd("systemctl", ("list-units", "--all", "--no-pager", "--plain", "--no-legend", "--output=json", "--type=service,timer,socket"), max_out=4 * 1024 * 1024, timeout_s=30)
    d["systemctl_list_timers"] = Cmd("systemctl", ("list-timers", "--all", "--no-pager", "--output=json"), max_out=1024 * 1024, timeout_s=30)
    d["systemctl_is_active"] = Cmd("systemctl", ("is-active", "<unit>"), slots=(("unit", "unit"),), ok_rc=(0, 3, 4))
    d["apt_simulate"] = Cmd("apt-get", ("-s", "-o", "Debug::NoLocking=1", "-o", "APT::Get::Show-Versions=0", "upgrade"), max_out=2 * 1024 * 1024, timeout_s=60, ok_rc=(0, 100))
    d["apt_showhold"] = Cmd("apt-mark", ("showhold",))
    d["apt_config_dump"] = Cmd("apt-config", ("dump",), max_out=1024 * 1024)
    d["dpkg_versions"] = Cmd("dpkg-query", ("-W", "-f", "${Package}\t${Version}\t${db:Status-Abbrev}\n", "<pkg...>"), slots=(("pkg", "pkg_pattern"),), ok_rc=(0, 1), max_list=16)
    d["ip_route"] = Cmd("ip", ("-j", "route", "show"))
    d["ss_listen"] = Cmd("ss", ("-tulnH",))
    d["ss_listen_procs"] = Cmd("ss", ("-tulnpH",))
    d["iptables_docker_user"] = Cmd("iptables", ("-S", "DOCKER-USER"))
    d["docker_ps_ids"] = Cmd("docker", ("ps", "-a", "-q", "--no-trunc"), timeout_s=30)
    d["docker_inspect"] = Cmd("docker", ("inspect", "--format", "{{json .Id}}\t{{json .Name}}\t{{json .Image}}\t{{json .Config.Image}}\t{{json .State.Status}}\t{{json .RestartCount}}\t"
                                                              "{{json .State.StartedAt}}\t{{json .State.Pid}}\t{{json .LogPath}}\t{{json .Config.Labels}}\t{{json .NetworkSettings.Ports}}\t"
                                                              "{{range .Mounts}}{{.Type}}|{{.Source}}|{{.Destination}}|{{.RW}};{{end}}", "<id...>"),
                              slots=(("id", "hex64"),), max_out=4 * 1024 * 1024, timeout_s=30, max_list=40)
    d["docker_image_inspect"] = Cmd("docker", ("image", "inspect", "--format", "{{json .Id}}\t{{json .RepoDigests}}", "<id...>"), slots=(("id", "image_id"),), timeout_s=30, max_list=40)
    d["virsh_list"] = Cmd("virsh", ("-r", "list", "--all"))
    d["virsh_pools"] = Cmd("virsh", ("-r", "pool-list", "--all"))
    d["openssl_x509_file"] = Cmd("openssl", ("x509", "-noout", "-enddate", "-subject", "-fingerprint", "-sha256", "-nameopt", "RFC2253", "-in", "<path>"), slots=(("path", "abs_path"),), timeout_s=10)
    d["openssl_x509_der"] = Cmd("openssl", ("x509", "-inform", "DER", "-noout", "-enddate", "-subject", "-fingerprint", "-sha256", "-nameopt", "RFC2253"), timeout_s=10, stdin=True)
    _git_env = (("GIT_CONFIG_GLOBAL", "/dev/null"), ("GIT_CONFIG_NOSYSTEM", "1"), ("GIT_OPTIONAL_LOCKS", "0"), ("GIT_TERMINAL_PROMPT", "0"), ("GIT_ASKPASS", "/bin/false"),
                ("GIT_EXTERNAL_DIFF", "/bin/false"), ("GIT_PAGER", "cat"))
    d["git_status_tracked"] = Cmd("git", ("--no-optional-locks", "-c", "safe.directory=<repo>", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "core.hooksPath=/dev/null",
                                          "-C", "<repo>", "status", "--porcelain=v1", "--untracked-files=no", "--no-renames"), slots=(("repo", "abs_path"),), timeout_s=60, max_out=512 * 1024, env=_git_env)
    d["sshd_effective"] = Cmd("sshd", ("-T",), timeout_s=10)
    d["journal_unit"] = Cmd("journalctl", ("-u", "<unit>", "--since=<since>", "-n", "<lines>", "--no-pager", "-o", "short-iso", "--no-hostname"),
                            slots=(("unit", "unit"), ("since", "seconds"), ("lines", "int")), max_out=256 * 1024, timeout_s=30)
    d["journal_last"] = Cmd("journalctl", ("-u", "<unit>", "-n", "1", "--no-pager", "-o", "short-unix", "--no-hostname"), slots=(("unit", "unit"),), max_out=32 * 1024, timeout_s=15)
    d["du_ionice"] = Cmd("ionice", ("-c3", "nice", "-n", "19", "du", "-s", "-b", "-x", "--", "<path>"), slots=(("path", "abs_path"),), timeout_s=120, max_out=4096)
    return d


CMDS = MappingProxyType(_cmds())


@dataclass
class Run:
    ok: bool
    reason: str                 # ok | missing | untrusted_binary | timeout | nonzero | oserror | bad_slot
    rc: int | None = None
    out: bytes = b""
    err: str = ""
    truncated: bool = False
    argv: tuple[str, ...] = field(default_factory=tuple)

    @property
    def text(self) -> str:
        return self.out.decode("utf-8", "replace")


class RunnerError(Exception):
    pass


def _resolve(binary: str) -> str | None:
    for d in FIXED_PATH:
        p = os.path.join(d, binary)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def _trusted(path: str) -> bool:
    """Re-observed on every call: the resolved binary (after symlinks) is root-owned and neither group- nor world-writable."""
    try:
        s = os.stat(path)
    except OSError:
        return False
    return s.st_uid == 0 and stat.S_ISREG(s.st_mode) and not (s.st_mode & 0o022)


def _expand(cmd: Cmd, slots: dict) -> list[str]:
    declared = dict(cmd.slots)
    if set(slots) != set(declared):
        raise RunnerError(f"slots must be exactly {sorted(declared)}")
    out: list[str] = []
    for tok in cmd.argv:
        names = re.findall(r"<([a-z_]+)(\.\.\.)?>", tok)
        if not names:
            out.append(tok)
            continue
        if len(names) != 1:
            raise RunnerError("one slot per token")
        name, many = names[0]
        pat = SLOT_PATTERNS[declared[name]]
        val = slots[name]
        vals = val if many else [val]
        if many and (not isinstance(val, (list, tuple)) or not 1 <= len(val) <= cmd.max_list):
            raise RunnerError(f"slot {name}: 1..{cmd.max_list} values")
        for v in vals:
            # a value that IS a whole argv element may not look like an option; inside a larger element ("--since=-3600s") the prefix makes that impossible
            if not isinstance(v, str) or not pat.match(v) or (v.startswith("-") and tok in (f"<{name}>", f"<{name}...>")) or (declared[name] == "abs_path" and (".." in v.split("/") or "\x00" in v)):
                raise RunnerError(f"slot {name}: value rejected")
        out.extend(tok.replace("<" + name + ("..." if many else "") + ">", v) for v in vals)
    return out


def _env(cmd: Cmd) -> dict:
    return {**_ENV_BASE, **dict(cmd.env)}


def run(cmd_id: str, slots: dict | None = None, stdin: bytes | None = None) -> Run:
    """Execute one table entry. Raises RunnerError for a programming error (unknown id, bad slots); returns a Run for every operational outcome."""
    cmd = CMDS.get(cmd_id)
    if cmd is None:
        raise RunnerError(f"unknown command {cmd_id!r}")
    if (stdin is not None) != cmd.stdin:
        raise RunnerError("stdin does not match the command definition")
    argv_tail = _expand(cmd, slots or {})
    path = _resolve(cmd.binary)
    if path is None:
        return Run(False, "missing", argv=(cmd.binary, *argv_tail))
    if not _trusted(os.path.realpath(path)):
        return Run(False, "untrusted_binary", argv=(cmd.binary, *argv_tail))
    argv = [path, *argv_tail]
    try:
        p = subprocess.Popen(argv, stdin=subprocess.PIPE if cmd.stdin else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, close_fds=True,
                             start_new_session=True, env=_env(cmd), cwd="/")
    except OSError as e:
        return Run(False, "oserror", err=type(e).__name__, argv=tuple(argv))
    deadline = time.monotonic() + cmd.timeout_s
    out, err = bytearray(), bytearray()
    truncated = timed_out = False
    if cmd.stdin and p.stdin:
        try:
            p.stdin.write(stdin or b"")
            p.stdin.close()
        except OSError:
            pass
    fds = {p.stdout.fileno(): out, p.stderr.fileno(): err}
    try:
        while fds and not truncated:
            left = deadline - time.monotonic()
            if left <= 0:
                timed_out = True
                break
            ready, _, _ = select.select(list(fds), [], [], min(left, 1.0))
            for fd in ready:
                chunk = os.read(fd, 65536)
                if not chunk:
                    del fds[fd]
                    continue
                buf = fds[fd]
                cap = cmd.max_out if buf is out else 4096
                room = cap - len(buf)
                buf.extend(chunk[:room])
                if len(chunk) > room and buf is out:
                    truncated = True
                    break
    finally:
        if timed_out or truncated or p.poll() is None:
            _kill(p)
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _kill(p)
        for f in (p.stdout, p.stderr):
            try:
                f.close()
            except OSError:
                pass
    if timed_out:
        return Run(False, "timeout", None, bytes(out), bytes(err).decode("utf-8", "replace"), truncated, tuple(argv))
    rc = p.returncode
    if truncated:                       # we killed it ourselves; the partial output is usable
        return Run(True, "ok", rc, bytes(out), "", True, tuple(argv))
    ok = rc in cmd.ok_rc
    return Run(ok, "ok" if ok else "nonzero", rc, bytes(out), bytes(err).decode("utf-8", "replace")[:512], False, tuple(argv))


def _kill(p: subprocess.Popen):
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            p.kill()
        except OSError:
            pass


class ReadOnlyRunner:
    """Thin object wrapper so collectors take a runner instance (tests substitute a fake with the same two methods). The production instance has no state."""

    def run(self, cmd_id: str, slots: dict | None = None, stdin: bytes | None = None) -> Run:
        return run(cmd_id, slots, stdin)

    def available(self, cmd_id: str) -> bool:
        cmd = CMDS[cmd_id]
        p = _resolve(cmd.binary)
        return p is not None and _trusted(os.path.realpath(p))
