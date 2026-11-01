"""Transient-unit backends (Design 4.4, 9.4). privd starts every op as `forge-node-op-<job_id>-<attempt>.service` WITHOUT --collect (the state stays queryable) with a property set taken
from the op table (classes.py), never from request parameters.

  SystemdBackend       production: systemd-run / systemctl, trusted absolute binaries, argv lists only (no shell). Not runnable in the test container (no systemd): its argument
                       construction and the parsing of `systemctl show` are unit-tested with an injected command runner, and `doctor`/N4 prove it inside real units.
  LocalProcessBackend  a faithful stand-in for tests: the worker is a real process in its own session, with a registry entry (pid, start time, invocation id) that survives the death
                       of the process that started it, so 'privd killed, worker survives' can be exercised for real. NEVER constructed by the production entry point (a test checks)."""
import json
import os
import re
import signal
import subprocess
import time
import uuid
from dataclasses import dataclass
from typing import Callable, Mapping, Sequence

UNIT_RE = re.compile(r"^forge-node-op-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-[1-9][0-9]{0,3}\.service\Z")
PROBE_UNIT_RE = re.compile(r"^forge-node-probe-[0-9a-f]{32}\.service\Z")
ACTIVE_STATES = ("activating", "active", "deactivating", "reloading")
_PROP_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,63}\Z")


class UnitError(Exception):
    pass


def op_unit_name(job_id: str, attempt: int) -> str:
    n = f"forge-node-op-{job_id}-{attempt}.service"
    if not UNIT_RE.match(n):
        raise UnitError("invalid unit name")
    return n


@dataclass(frozen=True)
class UnitInfo:
    name: str
    active_state: str            # active | inactive | failed | activating | deactivating ...
    sub_state: str
    invocation_id: str | None
    result: str | None
    cgroup_empty: bool

    @property
    def is_active(self) -> bool:
        return self.active_state in ACTIVE_STATES


def prop_args(props: Mapping[str, str]) -> list[str]:
    out = []
    for k, v in sorted(props.items()):
        if not _PROP_RE.match(k) or not isinstance(v, str) or "\n" in v or "\x00" in v:
            raise UnitError(f"invalid unit property {k!r}")
        out += ["-p", f"{k}={v}"]
    return out


def systemd_run_argv(systemd_run: str, name: str, props: Mapping[str, str], argv: Sequence[str], *, pipe_wait: bool) -> list[str]:
    """`systemd-run` argument vector. No --collect (op units keep their state), no shell, the program and its arguments after `--`."""
    if not (UNIT_RE.match(name) or PROBE_UNIT_RE.match(name)):
        raise UnitError("unit name not allowed")
    if not argv or not os.path.isabs(argv[0]):
        raise UnitError("the program must be an absolute path")
    head = [systemd_run, "--quiet", f"--unit={name}", "--description=forge-node op"]
    head += ["--pipe", "--wait"] if pipe_wait else ["--no-block"]
    return [*head, *prop_args(props), "--", *argv]


def parse_show(text: str) -> dict:
    d = {}
    for line in text.splitlines():
        k, sep, v = line.partition("=")
        if sep:
            d[k] = v
    return d


class SystemdBackend:
    """`run` is the command runner: run(argv, stdin_bytes|None, timeout_s) -> (rc, stdout_bytes, stderr_bytes). It is a required argument (the production one is a trusted subprocess
    wrapper); tests inject a fake and check the argument vectors."""

    SHOW_PROPS = ("ActiveState", "SubState", "InvocationID", "Result", "ControlGroup")

    INVOCATION_WAIT_S = 10.0

    def __init__(self, *, systemd_run: str, systemctl: str, run: Callable, sleep: Callable, monotonic: Callable):
        self.systemd_run, self.systemctl, self.run, self.sleep, self.monotonic = systemd_run, systemctl, run, sleep, monotonic

    def start(self, name: str, props: Mapping[str, str], argv: Sequence[str]) -> str:
        """Start the transient unit (--no-block, no --collect) and return its InvocationID. systemd allocates the invocation id when the start JOB begins, which is after
        systemd-run returned: poll briefly for it. A unit that already ended (a very short worker) still carries the id of its run."""
        rc, out, err = self.run(systemd_run_argv(self.systemd_run, name, props, argv, pipe_wait=False), None, 30)
        if rc != 0:
            raise UnitError(f"systemd-run failed: {err[:200]!r}")
        deadline = self.monotonic() + self.INVOCATION_WAIT_S
        while True:
            info = self.show(name)
            if info is not None and info.invocation_id:
                return info.invocation_id
            if self.monotonic() >= deadline:
                raise UnitError("the started unit has no InvocationID (the start job did not begin)")
            self.sleep(0.05)

    def run_pipe(self, name: str, props: Mapping[str, str], argv: Sequence[str], stdin: bytes, timeout_s: int):
        return self.run(systemd_run_argv(self.systemd_run, name, props, argv, pipe_wait=True), stdin, timeout_s)

    def show(self, name: str) -> UnitInfo | None:
        if not (UNIT_RE.match(name) or PROBE_UNIT_RE.match(name)):
            raise UnitError("unit name not allowed")
        rc, out, err = self.run([self.systemctl, "show", "--no-pager", *[f"-p{p}" for p in self.SHOW_PROPS], name], None, 20)
        if rc != 0:
            return None
        d = parse_show(out.decode("utf-8", "replace"))
        if d.get("ActiveState") in (None, "") or (d.get("ActiveState") == "inactive" and d.get("SubState") == "dead" and not d.get("InvocationID") and not d.get("ControlGroup")):
            return None                                                  # never loaded / garbage-collected
        return UnitInfo(name, d["ActiveState"], d.get("SubState", ""), d.get("InvocationID") or None, d.get("Result") or None, self.cgroup_empty(d.get("ControlGroup", "")))

    def cgroup_empty(self, cgroup: str) -> bool:
        if not cgroup:
            return True
        path = "/sys/fs/cgroup" + cgroup + "/cgroup.procs"
        try:
            with open(path, "rb") as f:
                return f.read().strip() == b""
        except FileNotFoundError:
            return True
        except OSError:
            return False                                                 # cannot tell: not 'empty' (fail closed)

    def stop(self, name: str) -> None:
        rc, _, err = self.run([self.systemctl, "stop", name], None, 60)
        if rc != 0 and b"not loaded" not in err:
            raise UnitError(f"systemctl stop failed: {err[:200]!r}")

    def list_op_units(self) -> list[str]:
        rc, out, _ = self.run([self.systemctl, "list-units", "--all", "--no-legend", "--plain", "--no-pager", "forge-node-op-*.service"], None, 30)
        if rc != 0:
            raise UnitError("cannot list units")
        names = []
        for line in out.decode("utf-8", "replace").splitlines():
            tok = line.split()
            if tok and UNIT_RE.match(tok[0]):
                names.append(tok[0])
        return sorted(names)


def _proc_start(pid: int) -> int | None:
    """Process start time in clock ticks since boot (field 22 of /proc/<pid>/stat), to tell a live worker from a recycled pid."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            raw = f.read()
        return int(raw[raw.rindex(b")") + 2:].split()[19])
    except (OSError, ValueError, IndexError):
        return None


class LocalProcessBackend:
    """Test double with real processes. Each unit: a process group of its own; registry/<name>.json = {pid, start, invocation_id}."""

    def __init__(self, registry_dir: str):
        self.dir = registry_dir
        os.makedirs(registry_dir, mode=0o700, exist_ok=True)

    def _path(self, name: str) -> str:
        if not (UNIT_RE.match(name) or PROBE_UNIT_RE.match(name)):
            raise UnitError("unit name not allowed")
        return os.path.join(self.dir, name + ".json")

    def start(self, name: str, props: Mapping[str, str], argv: Sequence[str]) -> str:
        prop_args(props)                                                 # validate the property set exactly like the real backend
        p = self._path(name)
        if os.path.exists(p):
            raise UnitError("unit already exists (no --collect: names are never reused)")
        proc = subprocess.Popen(list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
        inv = uuid.uuid4().hex
        with open(p, "w") as f:
            json.dump({"pid": proc.pid, "start": _proc_start(proc.pid), "invocation_id": inv}, f)
        self._children = getattr(self, "_children", {})
        self._children[name] = proc
        return inv

    def run_pipe(self, name: str, props: Mapping[str, str], argv: Sequence[str], stdin: bytes, timeout_s: int):
        prop_args(props)
        try:
            r = subprocess.run(list(argv), input=stdin, capture_output=True, timeout=timeout_s, start_new_session=True)
            return r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired:
            return 124, b"", b"timeout"

    def _entry(self, name: str):
        try:
            with open(self._path(name)) as f:
                return json.load(f)
        except FileNotFoundError:
            return None

    def _alive(self, e) -> bool:
        pid = e["pid"]
        st = _proc_start(pid)
        if st is None or st != e["start"]:
            return False
        try:
            with open(f"/proc/{pid}/stat", "rb") as f:
                raw = f.read()
            return raw[raw.rindex(b")") + 2:][:1] != b"Z"                # a zombie is dead
        except OSError:
            return False

    def _group_alive(self, e) -> bool:
        try:
            os.killpg(e["pid"], 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        # a group containing only zombies counts as empty
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                try:
                    with open(f"/proc/{entry}/stat", "rb") as f:
                        raw = f.read()
                    rest = raw[raw.rindex(b")") + 2:].split()
                    if int(rest[2]) == e["pid"] and rest[0] != b"Z":
                        return True
                except (OSError, ValueError, IndexError):
                    continue
        return False

    def _reap(self, name: str) -> None:
        proc = getattr(self, "_children", {}).get(name)
        if proc is not None:
            proc.poll()

    def show(self, name: str) -> UnitInfo | None:
        e = self._entry(name)
        if e is None:
            return None
        self._reap(name)
        alive = self._alive(e)
        return UnitInfo(name, "active" if alive else "inactive", "running" if alive else "dead", e["invocation_id"], None if alive else "success", not self._group_alive(e))

    def stop(self, name: str) -> None:
        e = self._entry(name)
        if e is None:
            return
        for sig, wait_s in ((signal.SIGTERM, 2.0), (signal.SIGKILL, 5.0)):
            try:
                os.killpg(e["pid"], sig)
            except ProcessLookupError:
                break
            deadline = time.monotonic() + wait_s
            while time.monotonic() < deadline:
                self._reap(name)
                if not self._group_alive(e):
                    return
                time.sleep(0.01)

    def list_op_units(self) -> list[str]:
        return sorted(n[:-5] for n in os.listdir(self.dir) if n.endswith(".json") and UNIT_RE.match(n[:-5]))
