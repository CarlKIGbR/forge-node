"""Helpers for the audit tests (not a test module): log specs on a real directory, a forked 'agent' process (dropped uid/gid), crash injection at every mutating system call."""
import json
import os
import signal
import struct
from datetime import datetime, timedelta, timezone

from forge_node.audit import fsflags
from forge_node.audit.log import AuditAdmin, Appender
from forge_node.audit.spec import LogSpec

AGENT_UID = AGENT_GID = 1001
NODE = "g2"
T0 = datetime(2026, 10, 31, 13, 40, 10, tzinfo=timezone.utc)


class Clock:
    def __init__(self, start=T0):
        self.t = start

    def __call__(self):
        self.t += timedelta(seconds=1)
        return self.t


def make_specs(base: str, max_file_bytes=64 * 1024 * 1024) -> dict[str, LogSpec]:
    """priv + agent log layout below `base` exactly as the install creates it (root-owned directories)."""
    d = {}
    os.makedirs(f"{base}/priv", exist_ok=True)
    os.makedirs(f"{base}/agent", exist_ok=True)
    os.makedirs(f"{base}/locks", exist_ok=True)
    os.chown(f"{base}/priv", 0, AGENT_GID)
    os.chmod(f"{base}/priv", 0o750)
    os.chown(f"{base}/agent", 0, 0)
    os.chmod(f"{base}/agent", 0o755)
    os.chown(f"{base}/locks", 0, 0)
    os.chmod(f"{base}/locks", 0o700)
    d["priv"] = LogSpec("priv", "priv", f"{base}/priv", f"{base}/locks/priv.log.lock", AGENT_GID, 0, 0o640, 0o750, 0o600, base, max_file_bytes)
    d["agent"] = LogSpec("agent", "audit", f"{base}/agent", f"{base}/agent/audit.lock", AGENT_GID, 0, 0o660, 0o755, 0o660, base, max_file_bytes)
    return d


def admin(spec: LogSpec, clock=None) -> AuditAdmin:
    return AuditAdmin(spec, NODE, clock or Clock())


def appender(spec: LogSpec, clock=None) -> Appender:
    return Appender(spec, NODE, clock or Clock())


def run_as_agent(fn, *, uid=AGENT_UID, gid=AGENT_GID):
    """Run fn() in a forked child with the agent's identity; returns what fn returned (JSON-able) or raises AssertionError with the child's exception text."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(r)
            os.setgroups([gid])
            os.setgid(gid)
            os.setuid(uid)
            out = {"ok": True, "value": fn()}
        except BaseException as e:  # noqa: BLE001
            out = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        os.write(w, json.dumps(out).encode())
        os._exit(0)
    os.close(w)
    data = b""
    while True:
        b = os.read(r, 65536)
        if not b:
            break
        data += b
    os.close(r)
    os.waitpid(pid, 0)
    res = json.loads(data or b'{"ok": false, "error": "no result"}')
    if not res["ok"]:
        raise AssertionError(res["error"])
    return res["value"]


def errno_of(fn):
    try:
        fn()
        return None
    except OSError as e:
        return e.errno


# ---------------------------------------------------------------------------------------------------------------- crash injection
MUTATING = ("mkdir", "write", "fsync", "fchmod", "fchown", "rename", "unlink", "rmdir")


class Crash:
    """Counts the mutating system calls (os.mkdir/open(O_CREAT)/write/fsync/fchmod/fchown/rename/unlink/rmdir and the inode-flag ioctl) made while `armed`, and kills the process with
    SIGKILL before or after the n-th one. Installed only inside a forked child."""

    def __init__(self, kill_at=None, when="before"):
        self.n, self.kill_at, self.when, self.armed = 0, kill_at, when, False
        self.log: list[str] = []

    def _wrap(self, mod, name, label=None):
        real = getattr(mod, name)
        label = label or name

        def f(*a, **k):
            if not self.armed or (name == "open" and not (len(a) > 1 and a[1] & os.O_CREAT)):
                return real(*a, **k)
            self.n += 1
            self.log.append(label)
            if self.kill_at == self.n and self.when == "before":
                os.kill(os.getpid(), signal.SIGKILL)
            try:
                return real(*a, **k)
            finally:
                if self.kill_at == self.n and self.when == "after":
                    os.kill(os.getpid(), signal.SIGKILL)
        setattr(mod, name, f)

    def install(self):
        for n in MUTATING:
            self._wrap(os, n)
        self._wrap(os, "open")
        self._wrap(fsflags, "_set", "ioctl_setflags")


def in_child(fn, *, kill_at=None, when="before"):
    """Fork; the child runs fn() with crash injection (armed only around fn). Returns (killed: bool, calls: int, log: list). The child writes its call count/log before exiting normally."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        c = Crash(kill_at, when)
        c.install()
        try:
            c.armed = True
            fn()
        finally:
            c.armed = False
        os.write(w, json.dumps({"n": c.n, "log": c.log}).encode())
        os._exit(0)
    os.close(w)
    data = b""
    while True:
        b = os.read(r, 65536)
        if not b:
            break
        data += b
    os.close(r)
    _, status = os.waitpid(pid, 0)
    killed = os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
    if killed:
        return True, kill_at, []
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, f"child failed: {status}"
    j = json.loads(data)
    return False, j["n"], j["log"]


def tree_state(base_dir: str) -> list[dict]:
    """Every generation in a log directory: dir mode, file flags. For the 'no writable window' invariant."""
    out = []
    for name in sorted(os.listdir(base_dir)):
        p = os.path.join(base_dir, name)
        if os.path.isdir(p) and not os.path.islink(p):
            dm = os.stat(p).st_mode & 0o7777
            for f in sorted(os.listdir(p)):
                fd = os.open(os.path.join(p, f), os.O_RDONLY)
                try:
                    out.append({"gen": name, "file": f, "dir_mode": dm, "flags": fsflags.get_flags(fd), "size": os.fstat(fd).st_size})
                finally:
                    os.close(fd)
            if not os.listdir(p):
                out.append({"gen": name, "file": None, "dir_mode": dm, "flags": None, "size": None})
    return out


def check_no_unflagged_reachable_file(base_dir: str) -> None:
    """The invariant behind 'no writable window': a log file without +a exists only inside a root-only (0700) generation directory."""
    for e in tree_state(base_dir):
        if e["file"] is None:
            assert e["dir_mode"] == 0o700, e
            continue
        if not e["flags"] & fsflags.APPEND:
            assert e["dir_mode"] == 0o700, f"a log file without +a is reachable: {e}"
        if e["flags"] & fsflags.IMMUTABLE:
            assert e["flags"] & fsflags.APPEND, f"sealed without +a: {e}"
