"""privctl: the owner's root CLI on the node (Design 13.C/E/F). Every subcommand is a `cmd_*` function; each one starts with require_root() - the guard of this module (G27: a test counts
the commands and checks the guard dominates every path). Subcommands that change privd's state do it by sending a REQUEST to privd (so they go through gate() like everything else);
the few that must work while privd is down (audit-init, lockdown) or that are pure root-side maintenance (circuit-ack, audit-verify, audit-purge, unit-closure) act directly.

policy-apply never takes a path from anybody else: the two files are opened with O_NOFOLLOW, must be regular files, are read completely into memory, and the signature, the schema and
the installation all work on THOSE BYTES (no re-open by path, no TOCTOU in a world-writable /tmp)."""
import base64
import json
import os
import stat
import sys

from ..audit import fsproof
from ..audit.spec import CURRENT_NAME, AuditCorrupt, AuditDown, AuditNotInitialised
from . import resolver
from .client import PrivClient, PrivUnavailable
from .ledger import LedgerError

MAX_BLOB = 256 * 1024


class CtlError(Exception):
    pass


def require_root(euid: int) -> None:
    """The guard of every command. `euid` is passed in (os.geteuid() in main): there is no code path to a command that skips it."""
    if euid != 0:
        raise CtlError("privctl must run as root")


def read_nofollow(path: str, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)       # O_NONBLOCK: a FIFO in place of the file is refused below instead of blocking forever
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            raise CtlError(f"{path}: not a regular file or too large")
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            raise CtlError(f"{path}: too large")
        return data
    finally:
        os.close(fd)


class Ctl:
    """Everything a command needs, injected: nothing is read from the environment inside a command."""

    def __init__(self, *, euid: int, client: PrivClient, state_setup, admin_factory, ledger_path: str, local_stop: str,
                 systemctl_provider, systemctl_text_provider, protected_units: tuple, protected_paths: tuple, run_systemctl, clock, out):
        """state_setup(): create the root-only state directories (audit-init only). admin_factory() -> (priv AuditAdmin, agent AuditAdmin): built when a command needs them, because
        before audit-init the directories they open do not exist."""
        self.euid, self.client, self.state_setup, self.admin_factory = euid, client, state_setup, admin_factory
        self.ledger_path, self.local_stop, self.systemctl_provider, self.systemctl_text_provider = ledger_path, local_stop, systemctl_provider, systemctl_text_provider
        self.protected_units, self.protected_paths, self.run_systemctl, self.clock, self.out = protected_units, protected_paths, run_systemctl, clock, out

    def emit(self, doc) -> None:
        self.out.write(json.dumps(doc, sort_keys=True, indent=1, default=str) + "\n")

    # ---- commands -------------------------------------------------------------------------------------------------------------
    def cmd_audit_init(self) -> int:
        require_root(self.euid)
        res = {}
        self.state_setup()
        admins = list(zip(("priv", "agent"), self.admin_factory()))
        for name, admin in admins:                                                     # the seal protocol must work on EVERY log's filesystem, else nothing is created at all
            proof = fsproof.prove(admin.spec.dir)
            res[name] = {"fs_proof": proof}
            if not proof["ok"]:
                self.emit(res)
                raise CtlError(f"{name} log: the filesystem does not support the seal protocol (see fs_proof)")
        res["ledger"] = self._ledger_for_install(admins)                               # M-109: the install creates the ledger; before the logs, so a ledger that cannot be made leaves no half-installed node
        for name, admin in admins:
            res[name]["generation"] = admin.init()
        self.emit(res)
        return 0

    def _ledger_for_install(self, admins) -> dict:
        """Fresh node (no log has a CURRENT yet): create the ledger (idempotent for a partly done earlier install). Node that was installed (a log exists): the ledger MUST be there and
        initialised - a missing or schema-less one is damage, not a fresh start, and `audit-init` is not the way to hide it (M-109, fail closed)."""
        from .ledger import Ledger
        installed = any(os.path.lexists(os.path.join(a.spec.dir, CURRENT_NAME)) for _, a in admins)
        existed = os.path.lexists(self.ledger_path)
        try:
            led = Ledger(self.ledger_path, create=not installed)
        except LedgerError as e:
            raise CtlError(f"the node is installed (a log exists) but its ledger is unusable: {e}") from e
        try:
            schema = led._c.execute("PRAGMA user_version").fetchone()[0]
        finally:
            led.close()
        return {"path": self.ledger_path, "created": not existed, "state_schema": schema}

    def cmd_audit_verify(self) -> int:
        require_root(self.euid)
        res = {}
        for n, a in zip(("priv", "agent"), self.admin_factory()):
            try:
                res[n] = a.verify()
            except (AuditDown, AuditCorrupt, AuditNotInitialised) as e:          # one log that cannot be verified (a hostile holder of its lock, a damaged directory) must not hide the other's result
                res[n] = [f"verification could not run: {type(e).__name__}: {e}"]
        self.emit(res)
        return 0 if not any(res.values()) else 1

    def cmd_audit_rotate(self, which: str) -> int:
        """`both` / `priv` / `agent` rotate now; `due` (what the timer runs) rotates each log only when its size or age threshold is reached."""
        require_root(self.euid)
        body = {"log": "both", "when": "due"} if which == "due" else {"log": which}
        r = self.client.request("audit.rotate", body)
        self.emit(r)
        return 0 if r.get("ok") else 1

    def cmd_audit_purge(self, acked_priv: int, acked_agent: int) -> int:
        """`acked_*` = the highest seq per log the hub has acknowledged (read it from the hub: node.audit / the poll acks). Purge removes only sealed generations >= 90 days old."""
        require_root(self.euid)
        res = {}
        for name, admin, acked in zip(("priv", "agent"), self.admin_factory(), (acked_priv, acked_agent)):
            res[name] = admin.purge(acked, self.clock())
        self.emit(res)
        return 0

    def cmd_policy_apply(self, policy_path: str, sig_path: str) -> int:
        require_root(self.euid)
        raw = read_nofollow(policy_path, MAX_BLOB)
        sig = read_nofollow(sig_path, 16 * 1024).decode("ascii")
        r = self.client.request("policy.apply", {"policy_b64": base64.b64encode(raw).decode("ascii"), "sig": sig})
        self.emit(r)
        return 0 if r.get("ok") else 1

    def cmd_status(self) -> int:
        require_root(self.euid)
        r = self.client.request("status", {})
        self.emit(r)
        return 0 if r.get("ok") else 1

    def cmd_lockdown(self) -> int:
        """LOCAL_STOP, then stop the agent and disable the rotation timer and the privd socket. Works without privd: the file is created directly, systemctl is best effort and reported."""
        require_root(self.euid)
        d = os.path.dirname(self.local_stop)
        dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            try:
                os.close(os.open(os.path.basename(self.local_stop), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=dfd))
            except FileExistsError:
                pass
            os.fsync(dfd)
        finally:
            os.close(dfd)
        steps = {}
        # the rotation timer goes too: its service `Requires=` the privd socket, so an hourly tick would start the socket again. LOCAL_STOP is the durable part (privd itself refuses everything
        # above T0 while the file exists); the units are the belt to that brace.
        for label, argv in (("stop_agent", ["stop", "forge-node-agent.service"]), ("disable_rotate_timer", ["disable", "--now", "forge-node-audit-rotate.timer"]),
                            ("disable_privd_socket", ["disable", "--now", "forge-node-privd.socket"])):
            rc, out, err = self.run_systemctl(argv)
            steps[label] = {"rc": rc, "err": err.decode("utf-8", "replace")[:200]}
        self.emit({"local_stop": self.local_stop, "steps": steps})
        return 0

    def cmd_unit_closure(self, unit: str, action: str) -> int:
        """The closure_sha256 the owner puts into the policy for a unit.* target, computed from the live unit graph by the resolver the node itself uses."""
        require_root(self.euid)
        r = resolver.resolve(self.systemctl_provider, self.systemctl_text_provider, unit, action, job_mode="replace", protected_units=self.protected_units, protected_paths=self.protected_paths)
        # the hash is printed for a denied closure too (the owner needs it to acknowledge a known hit - T3 frozen_ack); `denied` and `hits` say that it must not be used as an ordinary target
        self.emit({"unit": unit, "action": action, "denied": r.denied, "hits": [h.text() for h in r.hits], "closure_sha256": r.closure_sha256(),
                   "F": sorted(r.F), "C": sorted(r.C), "S": sorted(r.S), "X": sorted(r.X)})
        return 1 if r.denied else 0

    def cmd_selftest_bypass(self, envelope_path: str, expect: str | None = None) -> int:
        """T0 acceptance (3), N4: send ONE hub-signed T1/T2 DRY-RUN job envelope straight to the privd socket, bypassing the agent and the hub, and report whether privd refused it. Exit 0 only when
        privd answered with a `denied` result (and, if `expect` is given, with exactly that reason code, e.g. DENY_STOP); anything else - a dry-run result, an execution, no answer - is 1: the bypass
        was NOT refused. It sends nothing but a dry-run envelope (checked here, and signed by the hub, so it cannot be altered), and it adds no capability: it is the request any root process can make."""
        require_root(self.euid)
        try:
            env = json.loads(read_nofollow(envelope_path, MAX_BLOB))
            payload = json.loads(env["payload"])
        except (ValueError, KeyError, TypeError) as e:
            raise CtlError(f"{envelope_path}: not a signed job envelope ({type(e).__name__})") from e
        if not isinstance(payload, dict) or payload.get("typ") != "job" or payload.get("dry_run") is not True or payload.get("tier") not in (1, 2, 3):
            raise CtlError("selftest-bypass sends signed DRY-RUN jobs of tier 1-3 only")
        r = self.client.request("exec", {"job": env})
        res = r.get("result") if r.get("ok") else None
        refused = bool(res) and res.get("status") == "denied" and (expect is None or res.get("reason_code") == expect)
        self.emit({"sent": {"job_id": payload.get("job_id"), "op": payload.get("op"), "tier": payload.get("tier"), "dry_run": True}, "expected": expect,
                   "reason_code": (res or {}).get("reason_code"), "status": (res or {}).get("status"), "bypass_refused": refused, "reply_ok": r.get("ok")})
        return 0 if refused else 1

    def cmd_circuit_ack(self, op: str, who: str) -> int:
        """Re-enable an op whose circuit opened - only by an acknowledgement here, never by the failing caller."""
        require_root(self.euid)
        from .ledger import Ledger
        led = Ledger(self.ledger_path)                                          # an existing, initialised ledger or a refusal (M-109): never creates one
        try:
            ok = led.circuit_ack(op, who)
        finally:
            led.close()
        self.emit({"op": op, "acknowledged": ok})
        return 0 if ok else 1


def main(argv: list[str], ctl: Ctl) -> int:
    """argv[0] = subcommand. Returns the exit code; errors are printed, never raised past here."""
    cmds = {"audit-init": lambda a: ctl.cmd_audit_init(), "audit-verify": lambda a: ctl.cmd_audit_verify(), "status": lambda a: ctl.cmd_status(), "lockdown": lambda a: ctl.cmd_lockdown(),
            "audit-rotate": lambda a: ctl.cmd_audit_rotate(a[0] if a else "both"), "policy-apply": lambda a: ctl.cmd_policy_apply(a[0], a[1]),
            "unit-closure": lambda a: ctl.cmd_unit_closure(a[0], a[1]), "circuit-ack": lambda a: ctl.cmd_circuit_ack(a[0], a[1]), "selftest-bypass": lambda a: ctl.cmd_selftest_bypass(a[0], a[1] if len(a) > 1 else None),
            "audit-purge": lambda a: ctl.cmd_audit_purge(int(a[0]), int(a[1]))}
    if not argv or argv[0] not in cmds:
        sys.stderr.write("usage: privctl " + "|".join(sorted(cmds)) + " ...\n")
        return 2
    try:
        return cmds[argv[0]](argv[1:])
    except (CtlError, PrivUnavailable, AuditDown, AuditCorrupt, LedgerError, OSError, ValueError, IndexError) as e:
        sys.stderr.write(f"privctl {argv[0]}: {type(e).__name__}: {e}\n")
        return 1
