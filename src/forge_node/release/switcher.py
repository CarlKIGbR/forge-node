#!/usr/bin/python3 -I
"""forge-node-release: the version-independent release switcher (Design 13.E). Installed OUTSIDE the release tree (/usr/local/sbin/forge-node-release) because it must be able to
switch ANY release, including a rollback to one older than itself. Stdlib only, no import from forge_node: it reads each release's RELEASE.json and drives units; nothing else.

One guard, verify_release(), stands in front of every command that changes anything (install-first, switch, self-update) and is also what `check` runs:
  * the release directory is a real, root-owned, not group/other-writable directory;
  * RELEASE.json carries a valid OWNER signature (ssh-keygen -Y verify, namespace forge-node-release, key from /etc/forge-node/allowed_signers);
  * the manifest names this release, the profile of the installed node, a switcher_api this switcher supports (else: 'run self-update'), a policy schema the INSTALLED policy fits,
    and a state-schema window that contains the ledger's PRAGMA user_version;
  * every file in the tree is listed with its sha256, nothing else is there, no symlinks, no hard links, nothing group/other-writable.
A ledger that is missing, or has no schema, on a node that has a `current` release is a REFUSAL (M-109; 'no ledger yet' is only the state before install-first): it would otherwise read as 'no open rows'.
`doctor --after-switch` has three verdicts (M-108): ok (rc 0) keeps the release, failed (rc 1) rolls back, INDETERMINATE (rc 4: the hub answered 5xx on every attempt - neither pass nor fail) rolls back
to the known-good release too, without treating the unproven release as broken, and leaves a HOLD (RELEASE_HOLD, next to LOCAL_STOP) that refuses every further `switch` until the owner clears it with
`clear-hold`; the hold file is the escalation record to the Betriebsleiter (exit status 5).
`switch` additionally refuses while a ledger row is non-terminal (re-read after EVERYTHING that can create a row - agent, privd socket and service, the rotation timer - has been stopped,
immediately before `current` is moved), moves agent, privd, units and the op table together (they all live below `current`), starts the privd socket, runs `doctor --after-switch` against it and
only then starts the agent and the rotation timer; it goes back to the previous release by itself when ANY step after the first change fails (not only doctor). If the way back fails too,
everything is stopped AND disabled (a quiet node that a reboot does not wake up; nothing runs that nobody has verified) and the exit status says so (3). Changing commands hold an exclusive
lock and ignore SIGHUP/SIGINT/SIGTERM while they run (a dropped ssh session must not leave a node half-switched). It never edits, truncates or replaces the ledger, the logs or the policy."""
import fcntl
import hashlib
import json
import os
import re
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

SWITCHER_API = 1
VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}\Z")
PRINCIPAL = "owner@forge"
NAMESPACE = "forge-node-release"
NONTERMINAL = ("received", "started", "effect_done", "reconciling", "indeterminate")      # `indeterminate` IS here (round 3): reconcile assigns it exactly when the worker could NOT be confirmed dead, the effect lock is held from outside its cgroup, or the settle hook failed - a live worker may exist; the owner resolves the row with `privctl resolve` first
PROFILES = ("full", "t0")
DOCTOR_TIMEOUT_S = 1800                 # worst case of doctor: 14 paced selfchecks, 4 hub attempts with backoff, each selfcheck bounded by its own 150 s (N4, B10: it was 900)
UNITS_START = ("forge-node-privd.socket", "forge-node-agent.service", "forge-node-audit-rotate.timer")
UNITS_STOP = ("forge-node-agent.service", "forge-node-audit-rotate.timer", "forge-node-audit-rotate.service", "forge-node-privd.socket", "forge-node-privd.service")
ENV_LINE = re.compile(r"^(FORGE_NODE_[A-Z0-9_]{1,48})=(?:\"([A-Za-z0-9._:/@+ -]{0,256})\"|'([A-Za-z0-9._:/@+ -]{0,256})'|([A-Za-z0-9._:/@+-]{0,256}))\Z")


class SwitchError(Exception):
    pass


class LockedDown(SwitchError):
    """LOCAL_STOP (`privctl lockdown`, pause) appeared while the switch was running: nothing may be started any more (N4, B7)."""


class Refused(SwitchError):
    """A guard said no; nothing was changed."""


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_nofollow(path: str, limit: int, owner_uid: int) -> bytes:
    """Read a regular file without following a symlink: one link, owned by `owner_uid`, not writable by group/others (checked on the open descriptor). No default: no caller can skip it."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            raise Refused(f"{path}: not a regular file or too large")
        if st.st_nlink != 1 or st.st_uid != owner_uid or st.st_mode & 0o022:
            raise Refused(f"{path}: not a root-owned file with one link that only root can write")
        return os.read(fd, limit + 1)
    finally:
        os.close(fd)


class Switcher:
    def __init__(self, *, base: str, root: str, ledger: str, signers: str, policy_dir: str, node_env: str, local_stop: str, hold_path: str, lock_path: str, trust_anchor: str, ssh_keygen: str, runuser: str, run,
                 self_path: str, owner_uid: int, out):
        """base: /opt/forge-node as a filesystem path (a test passes a temp directory); root: the LOGICAL prefix units refer to ('/opt/forge-node'); ledger: ledger.sqlite;
        signers: allowed_signers; policy_dir: the installed policies (schema check); node_env: /etc/forge-node/node.env (what `doctor` needs, exactly as the agent unit gets it); runuser: the util-linux binary (/usr/sbin/runuser on Ubuntu - NOT /usr/bin);
        local_stop: /etc/forge-node/LOCAL_STOP (a switch is refused while it exists); hold_path: /etc/forge-node/RELEASE_HOLD (written after an INDETERMINATE doctor; a switch is refused while it exists); lock_path: the lock file of changing commands; trust_anchor: '/' (a test passes its temp root) - every directory from
        the release tree, `allowed_signers` and the policy up to it must be root-owned and not writable by others;
        run(argv, stdin, timeout_s) -> (rc, out, err); self_path: where this switcher is installed.
        All required: there is no default that could stand in for a missing guard input."""
        self.base, self.root, self.ledger, self.signers, self.policy_dir, self.node_env = base, root, ledger, signers, policy_dir, node_env
        self.local_stop, self.hold_path, self.lock_path, self.trust_anchor = local_stop, hold_path, lock_path, trust_anchor
        self.ssh_keygen, self.runuser, self.run, self.self_path, self.owner_uid, self.out = ssh_keygen, runuser, run, self_path, owner_uid, out

    def chain_trusted(self, path: str, what: str) -> None:
        """Every directory from `path` up to the trust anchor is a real directory, owned by root, not writable by group/others."""
        d, anchor = os.path.abspath(path), os.path.abspath(self.trust_anchor)
        if d != anchor and not d.startswith(anchor.rstrip("/") + "/"):
            raise Refused(f"{what}: {d} is not below the trust anchor {anchor}")
        while True:
            try:
                st = os.lstat(d)
            except OSError as e:
                raise Refused(f"{what}: {d} cannot be examined ({type(e).__name__})") from e
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != self.owner_uid or st.st_mode & 0o022:
                raise Refused(f"{what}: {d} is not a root-owned directory that only root can write")
            if d == anchor:
                return
            d = os.path.dirname(d)

    def locked(self):
        """Context manager of a CHANGING command: exclusive non-blocking flock, and SIGHUP/SIGINT/SIGTERM/SIGQUIT/SIGUSR1/SIGUSR2 swallowed for its duration. A HANDLER, not SIG_IGN: an ignored
        signal stays ignored across exec, and the children (systemctl, runuser, doctor) must not inherit a refusal to die when they are stopped."""
        sw = self

        class _Lock:
            def __enter__(self):
                self.fd = os.open(sw.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                try:
                    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    os.close(self.fd)
                    raise Refused("another forge-node-release is running (lock held): wait for it") from None
                self.old = {sig: signal.signal(sig, lambda _s, _f: None) for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGQUIT, signal.SIGUSR1, signal.SIGUSR2)}
                return self

            def __exit__(self, *a):
                for sig, h in self.old.items():
                    signal.signal(sig, h)
                os.close(self.fd)
        return _Lock()

    # ------------------------------------------------------------------------------------------------------------------------ paths
    def rel_dir(self, ver: str) -> str:
        if not VERSION_RE.match(ver):
            raise Refused("invalid version string")
        return os.path.join(self.base, "releases", ver)

    @property
    def current_link(self) -> str:
        return os.path.join(self.base, "current")

    @property
    def previous_link(self) -> str:
        return os.path.join(self.base, "previous")

    @property
    def profile_file(self) -> str:
        return os.path.join(self.base, "profile")

    def _link_target(self, link: str) -> str | None:
        try:
            return os.path.basename(os.readlink(link))
        except OSError:
            return None

    def current(self) -> str | None:
        return self._link_target(self.current_link)

    # ------------------------------------------------------------------------------------------------------------------------ state
    def ledger_schema_and_open(self) -> tuple[int, int]:
        """(PRAGMA user_version, non-terminal rows) read-only. (0, 0) ONLY while no release is installed yet (install-first / check before the install); once a release is `current` a missing
        or schema-less ledger is a refusal (M-109): it would read as 'no open rows' and hide a deleted or replaced file."""
        installed = self.current() is not None
        if not os.path.lexists(self.ledger):
            if installed:
                raise Refused(f"ledger {self.ledger} is missing on an installed node: refusing to read 'no open rows' from nothing (the install creates it with `privctl audit-init`; a deleted one is damage - tell the Betriebsleiter)")
            return 0, 0
        try:
            c = sqlite3.connect(f"file:{self.ledger}?mode=ro", uri=True, timeout=10)
            try:
                ver = c.execute("PRAGMA user_version").fetchone()[0]
                try:
                    n = c.execute(f"SELECT COUNT(*) FROM exec WHERE state IN ({','.join('?' * len(NONTERMINAL))})", NONTERMINAL).fetchone()[0]
                except sqlite3.OperationalError as e:
                    if ver == 0 and not installed:
                        return 0, 0                                     # a ledger file nobody has initialised yet, before the install
                    raise Refused(f"ledger (schema {ver}) has no readable exec table ({e}): refusing to count 'no open rows'") from e
                return ver, n
            finally:
                c.close()
        except sqlite3.Error as e:
            raise Refused(f"ledger unreadable ({e}): refusing to touch anything") from e

    def installed_policy_schema(self) -> int | None:
        """Schema of the newest installed policy; None only when NO policy is installed (a fresh node). A policy that is there but cannot be read or has no schema is a refusal:
        'unknown' must not pass a compatibility check."""
        try:
            names = [n for n in os.listdir(self.policy_dir) if re.match(r"^policy-[1-9][0-9]{0,8}\.json\Z", n)]
        except FileNotFoundError:
            if self.current() is not None:                           # N4 (B9): the install creates the directory (13.C C3); gone on an installed node = damage, not "no policy yet"
                raise Refused(f"policy directory {self.policy_dir} is missing on an installed node: refusing to read 'no policy' from nothing") from None
            return None
        except OSError as e:
            raise Refused(f"policy directory unreadable ({e})") from e
        self.chain_trusted(self.policy_dir, "policy directory")
        if not names:
            return None
        newest = max(names, key=lambda n: int(n[7:-5]))
        try:
            doc = json.loads(_read_nofollow(os.path.join(self.policy_dir, newest), 256 * 1024, self.owner_uid))
            schema = doc["schema"]
        except (OSError, ValueError, KeyError, TypeError) as e:
            raise Refused(f"the installed policy {newest} cannot be read ({type(e).__name__}): refusing to judge compatibility") from e
        if isinstance(schema, bool) or not isinstance(schema, int):
            raise Refused(f"the installed policy {newest} has no integer schema")
        return schema

    # ------------------------------------------------------------------------------------------------------------------------- guard
    def verify_release(self, ver: str, self_update: bool) -> dict:
        """THE guard. Returns the verified manifest or raises Refused. Every effect of this program is behind a call to this function. `self_update` (required, no default) skips exactly ONE
        check - that this switcher is new enough for the release (switcher_api) - because that is the very condition self-update exists to cure; everything else is checked."""
        d = self.rel_dir(ver)
        for anc in (self.base, os.path.join(self.base, "releases"), d):
            st = os.lstat(anc) if os.path.lexists(anc) else None
            if st is None or not stat.S_ISDIR(st.st_mode) or st.st_uid != self.owner_uid or st.st_mode & 0o022:
                raise Refused(f"{anc}: not a root-owned directory that only root can write")
        self.chain_trusted(os.path.dirname(self.base), "/opt/forge-node")
        self.chain_trusted(os.path.dirname(self.signers), "allowed_signers")
        _read_nofollow(self.signers, 1 << 20, self.owner_uid)                       # the trust anchor itself: root-owned, one link, not writable by anyone else
        raw = _read_nofollow(os.path.join(d, "RELEASE.json"), 1 << 20, self.owner_uid)
        sig = _read_nofollow(os.path.join(d, "RELEASE.json.sig"), 16 * 1024, self.owner_uid)
        self._verify_signature(raw, sig)
        try:
            m = json.loads(raw)
        except ValueError as e:
            raise Refused("RELEASE.json is not valid JSON") from e
        need = {"fmt", "release", "profile", "switcher_api", "state_min", "state_max", "policy_schema", "units", "files"}
        if not isinstance(m, dict) or set(m) != need or m["fmt"] != 1:
            raise Refused("RELEASE.json: unexpected fields")
        if m["release"] != ver:
            raise Refused("RELEASE.json names another release than its directory")
        if m["profile"] not in PROFILES:
            raise Refused("unknown profile")
        installed = self.installed_profile()
        if installed is None and self.current() is not None:
            raise Refused("a release is current but the node's profile file is missing or unreadable: refusing to compare against 'unknown'")
        if installed is not None and installed != m["profile"]:
            raise Refused(f"profile mismatch: this node is '{installed}', the release is '{m['profile']}'")
        ints = ("switcher_api", "state_min", "state_max", "policy_schema")
        if any(isinstance(m[k], bool) or not isinstance(m[k], int) or m[k] < 0 for k in ints) or m["state_min"] > m["state_max"]:
            raise Refused("RELEASE.json: bad integers")
        if m["switcher_api"] > SWITCHER_API and not self_update:
            raise Refused(f"the release needs switcher_api {m['switcher_api']} (this switcher: {SWITCHER_API}): run 'sudo forge-node-release self-update {ver}'")
        schema, _ = self.ledger_schema_and_open()
        if schema and not m["state_min"] <= schema <= m["state_max"]:
            raise Refused(f"state schema {schema} is outside the window {m['state_min']}..{m['state_max']} of release {ver}")
        ps = self.installed_policy_schema()
        if ps is not None and ps > m["policy_schema"]:
            raise Refused(f"the installed policy has schema {ps}, release {ver} supports up to {m['policy_schema']}")
        if not isinstance(m["files"], dict) or not isinstance(m["units"], list):
            raise Refused("RELEASE.json: files/units")
        self._verify_tree(d, m["files"])
        for u in m["units"]:
            if not isinstance(u, str) or not re.match(r"^forge-node-[a-z-]+\.(service|socket|timer)\Z", u) or f"units/{u}" not in m["files"]:
                raise Refused(f"unit {u!r} is not a listed forge-node unit")
        return m

    def _verify_signature(self, raw: bytes, sig: bytes) -> None:
        with tempfile.TemporaryDirectory(prefix="fn-rel-") as t:
            os.chmod(t, 0o700)
            sp = os.path.join(t, "sig")
            with open(sp, "wb") as f:
                f.write(sig)
            rc, out, err = self.run([self.ssh_keygen, "-Y", "verify", "-f", self.signers, "-I", PRINCIPAL, "-n", NAMESPACE, "-s", sp], raw, 30)
        if rc != 0 or b'Good "' + NAMESPACE.encode() + b'" signature for ' + PRINCIPAL.encode() not in out:
            raise Refused("RELEASE.json: the owner signature does not verify")

    def _verify_tree(self, d: str, files: dict) -> None:
        seen = set()
        def fail(e):
            raise Refused(f"cannot scan the release tree ({e})")
        for dirpath, dirnames, filenames in os.walk(d, followlinks=False, onerror=fail):
            for n in dirnames:
                st = os.lstat(os.path.join(dirpath, n))
                if stat.S_ISLNK(st.st_mode) or st.st_uid != self.owner_uid or st.st_mode & 0o022:
                    raise Refused(f"{os.path.relpath(os.path.join(dirpath, n), d)}: directory is a link or not root-controlled")
            for n in filenames:
                p = os.path.join(dirpath, n)
                rel = os.path.relpath(p, d)
                if rel in ("RELEASE.json", "RELEASE.json.sig"):
                    continue
                st = os.lstat(p)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != self.owner_uid or st.st_mode & 0o022:
                    raise Refused(f"{rel}: not a regular root-owned file with one link that only root can write")
                want = files.get(rel)
                if want is None:
                    raise Refused(f"{rel}: not listed in RELEASE.json")
                if _sha256_file(p) != want:
                    raise Refused(f"{rel}: content differs from RELEASE.json")
                seen.add(rel)
        missing = sorted(set(files) - seen)
        if missing:
            raise Refused(f"listed but missing: {missing[:3]}")

    def installed_profile(self) -> str | None:
        try:
            return _read_nofollow(self.profile_file, 16, self.owner_uid).decode().strip() or None
        except (OSError, SwitchError, UnicodeDecodeError):
            return None

    # ----------------------------------------------------------------------------------------------------------------------- helpers
    def _systemctl(self, *args: str) -> None:
        rc, out, err = self.run(["/usr/bin/systemctl", *args], None, 120)
        if rc != 0:
            raise SwitchError(f"systemctl {' '.join(args)} failed: {err.decode('utf-8', 'replace')[:200]}")

    def _repoint(self, link: str, target: str) -> None:
        tmp = link + ".new"
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        os.symlink(target, tmp)
        os.rename(tmp, link)

    def _link_units(self, manifest: dict) -> None:
        for u in manifest["units"]:
            self._systemctl("link", f"{self.root}/current/units/{u}")
        self._systemctl("daemon-reload")

    def say(self, doc: dict) -> None:
        """A dead stdout (dropped ssh session) must change neither the verdict nor the exit status: the report is best effort, the state of the node is not."""
        try:
            self.out.write(json.dumps(doc, sort_keys=True, indent=1) + "\n")
        except OSError:
            pass

    # --------------------------------------------------------------------------------------------------------------------- commands
    def show_status(self) -> int:
        rels = sorted(os.listdir(os.path.join(self.base, "releases"))) if os.path.isdir(os.path.join(self.base, "releases")) else []
        doc = {"current": self.current(), "previous": self._link_target(self.previous_link), "profile": self.installed_profile(), "switcher_api": SWITCHER_API, "releases": rels,
               "hold": self.read_hold()}
        for key, fn in (("ledger", lambda: dict(zip(("state_schema", "non_terminal_rows"), self.ledger_schema_and_open()))), ("installed_policy_schema", self.installed_policy_schema)):
            try:
                doc[key] = fn()
            except Refused as e:
                doc[key] = f"UNREADABLE: {e}"                                  # status reports it; every changing command refuses on it
        self.say(doc)
        return 0

    def cmd_check(self, ver: str) -> int:
        m = self.verify_release(ver, False)
        self.say({"release": ver, "ok": True, "profile": m["profile"], "state_window": [m["state_min"], m["state_max"]], "policy_schema": m["policy_schema"], "files": len(m["files"])})
        return 0

    def cmd_install_first(self, ver: str) -> int:
        if os.path.lexists(self.current_link):
            raise Refused("a release is already current: use 'switch'")
        m = self.verify_release(ver, False)
        fd = os.open(self.profile_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        try:
            os.write(fd, m["profile"].encode() + b"\n")
        finally:
            os.close(fd)
        try:
            self._repoint(self.current_link, os.path.join("releases", ver))
            self._link_units(m)
        except (SwitchError, OSError):
            for leftover in (self.current_link, self.profile_file):               # a failed first install must be repeatable, not "already current"
                try:
                    os.unlink(leftover)
                except OSError:
                    pass
            raise
        self.say({"installed": ver, "profile": m["profile"], "started": False})
        return 0

    def _lockdown(self) -> bool:
        return os.path.lexists(self.local_stop)

    def _active_units(self) -> list[str]:
        """The units of UNITS_START that are active (or may be: an answer that is not an explicit 'inactive/failed/unknown' counts as active)."""
        up = []
        for u in UNITS_START:
            try:
                rc, out, _ = self.run(["/usr/bin/systemctl", "is-active", u], None, 30)
                state = out.decode("utf-8", "replace").strip()
            except OSError:
                rc, state = 1, ""
            if state not in ("inactive", "failed", "unknown"):
                up.append(u)
        return up

    def _stop_all(self) -> None:
        """Stop agent, timer, rotation service, privd socket and service. A node left quiet by `_safe_stop` has its units DISABLED (links removed), so `stop` of an unloaded unit fails: that is
        'already stopped', not a refusal - but only when every unit explicitly says inactive/failed/unknown (an empty or odd answer stays a refusal)."""
        try:
            self._systemctl("stop", *UNITS_STOP)
        except SwitchError:
            for u in UNITS_STOP:
                rc, out, _ = self.run(["/usr/bin/systemctl", "is-active", u], None, 30)
                if out.decode("utf-8", "replace").strip() not in ("inactive", "failed", "unknown"):
                    raise

    def _quiesce_and_check_ledger(self, *, restart_on_refusal: bool) -> None:
        """Stop everything that can create or change a ledger row (agent, rotation timer and service, privd socket and service), THEN read the ledger (G28: the observation that decides
        the switch is made after the last thing that could change it has stopped). Open rows - or a stop that did not work - : refuse. `restart_on_refusal` is True only BEFORE the first change
        (start again what was running before - and only that: a node left quiet by an earlier failure stays quiet); on the way back `current` points at the release that just failed, so nothing is started - the caller leaves a quiet node."""
        was_active = self._active_units() if restart_on_refusal else []
        try:
            self._stop_all()
            _, n = self.ledger_schema_and_open()
        except SwitchError as e:
            if restart_on_refusal:
                self._best_effort_start(was_active)
            if isinstance(e, Refused):
                raise
            raise Refused(f"the node could not be quiesced ({e})" + ("; what was running was started again, nothing was changed" if restart_on_refusal else "")) from e
        if n:
            if restart_on_refusal:
                self._best_effort_start(was_active)
            raise Refused(f"{n} ledger row(s) are not terminal (received/started/effect_done/reconciling/indeterminate; an `indeterminate` row is resolved by root with the privd `reconcile` request carrying `resolve` - there is no privctl wrapper for it yet): a switch (or rollback) while an op is in flight would orphan its worker")

    def _best_effort_start(self, units) -> None:
        if not units or self._lockdown():
            return
        try:
            self._systemctl("start", *units)
        except (SwitchError, OSError):
            pass

    def _activate(self, ver: str, m: dict) -> None:
        """Move `current`, link the units and start ONLY the privd socket: doctor needs nothing else, and the agent must not run a release nobody has checked yet."""
        prev = self.current()
        if prev and prev != ver:
            self._repoint(self.previous_link, os.path.join("releases", prev))
        self._repoint(self.current_link, os.path.join("releases", ver))
        self._link_units(m)
        if self._lockdown():
            raise LockedDown(f"{self.local_stop} appeared during the switch")
        self._systemctl("start", UNITS_START[0])

    def _start_rest(self) -> None:
        """The release passed doctor: enable (idempotent; a STOPPED node had its units disabled) and start the agent and the rotation timer."""
        if self._lockdown():                                     # B7: `privctl lockdown` ran while doctor was running - the switch must not undo it
            raise LockedDown(f"{self.local_stop} appeared during the switch")
        self._systemctl("enable", *UNITS_START)
        self._systemctl("start", *UNITS_START)

    def doctor_env(self) -> list[str]:
        """The environment `doctor` needs, from node.env exactly as the agent unit gets it (EnvironmentFile): only well-formed FORGE_NODE_* assignments (optionally quoted); FORGE_NODE_NODE_ID is
        required. Read BEFORE anything is changed, so a node without it is refused up front instead of failing doctor after the switch."""
        try:
            raw = _read_nofollow(self.node_env, 64 * 1024, self.owner_uid).decode("utf-8")
        except (OSError, UnicodeDecodeError) as e:
            raise Refused(f"{self.node_env} cannot be read ({type(e).__name__})") from e
        env = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            mt = ENV_LINE.match(line)
            if mt is None:
                raise Refused(f"{self.node_env}: line not understood: {line[:40]!r}")
            env.append(f"{mt.group(1)}={next(g for g in mt.groups()[1:] if g is not None)}")
        if not any(e.startswith("FORGE_NODE_NODE_ID=") for e in env):
            raise Refused(f"{self.node_env} has no FORGE_NODE_NODE_ID")
        return env

    def read_hold(self):
        """None, or the hold record as text-safe dict. Anything at the path counts as a hold - a symlink, an unreadable or malformed file too (fail closed)."""
        if not os.path.lexists(self.hold_path):
            return None
        try:
            return json.loads(_read_nofollow(self.hold_path, 16 * 1024, self.owner_uid))
        except (OSError, ValueError, SwitchError):
            return {"kind": "unreadable", "note": f"{self.hold_path} exists but cannot be read as a hold record"}

    def _write_hold(self, doc: dict) -> str | None:
        """The escalation record: written atomically (new file, fsync, rename) into the root-owned directory of LOCAL_STOP. Returns an error text instead of raising: the way back has already
        happened and must be reported either way."""
        tmp = self.hold_path + ".new"
        try:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            try:
                os.write(fd, (json.dumps(doc, sort_keys=True, indent=1) + "\n").encode())
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(tmp, self.hold_path)
            return None
        except OSError as e:
            return f"{type(e).__name__}: {e}"

    def cmd_clear_hold(self) -> int:
        """The owner's deliberate release of the hold, after the hub is back and `doctor` was run by hand. Says what it removed."""
        hold = self.read_hold()
        if hold is None:
            raise Refused("there is no hold")
        os.unlink(self.hold_path)
        self.say({"hold_cleared": hold})
        return 0

    def _doctor(self, env: list[str]) -> tuple[str, str]:
        """-> ("ok" | "failed" | "indeterminate", why). INDETERMINATE needs BOTH exit status 4 and doctor's own verdict line: any other non-zero status (a crash, a timeout = 124) is a failure."""
        argv = [self.runuser, "-u", "forgenode", "--", "/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", *env,
                "/usr/bin/python3", "-I", f"{self.root}/current/forge-node.pyz", "doctor", "--after-switch"]
        rc, out, err = self.run(argv, None, DOCTOR_TIMEOUT_S)
        text = (out + err).decode("utf-8", "replace")
        if rc == 0:
            return "ok", ""
        if rc == 4 and any('"doctor": "INDETERMINATE"' in ln for ln in text.splitlines()):
            return "indeterminate", "rc 4: " + " | ".join(ln for ln in text.splitlines() if '"status": "indeterminate"' in ln)[-1500:]
        failed = [ln for ln in text.splitlines() if '"status": "fail"' in ln or '"doctor": "FAILED"' in ln]
        return "failed", f"rc {rc}: " + " | ".join(failed)[-1500:]

    def _safe_stop(self) -> list[str]:
        """The way back failed: leave a quiet node - stopped AND disabled, so that a reboot does not start what nobody has verified (the next successful switch enables the units again).
        Returns what did NOT work: the report must not claim a quiet node it did not get."""
        failed = []
        for args in (("stop", *UNITS_STOP), ("disable", *UNITS_START)):
            try:
                self._systemctl(*args)
            except (SwitchError, OSError) as e:
                failed.append(f"{args[0]}: {e}")
        return failed

    def cmd_switch(self, ver: str, one_way: bool) -> int:
        """`one_way` (required): the owner accepts that the new release's state window is wider than the current one, i.e. that the first start of its privd may move the ledger schema to a version
        the current release cannot read - after which a failed doctor has NO way back and ends in a stopped, disabled node. Without it such a switch is refused before the first change."""
        hold = self.read_hold()
        if hold is not None:
            raise Refused(f"{self.hold_path} exists: a previous switch ended INDETERMINATE ({hold.get('attempted', '?')} could not be judged, the node stayed on {hold.get('known_good', '?')}); "
                          "no further switch until the owner has looked at it (`doctor` by hand) and removed the hold with `forge-node-release clear-hold`")
        m = self.verify_release(ver, False)
        prev = self.current()
        if prev is None:
            raise Refused("no release is current: use 'install-first'")
        if prev == ver:
            raise Refused("that release is already current")
        if os.path.lexists(self.local_stop):
            raise Refused(f"{self.local_stop} exists (pause or lockdown): a switch would start the agent, the socket and the timer again - remove it deliberately first")
        pm = self.verify_release(prev, False)                         # the way back must be walkable BEFORE the first change, not discovered afterwards
        way_back = m["state_max"] <= pm["state_max"] and m["state_min"] >= pm["state_min"]
        if not way_back and not one_way:
            raise Refused(f"release {ver} has the state window {m['state_min']}..{m['state_max']}, the current {prev} has {pm['state_min']}..{pm['state_max']}: after the new privd has opened the ledger "
                          "the way back is closed. Use 'switch --one-way <version>' to accept that")
        env = self.doctor_env()
        old_previous = self._link_target(self.previous_link)
        self._quiesce_and_check_ledger(restart_on_refusal=True)
        failure = None
        undecided = False
        try:
            self._activate(ver, m)
            verdict, why = self._doctor(env)
            if verdict == "ok":
                self._start_rest()
                done = {"switched": ver, "from": prev, "doctor": "ok", "rollback_possible": way_back}
            else:
                done = None
                undecided = verdict == "indeterminate"
                failure = f"doctor {'INDETERMINATE' if undecided else 'failed'} ({why})"
        except (SwitchError, OSError) as e:
            done = None
            failure = f"{type(e).__name__}: {e}"
        if done is not None:
            self.say(done)                                          # outside the try: a dead stdout after a good switch must not roll it back
            return 0
        # ANY failure after the first change: back to the previous release (verified again - the guard is not skipped on the way back)
        try:
            pm = self.verify_release(prev, False)
            self._quiesce_and_check_ledger(restart_on_refusal=False)
            self._activate(prev, pm)
            verdict, why = self._doctor(env)
            if verdict == "failed":
                raise SwitchError(f"the restored release {prev} fails doctor too ({why})")
            if verdict == "indeterminate":                              # the known-good release cannot be judged while the hub answers 5xx: it was proven before, it stays (M-108)
                undecided = True
                failure = f"{failure}; the restored release {prev} could not be judged either ({why})"
            self._start_rest()
            if old_previous is not None:                                # `previous` must not point at the release we just took back
                self._repoint(self.previous_link, os.path.join("releases", old_previous))
            else:
                try:
                    os.unlink(self.previous_link)
                except FileNotFoundError:
                    pass
        except (SwitchError, OSError) as e:
            not_quiet = self._safe_stop()
            state = (f"LOCKDOWN ({self.local_stop} appeared during the switch): nothing was started, everything is stopped and disabled; current -> {self.current()}; remove LOCAL_STOP deliberately, then 'switch'" if isinstance(e, LockedDown) and not not_quiet else
                     f"STOPPED and disabled: nothing is running; current -> {self.current()}; fix, then 'switch' (it enables the units again) or 'check' a release" if not not_quiet else
                     f"NOT CONFIRMED STOPPED ({'; '.join(not_quiet)}): units of the release that FAILED may still be running; current -> {self.current()}; stop them by hand before anything else")
            self.say({"switched": None, "attempted": ver, "failure": failure, "restored": None, "restore_error": f"{type(e).__name__}: {e}", "state": state})
            return 3
        if undecided:
            # M-108: neither pass nor fail. The known-good release runs again (it was proven before this switch, the hub's 5xx says nothing against it); the unproven one is not kept, and nothing
            # more is switched until the owner has looked: the hold file IS the escalation record to the Betriebsleiter.
            record = {"kind": "doctor_indeterminate", "escalate_to": "betriebsleiter", "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "attempted": ver, "known_good": prev,
                      "reason": failure, "state": f"node runs the known-good release {prev}; no further switch until `forge-node-release clear-hold`"}
            held = self._write_hold(record)
            self.say({"switched": None, "attempted": ver, "failure": failure, "restored": prev, "restored_doctor": "indeterminate", "state": "INDETERMINATE", "escalation": record,
                      "hold": self.hold_path if held is None else f"NOT WRITTEN ({held}): the escalation is this output only - tell the Betriebsleiter"})
            return 5
        self.say({"switched": None, "attempted": ver, "failure": failure, "restored": prev, "restored_doctor": "ok"})
        return 1

    def cmd_self_update(self, ver: str) -> int:
        m = self.verify_release(ver, True)
        src = os.path.join(self.rel_dir(ver), "sbin", "forge-node-release")
        if m["files"].get("sbin/forge-node-release") is None:
            raise Refused("the release carries no switcher")
        if m["switcher_api"] < SWITCHER_API:
            raise Refused("refusing to downgrade the switcher")
        data = _read_nofollow(src, 1 << 20, self.owner_uid)
        if hashlib.sha256(data).hexdigest() != m["files"]["sbin/forge-node-release"]:
            raise Refused("the release's switcher differs from its manifest")
        tmp = self.self_path + ".new"
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(tmp, 0o755)
        if os.path.exists(self.self_path):
            # keep the old switcher as .prev WITHOUT a moment in which self_path does not exist: hard-link it under a temporary name, move that over .prev, then rename the new file
            # over self_path (atomic). Rollback of the switcher itself: mv forge-node-release.prev forge-node-release
            keep = self.self_path + ".prev.new"
            try:
                os.unlink(keep)
            except FileNotFoundError:
                pass
            os.link(self.self_path, keep)
            os.replace(keep, self.self_path + ".prev")
        os.rename(tmp, self.self_path)
        self.say({"switcher_updated_from_release": ver, "previous_kept_as": self.self_path + ".prev"})
        return 0


def run_process(argv, stdin, timeout_s):
    """Run in its own session so that a timeout kills the whole process group (runuser -> env -> python), not only the direct child (N4, B10)."""
    p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}, start_new_session=True)
    try:
        out, err = p.communicate(stdin if stdin is not None else b"", timeout=timeout_s)
        return p.returncode, out, err
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        p.communicate()
        return 124, b"", b"timeout"


def main(argv, sw: Switcher) -> int:
    cmds = {"status": lambda a: sw.show_status(), "check": lambda a: sw.cmd_check(a[0]), "switch": lambda a: sw.cmd_switch(a[-1], a[0] == "--one-way"), "install-first": lambda a: sw.cmd_install_first(a[0]),
            "self-update": lambda a: sw.cmd_self_update(a[0]), "clear-hold": lambda a: sw.cmd_clear_hold()}
    ok_len = (1 if argv[0] in ("status", "clear-hold") else 3 if argv[:2] == ["switch", "--one-way"] else 2) if argv else 0
    if not argv or argv[0] not in cmds or len(argv) != ok_len:
        sys.stderr.write("usage: forge-node-release status | check|switch|install-first|self-update <version> | switch --one-way <version> | clear-hold\n")
        return 2
    try:
        if argv[0] in ("switch", "install-first", "self-update", "clear-hold"):
            with sw.locked():
                return cmds[argv[0]](argv[1:])
        return cmds[argv[0]](argv[1:])
    except Refused as e:
        sys.stderr.write(f"refused: {e}\n")
        return 1
    except (SwitchError, OSError) as e:
        sys.stderr.write(f"failed: {type(e).__name__}: {e}\n")
        return 1


def production() -> int:
    if os.geteuid() != 0:
        sys.stderr.write("forge-node-release must run as root\n")
        return 2
    ssh_keygen = next((p for p in ("/usr/bin/ssh-keygen", "/bin/ssh-keygen") if os.path.exists(p)), None)
    if ssh_keygen is None:
        sys.stderr.write("no ssh-keygen\n")
        return 2
    runuser = next((p for p in ("/usr/sbin/runuser", "/sbin/runuser", "/usr/bin/runuser") if os.path.exists(p)), None)
    if runuser is None:
        sys.stderr.write("no runuser\n")
        return 2
    sw = Switcher(base="/opt/forge-node", root="/opt/forge-node", ledger="/var/lib/forge-node-priv/ledger.sqlite", signers="/etc/forge-node/allowed_signers",
                  policy_dir="/etc/forge-node/policy", node_env="/etc/forge-node/node.env", local_stop="/etc/forge-node/LOCAL_STOP", hold_path="/etc/forge-node/RELEASE_HOLD",
                  lock_path="/run/forge-node-release.lock", trust_anchor="/", ssh_keygen=ssh_keygen, runuser=runuser, run=run_process, self_path="/usr/local/sbin/forge-node-release", owner_uid=0, out=sys.stdout)
    return main(sys.argv[1:], sw)


if __name__ == "__main__":
    sys.exit(production())
