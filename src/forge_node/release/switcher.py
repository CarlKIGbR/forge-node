#!/usr/bin/python3
"""forge-node-release: the version-independent release switcher (Design 13.E). Installed OUTSIDE the release tree (/usr/local/sbin/forge-node-release) because it must be able to
switch ANY release, including a rollback to one older than itself. Stdlib only, no import from forge_node: it reads each release's RELEASE.json and drives units; nothing else.

One guard, verify_release(), stands in front of every command that changes anything (install-first, switch, self-update) and is also what `check` runs:
  * the release directory is a real, root-owned, not group/other-writable directory;
  * RELEASE.json carries a valid OWNER signature (ssh-keygen -Y verify, namespace forge-node-release, key from /etc/forge-node/allowed_signers);
  * the manifest names this release, the profile of the installed node, a switcher_api this switcher supports (else: 'run self-update'), a policy schema the INSTALLED policy fits,
    and a state-schema window that contains the ledger's PRAGMA user_version;
  * every file in the tree is listed with its sha256, nothing else is there, no symlinks, no hard links, nothing group/other-writable.
`switch` additionally refuses while a ledger row is non-terminal (re-read after the agent has been stopped, immediately before `current` is moved), moves agent, privd, units and the op
table together (they all live below `current`), starts, runs `doctor`, and goes back to the previous release by itself when doctor fails. It never edits, truncates or replaces the
ledger, the logs or the policy."""
import hashlib
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile

SWITCHER_API = 1
VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}\Z")
PRINCIPAL = "owner@forge"
NAMESPACE = "forge-node-release"
NONTERMINAL = ("received", "started", "effect_done", "reconciling")
PROFILES = ("full", "t0")
UNITS_START = ("forge-node-privd.socket", "forge-node-agent.service", "forge-node-audit-rotate.timer")


class SwitchError(Exception):
    pass


class Refused(SwitchError):
    """A guard said no; nothing was changed."""


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_nofollow(path: str, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            raise Refused(f"{path}: not a regular file or too large")
        return os.read(fd, limit + 1)
    finally:
        os.close(fd)


class Switcher:
    def __init__(self, *, base: str, root: str, ledger: str, signers: str, policy_dir: str, ssh_keygen: str, run, self_path: str, owner_uid: int, out):
        """base: /opt/forge-node as a filesystem path (a test passes a temp directory); root: the LOGICAL prefix units refer to ('/opt/forge-node'); ledger: ledger.sqlite;
        signers: allowed_signers; policy_dir: the installed policies (schema check); run(argv, timeout_s) -> (rc, out, err); self_path: where this switcher is installed.
        All required: there is no default that could stand in for a missing guard input."""
        self.base, self.root, self.ledger, self.signers, self.policy_dir = base, root, ledger, signers, policy_dir
        self.ssh_keygen, self.run, self.self_path, self.owner_uid, self.out = ssh_keygen, run, self_path, owner_uid, out

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
        """(PRAGMA user_version, non-terminal rows) read-only; (0, 0) when there is no ledger yet."""
        if not os.path.exists(self.ledger):
            return 0, 0
        try:
            c = sqlite3.connect(f"file:{self.ledger}?mode=ro", uri=True, timeout=10)
            try:
                ver = c.execute("PRAGMA user_version").fetchone()[0]
                try:
                    n = c.execute(f"SELECT COUNT(*) FROM exec WHERE state IN ({','.join('?' * len(NONTERMINAL))})", NONTERMINAL).fetchone()[0]
                except sqlite3.OperationalError:
                    n = 0
                return ver, n
            finally:
                c.close()
        except sqlite3.Error as e:
            raise Refused(f"ledger unreadable ({e}): refusing to touch anything") from e

    def installed_policy_schema(self) -> int | None:
        try:
            names = [n for n in os.listdir(self.policy_dir) if re.match(r"^policy-[1-9][0-9]{0,8}\.json\Z", n)]
        except OSError:
            return None
        if not names:
            return None
        newest = max(names, key=lambda n: int(n[7:-5]))
        try:
            doc = json.loads(_read_nofollow(os.path.join(self.policy_dir, newest), 256 * 1024))
            return doc["schema"] if isinstance(doc.get("schema"), int) else None
        except (OSError, ValueError, KeyError, SwitchError):
            return None

    # ------------------------------------------------------------------------------------------------------------------------- guard
    def verify_release(self, ver: str) -> dict:
        """THE guard. Returns the verified manifest or raises Refused. Every effect of this program is behind a call to this function."""
        d = self.rel_dir(ver)
        st = os.lstat(d) if os.path.lexists(d) else None
        if st is None or not stat.S_ISDIR(st.st_mode) or st.st_uid != self.owner_uid or st.st_mode & 0o022:
            raise Refused(f"release {ver}: not a root-owned directory that only root can write")
        raw = _read_nofollow(os.path.join(d, "RELEASE.json"), 1 << 20)
        sig = _read_nofollow(os.path.join(d, "RELEASE.json.sig"), 16 * 1024)
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
        if installed is not None and installed != m["profile"]:
            raise Refused(f"profile mismatch: this node is '{installed}', the release is '{m['profile']}'")
        ints = ("switcher_api", "state_min", "state_max", "policy_schema")
        if any(isinstance(m[k], bool) or not isinstance(m[k], int) or m[k] < 0 for k in ints) or m["state_min"] > m["state_max"]:
            raise Refused("RELEASE.json: bad integers")
        if m["switcher_api"] > SWITCHER_API:
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
        for dirpath, dirnames, filenames in os.walk(d, followlinks=False):
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
            return _read_nofollow(self.profile_file, 16).decode().strip() or None
        except (OSError, SwitchError):
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
        self.out.write(json.dumps(doc, sort_keys=True, indent=1) + "\n")

    # --------------------------------------------------------------------------------------------------------------------- commands
    def show_status(self) -> int:
        schema, open_rows = self.ledger_schema_and_open()
        rels = sorted(os.listdir(os.path.join(self.base, "releases"))) if os.path.isdir(os.path.join(self.base, "releases")) else []
        self.say({"current": self.current(), "previous": self._link_target(self.previous_link), "profile": self.installed_profile(), "switcher_api": SWITCHER_API,
                  "state_schema": schema, "non_terminal_rows": open_rows, "installed_policy_schema": self.installed_policy_schema(), "releases": rels})
        return 0

    def cmd_check(self, ver: str) -> int:
        m = self.verify_release(ver)
        self.say({"release": ver, "ok": True, "profile": m["profile"], "state_window": [m["state_min"], m["state_max"]], "policy_schema": m["policy_schema"], "files": len(m["files"])})
        return 0

    def cmd_install_first(self, ver: str) -> int:
        m = self.verify_release(ver)
        if os.path.lexists(self.current_link):
            raise Refused("a release is already current: use 'switch'")
        fd = os.open(self.profile_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        try:
            os.write(fd, m["profile"].encode() + b"\n")
        finally:
            os.close(fd)
        self._repoint(self.current_link, os.path.join("releases", ver))
        self._link_units(m)
        self.say({"installed": ver, "profile": m["profile"], "started": False})
        return 0

    def _quiesce_and_check_ledger(self) -> None:
        self._systemctl("stop", "forge-node-agent.service")
        _, n = self.ledger_schema_and_open()                           # re-read NOW, after the agent can no longer cause work (G28)
        if n:
            self._systemctl("start", "forge-node-agent.service")
            raise Refused(f"{n} ledger row(s) are not terminal: a switch (or rollback) while an op is in flight would orphan its worker")

    def _activate(self, ver: str, m: dict) -> None:
        prev = self.current()
        self._systemctl("stop", "forge-node-privd.service", "forge-node-privd.socket", "forge-node-audit-rotate.timer")
        if prev and prev != ver:
            self._repoint(self.previous_link, os.path.join("releases", prev))
        self._repoint(self.current_link, os.path.join("releases", ver))
        self._link_units(m)
        self._systemctl("start", *UNITS_START)

    def _doctor(self) -> bool:
        rc, out, err = self.run(["/usr/bin/runuser", "-u", "forgenode", "--", "/usr/bin/python3", "-I", f"{self.root}/current/forge-node.pyz", "doctor"], None, 300)
        return rc == 0

    def cmd_switch(self, ver: str) -> int:
        m = self.verify_release(ver)
        prev = self.current()
        if prev is None:
            raise Refused("no release is current: use 'install-first'")
        if prev == ver:
            raise Refused("that release is already current")
        self._quiesce_and_check_ledger()
        self._activate(ver, m)
        if self._doctor():
            self.say({"switched": ver, "from": prev, "doctor": "ok"})
            return 0
        # doctor failed: back to the previous release (verified again - the guard is not skipped on the way back)
        pm = self.verify_release(prev)
        self._quiesce_and_check_ledger()
        self._activate(prev, pm)
        self.say({"switched": None, "attempted": ver, "restored": prev, "doctor": "failed", "restored_doctor": "ok" if self._doctor() else "failed"})
        return 1

    def cmd_self_update(self, ver: str) -> int:
        m = self.verify_release(ver)
        src = os.path.join(self.rel_dir(ver), "sbin", "forge-node-release")
        if m["files"].get("sbin/forge-node-release") is None:
            raise Refused("the release carries no switcher")
        if m["switcher_api"] < SWITCHER_API:
            raise Refused("refusing to downgrade the switcher")
        data = _read_nofollow(src, 1 << 20)
        if hashlib.sha256(data).hexdigest() != m["files"]["sbin/forge-node-release"]:
            raise Refused("the release's switcher differs from its manifest")
        tmp = self.self_path + ".new"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o755)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(tmp, 0o755)
        if os.path.exists(self.self_path):
            os.replace(self.self_path, self.self_path + ".prev")        # rollback of the switcher itself: mv forge-node-release.prev forge-node-release
        os.rename(tmp, self.self_path)
        self.say({"switcher_updated_from_release": ver, "previous_kept_as": self.self_path + ".prev"})
        return 0


def run_cmd(argv, stdin, timeout_s):
    try:
        r = subprocess.run(argv, input=stdin if stdin is not None else b"", capture_output=True, timeout=timeout_s, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}, check=False)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return 124, b"", b"timeout"


def main(argv, sw: Switcher) -> int:
    cmds = {"status": lambda a: sw.show_status(), "check": lambda a: sw.cmd_check(a[0]), "switch": lambda a: sw.cmd_switch(a[0]), "install-first": lambda a: sw.cmd_install_first(a[0]),
            "self-update": lambda a: sw.cmd_self_update(a[0])}
    if not argv or argv[0] not in cmds or len(argv) != (1 if argv[0] == "status" else 2):
        sys.stderr.write("usage: forge-node-release status | check|switch|install-first|self-update <version>\n")
        return 2
    try:
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
    sw = Switcher(base="/opt/forge-node", root="/opt/forge-node", ledger="/var/lib/forge-node-priv/ledger.sqlite", signers="/etc/forge-node/allowed_signers",
                  policy_dir="/etc/forge-node/policy", ssh_keygen=ssh_keygen, run=run_cmd, self_path="/usr/local/sbin/forge-node-release", owner_uid=0, out=sys.stdout)
    return main(sys.argv[1:], sw)


if __name__ == "__main__":
    sys.exit(production())
