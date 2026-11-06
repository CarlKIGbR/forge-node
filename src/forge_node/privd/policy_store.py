"""privd's own view of the installed policy and `policy.apply` (Design 7.3, 5.3).

current():  the highest serial in the root-owned policy directory, its owner signature (namespace forge-node-policy, key from /etc/forge-node/allowed_signers) and the COMPLETE schema
            (policy_full.parse_full) - any failure means NO policy (never an older file). Cached only while every trust-relevant attribute of the files and directories is unchanged.
apply():    works on BYTES: signature, node, serial > installed, not_before <= now, schema and rules are all evaluated on the same bytes that are then installed (no re-open by path, no
            TOCTOU), the signature file first and the policy file second, each by temp+fsync+rename inside the root-owned directory (descriptor-relative). Any failure leaves the previous
            policy in force. Rollback is 'sign the old content with serial+1' (the monotonic serial)."""
import os
import stat
import threading
from datetime import datetime
from typing import Callable

from .. import canon, protocol, sshsig
from ..t0 import policy as t0policy
from ..t0.policy import MAX_POLICY_BYTES, OWNER_PRINCIPAL, PolicyError
from .policy_full import FullPolicy, parse_full

MAX_SERIAL = 999_999_999


def release_table_ops(table, build_profile: str) -> Callable[[str], frozenset]:
    """`table_ops` of the production PolicyStore. A `t0` release has no op code at all, so it can only ever run a `t0` policy: a policy that names profile `full` (forge roots, tier 1/2 ops,
    tiers > 0 once their gates are met) is refused HERE, whatever else it says - the policy's own profile must not be able to talk a T0-only release into a mode its artifact was built without."""
    def ops(policy_profile: str) -> frozenset:
        if build_profile == "t0" and policy_profile != "t0":
            raise PolicyError("DENY_POLICY_INVALID", f"this release is profile t0: a policy for profile {policy_profile!r} is refused")
        return table.names(policy_profile)
    return ops


def _stat_key(path: str):
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return None
    return (st.st_ino, st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_mode, st.st_uid, st.st_gid, st.st_nlink)


def _chain_key(path: str):
    out, d = [], os.path.abspath(path)
    while True:
        try:
            st = os.stat(d)
            out.append((d, st.st_ino, st.st_mode, st.st_uid, st.st_gid))
        except OSError:
            out.append((d, None))
        if d == "/":
            return tuple(out)
        d = os.path.dirname(d)


class PolicyStore:
    def __init__(self, *, policy_dir: str, allowed_signers: str, serial_file: str, node: str, owner_uid: int, ssh_keygen: str, clock: Callable[[], datetime], gates_map,
                 table_ops: Callable[[str], frozenset], devof: Callable[[str], int | None], protected_devs: Callable[[], set]):
        self.policy_dir, self.allowed_signers, self.serial_file = policy_dir, allowed_signers, serial_file
        self.node, self.owner_uid, self.ssh_keygen, self.clock, self.gates_map = node, owner_uid, ssh_keygen, clock, gates_map
        self.table_ops, self.devof, self.protected_devs = table_ops, devof, protected_devs
        self._lock = threading.RLock()
        self._cache: tuple | None = None

    # --------------------------------------------------------------------------------------------------------------- read
    def _key(self):
        try:
            names = sorted(n for n in os.listdir(self.policy_dir) if n.startswith("policy-"))
        except OSError:
            return None
        return (tuple((n, _stat_key(os.path.join(self.policy_dir, n))) for n in names), _stat_key(self.allowed_signers), _chain_key(self.policy_dir),
                _chain_key(os.path.dirname(self.allowed_signers)))

    def _parse(self, raw: bytes, serial: int, now: datetime) -> FullPolicy:
        return parse_full(raw, expect_node=self.node, file_serial=serial, now=now, gates_map=self.gates_map, table_ops=self.table_ops, devof=self.devof, protected_devs=self.protected_devs)

    def current(self) -> FullPolicy:
        """Raises PolicyError(DENY_POLICY_INVALID) when there is no verifiable current policy."""
        with self._lock:
            now = self.clock()
            key = self._key()
            if key is not None and self._cache is not None and self._cache[0] == key and now >= self._cache[2]:
                return self._cache[1]
            self._cache = None
            raw, serial = t0policy.load_installed_blob(self.policy_dir, self.allowed_signers, now, owner_uid=self.owner_uid, ssh_keygen=self.ssh_keygen)
            pol = self._parse(raw, serial, now)
            if key is not None and key == self._key():
                self._cache = (key, pol, protocol.parse_ts(canon.loads(raw)["not_before"]))
            return pol

    def installed_serial(self) -> int:
        n = 0
        try:
            for name in os.listdir(self.policy_dir):
                m = t0policy._NAME.match(name)
                if m:
                    n = max(n, int(m.group(1)))
        except OSError:
            pass
        try:
            fd = os.open(self.serial_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                st = os.fstat(fd)
                if stat.S_ISREG(st.st_mode) and st.st_uid == self.owner_uid and not st.st_mode & 0o022 and st.st_size < 32:
                    n = max(n, int(os.read(fd, 32).strip() or b"0"))
            finally:
                os.close(fd)
        except (OSError, ValueError):
            pass
        return n

    # -------------------------------------------------------------------------------------------------------------- apply
    def apply(self, raw: bytes, sig: str) -> FullPolicy:
        if not isinstance(raw, (bytes, bytearray)) or not isinstance(sig, str) or len(raw) > MAX_POLICY_BYTES or len(sig) > 16 * 1024:
            raise PolicyError("DENY_POLICY_INVALID", "policy blob malformed or too large")
        raw = bytes(raw)
        with self._lock:
            now = self.clock()
            try:
                signers = t0policy.read_signers(self.allowed_signers, self.owner_uid)
                sshsig.verify(raw, sig, sshsig.NS_POLICY, OWNER_PRINCIPAL, signers, self.ssh_keygen)
            except (sshsig.SigError, OSError) as e:
                raise PolicyError("DENY_POLICY_INVALID", "policy signature invalid") from e
            try:
                doc = canon.loads(raw)
                serial = doc["serial"]
            except (canon.CanonError, KeyError, TypeError) as e:
                raise PolicyError("DENY_POLICY_INVALID", "policy is not strict JSON with a serial") from e
            if isinstance(serial, bool) or not isinstance(serial, int) or not 1 <= serial <= MAX_SERIAL:
                raise PolicyError("DENY_POLICY_INVALID", "serial out of range")
            if serial <= self.installed_serial():
                raise PolicyError("DENY_POLICY_INVALID", "serial is not newer than the installed policy (rollback = sign the old content with serial+1)")
            pol = self._parse(raw, serial, now)                                    # node, not_before, schema, gate rules, apt rule, forge roots - on the very bytes to be installed
            self._install(raw, sig, serial)
            self._cache = None
            return pol

    def _install(self, raw: bytes, sig: str, serial: int) -> None:
        dfd = os.open(self.policy_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(dfd)
            if st.st_uid != self.owner_uid or st.st_mode & 0o022 or not t0policy._chain_trusted(os.path.dirname(os.path.abspath(self.policy_dir)), self.owner_uid):
                raise PolicyError("DENY_POLICY_INVALID", "policy directory is not root-controlled")
            for name, data in ((f"policy-{serial}.json.sig", sig.encode("ascii")), (f"policy-{serial}.json", raw)):       # signature first: a visible policy always has its signature
                tmp = f".tmp-{serial}-{'sig' if name.endswith('.sig') else 'json'}"
                try:
                    os.unlink(tmp, dir_fd=dfd)
                except FileNotFoundError:
                    pass
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
                try:
                    os.fchmod(fd, 0o644)
                    os.fchown(fd, self.owner_uid, -1)
                    view = memoryview(data)
                    while view:
                        view = view[os.write(fd, view):]
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
            os.fsync(dfd)
        finally:
            os.close(dfd)
        sdir = os.path.dirname(self.serial_file)
        sfd = os.open(sdir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            tmp = ".serial.tmp"
            try:
                os.unlink(tmp, dir_fd=sfd)
            except FileNotFoundError:
                pass
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=sfd)
            try:
                os.write(fd, str(serial).encode() + b"\n")
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(tmp, os.path.basename(self.serial_file), src_dir_fd=sfd, dst_dir_fd=sfd)
            os.fsync(sfd)
        finally:
            os.close(sfd)
