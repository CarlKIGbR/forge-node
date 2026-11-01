"""The hub-signed lease as privd holds it (Design 3.2, 3.4, 9.1). privd verifies the lease ITSELF - the agent merely carries it - so 'STOP knowledge' is never an agent claim.

put():     signature (gate keys of the CURRENT policy, namespace forge-node-hub), node, validity, skew and a strictly increasing `seq` (the highest seq ever accepted is persisted in the
           ledger, so a restart cannot be used to replay an older lease); the envelope is stored in /run/forge-node (tmpfs: a reboot clears it, fail-closed until a new lease).
current(): re-verifies the stored envelope against the gate keys of the policy in force NOW (a revoked key invalidates the lease at once); freshness is the caller's decision."""
import os
import stat
import threading
from datetime import datetime
from typing import Callable

from .. import canon, protocol
from ..protocol import ProtoError

MAX_ENVELOPE = 70 * 1024


class LeaseStore:
    def __init__(self, *, path: str, ledger, node: str, ssh_keygen: str, clock: Callable[[], datetime], owner_uid: int):
        self.path, self.ledger, self.node, self.ssh_keygen, self.clock, self.owner_uid = path, ledger, node, ssh_keygen, clock, owner_uid
        self._lock = threading.RLock()
        self._cache = None

    def put(self, env, gate_keys) -> dict:
        with self._lock:
            now = self.clock()
            last = int(self.ledger.meta_get("lease_seq", "0"))
            p = protocol.verify_lease(env, gate_keys, self.node, now, last, self.ssh_keygen)
            if self.ledger.meta_set_max_int("lease_seq", p["seq"]) != p["seq"]:
                raise ProtoError("DENY_STALE_LEASE", "lease seq not newer")
            self._store(env)
            self._cache = None
            return p

    def _store(self, env) -> None:
        d = os.path.dirname(self.path)
        dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            tmp = ".lease.tmp"
            try:
                os.unlink(tmp, dir_fd=dfd)
            except FileNotFoundError:
                pass
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
            try:
                os.write(fd, canon.canonical(env) + b"\n")
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(tmp, os.path.basename(self.path), src_dir_fd=dfd, dst_dir_fd=dfd)
        finally:
            os.close(dfd)

    def _load(self):
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            return None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != self.owner_uid or st.st_mode & 0o077 or st.st_nlink != 1 or st.st_size > MAX_ENVELOPE:
                return None
            raw = os.read(fd, MAX_ENVELOPE + 1)
        finally:
            os.close(fd)
        try:
            return canon.loads(raw.rstrip(b"\n"))
        except canon.CanonError:
            return None

    def current(self, gate_keys) -> dict | None:
        """The stored lease payload if its envelope still verifies under the CURRENT gate keys (signature, namespace, node); None otherwise."""
        with self._lock:
            env = self._load()
            if env is None:
                return None
            ck = (canon.canonical(env), tuple(sorted((k.id, k.pub, str(k.not_after)) for k in gate_keys.values())))
            if self._cache is not None and self._cache[0] == ck:
                return self._cache[1]
            try:
                p = protocol.open_envelope(env, gate_keys, "lease", self.clock(), self.ssh_keygen)
            except ProtoError:
                return None
            if p["node"] != self.node:
                return None
            self._cache = (ck, p)
            return p
