"""Layout and modes of one audit log (Design 8.1/8.2, gate D protocol). Every field is required: a log without an explicit owner/mode/anchor does not exist.

On-disk layout (a deviation from the flat table of Design 8.2, forced by the kernel - an append-only inode can be neither renamed nor hard-linked, so a file cannot be prepared elsewhere and
moved in, and a descriptor opened for writing before +a stays writable afterwards; the new file is therefore created inside a generation directory that is root-only (0700) until the file
carries +a, and only then made reachable):

    <dir>/                          root:<gid> <dir_mode>   root-owned; nobody else can create, rename, link or unlink anything in it
    <dir>/CURRENT                   root:<gid> 0644         {"dir","file","fmt","gen"}; replaced only by an atomic rename inside <dir>
    <dir>/<prefix>.<NNNNNN>/        root:<gid> <dir_mode>   one generation (0700 while it is being created)
    <dir>/<prefix>.<NNNNNN>/<prefix>.<NNNNNN>.jsonl   root:<gid> <file_mode>, +a while live, +a+i once sealed
    <lock>                          the one lock file of this log (flock), in a root-controlled directory"""
import re
from dataclasses import dataclass

CURRENT_NAME = "CURRENT"
CURRENT_TMP = "CURRENT.tmp"
GEN_DIGITS = 6
MAX_CURRENT_BYTES = 512
MAX_DAMAGED_TAIL = 1024 * 1024
LOCK_TIMEOUT_S = 10.0
MIN_AGE_PURGE_S = 90 * 86400


class AuditError(Exception):
    pass


class AuditDown(AuditError):
    """The log cannot be appended to right now (retryable: DENY_AUDIT_DOWN). Fail closed."""


class AuditNotInitialised(AuditDown):
    pass


class AuditCorrupt(AuditError):
    """State that recovery must not 'repair' on its own (tampering, missing predecessor, CURRENT pointing at a file without chain_link): quarantine and tell the owner."""


@dataclass(frozen=True)
class LogSpec:
    source: str            # "priv" | "agent" (chain.SOURCE_TYPES)
    prefix: str            # file name prefix: "priv" | "audit"
    dir: str               # log directory (root-owned)
    lock: str              # lock file path (root-controlled directory)
    gid: int               # group of the files: forgenode
    owner_uid: int         # 0 in production
    file_mode: int         # 0o640 priv, 0o660 agent
    dir_mode: int          # 0o750 priv, 0o755 agent
    lock_mode: int         # 0o600 priv, 0o660 agent
    trust_anchor: str      # directories from `dir` up to here must be owned by owner_uid and not writable by group/others ("/" in production)
    max_file_bytes: int    # rotation threshold (size)
    max_age_s: int         # rotation threshold (age of the active file; a file holding only its chain_link is never rotated for age)


def priv_spec(*, dir="/var/log/forge-node-priv", lock="/var/lib/forge-node-priv/locks/priv.log.lock", gid: int, owner_uid=0, trust_anchor="/", max_file_bytes=64 * 1024 * 1024, max_age_s=86400) -> LogSpec:
    return LogSpec("priv", "priv", dir, lock, gid, owner_uid, 0o640, 0o750, 0o600, trust_anchor, max_file_bytes, max_age_s)


def agent_spec(*, dir="/var/log/forge-node-agent", lock="/var/log/forge-node-agent/audit.lock", gid: int, owner_uid=0, trust_anchor="/", max_file_bytes=64 * 1024 * 1024, max_age_s=86400) -> LogSpec:
    return LogSpec("agent", "audit", dir, lock, gid, owner_uid, 0o660, 0o755, 0o660, trust_anchor, max_file_bytes, max_age_s)


def gen_name(prefix: str, n: int) -> str:
    return f"{prefix}.{n:0{GEN_DIGITS}d}"


def gen_file(prefix: str, n: int) -> str:
    return f"{gen_name(prefix, n)}.jsonl"


def gen_re(prefix: str) -> "re.Pattern":
    return re.compile(rf"^{re.escape(prefix)}\.([0-9]{{{GEN_DIGITS}}})\Z")
