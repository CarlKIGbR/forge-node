"""Entry point of one `ro-probe` unit (started by privd, N3): `python -m forge_node.t0.probe_main <probe>`; parameters as one JSON line on stdin, result as one JSON line on stdout.
The policy is loaded and re-verified HERE, from the root-owned install, not taken from the caller."""
import sys
from datetime import datetime, timezone

from .. import canon
from . import wire
from .env import Env
from .fsread import Fs, ProtectedSet
from .policy import PolicyError, load_installed
from .runner import ReadOnlyRunner, trusted_binary


def main(argv, stdin, stdout, *, node_id: str, policy_dir: str, allowed_signers: str, fs_root: str, owner_uid: int, now, ssh_keygen: str) -> int:
    """Thin wrapper over wire.handle_request so privd (in-process, N3) and the unit entry share one code path."""
    if len(argv) != 1:
        stdout.write(canon.canonical_text({"ok": False, "code": "BAD_REQUEST", "detail": "usage: probe_main <probe>"}) + "\n")
        return 2
    clock = now
    try:
        view = load_installed(policy_dir, allowed_signers, node_id, clock(), owner_uid=owner_uid, ssh_keygen=ssh_keygen)
    except PolicyError as e:
        stdout.write(canon.canonical_text({"ok": False, "code": e.code, "detail": e.detail[:200]}) + "\n")
        return 1
    env = Env(Fs(ProtectedSet.from_policy(view.protected_paths), fs_root), ReadOnlyRunner(), clock, view)
    try:
        params = canon.loads(stdin.readline(wire.MAX_LINE))
    except canon.CanonError:
        stdout.write(canon.canonical_text({"ok": False, "code": "BAD_REQUEST", "detail": "parameters are not strict JSON"}) + "\n")
        return 2
    line = wire.encode_request(argv[0], params if isinstance(params, dict) else {"_": 1})
    stdout.write(wire.handle_request(line, env).decode("utf-8"))
    return 0


if __name__ == "__main__":
    import os
    sys.exit(main(sys.argv[1:], sys.stdin, sys.stdout, node_id=os.environ["FORGE_NODE_NODE_ID"], policy_dir="/etc/forge-node/policy", allowed_signers="/etc/forge-node/allowed_signers",
                  fs_root="/", owner_uid=0, now=lambda: datetime.now(timezone.utc), ssh_keygen=trusted_binary("ssh-keygen")))
