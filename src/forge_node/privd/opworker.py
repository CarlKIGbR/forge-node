"""Entry of the op worker as the release ships it: `python -I forge-node.pyz opworker run|selfcheck <work_dir>` (or `python -m forge_node.privd.opworker ...`). Binds the compiled-in effects."""
import os
import sys

from .. import canon
from .ops import EFFECTS
from .worker import run


def selfcheck(work_dir: str, ledger_path: str, lock_dir: str) -> dict:
    """Side-effect-free `--selfcheck` of the op class (Design 4.4): from INSIDE the unit - can the work directory be written, the effect-lock directory locked, the ledger opened
    read-only? `doctor` runs this in the op's real transient unit and fails the install step if anything is denied."""
    from .ledger import Ledger
    out = {"work_dir_writable": False, "lock_dir_lockable": False, "ledger_readable": False}
    try:
        p = os.path.join(work_dir, ".selfcheck")
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        os.unlink(p)
        out["work_dir_writable"] = True
    except OSError:
        pass
    try:
        import fcntl
        fd = os.open(os.path.join(lock_dir, "selfcheck.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            out["lock_dir_lockable"] = True
        finally:
            os.close(fd)
    except OSError:
        pass
    try:
        led = Ledger(ledger_path, read_only=True)
        try:
            led.open_rows()
        finally:
            led.close()
        out["ledger_readable"] = True
    except Exception:  # noqa: BLE001
        pass
    out["ok"] = all(out.values())
    return out


def main(argv: list) -> int:
    if len(argv) == 2 and argv[0] == "run":
        return run(argv[1], EFFECTS, owner_uid=0)
    if len(argv) == 2 and argv[0] == "selfcheck":
        req = canon.loads(open(os.path.join(argv[1], "selfcheck.json"), "rb").read())
        print(canon.canonical_text({"ok": True, "data": selfcheck(argv[1], req["ledger_path"], req["lock_dir"])}))
        return 0
    raise SystemExit("usage: opworker run|selfcheck <work_dir>")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
