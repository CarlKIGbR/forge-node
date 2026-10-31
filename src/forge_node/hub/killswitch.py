"""STOP-Anbindung des Hubs (Design 9.1) - LESEND. Gleiche Semantik wie forge_core.killswitch (F5b): control/STOP existiert => aktiv; nicht lesbar/Fehler => aktiv;
control/.dispatch.lock (flock, exklusiv) schliesst Signieren gegen Stop aus: ein Stop wirkt entweder vor der Pruefung (Job abgelehnt) oder erst nach dem committeten Job.

Absichtlich KEINE Funktionen zum Setzen oder Loesen von STOP: der Hub kann STOP weder ausloesen noch aufheben (Knoten duerfen die Fabrik nicht per Signal stoppen, M-92;
Freigabe nur Owner/Cockpit/forge-release). Das Verzeichnis control/ wird fuer das Lock rw eingehaengt, der Code beruehrt dort ausschliesslich die Lock-Datei.
Pro-Projekt-Stopps (Lease `stopped_projects`): leere Dateien control/stop.d/<slug>; der Hub liest sie nur."""
import fcntl
import os
import re
import stat
import time
from contextlib import contextmanager
from pathlib import Path

LOCK_NAME = ".dispatch.lock"
LOCK_TIMEOUT_S = 10.0
PROJECT_DIR = "stop.d"
_SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}\Z")


class LockTimeout(RuntimeError):
    pass


def stop_active(control_dir: Path) -> bool:
    """True = STOP (oder nicht pruefbar). Fehlt das Verzeichnis control/, gilt STOP (F5b rework 4: fail closed)."""
    try:
        st = os.lstat(control_dir)
        if not stat.S_ISDIR(st.st_mode):
            return True
    except OSError:
        return True
    try:
        os.lstat(Path(control_dir) / "STOP")
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def stopped_projects(control_dir: Path) -> tuple[list[str], bool]:
    """(Slugs, ok). ok=False wenn das Verzeichnis nicht lesbar war - der Aufrufer behandelt das fail-closed."""
    d = Path(control_dir) / PROJECT_DIR
    try:
        names = os.listdir(d)
    except FileNotFoundError:
        return [], True
    except OSError:
        return [], False
    return sorted({n for n in names if _SLUG.match(n)}), True


@contextmanager
def dispatch_lock(control_dir: Path, timeout: float = LOCK_TIMEOUT_S):
    """Exklusives flock auf control/.dispatch.lock. Ohne Verzeichnis/Rechte -> OSError, nach Timeout -> LockTimeout; beides lehnt der Aufrufer ab."""
    fd = os.open(Path(control_dir) / LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o664)
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise LockTimeout("dispatch lock busy") from None
                time.sleep(0.02)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
