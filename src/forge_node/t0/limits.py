"""Rate buckets for T0 reads (Design 9.2): light <= 2/min, heavy <= 1 per 10 min, per op. State is persisted so an agent restart does not hand out a fresh burst; the file lives in the
agent's own state directory (the authoritative bucket for root probes is privd's ledger in N3 - this one protects the host from the agent's own loop)."""
import json
import os
import tempfile
import threading
from datetime import datetime

LIGHT = (2.0, 2.0 / 60.0)          # capacity, refill per second
HEAVY = (1.0, 1.0 / 600.0)


class RateLimiter:
    def __init__(self, state_file: str, clock):
        """Both arguments are required: there is no limiter-less mode."""
        self.state_file, self.clock = state_file, clock
        self._lock = threading.Lock()
        self._b: dict[str, tuple[float, float]] = {}
        self._load()

    def _load(self):
        try:
            with open(self.state_file, "rb") as f:
                raw = json.loads(f.read(65536))
            if isinstance(raw, dict):
                self._b = {k: (float(v[0]), float(v[1])) for k, v in raw.items() if isinstance(k, str) and isinstance(v, list) and len(v) == 2}
        except (OSError, ValueError, TypeError, IndexError):
            self._b = {}

    def _save(self):
        d = os.path.dirname(self.state_file)
        try:
            fd, tmp = tempfile.mkstemp(dir=d, prefix=".rl.")
            with os.fdopen(fd, "w") as f:
                json.dump({k: list(v) for k, v in self._b.items()}, f)
            os.replace(tmp, self.state_file)
        except OSError:
            pass            # in-memory state still enforces the limit

    def take(self, op: str, heavy: bool) -> bool:
        cap, rate = HEAVY if heavy else LIGHT
        now = self.clock().timestamp()
        with self._lock:
            tokens, last = self._b.get(op, (cap, now))
            # Time only moves forward here: a clock that steps back neither refills (elapsed is clamped at 0) NOR drags the saved timestamp back - otherwise the step back
            # followed by the return to the true time would be counted as elapsed time (T -> T-600 -> T replenished a heavy token).
            tokens = min(cap, tokens + max(0.0, now - last) * rate)
            last = max(last, now)
            ok = tokens >= 1.0
            if ok:
                tokens -= 1.0
            self._b[op] = (tokens, last)
            self._save()
            return ok
