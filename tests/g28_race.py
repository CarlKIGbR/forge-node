"""G28 helpers: deterministic race tests and fresh-evidence assertions. Dependency-free; copy next to the project's tests.

1. `Interleaver` - hook based. Code under test exposes a hook (or the test wraps a method with `hook_after`/`hook_before`); a thread that reaches it
   *parks* until the test releases it. The test thereby fixes the interleaving ("A checked, B ran completely, now A acts"), with no sleeps.
2. `run_schedule` / `all_schedules` - single-thread cooperative variant: actors are generators that `yield` at every point where another actor may run;
   the test supplies the order, or enumerates all orders.
3. `EvidenceLog` + `assert_observed_before` - G28 "evidence is fresh": the decision log must show a re-observation right before each irreversible action.

Typical race test (TOCTOU): A observes "file is stale" -> park -> B refreshes the file -> release A -> A must NOT delete.
"""
from __future__ import annotations

import functools
import itertools
import threading
from typing import Any, Callable, Generator, Iterable, Sequence

TIMEOUT = 5.0


class Interleaver:
    def __init__(self, timeout: float = TIMEOUT):
        self.timeout = timeout
        self._cv = threading.Condition()
        self._parked: set[str] = set()
        self._finished: set[str] = set()
        self._released: set[str] = set()
        self._threads: dict[str, threading.Thread] = {}
        self._errors: dict[str, BaseException] = {}
        self._results: dict[str, Any] = {}

    # --- called from the code under test (the hook) -------------------------------------------------------------------------------------
    def park(self, point: str) -> None:
        """Block the calling thread at `point` until the test calls release(point). Raises on timeout instead of hanging."""
        with self._cv:
            self._parked.add(point)
            self._cv.notify_all()
            if not self._cv.wait_for(lambda: point in self._released, self.timeout):
                raise TimeoutError(f"park({point!r}) was never released")

    # --- called from the test -----------------------------------------------------------------------------------------------------------
    def start(self, name: str, fn: Callable, *a, **kw) -> None:
        def run():
            try:
                self._results[name] = fn(*a, **kw)
            except BaseException as e:           # noqa: BLE001 - re-raised in join()
                self._errors[name] = e
            finally:
                with self._cv:
                    self._finished.add(name)
                    self._cv.notify_all()
        t = threading.Thread(target=run, name=f"il-{name}", daemon=True)
        self._threads[name] = t
        t.start()

    def wait_parked(self, point: str) -> None:
        with self._cv:
            if not self._cv.wait_for(lambda: point in self._parked or bool(self._errors) or self._finished >= set(self._threads), self.timeout):
                raise TimeoutError(f"nobody reached {point!r}")
            if point not in self._parked:
                raise AssertionError(f"threads ended (errors: {self._errors}) before anyone reached {point!r}")

    def release(self, point: str) -> None:
        with self._cv:
            self._released.add(point)
            self._cv.notify_all()

    def join(self, name: str, *, raises: bool = True) -> Any:
        t = self._threads[name]
        t.join(self.timeout)
        if t.is_alive():
            raise TimeoutError(f"thread {name!r} did not finish (deadlock?)")
        if raises and name in self._errors:
            raise self._errors[name]
        return self._results.get(name)

    def error(self, name: str) -> BaseException | None:
        return self._errors.get(name)


def hook_after(obj: Any, attr: str, il: Interleaver, point: str, *, only_thread: str | None = None) -> None:
    """Wrap obj.attr so the calling thread parks at `point` right AFTER the call returned (e.g. after the check, before the action).
    Only threads started via Interleaver.start(only_thread) park when only_thread is given; others pass through."""
    orig = getattr(obj, attr)

    @functools.wraps(orig)
    def wrapper(*a, **kw):
        r = orig(*a, **kw)
        if only_thread is None or threading.current_thread().name == f"il-{only_thread}":
            il.park(point)
        return r
    setattr(obj, attr, wrapper)


def hook_before(obj: Any, attr: str, il: Interleaver, point: str, *, only_thread: str | None = None) -> None:
    orig = getattr(obj, attr)

    @functools.wraps(orig)
    def wrapper(*a, **kw):
        if only_thread is None or threading.current_thread().name == f"il-{only_thread}":
            il.park(point)
        return orig(*a, **kw)
    setattr(obj, attr, wrapper)


Actor = Generator[str, None, Any]


def run_schedule(actors: dict[str, Callable[[], Actor]], order: Sequence[str]) -> dict[str, Any]:
    """Run generator actors cooperatively in exactly `order` (each entry = advance that actor to its next `yield`). Every actor must be
    exhausted at the end; returns each actor's return value. Single-threaded, so the interleaving is the order - nothing else."""
    gens = {k: f() for k, f in actors.items()}
    done: dict[str, Any] = {}
    for k in order:
        if k in done:
            raise AssertionError(f"schedule advances finished actor {k!r}")
        try:
            next(gens[k])
        except StopIteration as e:
            done[k] = e.value
    missing = set(gens) - set(done)
    if missing:
        raise AssertionError(f"schedule ended with unfinished actors: {sorted(missing)}")
    return done


def all_schedules(steps: dict[str, int]) -> list[list[str]]:
    """Every interleaving of actors with `steps[k]` advances each (a generator with n yields needs n+1 advances to finish). Deterministic order."""
    flat = [k for k, n in sorted(steps.items()) for _ in range(n)]
    return [list(p) for p in sorted(set(itertools.permutations(flat)))]


class EvidenceLog:
    """Append-only event log the code under test (or a fake) writes: ('observe', what) and ('act', what)."""
    def __init__(self):
        self.events: list[tuple[str, str]] = []

    def observe(self, what: str) -> None:
        self.events.append(("observe", what))

    def act(self, what: str) -> None:
        self.events.append(("act", what))


def assert_observed_before(log: EvidenceLog, action: str, evidence: str) -> None:
    """The event immediately before every `act(action)` must be `observe(evidence)`: an observation earlier in the run, with anything else in
    between, is a stale snapshot (G28). Also fails if the action never happened (a vacuous pass proves nothing)."""
    idx = [i for i, e in enumerate(log.events) if e == ("act", action)]
    if not idx:
        raise AssertionError(f"action {action!r} never happened; nothing was checked: {log.events}")
    for i in idx:
        if i == 0 or log.events[i - 1] != ("observe", evidence):
            raise AssertionError(f"action {action!r} at event {i} is not directly preceded by observe({evidence!r}): {log.events}")
