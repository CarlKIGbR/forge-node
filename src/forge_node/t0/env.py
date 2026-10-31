"""Execution environment handed to the collectors: filesystem access, command runner, clock, policy view. Collectors never reach for globals."""
from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from .fsread import Fs
from .policy import PolicyView
from .runner import ReadOnlyRunner


@dataclass
class Env:
    fs: Fs
    runner: ReadOnlyRunner
    now: Callable[[], datetime]
    policy: PolicyView


def run_slots(runner, cmd_id: str, slots: dict, max_wait_s: float | None = None):
    """Run a table command whose slot values come from the filesystem (directory names, repository paths): a name the table refuses (control characters, '..') is a per-item
    'bad_slot' result, never an exception that would take the whole probe down."""
    from .runner import Run, RunnerError
    try:
        return runner.run(cmd_id, slots, None, max_wait_s)
    except RunnerError:
        return Run(False, "bad_slot")


def ok(**data) -> dict:
    return {"status": "ok", **data}


def unavailable(reason: str) -> dict:
    return {"status": "unavailable", "reason": reason}


def failed(code: str, detail: str = "") -> dict:
    d = {"status": "error", "code": code}
    if detail:
        d["detail"] = detail
    return d


def run_failure(r) -> dict:
    """Map an unsuccessful runner result to a section."""
    if r.reason == "missing":
        return unavailable("command not installed")
    return failed(r.reason, (r.err or "")[:120])
