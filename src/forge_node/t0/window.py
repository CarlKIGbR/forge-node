"""Blackout window (Design 9.5): Berlin local time via zoneinfo (never a fixed offset). Heavy T0 follows the blackout; light T0 does not. The built-in window 02:00-05:45 daily and
Sundays before 06:00 is a floor: a policy window can only add to it."""
import re
from dataclasses import dataclass
from datetime import datetime, time
from zoneinfo import ZoneInfo

BERLIN = ZoneInfo("Europe/Berlin")
_HM = re.compile(r"^([01][0-9]|2[0-3]):([0-5][0-9])\Z")
_RANGE = re.compile(r"^([01][0-9]|2[0-3]):([0-5][0-9])-([01][0-9]|2[0-3]):([0-5][0-9])\Z")
BUILTIN_BLACKOUT = (time(2, 0), time(5, 45))
BUILTIN_SUNDAY_OPEN = time(6, 0)


class WindowError(ValueError):
    pass


def parse_hm(s) -> time:
    m = _HM.match(s) if isinstance(s, str) else None
    if not m:
        raise WindowError("time must be HH:MM")
    return time(int(m.group(1)), int(m.group(2)))


def parse_range(s) -> tuple[time, time]:
    m = _RANGE.match(s) if isinstance(s, str) else None
    if not m:
        raise WindowError("range must be HH:MM-HH:MM")
    a, b = time(int(m.group(1)), int(m.group(2))), time(int(m.group(3)), int(m.group(4)))
    if not a < b:
        raise WindowError("a blackout range must not wrap midnight (list two ranges instead)")
    return a, b


@dataclass(frozen=True)
class Window:
    ranges: tuple[tuple[time, time], ...] = (BUILTIN_BLACKOUT,)
    sunday_open: time = BUILTIN_SUNDAY_OPEN

    @classmethod
    def from_policy(cls, windows: dict | None) -> "Window":
        if not windows:
            return cls()
        ranges = [BUILTIN_BLACKOUT]
        if "blackout" in windows:
            ranges.append(parse_range(windows["blackout"]))
        so = BUILTIN_SUNDAY_OPEN
        if "sunday_open" in windows:
            so = max(so, parse_hm(windows["sunday_open"]))
        return cls(tuple(ranges), so)

    def in_blackout(self, now: datetime) -> bool:
        if now.tzinfo is None:
            raise WindowError("naive datetime")
        local = now.astimezone(BERLIN)
        t = local.time()
        if any(a <= t < b for a, b in self.ranges):
            return True
        return local.weekday() == 6 and t < self.sunday_open
