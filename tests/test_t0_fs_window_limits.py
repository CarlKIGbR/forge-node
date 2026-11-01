import os
import re
import threading
from datetime import datetime, timedelta, timezone

import pytest
from hypothesis import given, strategies as st

from forge_node.t0 import window as W
from forge_node.t0.fsread import DEFAULT_PROTECTED, Fs, FsError, ProtectedSet, norm_abs, under
from forge_node.t0.limits import RateLimiter

from n2_helpers import PROC, write_tree


@pytest.fixture
def fs(tmp_path):
    write_tree(tmp_path, PROC)
    return Fs(ProtectedSet.from_policy(["/srv/extra"]), str(tmp_path))


# --------------------------------------------------------------------------------------------------------------------------- fsread
def test_allowlisted_proc_file_is_readable(fs):
    assert "MemTotal" in fs.read_text("/proc/meminfo")


def test_non_allowlisted_path_is_refused_even_if_it_exists(fs, tmp_path):
    write_tree(tmp_path, {"/etc/shadow": "root:$6$secret::::::\n", "/home/carl/.ssh/id_ed25519": "KEY"})
    for p in ("/etc/shadow", "/home/carl/.ssh/id_ed25519", "/etc/ssh/sshd_config", "/proc/1/environ", "/proc/kcore"):
        with pytest.raises(FsError) as e:
            fs.read_text(p)
        assert e.value.code == "not_allowed"


def test_protected_set_blocks_an_allowlisted_path_when_the_policy_protects_it(tmp_path):
    """The allowlist and the protected set are independent layers: a policy that protects an allowlisted file makes it unreadable (code 'protected', not 'not_allowed')."""
    write_tree(tmp_path, PROC)
    f = Fs(ProtectedSet.from_policy(["/etc/passwd"]), str(tmp_path))
    with pytest.raises(FsError) as e:
        f.read_text("/etc/passwd")
    assert e.value.code == "protected"
    assert "root" in Fs(ProtectedSet.from_policy([]), str(tmp_path)).read_text("/etc/passwd")


def test_protected_set_blocks_content_reads_below_it(tmp_path):
    write_tree(tmp_path, {"/srv/models/m/weights.bin": "w", "/opt/kmu-ai/x": "x"})
    f = Fs(ProtectedSet.from_policy([]), str(tmp_path))
    for p in ("/srv/models/m/weights.bin", "/opt/kmu-ai/x"):
        with pytest.raises(FsError) as e:
            f.read_text(p)
        assert e.value.code in ("not_allowed", "protected")


def test_protected_set_cannot_lose_builtin_entries_and_can_gain():
    ps = ProtectedSet.from_policy(["/srv/extra"])
    assert set(DEFAULT_PROTECTED) <= set(ps.paths) and "/srv/extra" in ps.paths
    assert ps.hit("/srv/models/a/b") == "/srv/models" and ps.hit("/srv/modelsX") is None and ps.hit("/srv/extra") == "/srv/extra"


def test_symlink_to_something_not_allowlisted_is_refused_as_escape(fs, tmp_path):
    write_tree(tmp_path, {"/etc/shadow": "root:$6$secret::::::\n"})
    os.unlink(tmp_path / "proc" / "loadavg")
    os.symlink(str(tmp_path / "etc" / "shadow"), tmp_path / "proc" / "loadavg")
    with pytest.raises(FsError) as e:
        fs.read_text("/proc/loadavg")
    assert e.value.code == "escape"
    assert not fs.exists("/proc/loadavg")


def test_directory_symlink_to_a_non_allowlisted_tree_is_refused(tmp_path):
    (tmp_path / "real").mkdir()
    write_tree(tmp_path, {"/real/os-release": "ID=x\n"})
    os.symlink(str(tmp_path / "real"), tmp_path / "etc")
    f = Fs(ProtectedSet.from_policy([]), str(tmp_path))
    with pytest.raises(FsError) as e:
        f.read_text("/etc/os-release")
    assert e.value.code == "escape"


def test_real_world_symlinks_to_allowlisted_targets_are_followed(tmp_path):
    """Live proof (Ubuntu 24.04): /etc/os-release -> ../usr/lib/os-release, /proc/net -> self/net, /var/run -> /run. Refusing them made inv.host 'ok' but empty and net counters 0."""
    write_tree(tmp_path, {"/usr/lib/os-release": 'PRETTY_NAME="Ubuntu 24.04"\n', "/run/reboot-required": "x\n", "/run/reboot-required.pkgs": "linux-image\n",
                          "/proc/4242/net/dev": "Inter-|   Receive\n face |bytes\n  eth0: 5000 50 0 0 0 0 0 0 7000 70 0 0 0 0 0 0\n", "/proc/4242/mounts": "srv:/e /mnt nfs4 rw 0 0\n"})
    (tmp_path / "etc").mkdir()
    os.symlink("../usr/lib/os-release", tmp_path / "etc" / "os-release")
    os.symlink("4242/net", tmp_path / "proc" / "net")                      # on a real host: -> self/net, i.e. /proc/<pid>/net
    os.symlink("4242/mounts", tmp_path / "proc" / "mounts")
    assert "nfs4" in Fs(ProtectedSet.from_policy([]), str(tmp_path)).read_text("/proc/mounts")
    (tmp_path / "var").mkdir()
    os.symlink("/run", tmp_path / "var" / "run")                  # absolute link: relative to the relocated root in this test via the realpath below
    f = Fs(ProtectedSet.from_policy([]), str(tmp_path))
    assert "Ubuntu" in f.read_text("/etc/os-release")
    assert "eth0" in f.read_text("/proc/net/dev")
    # /var/run -> /run is an absolute link: in the relocated tree it leaves the root, which is refused (production root is '/', where it resolves)
    assert f.exists("/run/reboot-required") and f.read_text("/run/reboot-required.pkgs") == "linux-image\n"


def test_real_host_symlinks_are_followed_on_the_real_filesystem():
    """Not a fixture: the same reads on the machine the tests run on (the test image is Debian: /etc/os-release is a symlink there too)."""
    f = Fs(ProtectedSet.from_policy([]))
    assert "ID=" in f.read_text("/etc/os-release")
    assert f.read_text("/proc/net/dev").count(":") >= 1
    assert f.read_text("/proc/mounts").strip()                    # -> self/mounts: refused in the first review round
    assert f.exists("/proc/mounts") and f.exists("/etc/passwd")
    from forge_node.t0 import selfcheck as sc
    from forge_node.t0.env import Env
    from forge_node.t0.runner import ReadOnlyRunner
    from n2_helpers import view as _view
    r = sc.selfcheck(Env(f, ReadOnlyRunner(), lambda: __import__("datetime").datetime.now(__import__("datetime").timezone.utc), _view()))
    assert all(r["paths"].values()), r["paths"]               # every probe path of the selfcheck is readable on a real filesystem


def test_dot_dot_and_relative_paths_are_normalized_or_refused(fs):
    with pytest.raises(FsError):
        fs.read_text("proc/meminfo")
    with pytest.raises(FsError):
        fs.read_text("/proc/../etc/shadow")        # normalizes to /etc/shadow: not on the allowlist
    with pytest.raises(FsError):
        norm_abs("/a\x00b")


def test_non_regular_file_is_refused(fs, tmp_path):
    os.mkfifo(tmp_path / "proc" / "mdstat")
    with pytest.raises(FsError) as e:
        fs.read_text("/proc/mdstat")
    assert e.value.code == "not_regular"


def test_sys_symlink_farm_is_resolved_but_must_stay_in_sys(tmp_path):
    write_tree(tmp_path, {"/sys/devices/pci0/nvme/nvme0/model": "Samsung 990\n"})
    (tmp_path / "sys/class/nvme").mkdir(parents=True)
    os.symlink("../../devices/pci0/nvme/nvme0", tmp_path / "sys/class/nvme/nvme0")
    f = Fs(ProtectedSet.from_policy([]), str(tmp_path))
    assert f.read_text("/sys/class/nvme/nvme0/model").startswith("Samsung")
    os.symlink("../../../etc", tmp_path / "sys/class/nvme/evil")
    write_tree(tmp_path, {"/etc/model": "x"})
    with pytest.raises(FsError):
        f.read_text("/sys/class/nvme/evil/model")


def test_large_log_returns_the_newest_tail(tmp_path):
    lines = "".join(f"2026-10-31 06:00:{i % 60:02d},000 INFO line {i}\n" for i in range(5000))
    write_tree(tmp_path, {"/var/log/unattended-upgrades/unattended-upgrades.log": lines})
    f = Fs(ProtectedSet.from_policy([]), str(tmp_path))
    t = f.read_text("/var/log/unattended-upgrades/unattended-upgrades.log", 10000)
    assert t.endswith("line 4999\n") and len(t) <= 10000 and "line 0\n" not in t


def test_small_file_over_limit_for_proc_is_too_large(fs, tmp_path):
    write_tree(tmp_path, {"/proc/mdstat": "x" * 5000})
    with pytest.raises(FsError) as e:
        fs.read_text("/proc/mdstat", 100)
    assert e.value.code == "too_large"


def test_metadata_listing_never_opens_files(tmp_path):
    write_tree(tmp_path, {"/srv/models/a/w.bin": "secret-weights", "/srv/models/b.txt": "x"})
    f = Fs(ProtectedSet.from_policy([]), str(tmp_path))
    real = f.resolve_dir("/srv/models")
    entries, trunc = f.list_meta(real)
    assert [e["name"] for e in entries] == ["a", "b.txt"] and not trunc
    assert all(set(e) == {"name", "kind", "size", "mtime", "dev"} for e in entries)
    assert "secret" not in repr(entries)


def test_resolve_dir_follows_policy_symlinks_but_not_out_of_the_tree(tmp_path):
    write_tree(tmp_path, {"/etc/letsencrypt/archive/d/fullchain1.pem": "c"})
    (tmp_path / "etc/letsencrypt/live/d").mkdir(parents=True)
    os.symlink("../archive/d", tmp_path / "etc/letsencrypt/live/d2")
    f = Fs(ProtectedSet.from_policy([]), str(tmp_path))
    assert f.resolve_dir("/etc/letsencrypt/live/d2") == "/etc/letsencrypt/archive/d"
    os.symlink("/", tmp_path / "etc/outside")
    # an absolute symlink is relative to the real root, i.e. leaves the relocated tree: refused
    with pytest.raises(FsError) as e:
        f.resolve_dir("/etc/outside/etc")
    assert e.value.code == "escape"


def test_read_exception_requires_the_reviewed_pattern(tmp_path):
    write_tree(tmp_path, {"/opt/kmu-ai/.git/HEAD": "ref: refs/heads/main\n", "/opt/kmu-ai/secret.env": "KEY=1"})
    f = Fs(ProtectedSet.from_policy([]), str(tmp_path))
    pat = re.compile(r"^/.{1,4000}/\.git/HEAD\Z")
    assert f.read_exception("/opt/kmu-ai/.git/HEAD", pat).startswith("ref:")
    with pytest.raises(FsError) as e:
        f.read_exception("/opt/kmu-ai/secret.env", pat)
    assert e.value.code == "not_allowed"


def test_under_is_component_aware():
    assert under("/a/b", "/a") and under("/a", "/a") and not under("/ab", "/a") and under("/x", "/")


@given(st.text(alphabet="/.abc ", max_size=40))
def test_property_norm_abs_never_returns_dotdot_components(s):
    try:
        n = norm_abs(s)
    except FsError:
        return
    assert ".." not in n.split("/") and n.startswith("/")


# --------------------------------------------------------------------------------------------------------------------------- window
BERLIN_DST_END = datetime(2026, 10, 25, 1, 30, tzinfo=timezone.utc)


def utc_for_berlin(y, mo, d, h, mi):
    return datetime(y, mo, d, h, mi, tzinfo=W.BERLIN).astimezone(timezone.utc)


def test_blackout_boundaries_in_berlin_time_winter_and_summer():
    w = W.Window()
    for (y, mo, d) in ((2026, 12, 15), (2027, 7, 15)):                  # CET and CEST: same local boundaries, different UTC offsets
        assert not w.in_blackout(utc_for_berlin(y, mo, d, 1, 59))
        assert w.in_blackout(utc_for_berlin(y, mo, d, 2, 0))
        assert w.in_blackout(utc_for_berlin(y, mo, d, 5, 44))
        assert not w.in_blackout(utc_for_berlin(y, mo, d, 5, 45))


def test_blackout_across_the_autumn_dst_change_2026_10_25():
    w = W.Window()
    assert w.in_blackout(datetime(2026, 10, 25, 1, 30, tzinfo=timezone.utc))        # 02:30 CET after the change (Sunday): inside
    assert w.in_blackout(datetime(2026, 10, 25, 0, 30, tzinfo=timezone.utc))        # 01:30 UTC == 02:30 CEST, first occurrence: inside
    assert not w.in_blackout(utc_for_berlin(2026, 10, 24, 12, 0))


def test_sunday_is_closed_until_06_and_only_sunday():
    w = W.Window()
    assert w.in_blackout(utc_for_berlin(2026, 11, 1, 5, 50)) and w.in_blackout(utc_for_berlin(2026, 11, 1, 0, 10))     # Sunday 01 Nov 2026
    assert not w.in_blackout(utc_for_berlin(2026, 11, 1, 6, 0)) and not w.in_blackout(utc_for_berlin(2026, 11, 2, 0, 10))  # Monday 00:10 is open
    assert not w.in_blackout(utc_for_berlin(2026, 11, 3, 5, 50))


def test_policy_can_only_widen_the_window():
    w = W.Window.from_policy({"blackout": "21:00-22:00", "sunday_open": "04:00"})
    assert w.in_blackout(utc_for_berlin(2026, 11, 3, 21, 30)) and w.in_blackout(utc_for_berlin(2026, 11, 3, 3, 0))
    assert w.in_blackout(utc_for_berlin(2026, 11, 1, 5, 50))                  # sunday_open 04:00 cannot reopen the built-in 06:00
    assert W.Window.from_policy(None) == W.Window()


@pytest.mark.parametrize("bad", ["25:00-26:00", "10:00", "05:00-04:00", "ab", None, 5])
def test_bad_policy_ranges_rejected(bad):
    with pytest.raises(W.WindowError):
        W.Window.from_policy({"blackout": bad})


def test_naive_datetime_rejected():
    with pytest.raises(W.WindowError):
        W.Window().in_blackout(datetime(2026, 1, 1, 3, 0))


# --------------------------------------------------------------------------------------------------------------------------- limits
class Clk:
    def __init__(self):
        self.t = datetime(2026, 10, 31, 13, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.t


def test_light_bucket_two_per_minute_heavy_one_per_ten(tmp_path):
    c = Clk()
    rl = RateLimiter(str(tmp_path / "rl.json"), c)
    assert rl.take("inv.host", False) and rl.take("inv.host", False) and not rl.take("inv.host", False)
    c.t += timedelta(seconds=31)
    assert rl.take("inv.host", False) and not rl.take("inv.host", False)
    assert rl.take("inv.git", True) and not rl.take("inv.git", True)
    c.t += timedelta(minutes=9)
    assert not rl.take("inv.git", True)
    c.t += timedelta(minutes=2)
    assert rl.take("inv.git", True)
    assert rl.take("inv.models", True)                                         # per op


def test_bucket_state_survives_restart_and_clock_steps_back_mint_nothing(tmp_path):
    c = Clk()
    f = str(tmp_path / "rl.json")
    rl = RateLimiter(f, c)
    assert rl.take("inv.git", True)
    rl2 = RateLimiter(f, c)
    assert not rl2.take("inv.git", True)
    c.t -= timedelta(hours=5)
    assert not RateLimiter(f, c).take("inv.git", True)


def test_corrupt_state_file_starts_fresh_and_unwritable_dir_still_limits(tmp_path):
    f = tmp_path / "rl.json"
    f.write_text("{not json")
    c = Clk()
    rl = RateLimiter(str(f), c)
    assert rl.take("x", True) and not rl.take("x", True)
    rl2 = RateLimiter(str(tmp_path / "nodir" / "rl.json"), c)
    assert rl2.take("y", True) and not rl2.take("y", True)


def test_bucket_is_thread_safe(tmp_path):
    rl = RateLimiter(str(tmp_path / "rl.json"), Clk())
    got = []
    ts = [threading.Thread(target=lambda: got.append(rl.take("z", True))) for _ in range(20)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert got.count(True) == 1


def test_the_walk_itself_never_follows_a_link_even_if_one_appears_after_resolution(tmp_path):
    """Second layer: _resolve_for_read() resolves links, but the open that follows must still refuse any link (a swap between the two steps)."""
    write_tree(tmp_path, {"/etc/shadow": "x", "/proc/meminfo": "MemTotal: 1 kB\n"})
    (tmp_path / "proc" / "evil").mkdir()
    os.symlink(str(tmp_path / "etc" / "shadow"), tmp_path / "proc" / "evil" / "file")
    os.symlink(str(tmp_path / "etc"), tmp_path / "proc" / "evildir")
    f = Fs(ProtectedSet.from_policy([]), str(tmp_path))
    for path, want_dir in (("/proc/evil/file", False), ("/proc/evildir/shadow", False), ("/proc/evildir", True)):
        with pytest.raises(FsError) as e:
            os.close(f._walk_open(path, want_dir=want_dir))
        assert e.value.code == "escape", path
    os.close(f._walk_open("/proc/meminfo", want_dir=False))


def test_clock_rollback_and_return_does_not_replenish_tokens(tmp_path):
    """Review finding (rework 1): the saved timestamp followed the clock backwards, so T -> T-600 -> T counted 600 s that never elapsed and handed out a second heavy read."""
    c = Clk()
    f = str(tmp_path / "rl.json")
    rl = RateLimiter(f, c)
    assert rl.take("inv.git", True)
    t = c.t
    c.t = t - timedelta(seconds=600)
    assert not rl.take("inv.git", True)
    c.t = t
    assert not rl.take("inv.git", True)
    # the same through a restart in the middle and for the light bucket
    c.t = t - timedelta(seconds=600)
    rl2 = RateLimiter(f, c)
    assert not rl2.take("inv.git", True)
    c.t = t
    assert not RateLimiter(f, c).take("inv.git", True)
    assert rl.take("inv.host", False) and rl.take("inv.host", False)
    c.t = t - timedelta(seconds=300)
    assert not rl.take("inv.host", False)
    c.t = t
    assert not rl.take("inv.host", False)
    import json
    saved = json.loads(open(f).read())
    assert saved["inv.git"][1] == t.timestamp() and saved["inv.host"][1] == t.timestamp()          # the stored time never moved backwards
    c.t = t + timedelta(seconds=601)                                                                 # real time passing still refills
    assert rl.take("inv.git", True)
