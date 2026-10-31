"""Side-effect-free `--selfcheck` for the T0 layer (Design 4.4 "validation inside the real unit"): which allowlisted commands exist and are trusted, which kernel files are readable, whether
cgroup v2 is present. `doctor` (N3/N4) runs this inside the real transient unit / agent unit and decides what is acceptable per host; this function only observes."""
from . import runner
from .env import Env
from .fsread import FsError

REQUIRED_COMMANDS = ("lsblk", "findmnt", "systemctl_show_all", "ss_listen", "ip_route", "openssl_x509_file", "apt_config_dump")
PROBE_PATHS = ("/proc/meminfo", "/proc/loadavg", "/proc/uptime", "/proc/stat", "/proc/diskstats", "/proc/net/dev", "/proc/mounts", "/etc/os-release", "/etc/passwd", "/etc/group")


def selfcheck(env: Env) -> dict:
    commands = {cid: env.runner.available(cid) for cid in sorted(runner.CMDS)}
    paths = {}
    for p in PROBE_PATHS:
        try:
            env.fs.read_text(p)
            paths[p] = True
        except FsError:
            paths[p] = False
    try:
        env.fs.list_meta("/sys/fs/cgroup/system.slice", 1)
        cg = True
    except FsError:
        cg = False
    missing_required = [c for c in REQUIRED_COMMANDS if not commands.get(c)]
    return {"commands": commands, "paths": paths, "cgroup_v2_system_slice": cg, "missing_required_commands": missing_required, "ok": not missing_required and all(paths.values())}
