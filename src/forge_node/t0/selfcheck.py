"""Side-effect-free `--selfcheck` for the T0 layer (Design 4.4 "validation inside the real unit"): which allowlisted commands exist and are trusted, which kernel files are readable, whether
cgroup v2 is present. `doctor` (N3/N4) runs this inside the real transient unit / agent unit and decides what is acceptable per host; this function only observes."""
from . import runner
from .env import Env
from .fsread import FsError
from .needs import PROBE_NEEDS

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


def probe_selfcheck(name: str, env: Env) -> dict:
    """Side-effect-free: do the commands and paths THIS probe declares (needs.PROBE_NEEDS) exist and work from inside this unit? ok = every non-optional need is met. Declared reads are opened
    exactly as the probe opens them (same path, same limit); `missing` names the reason, so a refusal by forge-node's own allowlist is not reported as a sandbox denial."""
    need = PROBE_NEEDS[name]
    commands = {c: env.runner.available(c) for c in (*need.commands, *need.optional)}
    paths, why = {}, {}
    for rd in need.reads:
        p = rd.sample()
        try:
            env.fs.read_text(p, rd.limit)
            paths[p] = True
        except FsError as e:
            paths[p], why[p] = False, e.code
    missing = [c for c in need.commands if not commands[c]] + [f"{p}: {why[p]}" for p, okp in paths.items() if not okp]
    return {"probe": name, "commands": commands, "paths": paths, "missing": missing, "ok": not missing}
