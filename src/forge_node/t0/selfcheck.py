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


# What each root probe needs to do its work, checked INSIDE that probe's own sandbox (doctor runs it in the probe's real transient unit). `optional`: a missing optional command is
# reported but does not fail the check (sshd / virsh are not on every host).
PROBE_NEEDS = {
    "net": {"commands": ("ss_listen_procs",), "optional": (), "paths": ("/proc/net/dev",)},
    "firewall": {"commands": ("iptables_docker_user",), "optional": (), "paths": ()},
    "containers": {"commands": ("docker_ps_ids", "docker_inspect", "docker_image_inspect"), "optional": (), "paths": ()},
    "container_net": {"commands": ("docker_ps_ids", "docker_inspect"), "optional": (), "paths": ("/proc/self/net/dev",)},
    "vms": {"commands": (), "optional": ("virsh_list", "virsh_pools"), "paths": ()},
    "certs": {"commands": ("openssl_x509_file",), "optional": (), "paths": ()},
    "git": {"commands": ("git_status_tracked",), "optional": (), "paths": ()},
    "access": {"commands": (), "optional": ("sshd_effective",), "paths": ("/etc/group", "/etc/passwd")},
    "models": {"commands": ("du_ionice",), "optional": (), "paths": ()},
    "journal": {"commands": ("journal_unit",), "optional": (), "paths": ()},
    "activity": {"commands": ("journal_last",), "optional": (), "paths": ()},
    "uulog": {"commands": (), "optional": (), "paths": ("/var/log/unattended-upgrades/unattended-upgrades.log",)},
}


def probe_selfcheck(name: str, env: Env) -> dict:
    """Side-effect-free: do the commands and paths THIS probe needs exist and work from inside this unit? ok = every non-optional need is met."""
    need = PROBE_NEEDS[name]
    commands = {c: env.runner.available(c) for c in (*need["commands"], *need["optional"])}
    paths = {}
    for p in need["paths"]:
        try:
            env.fs.read_text(p, 1024)
            paths[p] = True
        except FsError:
            paths[p] = False
    missing = [c for c in need["commands"] if not commands[c]] + [p for p, okp in paths.items() if not okp]
    return {"probe": name, "commands": commands, "paths": paths, "missing": missing, "ok": not missing}
