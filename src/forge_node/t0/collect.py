"""T0 sections that the unprivileged agent collects itself (Design 4.1 "agent uid"): inv.host, inv.disks, inv.gpu, inv.units, inv.pkgs, inv.backups and the local halves of
inv.net, inv.certs, inv.usage. Every section returns a status dict; one failing section never fails the op."""
import os
import re
import threading
from datetime import datetime
from fnmatch import fnmatchcase

from . import parse
from .env import Env, failed, ok, run_failure, unavailable
from .fsread import FsError, norm_abs, under

NFS_TYPES = ("nfs", "nfs4", "cifs", "smb3", "fuse.sshfs")


def _rd(env: Env, path: str, limit: int = 1024 * 1024) -> str | None:
    try:
        return env.fs.read_text(path, limit)
    except FsError:
        return None


# ------------------------------------------------------------------------------------------------------------------------ inv.host
def host(env: Env) -> dict:
    mem = parse.meminfo(_rd(env, "/proc/meminfo") or "")
    cpu = parse.cpuinfo(_rd(env, "/proc/cpuinfo") or "")
    osr = parse.os_release(_rd(env, "/etc/os-release") or "")
    up = parse.uptime(_rd(env, "/proc/uptime") or "")
    td = env.runner.run("timedatectl")
    ntp = parse.timedatectl(td.text) if td.ok else None
    rr = env.fs.exists("/var/run/reboot-required") or env.fs.exists("/run/reboot-required")
    sections = {
        "os": ok(**osr),
        "kernel": ok(release=(_rd(env, "/proc/sys/kernel/osrelease") or "").strip()),
        "hostname": ok(name=(_rd(env, "/proc/sys/kernel/hostname") or "").strip()),
        "uptime": ok(seconds=up) if up is not None else unavailable("/proc/uptime unreadable"),
        "load": ok(**parse.loadavg(_rd(env, "/proc/loadavg") or "")),
        "cpu": ok(**cpu),
        "memory": ok(ram_total=mem.get("MemTotal"), ram_available=mem.get("MemAvailable"), swap_total=mem.get("SwapTotal"), swap_free=mem.get("SwapFree"),
                     swap_used=(mem["SwapTotal"] - mem["SwapFree"]) if "SwapTotal" in mem and "SwapFree" in mem else None),
        "time": ok(**ntp) if ntp else run_failure(td),
        "reboot_required": ok(required=rr),
    }
    return sections


# ----------------------------------------------------------------------------------------------------------------------- inv.disks
def _statvfs(path: str, timeout: float = 3.0) -> dict | None:
    """statvfs in a helper thread: a dead NFS server must cost 3 s, not hang the agent."""
    res: list = []

    def work():
        try:
            s = os.statvfs(path)
            res.append({"size": s.f_blocks * s.f_frsize, "avail": s.f_bavail * s.f_frsize, "used": (s.f_blocks - s.f_bfree) * s.f_frsize})
        except OSError:
            res.append(None)

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    return res[0] if res else {"unresponsive": True}


def disks(env: Env, statvfs=_statvfs) -> dict:
    lb = env.runner.run("lsblk")
    fm = env.runner.run("findmnt")
    prot = env.fs.protected
    out: dict = {}
    out["block_devices"] = ok(devices=parse.lsblk(lb.text)) if lb.ok else run_failure(lb)
    if fm.ok:
        mnts = []
        for m in parse.findmnt(fm.text):
            if m["fstype"] in ("proc", "sysfs", "cgroup2", "devpts", "devtmpfs", "tmpfs", "securityfs", "pstore", "bpf", "tracefs", "debugfs", "mqueue", "hugetlbfs", "fusectl", "configfs", "autofs", "binfmt_misc", "overlay", "squashfs", "nsfs", "ramfs", "efivarfs"):
                continue
            t = m["target"] or ""
            hit = prot.hit(norm_abs(t)) if t.startswith("/") else None
            e = {"target": t, "source": m["source"], "fstype": m["fstype"], "options": m["options"], "protected": bool(hit), "role": "kmu-protected" if hit else None}
            if len(mnts) < 120:
                e["df"] = statvfs(t)
            mnts.append(e)
        out["mounts"] = ok(mounts=mnts[:200], truncated=len(mnts) > 200)
    else:
        out["mounts"] = run_failure(fm)
    md = _rd(env, "/proc/mdstat")
    out["md_raid"] = ok(arrays=parse.mdstat(md)) if md is not None else unavailable("/proc/mdstat not present")
    out["nfs_mounts"] = ok(mounts=[m for m in parse.mounts(_rd(env, "/proc/mounts") or "") if m["fstype"] in NFS_TYPES])
    out["nvme"] = _nvme(env)
    # Design 4.1: SMART only where smartctl/nvme exist (absent on g2 today). Collecting it needs CAP_SYS_RAWIO/CAP_SYS_ADMIN, which the ro-probe class deliberately does not get
    out["smart"] = unavailable("smartctl/nvme not installed") if not _which_smartctl() else unavailable("SMART collection is not enabled in this release")
    return out


def _which_smartctl() -> bool:
    return any(os.path.isfile(os.path.join(d, n)) for d in ("/usr/sbin", "/usr/bin", "/sbin", "/bin") for n in ("smartctl", "nvme"))


def _nvme(env: Env) -> dict:
    try:
        names, _ = env.fs.list_meta("/sys/class/nvme", 64)
    except FsError:
        return unavailable("no NVMe controllers visible")
    devs = []
    for n in names:
        base = f"/sys/class/nvme/{n['name']}"
        devs.append({"name": n["name"], "model": (_rd(env, f"{base}/model") or "").strip() or None, "state": (_rd(env, f"{base}/state") or "").strip() or None,
                     "transport": (_rd(env, f"{base}/transport") or "").strip() or None})
    return ok(controllers=devs)


# ------------------------------------------------------------------------------------------------------------------------- inv.gpu
def gpu(env: Env) -> dict:
    g = env.runner.run("nvidia_gpus")
    if not g.ok:
        return {"gpus": run_failure(g)}
    gpus = parse.nvidia_gpus(g.text)
    a = env.runner.run("nvidia_apps")
    apps = parse.nvidia_apps(a.text) if a.ok else []
    by_uuid = {x["uuid"]: x["index"] for x in gpus}
    for app in apps:
        app["gpu_index"] = by_uuid.get(app.pop("gpu_uuid"))
    return {"gpus": ok(gpus=[{k: v for k, v in x.items() if k != "uuid"} for x in gpus]), "compute_apps": ok(apps=apps[:200]) if a.ok else run_failure(a)}


# ------------------------------------------------------------------------------------------------------------------------ inv.units
def units(env: Env) -> dict:
    r = env.runner.run("systemctl_show_all")
    out: dict = {}
    if r.ok:
        blocks = [b for b in parse.kv_blocks(r.text) if b.get("Id")]
        rows = [{"unit": b.get("Id"), "load": b.get("LoadState"), "active": b.get("ActiveState"), "sub": b.get("SubState"), "result": b.get("Result"), "fragment": b.get("FragmentPath") or None,
                 "description": b.get("Description"), "restarts": parse.to_int(b.get("NRestarts"))} for b in blocks]
        failed_units = [x["unit"] for x in rows if x["active"] == "failed" or x["result"] not in (None, "", "success")]
        interesting = [x for x in rows if x["active"] in ("active", "failed", "activating", "deactivating") and x["load"] == "loaded"]
        out["units"] = ok(count=len(rows), failed=sorted(set(failed_units)), listed=sorted(interesting, key=lambda x: (x["active"] != "failed", x["unit"]))[:400], truncated=len(interesting) > 400)
    else:
        out["units"] = run_failure(r)
    t = env.runner.run("systemctl_list_timers")
    if t.ok:
        timers = []
        for d in parse.list_units_json(t.text):
            timers.append({"unit": d.get("unit"), "activates": d.get("activates"), "next_us": parse.to_int(d.get("next")), "last_us": parse.to_int(d.get("last"))})
        out["timers"] = ok(timers=sorted(timers, key=lambda x: str(x["unit"]))[:200])
    else:
        out["timers"] = run_failure(t)
    return out


# ------------------------------------------------------------------------------------------------------------------------ inv.pkgs
_PKG_PATTERNS = ["docker-ce", "docker-ce-cli", "containerd.io", "docker-compose-plugin", "nvidia-driver-*", "nvidia-container-toolkit", "linux-image-generic*", "unattended-upgrades"]


def pkgs(env: Env) -> dict:
    out: dict = {}
    cfg = env.runner.run("apt_config_dump")
    conf = parse.apt_config(cfg.text) if cfg.ok else {}
    inst = env.runner.run("dpkg_versions", {"pkg": _PKG_PATTERNS})
    versions = parse.dpkg_versions(inst.text) if inst.ok else []
    installed_uu = any(v["package"] == "unattended-upgrades" for v in versions)
    log = _rd(env, "/var/log/unattended-upgrades/unattended-upgrades.log", 256 * 1024)
    last = parse.uu_log(log) if log is not None else {"last_run": None, "result": "log_unreadable", "origins": []}
    allowed = conf.get("Unattended-Upgrade::Allowed-Origins", []) + conf.get("Unattended-Upgrade::Origins-Pattern", [])
    classes = {e: parse.origin_class(e) for e in allowed}
    log_classes = {e: parse.origin_class(e) for e in last["origins"]}
    drift = sorted([e for e, c in {**classes, **log_classes}.items() if c == "other"])
    enabled = (conf.get("APT::Periodic::Unattended-Upgrade") or ["0"])[-1] not in ("0", "")
    out["unattended_upgrades"] = ok(installed=installed_uu, enabled=enabled, last_run=last["last_run"], last_result=last["result"], origins_configured=sorted(classes),
                                    origin_drift=drift, drift=bool(drift), failed_last_run=last["result"] == "failed",
                                    blacklist=conf.get("Unattended-Upgrade::Package-Blacklist", [])[:50], automatic_reboot=(conf.get("Unattended-Upgrade::Automatic-Reboot") or ["false"])[-1] == "true")
    sim = env.runner.run("apt_simulate")
    if sim.ok:
        pend = parse.apt_simulate(sim.text)
        out["pending"] = ok(total=len(pend), security=sum(1 for p in pend if p["security"]), security_packages=sorted(p["package"] for p in pend if p["security"])[:100],
                            other_packages=sorted(p["package"] for p in pend if not p["security"])[:100])
    else:
        out["pending"] = run_failure(sim)
    hold = env.runner.run("apt_showhold")
    out["holds"] = ok(packages=sorted(x for x in hold.text.split() if x)[:200]) if hold.ok else run_failure(hold)
    rr = _rd(env, "/var/run/reboot-required.pkgs") or _rd(env, "/run/reboot-required.pkgs") or ""
    out["reboot"] = ok(required=env.fs.exists("/var/run/reboot-required") or env.fs.exists("/run/reboot-required"), packages=sorted(set(rr.split()))[:50])
    out["versions"] = ok(packages=versions, kernel=(_rd(env, "/proc/sys/kernel/osrelease") or "").strip()) if inst.ok or versions else run_failure(inst)
    return out


# --------------------------------------------------------------------------------------------------------------------- inv.backups
def backups(env: Env) -> dict:
    pol = env.policy.t0
    out: dict = {}
    names: set[str] = set()
    lu = env.runner.run("systemctl_list_units")
    if lu.ok:
        for d in parse.list_units_json(lu.text):
            u = d.get("unit")
            if isinstance(u, str) and any(fnmatchcase(u, g) for g in pol.backup_units):
                names.add(u)
        shown = sorted(n for n in names if re.match(r"^[A-Za-z0-9:_.@\\-]{1,128}\.(service|timer|socket)\Z", n))[:30]
        if shown:
            r = env.runner.run("systemctl_show_unit", {"unit": shown})
            rows = []
            for b in parse.kv_blocks(r.text) if r.ok else []:
                rows.append({"unit": b.get("Id"), "active": b.get("ActiveState"), "sub": b.get("SubState"), "result": b.get("Result"), "exit_status": parse.to_int(b.get("ExecMainStatus")),
                             "last_exit": b.get("ExecMainExitTimestamp") or None, "active_since": b.get("ActiveEnterTimestamp") or None, "inactive_since": b.get("InactiveEnterTimestamp") or None})
            out["units"] = ok(units=rows) if r.ok else run_failure(r)
        else:
            out["units"] = ok(units=[], note="no unit matches policy t0.backup_units")
        t = env.runner.run("systemctl_list_timers")
        if t.ok:
            mine = [d for d in parse.list_units_json(t.text) if d.get("unit") in names or d.get("activates") in names]
            out["timers"] = ok(timers=[{"unit": d.get("unit"), "next_us": parse.to_int(d.get("next")), "last_us": parse.to_int(d.get("last"))} for d in mine][:50])
    else:
        out["units"] = run_failure(lu)
    now = env.now().timestamp()
    dirs = []
    for d in pol.backup_dirs:
        try:
            real = env.fs.resolve_dir(d)
            meta = env.fs.stat_meta(real)
            if meta["kind"] == "dir":
                entries, trunc = env.fs.list_meta(real, 5000)
                newest = max((e["mtime"] for e in entries), default=None)
                dirs.append({"path": d, "kind": "dir", "entries": len(entries), "newest_age_s": None if newest is None else max(0, int(now - newest)), "truncated": trunc})
            else:
                dirs.append({"path": d, "kind": meta["kind"], "age_s": max(0, int(now - meta["mtime"]))})
        except FsError as e:
            dirs.append({"path": d, "error": e.code})
    out["paths"] = ok(paths=dirs)
    return out


# -------------------------------------------------------------------------------------------------------------------- inv.net (local)
def net_local(env: Env) -> dict:
    out: dict = {}
    r = env.runner.run("ip_route")
    out["routes"] = ok(**parse.ip_routes(r.text)) if r.ok else run_failure(r)
    ufw = _rd(env, "/etc/ufw/ufw.conf") or ""
    m = re.search(r"^ENABLED=(\w+)", ufw, re.M)
    out["ufw"] = ok(enabled=(m.group(1).lower() == "yes")) if m else unavailable("ufw not configured")
    return out


def listeners_unprivileged(env: Env) -> dict:
    r = env.runner.run("ss_listen")
    return ok(listeners=parse.ss(r.text)[:300], processes_visible=False) if r.ok else run_failure(r)


# ------------------------------------------------------------------------------------------------------------ certs (agent's own side)
def own_certs(env: Env, node_cert: str | None, now: datetime) -> dict:
    """Expiry of the node's own certificate (the agent can read its pki directory)."""
    if not node_cert:
        return unavailable("node certificate path not configured")
    r = env.runner.run("openssl_x509_file", {"path": node_cert})
    if not r.ok:
        return run_failure(r)
    d = parse.x509(r.text)
    if d.get("not_after_epoch") is not None:
        d["days_left"] = int((d.pop("not_after_epoch") - now.timestamp()) // 86400)
    return ok(**d)


LOCAL_TLS_PORTS = (443, 8443)


def local_tls(env: Env) -> dict:
    """Live handshake to local TLS listeners, certificate not validated (we only read its expiry). Loopback only."""
    import socket
    import ssl
    rows = []
    for port in LOCAL_TLS_PORTS:
        row = {"port": port}
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection(("127.0.0.1", port), timeout=2) as s, ctx.wrap_socket(s) as t:
                der = t.getpeercert(binary_form=True)
            r = env.runner.run("openssl_x509_der", stdin=der)
            if r.ok:
                d = parse.x509(r.text)
                if d.get("not_after_epoch") is not None:
                    d["days_left"] = int((d.pop("not_after_epoch") - env.now().timestamp()) // 86400)
                row.update(d)
            else:
                row["error"] = r.reason
        except (OSError, ssl.SSLError):
            row["listening"] = False
        rows.append(row)
    return ok(listeners=rows)


__all__ = ["host", "disks", "gpu", "units", "pkgs", "backups", "net_local", "listeners_unprivileged", "own_certs", "local_tls", "under"]
