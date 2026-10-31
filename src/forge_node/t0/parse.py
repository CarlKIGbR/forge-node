"""Pure parsers for the output of the allowlisted read-only commands and /proc files. No I/O, no floats in the results (canonical JSON has none): fractional values become integers
in a stated unit (milli-units, bytes). Anything unparsable is skipped and counted, never guessed."""
import csv
import io
import json
import re

from .. import canon


def milli(s) -> int | None:
    """'70.12' -> 70120; '[N/A]'/'' -> None."""
    try:
        return int(round(float(str(s).strip()) * 1000))
    except (ValueError, TypeError):
        return None


def to_int(s) -> int | None:
    try:
        return int(str(s).strip())
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------------------------------------------------------- /proc
def meminfo(text: str) -> dict:
    kv = {}
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z_()0-9]+):\s+(\d+)(?:\s*kB)?\s*$", line)
        if m:
            kv[m.group(1)] = int(m.group(2)) * 1024
    return kv


def cpuinfo(text: str) -> dict:
    models, n = set(), 0
    for line in text.splitlines():
        if line.startswith("processor"):
            n += 1
        elif line.lower().startswith("model name"):
            models.add(line.split(":", 1)[1].strip())
    return {"threads": n, "model": sorted(models)[0] if models else None}


def loadavg(text: str) -> dict:
    p = text.split()
    return {"load1_milli": milli(p[0]), "load5_milli": milli(p[1]), "load15_milli": milli(p[2])} if len(p) >= 3 else {}


def uptime(text: str) -> int | None:
    p = text.split()
    m = milli(p[0]) if p else None
    return None if m is None else m // 1000


def os_release(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        m = re.match(r'^(PRETTY_NAME|VERSION_ID|ID|VERSION_CODENAME)=("?)(.*)\2$', line)
        if m:
            out[m.group(1).lower()] = m.group(3)
    return out


def mdstat(text: str) -> list[dict]:
    out, cur = [], None
    for line in text.splitlines():
        m = re.match(r"^(md\d+)\s*:\s*(\S+)\s+(\S+)\s*(.*)$", line)
        if m:
            cur = {"name": m.group(1), "state": m.group(2), "level": m.group(3), "devices": re.findall(r"([a-z0-9]+)\[\d+\]", m.group(4))}
            out.append(cur)
        elif cur is not None and re.search(r"\[[U_]+\]", line):
            cur["health"] = re.search(r"\[([U_]+)\]", line).group(1)
    return out


def mounts(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        p = line.split()
        if len(p) >= 4:
            out.append({"source": _unescape_mount(p[0]), "target": _unescape_mount(p[1]), "fstype": p[2], "options": p[3]})
    return out


def _unescape_mount(s: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


def diskstats(text: str) -> dict:
    """Per whole device (no partitions, no loop/ram): cumulative sectors read/written, io ms, in-flight."""
    out = {}
    for line in text.splitlines():
        p = line.split()
        if len(p) < 14:
            continue
        name = p[2]
        if re.match(r"^(loop|ram|zram|dm-|sr|fd)", name) or re.match(r"^(sd[a-z]+|vd[a-z]+|xvd[a-z]+)\d+$", name) or re.match(r"^nvme\d+n\d+p\d+$", name) or re.match(r"^md\d+p\d+$", name):
            continue
        out[name] = {"rd_sectors": int(p[5]), "wr_sectors": int(p[9]), "io_ms": int(p[12]), "inflight": int(p[11]), "rd_ios": int(p[3]), "wr_ios": int(p[7])}
    return out


def net_dev(text: str) -> dict:
    out = {}
    for line in text.splitlines()[2:]:
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        p = rest.split()
        if len(p) >= 9 and name.strip() != "lo":
            out[name.strip()] = {"rx_bytes": int(p[0]), "tx_bytes": int(p[8])}
    return out


def cpu_times(text: str) -> dict | None:
    for line in text.splitlines():
        if line.startswith("cpu "):
            v = [int(x) for x in line.split()[1:]]
            idle = v[3] + (v[4] if len(v) > 4 else 0)
            return {"total": sum(v[:8]) if len(v) >= 8 else sum(v), "idle": idle}
    return None


def cgroup_v2_path(text: str) -> str | None:
    for line in text.splitlines():
        if line.startswith("0::"):
            return line[3:].strip()
    return None


def kv_file(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        p = line.split()
        if len(p) == 2 and p[1].isdigit():
            out[p[0]] = int(p[1])
    return out


def io_stat(text: str) -> dict:
    rb = wb = 0
    for line in text.splitlines():
        rb += sum(int(x) for x in re.findall(r"\brbytes=(\d+)", line))
        wb += sum(int(x) for x in re.findall(r"\bwbytes=(\d+)", line))
    return {"rbytes": rb, "wbytes": wb}


# ----------------------------------------------------------------------------------------------------------------------- commands
def lsblk(text: str) -> list[dict]:
    try:
        doc = canon.loads(text)
    except canon.CanonError:
        try:
            doc = json.loads(text, parse_float=lambda s: int(float(s)))
        except ValueError:
            return []
    out = []

    def walk(devs, parent=None):
        for d in devs or []:
            mp = d.get("mountpoints") or ([d["mountpoint"]] if d.get("mountpoint") else [])
            out.append({"name": d.get("name"), "type": d.get("type"), "size": to_int(d.get("size")), "fstype": d.get("fstype"), "mountpoints": [m for m in mp if m],
                        "ro": bool(d.get("ro")), "rotational": bool(d.get("rota")), "model": (d.get("model") or "").strip() or None, "parent": parent})
            walk(d.get("children"), d.get("name"))
    walk(doc.get("blockdevices") if isinstance(doc, dict) else [])
    return out


def findmnt(text: str) -> list[dict]:
    try:
        doc = json.loads(text, parse_float=lambda s: int(float(s)))
    except ValueError:
        return []
    out = []

    def walk(fs):
        for f in fs or []:
            out.append({"target": f.get("target"), "source": f.get("source"), "fstype": f.get("fstype"), "options": f.get("options")})
            walk(f.get("children"))
    walk(doc.get("filesystems") if isinstance(doc, dict) else [])
    return out


def kv_blocks(text: str) -> list[dict]:
    """`systemctl show` output: key=value lines, blocks separated by an empty line."""
    out, cur = [], {}
    for line in text.splitlines():
        if not line.strip():
            if cur:
                out.append(cur)
                cur = {}
            continue
        k, sep, v = line.partition("=")
        if sep:
            cur[k] = v
    if cur:
        out.append(cur)
    return out


def kv_lines(text: str) -> dict:
    return {k: v for k, _, v in (l.partition("=") for l in text.splitlines()) if k}


def nvidia_gpus(text: str) -> list[dict]:
    out = []
    for row in csv.reader(io.StringIO(text), skipinitialspace=True):
        if len(row) < 14:
            continue
        out.append({"index": to_int(row[0]), "uuid": row[1], "name": row[2], "mem_used_mib": to_int(row[3]), "mem_total_mib": to_int(row[4]), "util_pct": to_int(row[5]),
                    "temp_c": to_int(row[6]), "power_mw": milli(row[7]), "power_limit_mw": milli(row[8]), "clock_sm_mhz": to_int(row[9]), "clock_max_sm_mhz": to_int(row[10]),
                    "pcie_gen": to_int(row[11]), "pcie_width": to_int(row[12]), "throttle": _throttle(row[13])})
    return out


_THROTTLE_BITS = {0x1: "gpu_idle", 0x2: "applications_clocks_setting", 0x4: "sw_power_cap", 0x8: "hw_slowdown", 0x10: "sync_boost", 0x20: "sw_thermal_slowdown",
                  0x40: "hw_thermal_slowdown", 0x80: "hw_power_brake_slowdown", 0x100: "display_clocks_setting"}


def _throttle(s: str) -> list[str]:
    try:
        v = int(s.strip(), 16)
    except ValueError:
        return []
    return [name for bit, name in _THROTTLE_BITS.items() if v & bit and bit != 0x1]


def nvidia_apps(text: str) -> list[dict]:
    out = []
    for row in csv.reader(io.StringIO(text), skipinitialspace=True):
        if len(row) < 4:
            continue
        name = (row[2].split() or [""])[0].rsplit("/", 1)[-1]          # first word, basename only: command lines can carry tokens, paths add nothing
        out.append({"gpu_uuid": row[0], "pid": to_int(row[1]), "process": name, "used_mib": to_int(row[3])})
    return out


def timedatectl(text: str) -> dict:
    kv = kv_lines(text)
    return {"timezone": kv.get("Timezone"), "ntp_synchronized": kv.get("NTPSynchronized") == "yes", "ntp_enabled": kv.get("NTP") == "yes"}


def list_units_json(text: str) -> list[dict]:
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    return [d for d in doc if isinstance(d, dict)] if isinstance(doc, list) else []


_SS = re.compile(r"^(tcp|udp)\s+(\S+)\s+\d+\s+\d+\s+(\S+)\s+(\S+)(?:\s+(.*))?$")


def ss(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = _SS.match(line.strip())
        if not m:
            continue
        local = m.group(3)
        addr, _, port = local.rpartition(":")
        procs = re.findall(r'\(\("([^"]*)"', m.group(5) or "") + re.findall(r'\),\("([^"]*)"', m.group(5) or "")
        out.append({"proto": m.group(1), "addr": addr.strip("[]") or "*", "port": to_int(port), "state": m.group(2), "processes": sorted(set(procs))})
    return out


def ip_routes(text: str) -> dict:
    try:
        doc = json.loads(text)
    except ValueError:
        return {"routes": [], "default_gateways": []}
    routes = [{"dst": r.get("dst"), "gateway": r.get("gateway"), "dev": r.get("dev"), "prefsrc": r.get("prefsrc")} for r in doc if isinstance(r, dict)]
    return {"routes": routes, "default_gateways": sorted({r["gateway"] for r in routes if r["dst"] == "default" and r["gateway"]})}


_INST = re.compile(r"^Inst (\S+)(?: \[([^\]]+)\])? \((\S+) (.*?)(?: \[[^\]]*\])?\)\s*$")


def apt_simulate(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        m = _INST.match(line)
        if m:
            origins = [o.strip() for o in m.group(4).split(",") if o.strip()]
            out.append({"package": m.group(1), "old": m.group(2), "new": m.group(3), "origins": origins, "security": any("-security" in o for o in origins)})
    return out


def apt_config(text: str) -> dict:
    """apt-config dump -> {key: [values]} for keys we care about (lists are `Key::`, scalars `Key`)."""
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        m = re.match(r'^([A-Za-z0-9_:.+-]+?)(::)?\s+"(.*)";\s*$', line)
        if m and (m.group(1).startswith("Unattended-Upgrade") or m.group(1).startswith("APT::Periodic")):
            if m.group(3) == "":
                continue                # apt-config prints the empty list head `Key ""` before `Key:: "..."` entries; an empty value carries nothing
            out.setdefault(m.group(1).rstrip(":"), []).append(m.group(3))
    return out


def origin_class(entry: str) -> str:
    """security | base | other for an unattended-upgrades origin entry (`${distro_id}:${distro_codename}-security`, `o=Ubuntu,a=noble-updates`, ...)."""
    e = entry.strip()
    if "-security" in e:
        return "security"
    if e in ("${distro_id}:${distro_codename}",) or re.fullmatch(r"(?:o|origin)=[A-Za-z]+,(?:a|archive)=[a-z0-9]+", e) or re.fullmatch(r"[A-Za-z]+:[a-z0-9]+", e):
        return "base"
    return "other"


def uu_log(text: str) -> dict:
    """Last run of unattended-upgrades from its log: timestamp (local, as logged), result class, and the origins it reported."""
    lines = text.splitlines()
    start = None
    for i, l in enumerate(lines):
        if "Starting unattended upgrades script" in l:
            start = i
    if start is None:
        return {"last_run": None, "result": "no_run_recorded", "origins": []}
    ts = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", lines[start])
    body = lines[start:]
    result = "unknown"
    joined = "\n".join(body)
    if re.search(r"\b(ERROR|CRITICAL)\b|failed", joined, re.I):
        result = "failed"
    elif "All upgrades installed" in joined:
        result = "installed"
    elif "No packages found that can be upgraded unattended" in joined:
        result = "nothing_to_do"
    origins = []
    for l in body:
        m = re.search(r"Allowed origins are: (.*)$", l)
        if m:
            origins = [o.strip() for o in re.split(r",\s+", m.group(1)) if o.strip()]
            break
    return {"last_run": ts.group(1) if ts else None, "result": result, "origins": origins}


def dpkg_versions(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        p = line.split("\t")
        if len(p) == 3 and p[2].startswith("ii"):
            out.append({"package": p[0], "version": p[1]})
    return out


_X509_DATE = re.compile(r"^notAfter=(.*)$", re.M)


def x509(text: str) -> dict:
    import calendar
    import time as _t
    out = {"not_after": None, "days_left": None, "subject": None, "sha256": None}
    m = _X509_DATE.search(text)
    if m:
        try:
            ts = calendar.timegm(_t.strptime(m.group(1).strip().replace("  ", " "), "%b %d %H:%M:%S %Y GMT"))
            out["not_after"] = _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime(ts))
            out["not_after_epoch"] = ts
        except ValueError:
            pass
    m = re.search(r"^subject=\s*(.*)$", text, re.M)
    out["subject"] = m.group(1).strip()[:200] if m else None
    m = re.search(r"sha256 Fingerprint=([0-9A-Fa-f:]{95})", text, re.I)
    out["sha256"] = m.group(1).replace(":", "").lower() if m else None
    return out


def virsh_table(text: str) -> list[dict]:
    rows = []
    lines = [l for l in text.splitlines() if l.strip()]
    for l in lines[2:]:
        p = l.split(None, 2)
        if len(p) >= 2:
            rows.append({"id": p[0], "name": p[1], "state": p[2].strip() if len(p) > 2 else ""})
    return rows


def sshd_effective(text: str) -> dict:
    keep = {"allowusers", "allowgroups", "denyusers", "denygroups", "permitrootlogin", "passwordauthentication", "pubkeyauthentication", "port", "listenaddress", "authorizedkeysfile"}
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        k, _, v = line.partition(" ")
        if k.lower() in keep:
            out.setdefault(k.lower(), []).append(v.strip())
    return out


def etc_group(text: str, names: tuple[str, ...]) -> dict:
    out = {n: [] for n in names}
    for line in text.splitlines():
        p = line.split(":")
        if len(p) >= 4 and p[0] in out:
            out[p[0]] = sorted(m for m in p[3].split(",") if m)
    return out


def etc_passwd(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        p = line.split(":")
        if len(p) >= 7:
            out.append({"user": p[0], "uid": to_int(p[2]), "home": p[5], "shell": p[6]})
    return out


_KEYTYPES = ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com", "ssh-dss")


def authorized_keys(text: str) -> list[dict]:
    """Fingerprint (SHA256, computed here - no key body leaves the parser) + comment per key line. Option strings are not returned (they can hold command= with secrets)."""
    import base64
    import hashlib
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        toks = line.split()
        idx = next((i for i, t in enumerate(toks) if t in _KEYTYPES), None)
        if idx is None or idx + 1 >= len(toks):
            continue
        try:
            blob = base64.b64decode(toks[idx + 1], validate=True)
        except ValueError:
            continue
        fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        out.append({"type": toks[idx], "fingerprint": fp, "comment": " ".join(toks[idx + 2:])[:80], "has_options": idx > 0})
    return out


def du_bytes(text: str) -> int | None:
    m = re.match(r"^(\d+)\s", text)
    return int(m.group(1)) if m else None
