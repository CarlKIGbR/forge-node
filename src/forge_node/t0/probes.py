"""The `ro-probe` programs (Design 4.1 "t0-probe", 4.4 class `ro-probe`): the T0 reads that need more than the agent's uid. privd (N3) starts one probe per request in a transient unit of
class `ro-probe` (see hardening.py); the agent never runs these itself. In N2 they are plain functions plus the `probe_main` entry point, tested directly.

A probe takes ONLY a name and a small parameter object. Everything that decides what may be read - log units, cert paths, repositories, model directories, the protected set, the
window - comes from the root-installed, signature-checked policy loaded by the probe process, never from the request: whatever the agent sends is untrusted input."""
import re
from . import parse
from .env import Env, failed, ok, run_failure, unavailable
from .fsread import FsError, norm_abs, under

HEAVY_PROBES = frozenset({"models", "git"})
PROBE_NAMES = ("net", "containers", "vms", "certs", "git", "access", "models", "journal", "activity")
_SAFE_GIT_FILES = re.compile(r"^/.{1,4000}/\.git/(?:HEAD|packed-refs|config|refs/heads/[A-Za-z0-9._/-]{1,200}|refs/remotes/[A-Za-z0-9._/-]{1,200})\Z")
_JOURNAL_BUDGET = 48 * 1024


class ProbeError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


def run_probe(name: str, params, env: Env) -> dict:
    """Dispatch. The blackout window comes from the policy and is applied to heavy probes here, at execution time, regardless of what the caller checked before."""
    if name not in PROBE_NAMES:
        raise ProbeError("DENY_OP_UNKNOWN", name)
    if not isinstance(params, dict):
        raise ProbeError("DENY_PARAM", "params must be an object")
    if name in HEAVY_PROBES and env.policy.window.in_blackout(env.now()):
        raise ProbeError("DENY_WINDOW", "heavy probe inside the blackout window")
    return globals()["_probe_" + name](params, env)


def _no_params(params: dict):
    if params:
        raise ProbeError("DENY_PARAM", "this probe takes no parameters")


# ---------------------------------------------------------------------------------------------------------------------------- net
def _probe_net(params: dict, env: Env) -> dict:
    _no_params(params)
    out: dict = {}
    r = env.runner.run("ss_listen_procs")
    out["listeners"] = ok(listeners=parse.ss(r.text)[:300], processes_visible=True) if r.ok else run_failure(r)
    ipt = env.runner.run("iptables_docker_user")
    if ipt.ok:
        rules = [l for l in ipt.text.splitlines() if l.startswith("-")][:200]
        out["docker_user"] = ok(rules=rules, count=len(rules))
    else:
        out["docker_user"] = run_failure(ipt)
    return out


# ------------------------------------------------------------------------------------------------------------------------ containers
def _json_field(s: str):
    import json
    try:
        return json.loads(s)
    except ValueError:
        return None


def parse_inspect_line(line: str) -> dict | None:
    p = line.split("\t")
    if len(p) != 12:
        return None
    cid, name, image, image_ref, state, restarts, started, pid, logpath, labels, ports, mounts = p
    cid_v = _json_field(cid)
    if not isinstance(cid_v, str) or not re.match(r"^[0-9a-f]{64}$", cid_v):
        return None
    lab = _json_field(labels)
    pubs = []
    pj = _json_field(ports)
    if isinstance(pj, dict):
        for cport, binds in pj.items():
            for b in binds or []:
                if isinstance(b, dict):
                    pubs.append(f"{b.get('HostIp', '')}:{b.get('HostPort', '')}->{cport}")
    mts = []
    for m in mounts.split(";"):
        q = m.split("|")
        if len(q) == 4:
            mts.append({"type": q[0], "source": q[1], "destination": q[2], "rw": q[3] == "true"})
    return {"id": cid_v, "short": cid_v[:12], "name": str(_json_field(name) or "").lstrip("/"), "image_id": _json_field(image), "image": _json_field(image_ref),
            "state": _json_field(state), "restarts": _json_field(restarts), "started_at": _json_field(started), "pid": _json_field(pid), "log_path": _json_field(logpath),
            "labels": lab if isinstance(lab, dict) else {}, "ports": sorted(pubs), "mounts": mts}


_LABEL_KEEP = re.compile(r"^(forge\.[a-z0-9._-]{1,48}|com\.docker\.compose\.(?:project|service|project\.working_dir|project\.config_files)|org\.opencontainers\.image\.(?:title|version|source|revision))\Z")


def _containers(env: Env) -> tuple[list[dict], str | None]:
    ids = env.runner.run("docker_ps_ids")
    if not ids.ok:
        return [], ids.reason
    all_ids = [x for x in ids.text.split() if re.match(r"^[0-9a-f]{64}$", x)]
    rows = []
    for i in range(0, min(len(all_ids), 400), 40):
        r = env.runner.run("docker_inspect", {"id": all_ids[i:i + 40]})
        if not r.ok:
            return rows, r.reason
        for line in r.text.splitlines():
            row = parse_inspect_line(line)
            if row:
                rows.append(row)
    return rows, None


def _probe_containers(params: dict, env: Env) -> dict:
    if set(params) - {"with_usage"} or not isinstance(params.get("with_usage", False), bool):
        raise ProbeError("DENY_PARAM", "only with_usage:boolean is allowed")
    rows, err = _containers(env)
    if err:
        return {"containers": unavailable("docker not installed") if err == "missing" else failed(err)}
    digests: dict = {}
    img_ids = sorted({r["image_id"] for r in rows if isinstance(r["image_id"], str) and re.match(r"^sha256:[0-9a-f]{64}$", r["image_id"])})
    for i in range(0, min(len(img_ids), 200), 40):
        d = env.runner.run("docker_image_inspect", {"id": img_ids[i:i + 40]})
        for line in d.text.splitlines() if d.ok else []:
            p = line.split("\t")
            if len(p) == 2:
                iid, rd = _json_field(p[0]), _json_field(p[1])
                if isinstance(iid, str):
                    digests[iid] = [x for x in rd if isinstance(x, str)] if isinstance(rd, list) else []
    now = env.now().timestamp()
    out = []
    for r in rows:
        labels = {k: v for k, v in r["labels"].items() if _LABEL_KEEP.match(str(k))}
        e = {"id": r["short"], "name": r["name"], "image": r["image"], "image_id": r["image_id"], "image_digests": digests.get(r["image_id"], [])[:3], "state": r["state"],
             "restarts": r["restarts"], "started_at": r["started_at"], "labels": labels, "ports": r["ports"][:20], "bind_sources": sorted({m["source"] for m in r["mounts"] if m["type"] == "bind"})[:20],
             "forge_managed": labels.get("forge.managed") == "true", "forge_critical": labels.get("forge.critical") == "true"}
        # attribution for the Revision (Design 4.1 inv.usage): project, compose context, owner of the working directory; unattributed when nothing says who owns it
        wd = labels.get("com.docker.compose.project.working_dir")
        owner = None
        if isinstance(wd, str) and wd.startswith("/"):
            try:
                owner = env.fs.stat_meta(env.fs.resolve_dir(wd))["uid"]
            except FsError:
                owner = None
        e["attribution"] = {"forge_project": labels.get("forge.project"), "compose_project": labels.get("com.docker.compose.project"), "working_dir_owner_uid": owner,
                            "unattributed": not (labels.get("forge.project") or labels.get("com.docker.compose.project"))}
        lp = r["log_path"]
        if isinstance(lp, str) and lp.startswith("/") and under(norm_abs(lp), "/var/lib/docker/containers"):
            try:
                e["last_log_age_s"] = max(0, int(now - env.fs.stat_meta(norm_abs(lp))["mtime"]))
            except FsError:
                e["last_log_age_s"] = None
        if params.get("with_usage") and isinstance(r["pid"], int) and r["pid"] > 1:
            nd = None
            try:
                nd = parse.net_dev(env.fs.read_text(f"/proc/{r['pid']}/net/dev"))
            except FsError:
                pass
            if nd is not None:
                e["net"] = {"rx_bytes": sum(v["rx_bytes"] for v in nd.values()), "tx_bytes": sum(v["tx_bytes"] for v in nd.values())}
        out.append(e)
    return {"containers": ok(containers=out, count=len(out), truncated=len(rows) >= 400)}


# -------------------------------------------------------------------------------------------------------------------------------- vms
def _probe_vms(params: dict, env: Env) -> dict:
    _no_params(params)
    if not env.runner.available("virsh_list"):
        return {"domains": unavailable("virsh not installed"), "pools": unavailable("virsh not installed")}
    d, p = env.runner.run("virsh_list"), env.runner.run("virsh_pools")
    return {"domains": ok(domains=parse.virsh_table(d.text)[:200]) if d.ok else run_failure(d), "pools": ok(pools=parse.virsh_table(p.text)[:50]) if p.ok else run_failure(p)}


# ----------------------------------------------------------------------------------------------------------------------------- certs
_CERT_FILE = re.compile(r"^(?!.*(?i:priv|key|secret))[A-Za-z0-9_.@+-]{1,128}\.(?:crt|pem|cer)\Z")          # key material is never opened, even by name suspicion


def _probe_certs(params: dict, env: Env) -> dict:
    _no_params(params)
    rows = []
    now = env.now().timestamp()
    for configured in env.policy.t0.cert_paths:
        row = {"path": configured}
        try:
            real = env.fs.resolve_dir(configured)
            meta = env.fs.stat_meta(real)
            files = [real] if meta["kind"] == "file" else []
            if meta["kind"] == "dir":
                entries, _ = env.fs.list_meta(real, 500)
                files = [f"{real}/{e['name']}" for e in entries if e["kind"] in ("file", "link") and _CERT_FILE.match(e["name"])][:50]
            row["certs"] = []
            for f in files:
                try:
                    f_real = env.fs.resolve_dir(f)
                except FsError:
                    continue
                r = env.runner.run("openssl_x509_file", {"path": f_real})
                if r.ok:
                    d = parse.x509(r.text)
                    if d.get("not_after_epoch") is not None:
                        d["days_left"] = int((d.pop("not_after_epoch") - now) // 86400)
                    d["file"] = f.rsplit("/", 1)[-1]
                    row["certs"].append(d)
                else:
                    row["certs"].append({"file": f.rsplit("/", 1)[-1], "error": r.reason})
        except FsError as e:
            row["error"] = e.code
        rows.append(row)
    return {"certs": ok(paths=rows)}


# -------------------------------------------------------------------------------------------------------------------------------- git
_SAFE_CONFIG = {
    "core": {"repositoryformatversion", "filemode", "bare", "logallrefupdates", "ignorecase", "precomposeunicode", "symlinks", "autocrlf", "eol", "safecrlf", "sharedrepository", "trustctime", "checkstat", "ignorestat"},
    "remote": {"url", "fetch", "pushurl", "tagopt", "prune"},
    "branch": {"remote", "merge", "rebase", "description"},
    "user": {"name", "email"},
    "gc": {"auto", "autopacklimit", "reflogexpire", "reflogexpireunreachable", "pruneexpire"},
    "pack": {"threads", "windowmemory", "deltacachesize"},
    "receive": {"denycurrentbranch", "fsckobjects"},
    "fetch": {"prune", "fsckobjects"},
    "pull": {"rebase", "ff"},
    "push": {"default"},
    "init": {"defaultbranch"},
}


def git_config_is_safe(text: str) -> tuple[bool, str]:
    """`git status` runs programs named in the repository's own config (core.fsmonitor, filter.*.clean, diff drivers, hooks, includes). Only a closed set of inert settings
    passes; anything else - or anything the tiny parser does not understand - means `git` is not executed on that repository."""
    section = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        m = re.match(r'^\[\s*([A-Za-z0-9.-]+)(?:\s+"[^"\n]*")?\s*\]\s*(?:[#;].*)?$', line)
        if m:
            section = m.group(1).lower()
            if section not in _SAFE_CONFIG:
                return False, f"section [{section}]"
            continue
        if section is None:
            return False, "key outside a section"
        if line.endswith("\\"):
            return False, "line continuation"
        k = re.match(r"^([A-Za-z][A-Za-z0-9-]*)\s*(?:=.*)?$", line)
        if not k or k.group(1).lower() not in _SAFE_CONFIG[section]:
            return False, f"key {section}.{(k.group(1) if k else line[:20])!r}"
    return True, ""


def _git_rev(env: Env, real: str) -> dict:
    """Revision and branch read straight from .git/HEAD and refs - git itself is not executed for this."""
    head = env.fs.read_exception(f"{real}/.git/HEAD", _SAFE_GIT_FILES).strip()
    m = re.match(r"^ref: refs/heads/([A-Za-z0-9._/-]{1,200})\Z", head)
    if not m:
        return {"rev": head if re.match(r"^[0-9a-f]{40}$", head) else None, "branch": None, "detached": True}
    branch = m.group(1)
    if ".." in branch.split("/"):
        return {"rev": None, "branch": None, "detached": False}
    rev = None
    try:
        rev = env.fs.read_exception(f"{real}/.git/refs/heads/{branch}", _SAFE_GIT_FILES).strip()
    except FsError:
        try:
            for l in env.fs.read_exception(f"{real}/.git/packed-refs", _SAFE_GIT_FILES, 4 * 1024 * 1024).splitlines():
                if l.endswith(" refs/heads/" + branch):
                    rev = l.split()[0]
        except FsError:
            pass
    return {"rev": rev if rev and re.match(r"^[0-9a-f]{40}$", rev) else None, "branch": branch, "detached": False}


def _probe_git(params: dict, env: Env) -> dict:
    _no_params(params)
    rows = []
    for configured in env.policy.t0.repos:
        row: dict = {"path": configured}
        try:
            real = env.fs.resolve_dir(configured)
            if env.fs.stat_meta(f"{real}/.git")["kind"] != "dir":
                row["error"] = "unsupported_git_layout"
                rows.append(row)
                continue
            row.update(_git_rev(env, real))
            safe, why = git_config_is_safe(env.fs.read_exception(f"{real}/.git/config", _SAFE_GIT_FILES))
            if not safe:
                row["dirty_tracked"], row["dirty_status"], row["dirty_reason"] = None, "skipped_unsafe_config", why
            else:
                r = env.runner.run("git_status_tracked", {"repo": real})
                if r.ok:
                    row["dirty_tracked"], row["dirty_status"] = len([l for l in r.text.splitlines() if l.strip()]), "ok"
                else:
                    row["dirty_tracked"], row["dirty_status"] = None, "failed:" + r.reason
        except FsError as e:
            row["error"] = e.code
        rows.append(row)
    return {"repos": ok(repos=rows)}


# ----------------------------------------------------------------------------------------------------------------------------- access
def _probe_access(params: dict, env: Env) -> dict:
    _no_params(params)
    out: dict = {}
    r = env.runner.run("sshd_effective")
    out["sshd"] = ok(**parse.sshd_effective(r.text)) if r.ok else run_failure(r)
    try:
        grp = parse.etc_group(env.fs.read_text("/etc/group"), ("docker", "sudo", "adm"))
        out["groups"] = ok(**grp)
    except FsError as e:
        out["groups"] = failed(e.code)
    users = []
    try:
        pw = parse.etc_passwd(env.fs.read_text("/etc/passwd"))
    except FsError as e:
        out["authorized_keys"] = failed(e.code)
        return out
    for u in pw:
        if len(users) >= 100:
            break
        if u["uid"] is None or (u["uid"] != 0 and u["uid"] < 1000) or u["shell"].endswith(("nologin", "false")) or not u["home"].startswith("/") or u["user"] == "nobody":
            continue
        try:
            home = norm_abs(u["home"])
            text = env.fs.read_user_file(f"{home}/.ssh/authorized_keys")
        except FsError:
            continue
        users.append({"user": u["user"], "keys": parse.authorized_keys(text)[:50]})
    out["authorized_keys"] = ok(users=users)
    return out


# ---------------------------------------------------------------------------------------------------------------------------- models
MODELS_DU_BUDGET_S = 300


def _probe_models(params: dict, env: Env) -> dict:
    """Design 4.1/10.4: directory names (depth <= 2), sizes and mtimes of the policy model directories - metadata only. Sizes come from `du` run under `ionice -c3 nice -n19`;
    without ionice there are no sizes (never at normal I/O priority)."""
    _no_params(params)
    dirs = []
    sizes_ok = env.runner.available("du_ionice")
    t_end = env.now().timestamp() + MODELS_DU_BUDGET_S
    for configured in env.policy.t0.model_dirs:
        row: dict = {"path": configured}
        try:
            real = env.fs.resolve_dir(configured)
            top, trunc = env.fs.list_meta(real, 300)
            row["truncated"] = trunc
            entries = []
            for e in top:
                item = {"name": e["name"], "kind": e["kind"], "mtime": e["mtime"]}
                if e["kind"] == "dir":
                    try:
                        sub, st = env.fs.list_meta(f"{real}/{e['name']}", 60)
                        item["children"] = [{"name": c["name"], "kind": c["kind"], "size": c["size"] if c["kind"] == "file" else None, "mtime": c["mtime"]} for c in sub]
                        item["children_truncated"] = st
                    except FsError:
                        item["children"] = []
                    if sizes_ok and env.now().timestamp() < t_end:
                        d = env.runner.run("du_ionice", {"path": f"{real}/{e['name']}"})
                        item["size"] = parse.du_bytes(d.text) if d.ok else None
                    else:
                        item["size"] = None
                        item["size_status"] = "skipped_budget" if sizes_ok else "no_ionice"
                else:
                    item["size"] = e["size"]
                entries.append(item)
            row["entries"] = entries
        except FsError as e:
            row["error"] = e.code
        dirs.append(row)
    return {"models": ok(dirs=dirs)}


# --------------------------------------------------------------------------------------------------------------------------- journal
def _probe_journal(params: dict, env: Env) -> dict:
    from .. import redact
    from .params import validate_t0
    from ..protocol import ProtoError
    try:
        validate_t0("logs.unit", params)
    except ProtoError as e:
        raise ProbeError("DENY_PARAM", e.detail) from e
    lu = env.policy.log_unit(params["unit"])
    if lu is None:
        raise ProbeError("DENY_NOT_ALLOWLISTED", "unit is not in policy t0.units_for_logs")
    since = params.get("since_s", 3600)
    lines_n = params.get("lines", 200)
    r = env.runner.run("journal_unit", {"unit": params["unit"], "since": f"-{since}s", "lines": str(lines_n)})
    if not r.ok:
        return {"log": run_failure(r)}
    from .sanitize import clean_text
    lines = [redact.redact_full(clean_text(l, 400)) for l in r.text.splitlines() if l.strip() and not l.startswith("-- ")]
    kept, total = [], 0
    for l in reversed(lines):                      # newest lines win when the budget is short
        total += len(l.encode("utf-8")) + 4
        if total > _JOURNAL_BUDGET:
            break
        kept.append(l)
    kept.reverse()
    return {"log": ok(unit=params["unit"], lines=kept, dropped=len(lines) - len(kept), read_truncated=r.truncated, sensitivity=lu.sensitivity)}


def _probe_activity(params: dict, env: Env) -> dict:
    _no_params(params)
    now = env.now().timestamp()
    rows = []
    for lu in env.policy.t0.units_for_logs[:30]:
        r = env.runner.run("journal_last", {"unit": lu.unit})
        m = re.match(r"^(\d{9,11})(?:\.\d+)?\s", r.text) if r.ok else None
        rows.append({"unit": lu.unit, "last_log_age_s": max(0, int(now - int(m.group(1)))) if m else None})
    return {"activity": ok(units=rows)}
