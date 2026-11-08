"""The `ro-probe` programs (Design 4.1 "t0-probe", 4.4 class `ro-probe`): the T0 reads that need more than the agent's uid. privd (N3) starts one probe per request in a transient unit of
class `ro-probe` (see hardening.py); the agent never runs these itself. In N2 they are plain functions plus the `probe_main` entry point, tested directly.

A probe takes ONLY a name and a small parameter object. Everything that decides what may be read - log units, cert paths, repositories, model directories, the protected set, the
window - comes from the root-installed, signature-checked policy loaded by the probe process, never from the request: whatever the agent sends is untrusted input."""
import os
import re
import shutil
from . import confined, parse
from .env import Env, failed, ok, run_failure, run_slots, unavailable
from .fsread import FsError, norm_abs, under
from .needs import UULOG_LIMIT

HEAVY_PROBES = frozenset({"models", "git"})
PROBE_NAMES = ("net", "firewall", "containers", "container_net", "vms", "certs", "git", "access", "models", "journal", "activity", "uulog")
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
    """Listening sockets WITH process names (`ss -p`: needs CAP_SYS_PTRACE). The firewall rules are a separate probe (CAP_NET_ADMIN)."""
    _no_params(params)
    r = env.runner.run("ss_listen_procs")
    return {"listeners": ok(listeners=parse.ss(r.text)[:300], processes_visible=True) if r.ok else run_failure(r)}


def _probe_firewall(params: dict, env: Env) -> dict:
    _no_params(params)
    ipt = env.runner.run("iptables_docker_user")
    if ipt.ok:
        rules = [l for l in ipt.text.splitlines() if l.startswith("-")][:200]
        return {"docker_user": ok(rules=rules, count=len(rules))}
    return {"docker_user": run_failure(ipt)}


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
    mj = _json_field(mounts)
    for m in mj if isinstance(mj, list) else []:
        if isinstance(m, dict):
            mts.append({"type": m.get("Type"), "source": m.get("Source"), "destination": m.get("Destination"), "rw": m.get("RW") is True})
    return {"id": cid_v, "short": cid_v[:12], "name": str(_json_field(name) or "").lstrip("/"), "image_id": _json_field(image), "image": _json_field(image_ref),
            "state": _json_field(state), "restarts": _json_field(restarts), "started_at": _json_field(started), "pid": _json_field(pid), "log_path": _json_field(logpath),
            "labels": lab if isinstance(lab, dict) else {}, "ports": sorted(pubs), "mounts": mts}


_LABEL_KEEP = re.compile(r"^(forge\.[a-z0-9._-]{1,48}|com\.docker\.compose\.(?:project|service|project\.working_dir|project\.config_files)|org\.opencontainers\.image\.(?:title|version|source|revision))\Z")


DOCKER_BUDGET_S = 90            # all docker calls of one probe together; the unit's RuntimeMaxSec is 120


def _containers(env: Env) -> tuple[list[dict], str | None, int]:
    """(rows, error, skipped): `skipped` = containers docker listed that could not be parsed or that did not fit the time budget - reported, never silently dropped."""
    t_end = env.now().timestamp() + DOCKER_BUDGET_S
    ids = env.runner.run("docker_ps_ids", None, None, 30)
    if not ids.ok:
        return [], ids.reason, 0
    all_ids = [x for x in ids.text.split() if re.match(r"^[0-9a-f]{64}$", x)]
    rows = []
    for i in range(0, min(len(all_ids), 400), 40):
        left = t_end - env.now().timestamp()
        if left < 5:
            return rows, None, max(0, min(len(all_ids), 400) - len(rows))
        r = env.runner.run("docker_inspect", {"id": all_ids[i:i + 40]}, None, min(30.0, left))
        if not r.ok:
            return rows, r.reason, 0
        for line in r.text.split("\n"):             # NOT splitlines(): U+0085/U+2028 in a label would split a row and hide the container
            row = parse_inspect_line(line)
            if row:
                rows.append(row)
    return rows, None, max(0, min(len(all_ids), 400) - len(rows))


def _probe_containers(params: dict, env: Env) -> dict:
    _no_params(params)
    rows, err, skipped = _containers(env)
    if err:
        return {"containers": unavailable("docker not installed") if err == "missing" else failed(err)}
    digests: dict = {}
    img_ids = sorted({r["image_id"] for r in rows if isinstance(r["image_id"], str) and re.match(r"^sha256:[0-9a-f]{64}$", r["image_id"])})
    t_img = env.now().timestamp() + 20
    for i in range(0, min(len(img_ids), 200), 40):
        if env.now().timestamp() >= t_img:
            break
        d = env.runner.run("docker_image_inspect", {"id": img_ids[i:i + 40]}, None, 10)
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
             "restarts": r["restarts"], "started_at": r["started_at"], "labels": labels, "ports": r["ports"][:20], "bind_sources": sorted({m["source"] for m in r["mounts"] if m["type"] == "bind" and isinstance(m["source"], str)})[:20],
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
        out.append(e)
    return {"containers": ok(containers=out, count=len(out), unparsed=skipped, truncated=len(rows) >= 400)}


def _probe_container_net(params: dict, env: Env) -> dict:
    """Per container network byte counters, read from /proc/<pid>/net/dev of the container's init process. Needs CAP_SYS_PTRACE (other users' /proc entries), so it is its own
    probe: the plain `containers` inventory does not get that capability."""
    _no_params(params)
    rows, err, _ = _containers(env)
    if err:
        return {"container_net": unavailable("docker not installed") if err == "missing" else failed(err)}
    out = {}
    for r in rows:
        if isinstance(r["pid"], int) and r["pid"] > 1:
            try:
                nd = parse.net_dev(env.fs.read_text(f"/proc/{r['pid']}/net/dev"))
            except FsError:
                continue
            if nd:
                out[r["short"]] = {"rx_bytes": sum(v["rx_bytes"] for v in nd.values()), "tx_bytes": sum(v["tx_bytes"] for v in nd.values())}
    return {"container_net": ok(containers=out)}


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
                # a link in a cert directory (letsencrypt/live -> archive) is followed, but the TARGET must look like a certificate file and not be protected
                if not _CERT_FILE.match(f_real.rsplit("/", 1)[-1]) or env.fs.protected.hit(f_real):
                    row["certs"].append({"file": f.rsplit("/", 1)[-1], "error": "target_not_a_certificate_name"})
                    continue
                r = run_slots(env.runner, "openssl_x509_file", {"path": f_real}, 10)
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
# Git runs NO repository-controlled program here, by construction: the repository's own config is never read by git. The probe builds a private snapshot git directory (HEAD,
# refs/heads/<branch>, an empty objects dir, and a config WRITTEN BY THE PROBE) and points git at it (GIT_DIR=GIT_COMMON_DIR=<snapshot>, GIT_WORK_TREE=<repo>, GIT_INDEX_FILE and
# GIT_OBJECT_DIRECTORY inside <repo>/.git as data). Everything that can name a program (core.fsmonitor, filter.*, diff/merge drivers, hooks, includes, aliases, `commondir`,
# `config.worktree`, submodule configs) lives in files the snapshot does not contain, so replacing <repo>/.git/config - before, at or after the scan - changes nothing.
# Only a handful of inert core.* switches that decide what "modified" means are copied over, value-checked, from the repository config bytes read once.
_INERT_CORE = frozenset({"filemode", "ignorecase", "symlinks", "autocrlf", "eol", "safecrlf", "precomposeunicode", "trustctime", "checkstat", "ignorestat"})
_INERT_VALUE = re.compile(r"^[A-Za-z0-9_.-]{1,16}\Z")


def filter_git_config(text: str) -> tuple[str, list[str]]:
    """(config text for the snapshot, names of everything that was NOT carried over). The result is generated here from validated key/value pairs; nothing of the original text is
    copied. A key is only taken from a plain `[core]` section line `key = value`; anything the tiny parser does not understand is dropped."""
    keep: dict[str, str] = {}
    dropped: list[str] = []
    section = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        m = re.match(r'^\[\s*([A-Za-z0-9.-]+)(\s+"[^"\n]*")?\s*\]\s*(?:[#;].*)?$', line)
        if m:
            section = m.group(1).lower() if not m.group(2) else "other"
            if m.group(1).lower() != "core" or m.group(2):
                dropped.append(f"[{m.group(1).lower()}]")
            continue
        k = re.match(r"^([A-Za-z][A-Za-z0-9-]*)\s*=\s*([^\s#;\\]*)\s*(?:[#;].*)?$", line)
        if section == "core" and k and k.group(1).lower() in _INERT_CORE and _INERT_VALUE.match(k.group(2)):
            keep[k.group(1).lower()] = k.group(2)
        elif section == "core":
            dropped.append("core." + (line.split("=", 1)[0].strip().lower()[:30] or "?"))
        elif section is None:
            dropped.append("(outside any section)")
    cfg = "[core]\n\trepositoryformatversion = 0\n" + "".join(f"\t{k} = {v}\n" for k, v in sorted(keep.items()))
    return cfg, sorted(set(dropped))[:20]


def valid_branch(name) -> bool:
    """git check-ref-format semantics for refs/heads/<name>, on a stricter charset: no leading '/' or '-', no trailing '/' or '.', no '//', no '..', no component that is empty, starts
    with '.' or ends with '.lock', nothing outside [A-Za-z0-9._/-] (so no NUL, backslash, space, control character, ~ ^ : ? * [ @{). An HEAD that names anything else is not followed."""
    if not isinstance(name, str) or not 1 <= len(name) <= 200 or name == "@" or not re.fullmatch(r"[A-Za-z0-9._/-]+", name):
        return False
    if name.startswith(("/", "-")) or name.endswith(("/", ".")) or "//" in name or ".." in name:
        return False
    return all(c and not c.startswith(".") and not c.endswith(".lock") for c in name.split("/"))


def _git_snapshot(info: dict, config_text: str) -> str | None:
    """Private snapshot git dir (mode 0700 in the probe's private tmp). Returns its path, or None if the revision is unknown (git then has nothing to compare against). Everything is
    written through a directory descriptor with validated components (confined.py): the branch name comes from the repository's owner and must not be able to select a path."""
    import tempfile
    if not info.get("rev") or not re.fullmatch(r"[0-9a-f]{40}", info["rev"]):
        return None
    if not info.get("detached") and not valid_branch(info.get("branch")):
        raise confined.ConfinementError("branch name refused")
    snap = tempfile.mkdtemp(prefix="fn-git-")
    try:
        os.chmod(snap, 0o700)
        fd = confined.open_dir(snap)
        try:
            os.mkdir("objects", 0o700, dir_fd=fd)
            if info.get("detached"):
                head = info["rev"] + "\n"
                os.mkdir("refs", 0o700, dir_fd=fd)
            else:
                confined.write_new_at(fd, ["refs", "heads", *info["branch"].split("/")], (info["rev"] + "\n").encode())
                head = f"ref: refs/heads/{info['branch']}\n"
            confined.write_new_at(fd, ["HEAD"], head.encode())
            confined.write_new_at(fd, ["config"], config_text.encode())
        finally:
            os.close(fd)
    except BaseException:
        shutil.rmtree(snap, ignore_errors=True)
        raise
    return snap


def _git_rev(env: Env, real: str) -> dict:
    """Revision and branch read straight from .git/HEAD and refs - git itself is not executed for this."""
    head = env.fs.read_exception(f"{real}/.git/HEAD", _SAFE_GIT_FILES).strip()
    m = re.match(r"^ref: refs/heads/([A-Za-z0-9._/-]{1,200})\Z", head)
    if not m:
        return {"rev": head if re.match(r"^[0-9a-f]{40}$", head) else None, "branch": None, "detached": True}
    branch = m.group(1)
    if not valid_branch(branch):
        return {"rev": None, "branch": None, "detached": False, "ref_error": "malformed_ref"}
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


GIT_BUDGET_S = 120


def _probe_git(params: dict, env: Env) -> dict:
    _no_params(params)
    rows = []
    t_end = env.now().timestamp() + GIT_BUDGET_S
    for configured in env.policy.t0.repos:
        row: dict = {"path": configured}
        try:
            real = env.fs.resolve_dir(configured)
            if env.fs.stat_meta(f"{real}/.git")["kind"] != "dir":
                row["error"] = "unsupported_git_layout"
                rows.append(row)
                continue
            info = _git_rev(env, real)
            row.update({k: v for k, v in info.items() if k != "ref_error"})
            if info.get("ref_error"):
                row["error"], row["dirty_tracked"], row["dirty_status"] = info["ref_error"], None, "rejected:" + info["ref_error"]
                rows.append(row)
                continue
            cfg_text, dropped = filter_git_config(env.fs.read_exception(f"{real}/.git/config", _SAFE_GIT_FILES))
            if dropped:
                row["config_not_used"] = dropped          # e.g. filter.*, core.fsmonitor, includes: the dirty count is computed without them
            if env.now().timestamp() >= t_end:
                row["dirty_tracked"], row["dirty_status"] = None, "skipped_budget"
                rows.append(row)
                continue
            try:
                snap = _git_snapshot(info, cfg_text)
            except (confined.ConfinementError, OSError):
                row["dirty_tracked"], row["dirty_status"] = None, "failed:snapshot"
                rows.append(row)
                continue
            if snap is None:
                row["dirty_tracked"], row["dirty_status"] = None, "no_revision"
                rows.append(row)
                continue
            try:
                r = run_slots(env.runner, "git_status_tracked", {"repo": real, "snap": snap}, max(5.0, t_end - env.now().timestamp()))
            finally:
                shutil.rmtree(snap, ignore_errors=True)
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
MODELS_DU_BUDGET_S = 150          # + the last du may use what is left of it: total < RuntimeMaxSec (240)


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
                    left = t_end - env.now().timestamp()
                    if sizes_ok and left >= 5:
                        d = run_slots(env.runner, "du_ionice", {"path": f"{real}/{e['name']}"}, min(120.0, left))        # never longer than what is left of the budget
                        item["size"] = parse.du_bytes(d.text) if d.ok else None
                        if not d.ok:
                            item["size_status"] = "unsupported_name" if d.reason == "bad_slot" else d.reason
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
    t_end = now + 40                                                    # RuntimeMaxSec is 60
    rows = []
    for lu in env.policy.t0.units_for_logs[:30]:
        if env.now().timestamp() >= t_end:
            rows.append({"unit": lu.unit, "last_log_age_s": None, "skipped": "budget"})
            continue
        r = env.runner.run("journal_last", {"unit": lu.unit}, None, 10)
        m = re.match(r"^(\d{9,11})(?:\.\d+)?\s", r.text) if r.ok else None
        rows.append({"unit": lu.unit, "last_log_age_s": max(0, int(now - int(m.group(1)))) if m else None})
    return {"activity": ok(units=rows)}


def _probe_uulog(params: dict, env: Env) -> dict:
    """`/var/log/unattended-upgrades` is root:adm 0750 on Ubuntu, so the agent uid cannot read it (found in the live proof): the root probe reads the tail and returns only the
    parsed outcome of the last run - timestamp, result class, the origins the run reported - never log lines."""
    _no_params(params)
    try:
        text = env.fs.read_text("/var/log/unattended-upgrades/unattended-upgrades.log", UULOG_LIMIT)
    except FsError as e:
        return {"uulog": failed(e.code)}
    return {"uulog": ok(**parse.uu_log(text))}
