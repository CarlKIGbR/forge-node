"""`forge-node.pyz doctor` (Design 4.4 'validation inside the real unit', 13.C C7): the install-time proof, run as the agent user on the node, before the agent is enabled and after every
release switch. It OBSERVES and reports; it never changes anything (privd's own `selfcheck` requests run each op's side-effect-free check inside its REAL transient unit, which is the
point: a hardening profile that silently breaks an op shows up here, not in production).

Checks (status ok | warn | fail | skip): clock, identity (node key/cert/CA, expiry), policy (signature, node, serial, mode), privd (reachable, peer root, policy agrees, lease), hub (TLS 1.3 + pin;
'unregistered' is the expected answer before the Cockpit approval), audit (the seal protocol PROVEN on the log filesystem by privd, both logs readable), forge root volume (ext4 loop mount
with nodev,nosuid, backing file on the root device), every probe and every op of the release's table inside its own unit. Exit status 0 only if nothing failed."""
import json
import os
import sys
from datetime import datetime, timezone

from .agent.client import HubClient, HubError, HubUnreachable, PinError
from .agent.config import AgentConfig, ConfigError
from .privd.client import PrivClient, PrivUnavailable
from .t0 import hardening
from .t0.policy import PolicyError, load_installed

PACE_S = 6.0                         # privd rate-limits selfchecks (12/min per caller uid); EVERY selfcheck request - the audit one included - is paced, 14 requests in all


def check(name: str, status: str, detail: str = "", **data) -> dict:
    return {"check": name, "status": status, "detail": detail[:300], **data}


class Doctor:
    def __init__(self, *, cfg: AgentConfig, clock, runner, ssh_keygen: str, priv: PrivClient, sleep, op_names, after_switch: bool, fs_stat=os.stat, mountinfo=None, out=sys.stdout):
        """Everything external is injected (tests pass fakes; main() passes the real ones). `op_names` = the ops of this release's table for the policy's profile. `after_switch`: run by
        the release switcher to decide whether to keep the new release - failures of ENVIRONMENTAL checks (clock, identity, hub) are reported as warnings then, everything that a release
        can break (policy, privd, audit, forge root, every probe and op in its unit, a hub that answers but is refused: pin, HTTP status) still fails. Only results marked `environmental` are
        downgraded: the clock, the node's own certificate and key files, and a hub that cannot be REACHED."""
        self.cfg, self.clock, self.runner, self.ssh_keygen, self.priv, self.sleep, self.op_names = cfg, clock, runner, ssh_keygen, priv, sleep, op_names
        self.fs_stat, self.mountinfo, self.out, self.after_switch = fs_stat, mountinfo, out, after_switch
        self.policy = None
        self._selfchecks = 0

    # ---- individual checks -------------------------------------------------------------------------------------------------------
    def clock_check(self) -> dict:
        r = self.runner.run("timedatectl")
        if not r.ok:
            return check("clock", "fail", f"timedatectl unusable ({r.reason})", environmental=True)
        kv = dict(line.partition("=")[::2] for line in r.text.splitlines())
        if kv.get("NTPSynchronized") != "yes":
            return check("clock", "fail", "the system clock is not NTP-synchronised (leases and jobs are rejected beyond 60 s of skew)", environmental=True)
        return check("clock", "ok", f"NTP synchronised, time zone {kv.get('Timezone', '?')}")

    def identity_check(self) -> dict:
        problems, info = [], {}
        for label, path, secret in (("node key", self.cfg.node_key, True), ("node certificate", self.cfg.node_cert, False), ("CA", self.cfg.ca_file, False)):
            try:
                st = self.fs_stat(path)
            except OSError:
                problems.append(f"{label} missing ({path})")
                continue
            if secret and (st.st_mode & 0o077 or st.st_uid != os.getuid()):
                problems.append("node key must be owned by the agent user and not accessible by others")
        if problems:
            return check("identity", "fail", "; ".join(problems), environmental=True)
        r = self.runner.run("openssl_x509_file", {"path": self.cfg.node_cert})
        if not r.ok:
            return check("identity", "fail", f"cannot read the node certificate ({r.reason})", environmental=True)
        import re
        from email.utils import parsedate_to_datetime
        m = re.search(r"notAfter=(.+)", r.text)
        fp = re.search(r"sha256 Fingerprint=([0-9A-F:]+)", r.text, re.I)
        try:
            end = parsedate_to_datetime(m.group(1).replace("GMT", "+0000")) if m else None
        except (TypeError, ValueError):
            end = None
        if end is None:
            return check("identity", "fail", "cannot parse the certificate expiry", environmental=True)
        days = (end - self.clock()).days
        info = {"fingerprint": fp.group(1) if fp else None, "days_left": days}
        if days < 0:
            return check("identity", "fail", "the node certificate has expired", environmental=True, **info)
        return check("identity", "warn" if days < 14 else "ok", f"certificate valid for {days} more days (note the fingerprint for the Cockpit approval)", **info)

    def policy_check(self) -> dict:
        try:
            self.policy = load_installed(self.cfg.policy_dir, self.cfg.allowed_signers, self.cfg.node_id, self.clock(), owner_uid=self.cfg.owner_uid, ssh_keygen=self.ssh_keygen)
        except PolicyError as e:
            return check("policy", "fail", e.detail)
        p = self.policy
        return check("policy", "ok", f"serial {p.serial}, profile {p.profile}, mode {p.global_mode}, tiers {list(p.tiers_enabled)}", serial=p.serial, mode=p.global_mode)

    def privd_check(self) -> dict:
        try:
            r = self.priv.request("status", {})
        except PrivUnavailable as e:
            return check("privd", "fail", str(e))
        if not r.get("ok"):
            return check("privd", "fail", f"status refused ({r.get('code')})")
        st = r["status"]
        pol = st.get("policy")
        if self.policy is not None and (pol is None or pol.get("serial") != self.policy.serial):
            return check("privd", "fail", f"privd's policy ({None if pol is None else pol.get('serial')}) differs from the agent's ({self.policy.serial})")
        lease = st.get("lease")
        detail = "reachable, root peer; " + ("a lease is held" if lease else "no lease yet (expected until the node is approved and polls)")
        return check("privd", "ok" if lease else "warn", detail, local_stop=st.get("local_stop"), gates=st.get("gates"))

    def hub_check(self) -> dict:
        if self.policy is None:
            return check("hub", "skip", "no policy")
        c = HubClient(self.cfg.hub_host, self.cfg.hub_port, self.cfg.node_cert, self.cfg.node_key, self.cfg.ca_file, self.policy.hub_tls_pins, timeout_s=15.0)
        try:
            c.healthz()
            return check("hub", "ok", "TLS 1.3 handshake, chain, name and hub pin verified; /healthz answered")
        except PinError:
            return check("hub", "fail", "the hub's certificate is not in the policy's hub_tls_pins")
        except HubError as e:
            if e.status in (401, 403):
                return check("hub", "warn", "reachable and pinned; the node is not registered/approved yet (expected until the Cockpit approval)")
            return check("hub", "fail", f"hub answered {e.status}")
        except HubUnreachable as e:
            return check("hub", "fail", f"hub unreachable: {e}", environmental=True)
        finally:
            c.close()

    def _selfcheck(self, target: str, timeout=None):
        """Every selfcheck request, paced: the first goes at once, each later one PACE_S after the previous (privd allows 12 per minute per caller)."""
        if self._selfchecks:
            self.sleep(PACE_S)
        self._selfchecks += 1
        return self.priv.request("selfcheck", {"target": target}, timeout) if timeout else self.priv.request("selfcheck", {"target": target})

    def audit_check(self) -> dict:
        try:
            r = self._selfcheck("audit")
        except PrivUnavailable as e:
            return check("audit", "fail", str(e))
        if not r.get("ok"):
            return check("audit", "fail", f"selfcheck refused ({r.get('code')}: {r.get('detail')})")
        sc = r["selfcheck"]
        logs = {k: v for k, v in sc["detail"].items() if k != "live"}
        live = sc["detail"].get("live", {})
        fs = {k: (v or {}).get("fstype") for k, v in logs.items()}
        if not sc["ok"]:
            bad = {k: [c for c, v in (d or {}).get("checks", {}).items() if not v.get("ok")] for k, d in logs.items()}
            broken = sorted(k for k, v in live.items() if not v.get("ok"))
            return check("audit", "fail", f"the seal protocol does not work on this filesystem: {bad}" + (f"; the live log cannot be opened for appending: {broken}" if broken else ""), fstype=fs)
        blind = {k: v["unobservable"] for k, v in logs.items() if (v or {}).get("unobservable")}
        if blind:                                                                                  # a route whose unflagged control failed here proves nothing: say so, do not pass it silently
            return check("audit", "warn", f"seal protocol proven except for routes that cannot be observed in this unit/filesystem: {blind}", fstype=fs)
        return check("audit", "ok", f"append-only + immutable seal proven on {fs}: descriptors held across the flag change cannot write after the seal; live logs open for appending: {sorted(live)}", fstype=fs)

    def forge_root_check(self) -> list[dict]:
        if self.policy is None:
            return [check("forge_root", "skip", "no policy")]
        try:
            doc = json.loads(open(os.path.join(self.cfg.policy_dir, f"policy-{self.policy.serial}.json"), "rb").read())
        except (OSError, ValueError):
            return [check("forge_root", "fail", "cannot re-read the policy")]
        roots = doc.get("forge_roots", [])
        if not roots:
            return [check("forge_root", "skip", "this node has no forge root")]
        mounts = self.mountinfo() if self.mountinfo else self._findmnt()
        out = []
        for r in roots:
            m = next((x for x in mounts if x.get("target") == r["path"]), None)
            problems = []
            if m is None:
                problems.append("not a mount point: the loop volume is not mounted (the mountpoint is chattr +i, nothing can be written there)")
            else:
                opts = set(str(m.get("options", "")).split(","))
                if m.get("fstype") != "ext4" or not str(m.get("source", "")).startswith("/dev/loop") or not {"nodev", "nosuid"} <= opts:
                    problems.append(f"mount is {m.get('fstype')} {m.get('source')} {m.get('options')}: need ext4 on /dev/loopN with nodev,nosuid")
            try:
                if self.fs_stat(r["backing_image"]).st_dev != self.fs_stat("/").st_dev:
                    problems.append("the backing image is not on the root filesystem")
            except OSError:
                problems.append("backing image missing or unreadable")
            out.append(check("forge_root", "fail" if problems else "ok", "; ".join(problems) or f"{r['path']}: ext4 loop volume, nodev,nosuid, backing file on the root device", path=r["path"]))
        return out

    def _findmnt(self) -> list[dict]:
        r = self.runner.run("findmnt")
        if not r.ok:
            return []
        try:
            doc = json.loads(r.text)
        except ValueError:
            return []
        flat = []

        def walk(nodes):
            for n in nodes:
                flat.append(n)
                walk(n.get("children", []))
        walk(doc.get("filesystems", []))
        return flat

    def unit_checks(self) -> list[dict]:
        """privd runs each probe's and each op's side-effect-free selfcheck inside its REAL transient unit."""
        targets = [f"probe:{p}" for p in sorted(hardening.RO_PROBES)] + [f"op:{o}" for o in sorted(self.op_names)]
        out = []
        for t in targets:
            try:
                r = self._selfcheck(t, 150)
            except PrivUnavailable as e:
                out.append(check(t, "fail", str(e)))
                continue
            if not r.get("ok"):
                out.append(check(t, "fail", f"{r.get('code')}: {r.get('detail')}"))
                continue
            sc = r["selfcheck"]
            data = ((sc.get("detail") or {}).get("data") or {})
            out.append(check(t, "ok" if sc["ok"] else "fail", "side-effect-free selfcheck inside the real unit passed" if sc["ok"] else f"denied inside the real unit: {data.get('missing') or data}", rc=sc.get("rc")))
        return out

    def run(self) -> list[dict]:
        results = [self.clock_check(), self.identity_check(), self.policy_check(), self.privd_check(), self.hub_check(), self.audit_check(), *self.forge_root_check(), *self.unit_checks()]
        if self.after_switch:
            for r in results:
                if r.get("environmental") and r["status"] == "fail":
                    r["status"], r["detail"] = "warn", ("environmental, not a reason to roll back: " + r["detail"])[:300]
        for r in results:
            self.out.write(json.dumps(r, sort_keys=True) + "\n")
        failed = [r["check"] for r in results if r["status"] == "fail"]
        self.out.write(json.dumps({"doctor": "FAILED" if failed else "OK", "failed": failed, "warnings": [r["check"] for r in results if r["status"] == "warn"]}, sort_keys=True) + "\n")
        self._failed = failed
        return results


def main(argv=None) -> int:
    import time
    args = list(sys.argv[2:] if argv is None else argv)
    if args not in ([], ["--after-switch"]):
        sys.stderr.write("usage: doctor [--after-switch]\n")
        return 2

    from .privd.optable import build_optable
    from .profile import PROFILE
    from .t0.runner import ReadOnlyRunner, RunnerError, trusted_binary
    try:
        cfg = AgentConfig.from_environ()
        ssh_keygen = trusted_binary("ssh-keygen")
    except (ConfigError, RunnerError) as e:
        sys.stderr.write(f"doctor: {e}\n")
        return 2
    d = Doctor(cfg=cfg, clock=lambda: datetime.now(timezone.utc), runner=ReadOnlyRunner(), ssh_keygen=ssh_keygen, priv=PrivClient(cfg.priv_socket, cfg.owner_uid, 150), sleep=time.sleep,
               op_names=build_optable(PROFILE).names(PROFILE), after_switch=bool(args))
    d.run()
    return 1 if d._failed else 0
