"""Release artifact per profile, signed manifest, version-independent switcher (Design 13.C-13.E, T-REL) and the unit texts / policy templates it carries."""
import ast
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
from privd_helpers import NOW, SRC

from forge_node import canon, sshsig
from forge_node.privd.policy_full import parse_full
from forge_node.release import build, policies, units
from forge_node.release.switcher import SWITCHER_API, UNITS_START, UNITS_STOP, Refused, SwitchError, Switcher, VERSION_RE, main as switcher_main
from forge_node.t0.policy import OWNER_PRINCIPAL

SRC_ROOT = Path(SRC)


@pytest.fixture(scope="module")
def mkey(tmp_path_factory):
    d = tmp_path_factory.mktemp("relkey")
    os.chmod(d, 0o700)
    priv = d / "owner"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(priv)], check=True, capture_output=True)
    pub = " ".join((d / "owner.pub").read_text().split()[:2])
    return priv, pub


def docs(text):
    """All JSON documents in the switcher's output, in order."""
    dec, i, out = json.JSONDecoder(), 0, []
    while i < len(text):
        if text[i].isspace():
            i += 1
            continue
        d, i = dec.raw_decode(text, i)
        out.append(d)
    return out


class Env:
    """A fake node: /opt/forge-node tree, ledger, policy dir, signers, recorded systemctl, a doctor whose verdict the test chooses."""

    def __init__(self, tmp: Path, key):
        self.tmp, (self.priv, self.pub) = tmp, key
        self.base = tmp / "opt" / "forge-node"
        (self.base / "releases").mkdir(parents=True)
        for d in (self.tmp / "opt", self.base, self.base / "releases"):
            os.chmod(d, 0o755)
        self.signers = tmp / "allowed_signers"
        self.signers.write_text(sshsig.allowed_signers_text([(OWNER_PRINCIPAL, self.pub, sshsig.NS_RELEASE)]))
        os.chmod(self.signers, 0o644)
        self.policy_dir = tmp / "policy"
        self.policy_dir.mkdir()
        self.ledger = tmp / "ledger.sqlite"
        self.node_env = tmp / "node.env"
        self.node_env.write_text("# written by the installer\nFORGE_NODE_NODE_ID=g2\nFORGE_NODE_HUB_HOST=192.168.10.4\n")
        os.chmod(self.node_env, 0o644)
        self.calls = []
        self.doctor_ok = True
        self.doctor_script = []                                   # per-call verdicts (first doctor, second doctor, ...); falls back to doctor_ok
        self.on_doctor = None                                     # called at every doctor run (to change the world while it runs)
        self.local_stop = tmp / "LOCAL_STOP"
        self.lock_path = tmp / "release.lock"
        self.self_path = tmp / "sbin" / "forge-node-release"
        self.self_path.parent.mkdir()
        self.out = __import__("io").StringIO()

    def sign(self, ns=sshsig.NS_RELEASE):
        return lambda raw: sshsig.sign(raw, self.priv, ns)

    def run(self, argv, stdin, timeout):
        self.calls.append(list(argv))
        if argv[0].endswith("ssh-keygen"):
            r = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout)
            return r.returncode, r.stdout, r.stderr
        if "doctor" in argv:
            if self.on_doctor:
                self.on_doctor()
            ok = self.doctor_script.pop(0) if self.doctor_script else self.doctor_ok
            return (0, b"", b"") if ok else (1, b'{"check": "privd", "detail": "boom", "status": "fail"}\n{"doctor": "FAILED", "failed": ["privd"]}\n', b"")
        return 0, b"", b""

    def release(self, ver="0.3.0", profile="full", **kw):
        out = self.tmp / f"out-{ver}-{profile}"
        res = build.build_release(ver, profile, out, src_root=SRC_ROOT, sign=kw.pop("sign", self.sign()), **kw)
        d = self.base / "releases" / ver
        d.mkdir(parents=True)
        with tarfile.open(res["tar"]) as tf:                      # exactly 13.C C4: tar -xf ... -C releases/$VER --strip-components=1 --no-same-owner
            for m in tf.getmembers():
                m.name = m.name.split("/", 1)[1] if "/" in m.name else ""
                if m.name:
                    tf.extract(m, d, filter="fully_trusted")                # keeps the modes the builder wrote (the "tar" filter would clear group/other-write bits and hide a mode bug)
        os.chmod(d, 0o755)
        return res

    def switcher(self, **kw) -> Switcher:
        args = dict(base=str(self.base), root="/opt/forge-node", ledger=str(self.ledger), signers=str(self.signers), policy_dir=str(self.policy_dir), node_env=str(self.node_env), local_stop=str(self.local_stop), lock_path=str(self.lock_path), trust_anchor=str(self.tmp),
                    ssh_keygen=shutil.which("ssh-keygen"), runuser="/usr/sbin/runuser",
                    run=self.run, self_path=str(self.self_path), owner_uid=0, out=self.out)
        args.update(kw)
        return Switcher(**args)

    def make_ledger(self, user_version=1, state=None):
        c = sqlite3.connect(self.ledger)
        c.execute("CREATE TABLE IF NOT EXISTS exec(job_id TEXT, state TEXT)")
        if state:
            c.execute("INSERT INTO exec VALUES('j', ?)", (state,))
        c.execute(f"PRAGMA user_version={user_version}")
        c.commit()
        c.close()


@pytest.fixture
def env(tmp_path, mkey):
    os.chown(tmp_path, 0, 0)
    os.chmod(tmp_path, 0o755)
    return Env(tmp_path, mkey)


# -------------------------------------------------------------------------------------------------------------------------- artifact
def test_release_artifact_per_profile_contains_only_profile_ops(env):
    full = build.build_release("0.3.0", "full", env.tmp / "o-full", src_root=SRC_ROOT, sign=env.sign())
    t0 = build.build_release("0.3.0", "t0", env.tmp / "o-t0", src_root=SRC_ROOT, sign=env.sign())
    # open the zipapps straight out of the tars
    def pyz_names(res):
        with tarfile.open(res["tar"]) as tf:
            data = tf.extractfile("forge-node-0.3.0/forge-node.pyz").read()
        p = env.tmp / f"x-{res['sha256'][:6]}.pyz"
        p.write_bytes(data)
        return p, set(zipfile.ZipFile(p).namelist())
    pf, nf = pyz_names(full)
    pt, nt = pyz_names(t0)
    assert "forge_node/privd/ops.py" in nf and "forge_node/privd/opworker.py" in nf
    assert "forge_node/privd/ops.py" not in nt and "forge_node/privd/opworker.py" not in nt           # g1/g4 get no op code at all (test_g4_profile_has_no_t1_t2_helpers)
    for names in (nf, nt):
        assert not [n for n in names if n.startswith("forge_node/hub/") or n.startswith("forge_node/release/") or "test" in n]
        assert "forge_node/privd/gate.py" in names and "forge_node/privd/privctl.py" in names and "forge_node/cli.py" in names
    # the built-in profile of each artifact
    for p, want in ((pf, "full"), (pt, "t0")):
        code = "import sys; sys.path.insert(0, %r); from forge_node import profile; from forge_node.privd.optable import build_optable; print(profile.PROFILE, sorted(build_optable(profile.PROFILE).names('full')))" % str(p)
        out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
        assert out.stdout.split()[0] == want, out
        assert ("selftest.noop" in out.stdout) == (want == "full")
    # the t0 zipapp refuses to run an op worker; the full one parses its arguments
    assert subprocess.run([sys.executable, "-I", str(pt), "opworker", "run", "/nonexistent"], capture_output=True).returncode == 2
    assert b"contains no op worker" in subprocess.run([sys.executable, "-I", str(pt), "opworker", "run", "/x"], capture_output=True).stderr
    assert subprocess.run([sys.executable, "-I", str(pf), "nonsense"], capture_output=True).returncode == 2
    assert subprocess.run([sys.executable, "-I", str(pf)], capture_output=True).returncode == 2


def test_the_build_is_reproducible_and_carries_a_signed_manifest_of_every_file(env, mkey):
    a, b = env.release("0.3.0", "full"), build.build_release("0.3.0", "full", env.tmp / "again", src_root=SRC_ROOT, sign=env.sign())
    assert a["manifest"] == b["manifest"] and a["manifest"]["files"] == b["manifest"]["files"]
    with tarfile.open(a["tar"]) as t1, tarfile.open(b["tar"]) as t2:
        assert [(m.name, m.mode, m.uid, m.gid, m.mtime) for m in t1.getmembers()] == [(m.name, m.mode, m.uid, m.gid, m.mtime) for m in t2.getmembers()]
        for m in t1.getmembers():
            if m.isfile() and m.name != "forge-node-0.3.0/RELEASE.json.sig":                    # signatures carry no randomness for ed25519, but compare the rest strictly
                assert t1.extractfile(m).read() == t2.extractfile(m.name).read(), m.name
    man = a["manifest"]
    assert man["profile"] == "full" and man["switcher_api"] == SWITCHER_API and set(man["units"]) == set(units.all_units())
    assert set(man["files"]) == {"forge-node.pyz", "bin/privctl", "sbin/forge-node-release", *[f"units/{u}" for u in units.all_units()], "policy/policy-g2.json", "policy/policy-g3.json"}
    assert {k for k in build.build_release("0.3.0", "t0", env.tmp / "t0", src_root=SRC_ROOT, sign=env.sign())["manifest"]["files"] if k.startswith("policy/")} == {"policy/policy-g1.json", "policy/policy-g4.json"}
    # the tar's own signature verifies the way 13.C C2 does it
    sig = Path(str(a["tar"]) + ".sig").read_text()
    assert sshsig.verify(Path(a["tar"]).read_bytes(), sig, sshsig.NS_RELEASE, OWNER_PRINCIPAL, env.signers.read_text(), shutil.which("ssh-keygen"))
    for bad in ("../x", "a b", "", "x" * 70, ".hidden"):
        with pytest.raises(build.BuildError):
            build.build_release(bad, "full", env.tmp / "bad", src_root=SRC_ROOT, sign=env.sign())
    with pytest.raises(build.BuildError):
        build.build_release("1", "other", env.tmp / "bad", src_root=SRC_ROOT, sign=env.sign())


def test_no_unit_files_sudoers_or_keys_are_installed_by_the_builder(env):
    before = set(os.listdir("/tmp"))
    env.release("0.3.0", "full")
    man = json.loads(next((env.base / "releases" / "0.3.0").glob("RELEASE.json")).read_text())
    assert not [f for f in man["files"] if "sudoers" in f or f.endswith((".key", ".pem")) or "id_" in f]
    assert not os.path.exists("/etc/systemd/system/forge-node-agent.service") and not os.path.exists("/etc/sudoers.d/forge-node")


# -------------------------------------------------------------------------------------------------------------------------- units
def parse_unit(text):
    sec, out = None, {}
    for line in text.splitlines():
        if line.startswith("["):
            sec = line[1:-1]
            out[sec] = {}
        elif "=" in line:
            k, _, v = line.partition("=")
            out[sec][k] = v
    return out


def test_agent_and_privd_units_match_the_design(env):
    u = {n: parse_unit(t) for n, t in units.all_units().items()}
    a, p, s = u["forge-node-agent.service"]["Service"], u["forge-node-privd.service"]["Service"], u["forge-node-privd.socket"]["Socket"]
    assert a["User"] == "forgenode" and a["NoNewPrivileges"] == "yes" and a["CapabilityBoundingSet"] == "" and a["IPAddressDeny"] == "any" and a["IPAddressAllow"].startswith("192.168.10.4/32")
    assert a["ReadWritePaths"] == "/var/lib/forge-node /var/log/forge-node-agent"          # the agent's directory log path is root-owned; it only appends to the file
    assert a["ExecStart"].endswith("forge-node.pyz agent run") and a["EnvironmentFile"] == "/etc/forge-node/node.env"
    assert a["LimitFSIZE"] == "134217728"                                                  # a compromised agent cannot grow its (append-only, group-writable) audit file without bound
    assert p["User"] == "root" and p["NoNewPrivileges"] == "yes" and p["ProtectSystem"] == "strict" and p["RestrictAddressFamilies"] == "AF_UNIX" and p["IPAddressDeny"] == "any"
    assert p["CapabilityBoundingSet"] == "CAP_LINUX_IMMUTABLE CAP_CHOWN" and p["KillMode"] == "process"
    # test_privd_unit_writes_only_state_log_policy
    assert set(p["ReadWritePaths"].split()) == {"/var/lib/forge-node-priv", "/var/log/forge-node-priv", "/var/log/forge-node-agent", "/run/forge-node", "/etc/forge-node"}
    assert s == {"ListenStream": "/run/forge-node/priv.sock", "SocketMode": "0660", "SocketUser": "root", "SocketGroup": "forgenode", "DirectoryMode": "0755", "Accept": "no", "RemoveOnStop": "yes"}
    assert u["forge-node-audit-rotate.timer"]["Timer"]["Persistent"] == "yes" and "audit-rotate due" in u["forge-node-audit-rotate.service"]["Service"]["ExecStart"]
    for name, t in units.all_units().items():
        assert "sudo" not in t and "\t" not in t and not any(line.endswith(" ") for line in t.splitlines()), name


def test_units_are_linked_to_current_not_copied(env):
    env.release("0.3.0", "full")
    sw = env.switcher()
    assert sw.cmd_install_first("0.3.0") == 0
    links = [c for c in env.calls if c[:2] == ["/usr/bin/systemctl", "link"]]
    assert sorted(c[2] for c in links) == sorted(f"/opt/forge-node/current/units/{u}" for u in units.all_units())      # via `current`, never a version directory
    assert ["/usr/bin/systemctl", "daemon-reload"] in env.calls and not [c for c in env.calls if c[1:2] in (["enable"], ["start"])]
    assert os.readlink(env.base / "current") == "releases/0.3.0" and (env.base / "profile").read_text() == "full\n"


# --------------------------------------------------------------------------------------------------------------------------- switching
def test_release_switch_moves_agent_ops_units_together(env):
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    env.calls.clear()
    assert sw.cmd_switch("0.3.1", False) == 0
    seq = [(c[1], c[2:]) for c in env.calls if c[0] == "/usr/bin/systemctl"]
    assert seq[0] == ("stop", list(UNITS_STOP))                                              # quiesce first: EVERYTHING that can create a ledger row, then the ledger is read
    assert [c for c in seq if c[0] == "stop"] == [seq[0]]
    assert seq[-1] == ("start", ["forge-node-privd.socket", "forge-node-agent.service", "forge-node-audit-rotate.timer"])
    assert os.readlink(env.base / "current") == "releases/0.3.1" and os.readlink(env.base / "previous") == "releases/0.3.0"
    assert any("doctor" in c for c in env.calls)                                              # doctor ran after the switch, as forgenode
    # ONE pointer moves agent, privd, op table and units: everything version-bound is inside the release directory
    man = json.loads((env.base / "releases" / "0.3.1" / "RELEASE.json").read_text())
    assert "forge-node.pyz" in man["files"] and all(f"units/{u}" in man["files"] for u in man["units"])


def test_a_failing_doctor_restores_the_previous_release_by_itself(env):
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    env.doctor_script = [False, True]                                       # the new release fails doctor, the restored one passes
    assert sw.cmd_switch("0.3.1", False) == 1
    assert os.readlink(env.base / "current") == "releases/0.3.0"
    res = docs(env.out.getvalue())[-1]
    assert res["restored"] == "0.3.0" and res["failure"].startswith("doctor failed") and "privd" in res["failure"] and res["restored_doctor"] == "ok" and res["switched"] is None


def test_rollback_refused_on_state_schema_outside_window(env):
    env.release("0.3.0", "full")
    env.release("0.2.0", "full", state_window=(2, 3))                                       # an older release that cannot run on schema 1
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger(user_version=1)
    with pytest.raises(Refused, match="state schema 1 is outside the window 2..3"):
        sw.cmd_switch("0.2.0", False)
    with pytest.raises(Refused):
        sw.cmd_check("0.2.0")
    assert os.readlink(env.base / "current") == "releases/0.3.0" and not [c for c in env.calls if c[1:2] == ["stop"]]      # nothing was touched, not even stopped


def test_rollback_refused_while_ledger_nonterminal(env):
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    for state in ("received", "started", "effect_done", "reconciling"):
        env.ledger.unlink(missing_ok=True)
        env.make_ledger(state=state)
        env.calls.clear()
        with pytest.raises(Refused, match="not terminal"):
            sw.cmd_switch("0.3.1", False)
        assert os.readlink(env.base / "current") == "releases/0.3.0"
        stops = [c for c in env.calls if c[1:2] == ["stop"]]
        assert stops == [["/usr/bin/systemctl", "stop", *UNITS_STOP]]                        # everything was stopped to freeze the ledger, found it non-terminal, and was started again
        assert env.calls[-1] == ["/usr/bin/systemctl", "start", *UNITS_START]
    env.ledger.unlink()
    env.make_ledger(state="committed")                                                       # terminal rows do not block
    assert sw.cmd_switch("0.3.1", False) == 0


def test_the_ledger_is_reread_after_the_agent_is_stopped(env):
    """G28: an op that is claimed between 'the check looked clean' and 'current is moved' must stop the switch. The ledger is read AFTER the agent was stopped."""
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    real_run = env.run

    def run(argv, stdin, timeout):
        if argv[:3] == ["/usr/bin/systemctl", "stop", "forge-node-agent.service"] and "forge-node-privd.service" in argv:
            c = sqlite3.connect(env.ledger)
            c.execute("INSERT INTO exec VALUES('late', 'started')")                          # the last in-flight delivery lands while the agent is being stopped
            c.commit()
            c.close()
        return real_run(argv, stdin, timeout)
    sw.run = run
    with pytest.raises(Refused, match="not terminal"):
        sw.cmd_switch("0.3.1", False)
    assert os.readlink(env.base / "current") == "releases/0.3.0"


def test_rollback_keeps_ledger_audit_policy_untouched(env):
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    (env.policy_dir / "policy-1.json").write_text('{"schema":1}')
    audit = env.tmp / "audit"
    audit.mkdir()
    (audit / "priv.jsonl").write_text("x\n")
    env.make_ledger(state="committed")

    def snap():
        return {str(p): (p.stat().st_mtime_ns, p.stat().st_size, p.read_bytes()) for d in (env.policy_dir, audit) for p in d.rglob("*") if p.is_file()} | {"ledger": env.ledger.read_bytes()}
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    before = snap()
    assert sw.cmd_switch("0.3.1", False) == 0 and sw.cmd_switch("0.3.0", False) == 0
    assert snap() == before


def test_switcher_supports_lower_switcher_api_and_refuses_higher_with_self_update_hint(env):
    env.release("0.3.0", "full")
    env.release("0.4.0", "full", switcher_api=SWITCHER_API + 1)
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    with pytest.raises(Refused, match="switcher_api 2.*self-update 0.4.0"):
        sw.cmd_check("0.4.0")
    with pytest.raises(Refused):
        sw.cmd_switch("0.4.0", False)
    env.release("0.2.5", "full", switcher_api=SWITCHER_API - 1 if SWITCHER_API > 0 else 0)  # equal-or-lower api is fine
    assert sw.cmd_check("0.2.5") == 0


def test_switcher_self_update_verifies_signature_and_keeps_prev(env):
    env.release("0.3.0", "full")
    sw = env.switcher()
    env.self_path.write_text("#!/bin/sh\necho old\n")
    assert sw.cmd_self_update("0.3.0") == 0
    new = env.self_path.read_bytes()
    assert new == (SRC_ROOT / "forge_node" / "release" / "switcher.py").read_bytes() and os.access(env.self_path, os.X_OK)
    assert Path(str(env.self_path) + ".prev").read_text() == "#!/bin/sh\necho old\n"           # rollback of the switcher: mv forge-node-release.prev forge-node-release
    # a release whose switcher was swapped after signing is refused and nothing is installed
    env.release("0.3.1", "full")
    sw_path = env.base / "releases" / "0.3.1" / "sbin" / "forge-node-release"
    os.chmod(sw_path, 0o755)
    sw_path.write_text("#!/bin/sh\nrm -rf /\n")
    before = env.self_path.read_bytes()
    with pytest.raises(Refused, match="differs from RELEASE.json"):
        sw.cmd_self_update("0.3.1")
    assert env.self_path.read_bytes() == before
    # and a signature by anybody but the owner
    other = env.tmp / "otherkey"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(other)], check=True, capture_output=True)
    env.release("0.3.2", "full", sign=lambda raw: sshsig.sign(raw, other, sshsig.NS_RELEASE))
    with pytest.raises(Refused, match="owner signature"):
        sw.cmd_self_update("0.3.2")


def test_tampered_or_odd_release_trees_are_refused(env):
    env.release("0.3.0", "full")
    sw = env.switcher()
    d = env.base / "releases" / "0.3.0"
    assert sw.cmd_check("0.3.0") == 0
    # extra file / changed file / missing file / symlink / hard link / group-writable file or directory / wrong owner is checked via mode+uid
    (d / "units" / "evil.service").write_text("[Service]\nExecStart=/bin/sh\n")
    with pytest.raises(Refused, match="not listed"):
        sw.cmd_check("0.3.0")
    (d / "units" / "evil.service").unlink()
    (d / "bin" / "privctl").write_text("#!/bin/sh\necho pwned\n")
    with pytest.raises(Refused, match="differs from RELEASE.json"):
        sw.cmd_check("0.3.0")
    shutil.rmtree(d)
    env.release("0.3.0", "full")
    (d / "units" / "forge-node-agent.service").unlink()
    with pytest.raises(Refused, match="listed but missing"):
        sw.cmd_check("0.3.0")
    shutil.rmtree(d)
    env.release("0.3.0", "full")
    os.chmod(d / "forge-node.pyz", 0o666)
    with pytest.raises(Refused, match="only root can write"):
        sw.cmd_check("0.3.0")
    os.chmod(d / "forge-node.pyz", 0o644)
    os.symlink("/etc/passwd", d / "units" / "link.service")
    with pytest.raises(Refused):
        sw.cmd_check("0.3.0")
    os.unlink(d / "units" / "link.service")
    os.link(d / "forge-node.pyz", d / "units" / "hard.service")
    with pytest.raises(Refused):
        sw.cmd_check("0.3.0")
    os.unlink(d / "units" / "hard.service")
    os.chmod(d, 0o775)
    with pytest.raises(Refused, match="root-owned directory"):
        sw.cmd_check("0.3.0")
    os.chmod(d, 0o755)
    assert sw.cmd_check("0.3.0") == 0
    # RELEASE.json edited (e.g. a lower state_min) => the signature no longer verifies
    man = json.loads((d / "RELEASE.json").read_text())
    man["state_min"] = 0
    (d / "RELEASE.json").write_text(json.dumps(man, indent=1, sort_keys=True) + "\n")
    with pytest.raises(Refused, match="owner signature"):
        sw.cmd_check("0.3.0")


def test_signature_namespace_profile_and_version_must_match(env):
    sw = env.switcher()
    env.release("0.3.0", "full", sign=lambda raw: sshsig.sign(raw, env.priv, sshsig.NS_POLICY))        # signed in the policy namespace (signer allows only release)
    with pytest.raises(Refused, match="owner signature"):
        sw.cmd_check("0.3.0")
    shutil.rmtree(env.base / "releases" / "0.3.0")
    env.release("0.3.0", "full")
    sw.cmd_install_first("0.3.0")
    env.release("0.9.0", "t0")                                                               # a t0 artifact on a full node
    with pytest.raises(Refused, match="profile mismatch"):
        sw.cmd_check("0.9.0")
    shutil.move(env.base / "releases" / "0.9.0", env.base / "releases" / "0.9.9")
    with pytest.raises(Refused, match="another release|profile mismatch"):
        sw.cmd_check("0.9.9")
    for bad in ("../0.3.0", "0.3.0/..", "", "a b", "-rf"):
        with pytest.raises(Refused, match="invalid version"):
            sw.cmd_check(bad)


def test_install_first_refuses_when_something_is_current_and_switch_refuses_without_current(env):
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    with pytest.raises(Refused, match="no release is current"):
        sw.cmd_switch("0.3.1", False)
    sw.cmd_install_first("0.3.0")
    with pytest.raises(Refused, match="already current"):
        sw.cmd_install_first("0.3.1")
    with pytest.raises(Refused, match="already current"):
        sw.cmd_switch("0.3.0", False)


def test_policy_schema_newer_than_the_release_supports_blocks_a_rollback(env):
    env.release("0.3.0", "full")
    env.release("0.2.0", "full", policy_schema=0)
    (env.policy_dir / "policy-3.json").write_text(json.dumps({"schema": 1, "serial": 3}))
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    with pytest.raises(Refused, match="installed policy has schema 1"):
        sw.cmd_check("0.2.0")


def test_status_cli_and_usage(env, capsys):
    env.release("0.3.0", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.out.truncate(0)
    env.out.seek(0)
    assert switcher_main(["status"], sw) == 0
    doc = json.loads(env.out.getvalue())
    assert doc["current"] == "0.3.0" and doc["profile"] == "full" and doc["releases"] == ["0.3.0"] and doc["switcher_api"] == SWITCHER_API
    for argv in ([], ["bogus"], ["switch"], ["check", "a", "b"], ["status", "x"]):
        assert switcher_main(argv, sw) == 2
    assert switcher_main(["check", "9.9.9"], sw) == 1                                         # refused/failed -> exit 1, message on stderr
    assert "refused" in capsys.readouterr().err


def test_the_switcher_is_stdlib_only_and_independent_of_the_release_tree():
    tree = ast.parse((SRC_ROOT / "forge_node" / "release" / "switcher.py").read_text())
    mods = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods |= {a.name.split(".")[0] for a in n.names}
        if isinstance(n, ast.ImportFrom):
            assert n.level == 0, "relative import: the switcher must not depend on forge_node"
            mods.add((n.module or "").split(".")[0])
    assert mods <= {"fcntl", "hashlib", "json", "os", "re", "signal", "sqlite3", "stat", "subprocess", "sys", "tempfile"} and "forge_node" not in mods
    assert len((SRC_ROOT / "forge_node" / "release" / "switcher.py").read_text().splitlines()) < 600        # "a few hundred lines"


# --------------------------------------------------------------------------------------------------------------------- policy templates
def fill(doc):
    s = json.dumps(doc).replace("__HUB_TLS_PIN__", "ab" * 32).replace("__HUB_GATE_PUB__", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOCnQJdkGAnqC9RpKFPyX3e4R8Y5v0QG9hJmFqQqkG8E")
    return s.encode()


@pytest.mark.parametrize("nid", sorted(policies.NODES))
def test_policy_templates_are_valid_once_filled_and_invalid_before(nid):
    from privd_helpers import gates_with
    prof = policies.NODES[nid]["profile"]
    kw = dict(expect_node=nid, file_serial=1, now=NOW, gates_map=__import__("forge_node").gates.GATES, table_ops=lambda p: frozenset(), devof=lambda p: 1, protected_devs=lambda: set())
    doc = policies.template(nid)
    pol = parse_full(fill(doc), **kw)
    assert pol.profile == prof and pol.global_mode == "observe" and pol.tiers == (0,) and not pol.ops and pol.workloads_enabled is False
    assert bool(pol.forge_roots) == (policies.NODES[nid]["forge_root"] is not None)
    from forge_node.t0.policy import PolicyError
    with pytest.raises(PolicyError):
        parse_full(json.dumps(doc).encode(), **kw)                                          # placeholders unfilled: never applicable
    assert "__" in json.dumps(doc)
    assert not pol.view.t0.units_for_logs or all(lu.unit.startswith("forge-") for lu in pol.view.t0.units_for_logs)        # no KMU logs by default (OQ-7)


def test_t0_templates_have_no_forge_roots_and_g2_g3_values_match_13d():
    assert "forge_roots" not in policies.template("g1") and "forge_roots" not in policies.template("g4")
    r2, r3 = policies.template("g2")["forge_roots"][0], policies.template("g3")["forge_roots"][0]
    assert (r2["path"], r2["size_bytes"], r2["min_free_bytes"]) == ("/srv/forge/node", 107374182400, 214748364800)
    assert (r3["path"], r3["size_bytes"], r3["min_free_bytes"]) == ("/var/lib/forge-node/data", 53687091200, 161061273600)
    d = (SRC_ROOT.parent / "docs" / "design" / "FORGE_NODE.md").read_text()
    assert "107374182400" in d and "53687091200" in d


# ================================================================================================================= review findings
def _systemctl_calls(env):
    return [c[1:] for c in env.calls if c[0] == "/usr/bin/systemctl"]


def test_doctor_runs_as_forgenode_with_the_node_env_and_the_after_switch_flag(env):
    """Review B1: doctor ran with an empty environment, exited 2 without FORGE_NODE_NODE_ID, and so every switch (and every rollback) was undone. The call is now pinned."""
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    assert sw.cmd_switch("0.3.1", False) == 0
    call = [c for c in env.calls if "doctor" in c][-1]
    assert call[:5] == ["/usr/sbin/runuser", "-u", "forgenode", "--", "/usr/bin/env"] and call[5] == "-i"
    assert "FORGE_NODE_NODE_ID=g2" in call and "FORGE_NODE_HUB_HOST=192.168.10.4" in call
    assert call[-5:] == ["/usr/bin/python3", "-I", "/opt/forge-node/current/forge-node.pyz", "doctor", "--after-switch"]
    assert not [a for a in call if a.startswith("PYTHON")]                                  # nothing from the caller's environment leaks in


@pytest.mark.parametrize("content,why", [(None, "cannot be read"), ("", "no FORGE_NODE_NODE_ID"), ("FORGE_NODE_HUB_HOST=1.2.3.4\n", "no FORGE_NODE_NODE_ID"),
                                          ("FORGE_NODE_NODE_ID=g2\nPATH=/evil\n", "not understood"), ("FORGE_NODE_NODE_ID=g2 ; rm -rf /\n", "not understood"),
                                          ("FORGE_NODE_NODE_ID=$(id)\n", "not understood")])
def test_a_switch_without_a_usable_node_env_is_refused_before_anything_is_stopped(env, content, why):
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    if content is None:
        env.node_env.unlink()
    else:
        env.node_env.write_text(content)
    env.calls.clear()
    with pytest.raises(Refused, match=why):
        sw.cmd_switch("0.3.1", False)
    assert not _systemctl_calls(env) and os.readlink(env.base / "current") == "releases/0.3.0"


def test_a_failure_in_start_not_only_in_doctor_returns_to_the_previous_release(env):
    """Review M6: only a doctor failure triggered the way back; a failing `start` left `current` moved and the agent stopped."""
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    real = env.run

    def run(argv, stdin, timeout):
        if argv[:2] == ["/usr/bin/systemctl", "start"] and os.readlink(env.base / "current").endswith("0.3.1"):
            return 1, b"", b"Job for forge-node-privd.socket failed"
        return real(argv, stdin, timeout)
    sw.run = run
    assert sw.cmd_switch("0.3.1", False) == 1
    res = docs(env.out.getvalue())[-1]
    assert os.readlink(env.base / "current") == "releases/0.3.0" and res["restored"] == "0.3.0" and "failed" in res["failure"] and res["restored_doctor"] == "ok"


def test_when_the_way_back_fails_too_everything_is_stopped_and_disabled_and_the_exit_status_says_so(env):
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    env.doctor_script = [False]
    prev_tree = env.base / "releases" / "0.3.0"

    def tamper():                                                                              # after the pre-flight check, while the new release is being checked
        (prev_tree / "bin" / "privctl").write_text("#!/bin/sh\necho tampered after install\n")
    env.on_doctor = tamper
    env.calls.clear()
    assert sw.cmd_switch("0.3.1", False) == 3
    res = docs(env.out.getvalue())[-1]
    assert res["restored"] is None and "differs from RELEASE.json" in res["restore_error"] and res["state"].startswith("STOPPED and disabled")
    calls = _systemctl_calls(env)
    assert calls[-2:] == [["stop", *UNITS_STOP], ["disable", *UNITS_START]]                  # a quiet node that a reboot does not wake up


def test_the_restored_release_failing_doctor_too_also_ends_stopped(env):
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    env.doctor_ok = False
    assert sw.cmd_switch("0.3.1", False) == 3
    res = docs(env.out.getvalue())[-1]
    assert "fails doctor too" in res["restore_error"] and _systemctl_calls(env)[-1] == ["disable", *UNITS_START]


@pytest.mark.parametrize("sabotage,why", [
    ("profile_missing", "profile file is missing"),
    ("policy_garbage", "cannot be read"),
    ("policy_schema_string", "no integer schema"),
    ("ledger_no_state_column", "no readable exec table"),
    ("base_writable", "only root can write"),
    ("releases_writable", "only root can write"),
    ("signers_writable", "only root can write"),
    ("signers_foreign", "only root can write"),
    ("manifest_foreign", "only root can write"),
    ("sig_hardlink", "only root can write"),
])
def test_missing_or_odd_state_is_a_refusal_never_a_skipped_check(env, sabotage, why):
    """Review M8: a guard whose input is missing must refuse (fail closed), not pass."""
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    d = env.base / "releases" / "0.3.1"
    if sabotage == "profile_missing":
        (env.base / "profile").unlink()
    elif sabotage == "policy_garbage":
        (env.policy_dir / "policy-3.json").write_text("not json")
    elif sabotage == "policy_schema_string":
        (env.policy_dir / "policy-3.json").write_text('{"schema": "1"}')
    elif sabotage == "ledger_no_state_column":
        env.ledger.unlink()
        c = sqlite3.connect(env.ledger)
        c.execute("CREATE TABLE exec(job_id TEXT, status TEXT)")
        c.execute("PRAGMA user_version=1")
        c.commit()
        c.close()
    elif sabotage == "base_writable":
        os.chmod(env.base, 0o777)
    elif sabotage == "releases_writable":
        os.chmod(env.base / "releases", 0o775)
    elif sabotage == "signers_writable":
        os.chmod(env.signers, 0o666)
    elif sabotage == "signers_foreign":
        os.chown(env.signers, 65534, 0)
    elif sabotage == "manifest_foreign":
        os.chown(d / "RELEASE.json", 65534, 0)
    elif sabotage == "sig_hardlink":
        os.link(d / "RELEASE.json.sig", env.tmp / "sig-copy")
    env.calls.clear()
    with pytest.raises(Refused, match=why):
        sw.cmd_switch("0.3.1", False)
    assert not _systemctl_calls(env) and os.readlink(env.base / "current") == "releases/0.3.0"


def test_tree_checks_each_fail_on_their_own(env):
    """Review M9: the hard-link, owner and sub-directory-mode checks passed their tests even when removed, because another check refused the same case first. Each case here is valid
    in every other respect (listed, right content, root-owned where it is not the point)."""
    env.release("0.3.0", "full")
    sw = env.switcher()
    d = env.base / "releases" / "0.3.0"
    assert sw.cmd_check("0.3.0") == 0
    # (a) a listed file that is a second name of an inode somewhere else: identical content, only the link count differs
    f = d / "units" / "forge-node-agent.service"
    data = f.read_bytes()
    outside = env.tmp / "outside-copy"
    outside.write_bytes(data)
    f.unlink()
    os.link(outside, f)
    with pytest.raises(Refused, match="one link"):
        sw.cmd_check("0.3.0")
    f.unlink()
    f.write_bytes(data)
    os.chmod(f, 0o644)
    assert sw.cmd_check("0.3.0") == 0
    # (b) a listed file owned by somebody else
    os.chown(f, 65534, 0)
    with pytest.raises(Refused, match="only root can write"):
        sw.cmd_check("0.3.0")
    os.chown(f, 0, 0)
    # (c) a sub-directory that others can write / that somebody else owns
    os.chmod(d / "units", 0o775)
    with pytest.raises(Refused, match="not root-controlled"):
        sw.cmd_check("0.3.0")
    os.chmod(d / "units", 0o755)
    os.chown(d / "units", 65534, 0)
    with pytest.raises(Refused, match="not root-controlled"):
        sw.cmd_check("0.3.0")
    os.chown(d / "units", 0, 0)
    # (d) the release directory itself belongs to somebody else
    os.chown(d, 65534, 0)
    with pytest.raises(Refused, match="only root can write"):
        sw.cmd_check("0.3.0")
    os.chown(d, 0, 0)
    assert sw.cmd_check("0.3.0") == 0


def test_the_signature_check_tells_the_failures_apart(env):
    """Review M9: `match="another release|profile mismatch"` could not tell which check fired."""
    env.release("0.3.0", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.release("0.9.0", "t0")
    with pytest.raises(Refused) as e:
        sw.cmd_check("0.9.0")
    assert str(e.value).startswith("profile mismatch")
    shutil.move(env.base / "releases" / "0.9.0", env.base / "releases" / "0.9.9")
    with pytest.raises(Refused) as e:
        sw.cmd_check("0.9.9")
    assert "names another release than its directory" in str(e.value)


def test_install_first_masking_is_gone_each_guard_failure_is_checked_in_its_own_state(env):
    """Review M9: a tampered release passed `install-first` only because 'already current' came first. Fresh node each time, tampered release, no other reason to refuse."""
    env.release("0.3.0", "full")
    (env.base / "releases" / "0.3.0" / "units" / "evil.service").write_text("[Service]\nExecStart=/bin/sh\n")
    sw = env.switcher()
    assert not os.path.lexists(env.base / "current")
    with pytest.raises(Refused, match="not listed in RELEASE.json"):
        sw.cmd_install_first("0.3.0")
    assert not os.path.lexists(env.base / "current") and not (env.base / "profile").exists() and not _systemctl_calls(env)


def test_self_update_never_leaves_a_moment_without_a_switcher(env, monkeypatch):
    env.release("0.3.0", "full")
    sw = env.switcher()
    env.self_path.write_text("#!/bin/sh\necho old\n")
    seen = []
    real_rename = os.rename

    def rename(a, b, *x, **k):
        seen.append((str(a), str(b), env.self_path.exists(), Path(str(env.self_path) + ".prev").exists()))
        return real_rename(a, b, *x, **k)
    monkeypatch.setattr(os, "rename", rename)
    real_replace = os.replace

    def replace(a, b, *x, **k):
        seen.append((str(a), str(b), env.self_path.exists(), Path(str(env.self_path) + ".prev").exists()))
        return real_replace(a, b, *x, **k)
    monkeypatch.setattr(os, "replace", replace)
    assert sw.cmd_self_update("0.3.0") == 0
    assert seen and all(exists for _, _, exists, _ in seen), seen                         # the switcher exists at every step
    assert Path(str(env.self_path) + ".prev").read_text() == "#!/bin/sh\necho old\n"


def test_the_build_does_not_depend_on_the_builders_umask(env):
    import hashlib
    digests = set()
    for n, um in enumerate((0o022, 0o002, 0o077)):
        old = os.umask(um)
        try:
            res = build.build_release("0.3.0", "full", env.tmp / f"um{n}", src_root=SRC_ROOT, sign=env.sign())
        finally:
            os.umask(old)
        digests.add(res["manifest"]["files"]["forge-node.pyz"])
        assert hashlib.sha256(Path(res["tar"]).read_bytes()).hexdigest() == res["sha256"]
    assert len(digests) == 1, digests


def test_t0_artifacts_contain_only_listed_privd_modules_and_every_module_is_classified():
    """Review: the t0 exclusion was a deny-list; a future privd/ops_*.py would have shipped on g1/g4. Now an allow-list, and a new module must be classified by a reviewer."""
    pkg = SRC_ROOT / "forge_node" / "privd"
    modules = {p.name for p in pkg.glob("*.py")}
    assert modules == set(build.T0_PRIVD_ALLOWED) | set(build.T0_PRIVD_EXCLUDED), sorted(modules - set(build.T0_PRIVD_ALLOWED) - set(build.T0_PRIVD_EXCLUDED))
    t0 = {str(p.relative_to(SRC_ROOT / "forge_node")) for p in build.package_files(SRC_ROOT, "t0") if p.parent == pkg}
    assert t0 == {f"privd/{n}" for n in build.T0_PRIVD_ALLOWED}
    assert not (set(build.T0_PRIVD_ALLOWED) & set(build.T0_PRIVD_EXCLUDED))


def test_g28_the_switch_moves_current_directly_after_a_ledger_read_that_follows_the_stop(env):
    """Production code, not the helper: the evidence log is written by the switcher's own calls (ledger read, stops, the move of `current`). The variant that reads the ledger BEFORE it has
    stopped what can create rows must be flagged by the same assertion (a race test that cannot fail proves nothing)."""
    from g28_race import EvidenceLog, assert_observed_before
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")

    def instrumented(sw, log):
        real_read, real_repoint, real_run = sw.ledger_schema_and_open, sw._repoint, sw.run

        def read():
            log.observe("ledger")
            return real_read()

        def repoint(link, target):
            if link == sw.current_link:
                log.act("repoint-current")
            return real_repoint(link, target)

        def run(argv, stdin, timeout):
            if argv[:2] == ["/usr/bin/systemctl", "stop"]:
                log.act("stop-all")
            return real_run(argv, stdin, timeout)
        sw.ledger_schema_and_open, sw._repoint, sw.run = read, repoint, run
        return sw
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    log = EvidenceLog()
    instrumented(sw, log)
    assert sw.cmd_switch("0.3.1", False) == 0
    ev = log.events
    # (verify_release reads the ledger first, before anything is stopped; the read that decides is the last one before the move)
    last_obs = max(i for i, e in enumerate(ev) if e == ("observe", "ledger") and i < ev.index(("act", "repoint-current")))
    assert ev.index(("act", "stop-all")) < last_obs                                           # ... and it is made after everything that could change the ledger has stopped
    assert_observed_before(log, "repoint-current", "ledger")
    # the stale variant: read, THEN stop
    sw2 = env.switcher()
    env.release("0.3.2", "full")
    log2 = EvidenceLog()
    instrumented(sw2, log2)

    def stale(self=sw2, **_):
        self.ledger_schema_and_open()
        self._systemctl("stop", *UNITS_STOP)
    sw2._quiesce_and_check_ledger = stale
    assert sw2.cmd_switch("0.3.2", False) == 0
    with pytest.raises(AssertionError):
        assert_observed_before(log2, "repoint-current", "ledger")


def test_every_template_lists_the_model_directory_for_the_round_0_model_inventory():
    for nid in policies.NODES:
        assert policies.template(nid)["t0"]["model_dirs"] == ["/srv/models"], nid          # inv.models is round-0 scope on all four hosts (T0 nodes included)


def test_the_runuser_path_is_a_parameter_probed_where_ubuntu_keeps_it():
    """Found by looking at the real host: runuser is /usr/sbin/runuser on Ubuntu (there is no /usr/bin/runuser), so a hard-coded path would have failed every doctor run at install time
    (the test double accepts any argv). The switcher takes it as a required parameter; production() probes the places it can live."""
    import inspect
    src = inspect.getsource(Switcher)
    assert '"/usr/bin/runuser"' not in src and "self.runuser" in src and "runuser: str" in inspect.getsource(Switcher.__init__)
    prod = inspect.getsource(__import__("forge_node.release.switcher", fromlist=["production"]).production)
    assert prod.index('"/usr/sbin/runuser"') < prod.index('"/usr/bin/runuser"')


# ================================================================================================================= round-2 findings
def test_self_update_can_install_a_switcher_newer_than_the_running_one_while_check_and_switch_refuse(env):
    """Round 2 (MAJOR): self-update ran the same guard as everything else, which refuses a release that needs a newer switcher_api - the one case self-update exists for."""
    env.release("0.3.0", "full")
    env.release("0.4.0", "full", switcher_api=SWITCHER_API + 1)
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.self_path.write_text("#!/bin/sh\necho old\n")
    for cmd in (sw.cmd_check, lambda v: sw.cmd_switch(v, False)):
        with pytest.raises(Refused, match="self-update"):
            cmd("0.4.0")
    assert sw.cmd_self_update("0.4.0") == 0
    assert env.self_path.read_bytes() == (SRC_ROOT / "forge_node" / "release" / "switcher.py").read_bytes()
    # ... and nothing else is waived for it: a tampered release is still refused
    env.release("0.4.1", "full", switcher_api=SWITCHER_API + 1)
    (env.base / "releases" / "0.4.1" / "units" / "evil.service").write_text("[Service]\nExecStart=/bin/sh\n")
    with pytest.raises(Refused, match="not listed"):
        sw.cmd_self_update("0.4.1")


def test_a_node_that_cannot_be_quiesced_is_started_again_and_nothing_is_changed(env):
    """Round 2: a failing `systemctl stop` used to leave the node half-stopped and exit with the status of "restored"."""
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    real = env.run
    sw.run = lambda argv, stdin, t: (1, b"", b"Failed to stop forge-node-privd.service") if argv[:2] == ["/usr/bin/systemctl", "stop"] else real(argv, stdin, t)
    env.calls.clear()
    with pytest.raises(Refused, match="could not be quiesced"):
        sw.cmd_switch("0.3.1", False)
    assert os.readlink(env.base / "current") == "releases/0.3.0"
    assert _systemctl_calls(env)[-1] == ["start", *UNITS_START]


def test_only_the_privd_socket_runs_while_doctor_checks_the_new_release(env):
    """Round 2: the agent and the timer started BEFORE doctor, so an unchecked release created ledger rows and made the rollback impossible."""
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    seen = []
    env.on_doctor = lambda: seen.append([c[1:] for c in env.calls if c[0] == "/usr/bin/systemctl" and c[1] in ("start", "enable")])
    env.calls.clear()
    assert sw.cmd_switch("0.3.1", False) == 0
    assert seen[0] == [["start", "forge-node-privd.socket"]]                                   # at the time of doctor: the socket and nothing else
    assert _systemctl_calls(env)[-2:] == [["enable", *UNITS_START], ["start", *UNITS_START]]    # afterwards the rest, enabled again (a STOPPED node had them disabled)
    # a failing doctor never starts the agent or the timer of the unchecked release
    env.release("0.3.2", "full")
    env.doctor_script = [False, True]
    env.calls.clear()
    assert sw.cmd_switch("0.3.2", False) == 1
    starts = [c for c in _systemctl_calls(env) if c[0] == "start"]
    assert starts[0] == ["start", "forge-node-privd.socket"] and starts[1] == ["start", "forge-node-privd.socket"] and starts[2:] == [["start", *UNITS_START]]      # new socket, restored socket, then the rest of the RESTORED one


def test_a_switch_is_refused_while_local_stop_exists_and_checks_the_way_back_first(env):
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    env.local_stop.write_text("")
    env.calls.clear()
    with pytest.raises(Refused, match="LOCAL_STOP"):
        sw.cmd_switch("0.3.1", False)
    assert not _systemctl_calls(env)
    env.local_stop.unlink()
    (env.base / "releases" / "0.3.0" / "bin" / "privctl").write_text("#!/bin/sh\necho tampered\n")       # the CURRENT release no longer verifies: the way back would be closed
    with pytest.raises(Refused, match="differs from RELEASE.json"):
        sw.cmd_switch("0.3.1", False)
    assert not _systemctl_calls(env) and os.readlink(env.base / "current") == "releases/0.3.0"


def test_previous_does_not_point_at_the_release_that_was_just_taken_back(env):
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    env.release("0.3.2", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    assert sw.cmd_switch("0.3.1", False) == 0 and os.readlink(env.base / "previous") == "releases/0.3.0"
    env.doctor_script = [False, True]
    assert sw.cmd_switch("0.3.2", False) == 1
    assert os.readlink(env.base / "current") == "releases/0.3.1" and os.readlink(env.base / "previous") == "releases/0.3.0"      # not 0.3.2


def test_switch_reports_whether_the_way_back_stays_open(env):
    env.release("0.3.0", "full", state_window=(1, 1))
    env.release("0.3.1", "full", state_window=(1, 2))
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    assert sw.cmd_switch("0.3.1", True) == 0
    assert docs(env.out.getvalue())[-1]["rollback_possible"] is False                      # the new release may move the state beyond what 0.3.0 can run on


def test_a_failed_first_install_can_be_repeated(env):
    env.release("0.3.0", "full")
    sw = env.switcher()
    real = env.run
    sw.run = lambda argv, stdin, t: (1, b"", b"Failed to link") if argv[:2] == ["/usr/bin/systemctl", "link"] else real(argv, stdin, t)
    with pytest.raises(SwitchError):
        sw.cmd_install_first("0.3.0")
    assert not os.path.lexists(env.base / "current") and not (env.base / "profile").exists()
    sw.run = real
    assert sw.cmd_install_first("0.3.0") == 0


def test_changing_commands_hold_a_lock_and_survive_every_catchable_stop_signal_while_they_run(env):
    import fcntl
    import signal
    env.release("0.3.0", "full")
    sw = env.switcher()
    sigs = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGQUIT, signal.SIGUSR1, signal.SIGUSR2)
    with sw.locked():
        for sg in sigs:
            os.kill(os.getpid(), sg)                                                         # round 3: SIGQUIT/SIGUSR1/SIGUSR2 used to kill a switch half way
        child = subprocess.run([sys.executable, "-c", "import signal,sys; sys.exit(0 if all(signal.getsignal(s) != signal.SIG_IGN for s in (1,2,15,3,10,12)) else 1)"], check=False)
        assert child.returncode == 0                                                         # children do not inherit an ignored disposition
        fd = os.open(env.lock_path, os.O_RDWR)
        with pytest.raises(BlockingIOError):
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)                                   # nobody else gets in
        os.close(fd)
        with pytest.raises(Refused, match="another forge-node-release"):
            with sw.locked():
                pass
    assert signal.getsignal(signal.SIGHUP) == signal.SIG_DFL or callable(signal.getsignal(signal.SIGHUP))
    assert signal.getsignal(signal.SIGTERM) not in (signal.SIG_IGN,) and not getattr(signal.getsignal(signal.SIGTERM), "__name__", "") == "<lambda>"      # restored afterwards
    with sw.locked():                                                                          # and the lock was released
        pass
    # the dispatcher takes it for every changing command, not for status/check
    env.lock_path.unlink()
    sw2 = env.switcher()
    held = []
    real_locked = sw2.locked
    sw2.locked = lambda: (held.append(1), real_locked())[1]
    switcher_main(["check", "0.3.0"], sw2)
    switcher_main(["status"], sw2)
    assert held == []
    switcher_main(["install-first", "0.3.0"], sw2)
    assert held == [1]


def test_doctor_failure_text_reaches_the_operator(env):
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    env.doctor_script = [False, True]
    assert sw.cmd_switch("0.3.1", False) == 1
    assert "privd" in docs(env.out.getvalue())[-1]["failure"]


def test_a_profile_file_that_is_not_text_is_a_refusal_not_a_traceback(env):
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    (env.base / "profile").write_bytes(b"\xff\xfe\x00")
    with pytest.raises(Refused, match="profile file is missing or unreadable"):
        sw.cmd_check("0.3.1")


@pytest.mark.parametrize("where", ["above_base", "signers_dir", "policy_dir"])
def test_the_directories_above_the_trust_anchors_are_checked_too(env, where):
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    (env.policy_dir / "policy-1.json").write_text('{"schema": 1}')
    os.chmod(env.policy_dir / "policy-1.json", 0o644)
    target = {"above_base": env.tmp / "opt", "signers_dir": env.tmp, "policy_dir": env.policy_dir}[where]
    os.chmod(target, 0o777)
    try:
        with pytest.raises(Refused, match="only root can write"):
            sw.cmd_check("0.3.1")
    finally:
        os.chmod(target, 0o755)
    assert sw.cmd_check("0.3.1") == 0


def test_node_env_may_quote_its_values_like_systemd_does(env):
    env.node_env.write_text('FORGE_NODE_NODE_ID="g2"\nFORGE_NODE_HUB_HOST=\'192.168.10.4\'\n; comment\n')
    assert env.switcher().doctor_env() == ["FORGE_NODE_NODE_ID=g2", "FORGE_NODE_HUB_HOST=192.168.10.4"]
    env.node_env.write_text('FORGE_NODE_NODE_ID="g2;rm"\n')
    with pytest.raises(Refused, match="not understood"):
        env.switcher().doctor_env()


def test_the_build_constants_match_what_the_code_actually_runs_on():
    """Round 2: STATE_MIN/MAX and POLICY_SCHEMA were literals nothing tied to the ledger or to the policy parser."""
    from forge_node.privd.ledger import STATE_SCHEMA
    assert build.STATE_MIN <= STATE_SCHEMA <= build.STATE_MAX
    assert json.loads(json.dumps(policies.template("g2")))["schema"] == build.POLICY_SCHEMA


def test_the_zipapp_does_not_depend_on_the_builders_time_zone(env):
    """Round 2: zipapp wrote DOS timestamps in LOCAL time - three time zones, three different artifacts and signatures."""
    import hashlib
    digests = set()
    old = os.environ.get("TZ")
    try:
        for tz in ("UTC", "Europe/Berlin", "America/New_York", "Pacific/Auckland"):
            os.environ["TZ"] = tz
            __import__("time").tzset()
            res = build.build_release("0.3.0", "full", env.tmp / f"tz{tz.replace('/', '_')}", src_root=SRC_ROOT, sign=env.sign())
            digests.add((res["manifest"]["files"]["forge-node.pyz"], hashlib.sha256(Path(res["tar"]).read_bytes()).hexdigest()))
    finally:
        if old is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = old
        __import__("time").tzset()
    assert len(digests) == 1, digests


# ----------------------------------------------------------------------------------------------------- round 2: tests that claimed more than they proved
def test_the_way_back_re_reads_the_ledger_after_stopping_again(env):
    """Round 2 (G28): 'rollback without _quiesce_and_check_ledger' passed every test. A row that appears while the new release runs must stop the rollback - it would orphan that worker."""
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    env.doctor_script = [False]

    def a_row_appears():
        c = sqlite3.connect(env.ledger)
        c.execute("INSERT INTO exec VALUES('late', 'started')")
        c.commit()
        c.close()
    env.on_doctor = a_row_appears
    assert sw.cmd_switch("0.3.1", False) == 3
    res = docs(env.out.getvalue())[-1]
    assert "not terminal" in res["restore_error"] and res["restored"] is None


def test_an_oserror_while_moving_current_is_a_failure_that_takes_the_previous_release_back(env, monkeypatch):
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    real = sw._repoint
    calls = []

    def flaky(link, target):
        calls.append(target)
        if target.endswith("0.3.1") and link.endswith("current"):
            raise OSError(28, "No space left on device")
        return real(link, target)
    sw._repoint = flaky
    assert sw.cmd_switch("0.3.1", False) == 1
    assert os.readlink(env.base / "current") == "releases/0.3.0" and "No space" in docs(env.out.getvalue())[-1]["failure"]


def test_self_update_hashes_the_bytes_it_writes_and_refuses_a_downgrade(env, monkeypatch):
    env.release("0.3.0", "full")
    sw = env.switcher()
    env.self_path.write_text("#!/bin/sh\necho old\n")
    from forge_node.release import switcher as sw_mod
    real = sw_mod._read_nofollow

    def swapped(path, limit, owner_uid):
        data = real(path, limit, owner_uid)
        return b"#!/bin/sh\nrm -rf /\n" if path.endswith("sbin/forge-node-release") else data               # the file changed between the tree check and the read
    monkeypatch.setattr(sw_mod, "_read_nofollow", swapped)
    with pytest.raises(Refused, match="differs from its manifest"):
        sw.cmd_self_update("0.3.0")
    monkeypatch.undo()
    assert env.self_path.read_text() == "#!/bin/sh\necho old\n"
    env.release("0.0.1", "full", switcher_api=SWITCHER_API - 1)
    with pytest.raises(Refused, match="downgrade"):
        sw.cmd_self_update("0.0.1")


def test_reads_never_follow_a_symlink_and_a_first_install_never_overwrites_a_profile(env, tmp_path):
    from forge_node.release.switcher import _read_nofollow
    (tmp_path / "real").write_text("full\n")
    os.chmod(tmp_path / "real", 0o644)
    os.symlink(tmp_path / "real", tmp_path / "link")
    with pytest.raises(OSError):
        _read_nofollow(str(tmp_path / "link"), 100, 0)
    env.release("0.3.0", "full")
    (env.base / "profile").write_text("full\n")                                                  # a leftover profile file that even matches
    os.chmod(env.base / "profile", 0o644)
    sw = env.switcher()
    with pytest.raises(FileExistsError):
        sw.cmd_install_first("0.3.0")
    assert (env.base / "profile").read_text() == "full\n" and not os.path.lexists(env.base / "current")


def test_a_directory_that_cannot_be_scanned_is_a_refusal(env, monkeypatch):
    env.release("0.3.0", "full")
    sw = env.switcher()
    real_walk = os.walk

    def walk(top, topdown=True, onerror=None, followlinks=False):
        if str(top).endswith("0.3.0") and onerror:
            onerror(PermissionError(13, "denied", str(top)))
        return real_walk(top, topdown, onerror, followlinks)
    monkeypatch.setattr(os, "walk", walk)
    with pytest.raises(Refused, match="cannot scan"):
        sw.cmd_check("0.3.0")


def test_a_group_writable_file_in_the_tree_is_refused_not_only_a_world_writable_one(env):
    env.release("0.3.0", "full")
    sw = env.switcher()
    f = env.base / "releases" / "0.3.0" / "forge-node.pyz"
    os.chmod(f, 0o664)
    with pytest.raises(Refused, match="only root can write"):
        sw.cmd_check("0.3.0")
    os.chmod(f, 0o644)
    assert sw.cmd_check("0.3.0") == 0


def _resign(env, ver, edit):
    d = env.base / "releases" / ver
    m = json.loads((d / "RELEASE.json").read_text())
    edit(m, d)
    raw = (json.dumps(m, indent=1, sort_keys=True) + "\n").encode()
    (d / "RELEASE.json").write_bytes(raw)
    (d / "RELEASE.json.sig").write_text(sshsig.sign(raw, env.priv, sshsig.NS_RELEASE))


def test_only_forge_node_units_may_be_named_by_a_signed_manifest(env):
    env.release("0.3.0", "full")
    sw = env.switcher()

    def add_unit(m, d):
        (d / "units" / "evil.service").write_text("[Service]\nExecStart=/bin/sh\n")
        os.chmod(d / "units" / "evil.service", 0o644)
        m["units"].append("evil.service")
        m["files"]["units/evil.service"] = __import__("hashlib").sha256((d / "units" / "evil.service").read_bytes()).hexdigest()
    _resign(env, "0.3.0", add_unit)
    with pytest.raises(Refused, match="not a listed forge-node unit"):
        sw.cmd_check("0.3.0")


def test_the_modes_the_builder_writes_are_the_modes_the_switcher_demands():
    res_modes = {}
    import tempfile
    with tempfile.TemporaryDirectory() as t:
        priv = Path(t) / "k"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(priv)], check=True, capture_output=True)
        res = build.build_release("0.3.0", "full", Path(t) / "o", src_root=SRC_ROOT, sign=lambda raw: sshsig.sign(raw, priv, sshsig.NS_RELEASE))
        with tarfile.open(res["tar"]) as tf:
            res_modes = {m.name.split("/", 1)[-1]: m.mode for m in tf.getmembers() if m.isfile()}
    assert res_modes["bin/privctl"] == 0o755 and res_modes["sbin/forge-node-release"] == 0o755
    assert all(m == 0o644 for n, m in res_modes.items() if n not in ("bin/privctl", "sbin/forge-node-release")), res_modes


# ================================================================================================================= round-3 findings
def _after_first_doctor(env):
    i = next(i for i, c in enumerate(env.calls) if "doctor" in c)
    return [c[1:] for c in env.calls[i:] if c[0] == "/usr/bin/systemctl"]


def test_a_rollback_whose_stop_fails_does_not_start_the_release_that_just_failed_and_does_not_claim_a_quiet_node(env):
    """Round 3 (MAJOR): on the way back `_best_effort_start` started the agent of the release that had just failed doctor (`current` still pointed at it) and the report then said 'nothing is running'."""
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw0 = env.switcher()
    sw0.cmd_install_first("0.3.0")
    env.make_ledger()
    env.doctor_ok = False
    orig, seen = env.run, {"doctor": False}

    def run(argv, stdin, timeout):
        seen["doctor"] = seen["doctor"] or "doctor" in argv
        if seen["doctor"] and argv[0] == "/usr/bin/systemctl" and argv[1] == "stop":
            env.calls.append(list(argv))
            return 1, b"", b"Failed to stop"
        return orig(argv, stdin, timeout)
    sw = env.switcher(run=run)
    assert sw.cmd_switch("0.3.1", False) == 3
    after = _after_first_doctor(env)
    assert not [c for c in after if c[0] == "start"], after                                  # nothing was started on the way back
    res = docs(env.out.getvalue())[-1]
    assert res["state"].startswith("NOT CONFIRMED STOPPED") and "may still be running" in res["state"] and "nothing is running" not in res["state"]


def test_a_rollback_that_finds_an_open_row_does_not_start_the_failed_release_either(env):
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    env.doctor_ok = False

    def row_appears():                                                                       # the new release's privd (briefly up for doctor) left a row behind
        env.make_ledger(state="started")
    env.on_doctor = row_appears
    assert sw.cmd_switch("0.3.1", False) == 3
    assert not [c for c in _after_first_doctor(env) if c[0] == "start"]
    assert docs(env.out.getvalue())[-1]["state"].startswith("STOPPED and disabled")


def test_a_switch_that_closes_the_way_back_is_refused_before_the_first_change_unless_the_owner_says_so(env):
    """Round 3 (MAJOR): the new privd raises the ledger schema at doctor time; a failed doctor then had no way back (rc 3, node stopped on the failed release) although the switch had been
    started without a word about it."""
    env.release("0.3.0", "full", state_window=(1, 1))
    env.release("0.3.1", "full", state_window=(1, 2))
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger()
    env.calls.clear()
    with pytest.raises(Refused, match="--one-way"):
        sw.cmd_switch("0.3.1", False)
    assert os.readlink(env.base / "current") == "releases/0.3.0" and not _systemctl_calls(env)       # nothing was touched, not even a stop
    assert switcher_main(["switch", "0.3.1"], sw) == 1 and switcher_main(["switch", "--one-way"], sw) == 2
    assert switcher_main(["switch", "--one-way", "0.3.1"], sw) == 0 and os.readlink(env.base / "current") == "releases/0.3.1"
    env.release("0.3.2", "full", state_window=(1, 2))
    assert sw.cmd_switch("0.3.2", False) == 0                                                # an equal window needs no flag


@pytest.mark.parametrize("state", ["received", "started", "effect_done", "reconciling", "indeterminate"])
def test_every_non_final_ledger_state_blocks_a_switch_including_indeterminate(env, state):
    """Round 3 (MAJOR): `indeterminate` is assigned when the worker could NOT be confirmed dead; the switch must not move `current` under a worker that may be alive."""
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")
    sw = env.switcher()
    sw.cmd_install_first("0.3.0")
    env.make_ledger(state=state)
    with pytest.raises(Refused, match="not terminal"):
        sw.cmd_switch("0.3.1", False)
    assert os.readlink(env.base / "current") == "releases/0.3.0"


def test_a_dead_stdout_after_a_good_switch_does_not_roll_it_back(env):
    """Round 3 (MINOR): the final report was written inside the try; a dropped ssh session turned a completely successful switch into a rollback."""
    env.release("0.3.0", "full")
    env.release("0.3.1", "full")

    class Dead:
        def write(self, _):
            raise BrokenPipeError()

        def flush(self):
            pass
    env.make_ledger()
    env.switcher().cmd_install_first("0.3.0")
    sw = env.switcher(out=Dead())
    env.calls.clear()
    with pytest.raises(BrokenPipeError):
        sw.cmd_switch("0.3.1", False)
    assert os.readlink(env.base / "current") == "releases/0.3.1"
    assert len([c for c in env.calls if "doctor" in c]) == 1                                 # no second doctor = no rollback


def test_the_release_name_is_built_into_the_zipapp_and_into_the_version_privd_records(env, monkeypatch):
    """Round 3 (MAJOR): privd's version was the constant `__version__`, so a switch between two releases of the same tree left no `release_switch` record."""
    names = {}
    for ver in ("0.3.0", "0.3.1"):
        res = build.build_release(ver, "full", env.tmp / f"o-{ver}", src_root=SRC_ROOT, sign=env.sign())
        with tarfile.open(res["tar"]) as tf:
            data = tf.extractfile(f"forge-node-{ver}/forge-node.pyz").read()
        p = env.tmp / f"{ver}.pyz"
        p.write_bytes(data)
        names[ver] = zipfile.ZipFile(p).read("forge_node/profile.py").decode()
        assert f'RELEASE = "{ver}"' in names[ver] and 'PROFILE = "full"' in names[ver]
    assert names["0.3.0"] != names["0.3.1"]
    from forge_node.privd import main as pmain
    monkeypatch.setattr(pmain, "RELEASE", "0.3.1")
    assert pmain.full_version().endswith("+0.3.1") and pmain.full_version().startswith(pmain.__version__)
