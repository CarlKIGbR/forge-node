#!/usr/bin/env python3
"""Runs inside the harness container (root). Sets up the host layout, then executes every bash block of the owner guide in order as the user its `<!-- run: mac|host -->` marker names.
Exit 0 only if every block ends `== OK`, exits 0, and its post-conditions hold. See run.sh for what is stubbed."""
import argparse
import os
import pty
import re
import select
import shutil
import subprocess
import sys
import time

GUIDE = "/src/node/docs/reports/N5PREP_OWNER_GUIDE.md"
UPGRADE = "/src/node/docs/reports/PROBEFIX_OWNER_UPGRADE.md"
STUBBED = [
    "systemd: systemctl/systemd-run/journalctl/timedatectl are stubs (state in /run/stubs; `link`/`disable` really create/remove /etc/systemd/system links; privd.socket really starts the release's privd)",
    "forge-node doctor (needs systemd transient units): permission check as forgenode + injected verdict; agent/rotate timer are not started",
    "Docker daemon and Postgres: `docker ps` canned, `docker exec … sh -c` runs the script with a logging psql stub",
    "iptables (state file; -C/-D/-I/-S semantics), curl and openssl s_client (no hub; curl keeps the real exit 77 for an unreadable --cacert)",
    "ssh/scp: 'carl@<any host>' is the local user carl (same sudo/no-forgebox permissions); the interactive login is replaced by running host blocks as carl",
    "pager (less = cat); sudo password prompts are not simulated (carl has !authenticate)",
]
ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8", "TERM": "dumb"}


def sh(cmd: str, check=True, **kw):
    return subprocess.run(["bash", "-c", cmd], check=check, capture_output=True, text=True, **kw)


def setup(host_ip: str) -> str:
    sh("""set -e
echo "127.0.0.1 $(hostname)" >> /etc/hosts
groupadd -g 980 forge; groupadd -g 981 forgebox; groupadd -g 1001 carl
useradd -u 994 -g 980 -G 981 -m -s /bin/bash forge
useradd -u 1001 -g 1001 -G sudo -m -s /bin/bash carl            # sudo, NOT in forgebox
useradd -u 501 -m -s /bin/bash owner                            # the Mac
useradd -u 2000 -m -s /bin/bash kmuai
printf 'carl ALL=(ALL) NOPASSWD: ALL\\nDefaults:carl !authenticate\\n' > /etc/sudoers.d/90-carl; echo 'owner ALL=(carl) NOPASSWD: ALL' > /etc/sudoers.d/91-owner; chmod 440 /etc/sudoers.d/90-carl /etc/sudoers.d/91-owner
chmod 755 /etc/sudoers.d
mkdir -p /run/stubs && chmod 1777 /run/stubs && : > /run/stubs/calls.log && chmod 666 /run/stubs/calls.log
install -d -m 0755 -o root -g root /usr/local/sbin
chown root:root /var/log; chmod 755 /var/log                       # bind mount from the host: root-controlled like on a real host
mkdir -p /srv/forge/work /srv/forge/post/control /opt/harness-src
install -d -m 2700 -o forge -g forgebox /srv/forge/work/forge-core /srv/forge/work/forge-core/secrets
chmod 0755 /srv/forge/work/forge-core
install -d -m 0755 -o forge -g forgebox /srv/forge/work/forge-edge /srv/forge/work/forge-edge/systemd
cp /opt/harness-units/* /srv/forge/work/forge-edge/systemd/; chown -R forge:forgebox /srv/forge/work/forge-edge
install -d -m 0755 -o kmuai -g kmuai /opt/kmu-ai /srv/models
runuser -u kmuai -- git -C /opt/kmu-ai init -q && runuser -u kmuai -- git -C /opt/kmu-ai -c user.name=k -c user.email=k@k commit -q --allow-empty -m kmu
""")
    out = {}
    for name in ("node", "ops"):
        dst = f"/srv/forge/work/forge-{name}"
        sh(f"""set -e
mkdir -p {dst}; tar -C /src/{name} --exclude=.git --exclude=__pycache__ --exclude=.pytest_cache -c . | tar -C {dst} -x
chown -R forge:forgebox {dst}
runuser -u forge -- git -C {dst} init -q
runuser -u forge -- git -C {dst} add -A
runuser -u forge -- git -C {dst} -c user.name=h -c user.email=h@h commit -q -m harness
""")
        out[name] = sh(f"runuser -u forge -- git -C {dst} rev-parse HEAD").stdout.strip()
    # the guide's `ssh-keygen -a 100` etc. need a home for the Mac user
    sh("install -d -m 0700 -o owner -g owner /home/owner/.ssh; touch /home/owner/.ssh/sshcarljump01; chown owner:owner /home/owner/.ssh/sshcarljump01")
    return out["node"]


def blocks(text: str):
    return re.findall(r"<!-- run: (mac|host) -->\n```bash\n(.*?)^```$", text, re.S | re.M)


def run_block(n: int, actor: str, script: str, timeout=240):
    """Execute one block as `owner` (Mac) or `carl` (host) in a pty (passphrase prompts); returns (rc, output)."""
    user = "owner" if actor == "mac" else "carl"
    os.makedirs("/tmp/harness", exist_ok=True)
    os.chmod("/tmp/harness", 0o755)
    path = f"/tmp/harness/blk{n:02d}.sh"
    open(path, "w").write(script)
    os.chmod(path, 0o644)
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(f"/home/{user}")
        os.execvpe("sudo", ["sudo", "-n", "-u", user, "-H", "env", *[f"{k}={v}" for k, v in ENV.items()], "bash", "--noprofile", "--norc", path], ENV)
    out, answered_to, end = b"", 0, time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.3)
        if r:
            try:
                chunk = os.read(fd, 8192)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
            tail = out[answered_to:].lower().rstrip()
            if tail.endswith(b":") and b"passphrase" in tail:
                os.write(fd, b"harness-passphrase\n")
                answered_to = len(out)
    if time.time() >= end:
        out += b"\n[harness] TIMEOUT - block killed\n"
        subprocess.run(["pkill", "-9", "-f", path])
        try:
            os.kill(pid, 9)
        except OSError:
            pass
    try:
        _, status = os.waitpid(pid, 0)
    except ChildProcessError:
        status = 0
    return os.waitstatus_to_exitcode(status), out.decode("utf-8", "replace").replace("\r\n", "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="g2", choices=["g2", "g3", "g1", "g4"])
    ap.add_argument("--doctor-rc", type=int, default=0)
    ap.add_argument("--upgrade", action="store_true", help="g2 state after a failed 5.4 doctor (needs --doctor-rc N != 0), then the blocks of PROBEFIX_OWNER_UPGRADE.md with a passing doctor")
    a = ap.parse_args()
    ips = {"g2": "192.168.10.4", "g3": "192.168.30.3", "g1": "192.168.10.3", "g4": "192.168.30.4"}
    sha = setup(ips[a.host])
    global VER
    VER = "0.5.0" if a.upgrade else "0.5.1"
    open("/run/stubs/doctor_rc", "w").write(str(a.doctor_rc))
    os.chmod("/run/stubs/doctor_rc", 0o644)
    text = open(GUIDE).read()
    bl = blocks(text)
    total_bash = len(re.findall(r"^```bash\n", text, re.M))
    if len(bl) != total_bash:
        print(f"FAIL: {total_bash - len(bl)} bash block(s) without a `<!-- run: mac|host -->` marker")
        return 1
    failures, results = [], []
    nid = a.host
    for n, (actor, script) in enumerate(bl):
        script = script.replace("<MAIN_SHA>", sha)
        if a.upgrade:
            script = script.replace("0.5.1", "0.5.0")                         # g2's real history: the first install was 0.5.0, the guide now names the fixed 0.5.1
        if a.host != "g2":                                                    # "für jeden Host nur NID und IP ändern"
            script = script.replace("NID=g2\nIP=192.168.10.4\n", f"NID={nid}\nIP={ips[nid]}\n").replace("NID=g2  ", f"NID={nid}  ")
        title = next((l for l in script.splitlines() if l.strip() and not l.startswith(("(", "set -"))), "")[:60]
        rc, out = run_block(n, actor, script)
        login_tail = script.rstrip().splitlines()[-1].startswith("rc=$?; if [ $rc = 0 ]; then ssh -t")                       # blocks that end with the login into the server (5.1, 5.3)
        ok = rc == 0 and "== FEHLER" not in out and ("(interactive login skipped by the harness)" in out if login_tail else "== OK" in out)
        err = post_check(n, nid, ips[nid])
        expected_fail = a.doctor_rc != 0 and n == 11
        if expected_fail:
            ok = "== FEHLER" in out and "Agent wird NICHT gestartet" in out and not os.path.exists("/run/stubs/sc/enabled/forge-node-agent.service") and "enable --now forge-node-agent.service" not in open("/run/stubs/calls.log").read()
            err = None
        status = "PASS" if ok and not err else "FAIL"
        results.append((n, actor, title, status))
        print(f"[{n:02d}] {actor:4s} {status}  {title}")
        if status == "FAIL":
            failures.append(n)
            print("----- output -----\n" + out[-3000:] + ("\n----- post-check: " + err if err else "") + "\n------------------")
        if expected_fail:
            break
        if status == "FAIL":
            break
    if a.upgrade and not failures:
        failures += run_upgrade(sha, nid, results)
    print("\nSTUBBED in this harness:")
    for s in STUBBED:
        print("  - " + s)
    print(f"\nRESULT host={nid}: {'FAIL' if failures else 'PASS'} ({sum(1 for r in results if r[3] == 'PASS')}/{len(results)} blocks)")
    return 1 if failures else 0


def run_upgrade(sha: str, nid: str, results: list) -> list:
    """The real g2 state after the failed first doctor (agent never started), then the upgrade doc: build 0.5.1, check, `switch` (REAL switcher against the stub systemd and the stub doctor, which now passes)."""
    assert a_doctor_rc() != 0, "--upgrade starts from a failed 5.4 doctor"
    pre = open("/run/stubs/calls.log").read()
    assert "enable --now forge-node-agent.service" not in pre
    open("/run/stubs/doctor_rc", "w").write("0")
    text = open(UPGRADE).read()
    bl = blocks(text)
    total_bash = len(re.findall(r"^```bash\n", text, re.M))
    if len(bl) != total_bash:
        print(f"FAIL: upgrade doc: {total_bash - len(bl)} bash block(s) without a marker")
        return [-1]
    failures = []
    for n, (actor, script) in enumerate(bl):
        script = script.replace("<FIX_SHA>", sha)
        title = "upgrade U%d: " % (n + 1) + next((l for l in script.splitlines() if l.strip() and not l.startswith(("(", "set -", "cat >"))), "")[:50]
        rc, out = run_block(100 + n, actor, script, timeout=400)
        ok = rc == 0 and "== FEHLER" not in out and "== OK" in out
        err = upgrade_post_check(n, sha)
        status = "PASS" if ok and not err else "FAIL"
        results.append((100 + n, actor, title, status))
        print(f"[U{n + 1}] {actor:4s} {status}  {title}")
        if status == "FAIL":
            failures.append(100 + n)
            print("----- output -----\n" + out[-3000:] + ("\n----- post-check: " + err if err else "") + "\n------------------")
            break
    return failures


def a_doctor_rc() -> int:
    return int(open("/run/stubs/doctor_rc").read() or 0) if os.path.exists("/run/stubs/doctor_rc") else 0


def upgrade_post_check(n: int, sha: str):
    M = "/home/owner/forge-node-owner"
    try:
        if n == 0:
            assert os.path.exists(f"{M}/release/forge-node-0.5.1-t0.tar.sig") and os.path.exists(f"{M}/release/forge-node-0.5.0-t0.tar.sig")
            assert not os.path.exists("/tmp/fn-src.tar") and os.path.exists("/tmp/forge-node-0.5.1-t0.tar")
        elif n == 1:
            assert os.path.isdir("/opt/forge-node/releases/0.5.1") and os.readlink("/opt/forge-node/current").endswith("0.5.0"), "check must not move current"
        elif n == 2:
            assert os.readlink("/opt/forge-node/current").endswith("releases/0.5.1") and os.readlink("/opt/forge-node/previous").endswith("releases/0.5.0")
            calls = open("/run/stubs/calls.log").read()
            assert "enable forge-node-privd.socket forge-node-agent.service forge-node-audit-rotate.timer" in calls, "switch must enable+start the agent after a passing doctor"
            assert os.path.exists("/run/stubs/sc/active/forge-node-agent.service")
        elif n == 3:
            assert not os.path.exists("/tmp/forge-node-0.5.1-t0.tar") and not os.path.exists("/tmp/fn.env")
    except (AssertionError, OSError) as e:
        return f"{type(e).__name__}: {e}"
    return None


VER = "0.5.1"


def post_check(n: int, nid: str, ip: str):
    """Post-conditions per block index (guide order). Returns an error string or None."""
    def own(p):
        st = os.stat(p)
        import pwd, grp
        return pwd.getpwuid(st.st_uid).pw_name, grp.getgrgid(st.st_gid).gr_name, st.st_mode & 0o7777
    try:
        S = "/srv/forge/work/forge-core/secrets/nodehub"
        M = "/home/owner/forge-node-owner"
        if n == 0:
            assert own(f"{M}/owner_ed25519")[2] == 0o600 and os.path.exists(f"{M}/allowed_signers") and os.path.exists(f"{M}/ca/ca.crt")
        elif n == 1:
            assert os.path.exists(f"{M}/release/forge-node-{VER}-t0.tar.sig")
            assert not os.path.exists("/tmp/fn-src.tar"), "forge's /tmp/fn-src.tar left behind"
        elif n == 2:
            assert own("/tmp/hub.csr")[0] == "carl" and own(f"{S}/hub.key")[:2] == ("forge", "forgebox") and own(f"{S}/hub.key")[2] == 0o600
        elif n == 3:
            assert os.path.exists(f"{M}/issued/hub.crt") and own(f"{S}/hub.crt")[:3] == ("forge", "forgebox", 0o644)
            assert not os.path.exists("/tmp/hub.crt") and not os.path.exists("/tmp/hub.csr")
        elif n == 4:
            assert subprocess.run(["cmp", "/srv/forge/work/forge-ops/bin/forge-docker-user.sh", "/usr/local/sbin/forge-docker-user.sh"]).returncode == 0
        elif n == 5:
            assert open("/run/stubs/ipt").read().count("forge-nodehub") == 3
        elif n == 7:
            assert os.path.exists("/var/lib/forge-edge/hub-rules-confirmed")
        elif n == 8:
            assert own("/tmp/fn.env")[0] == "carl"
        elif n == 9:
            assert os.path.islink("/opt/forge-node/current") and own(f"/tmp/{nid}.csr")[0] == "forgenode"
            ev = open(f"/var/tmp/fn-ev-before-{nid}.txt").read()
            assert re.search(r"^[0-9a-f]{40}$", ev, re.M), "evidence has no kmu-ai HEAD (git refused as carl?)"
            logs = subprocess.run(["bash", "-c", "find /var/log/forge-node-priv /var/log/forge-node-agent -name '*.jsonl' | wc -l"], capture_output=True, text=True).stdout.strip()
            assert int(logs) >= 2, logs
        elif n == 10:
            assert os.path.exists(f"/home/owner/forge-node-owner/policy/policy-{nid}.json.sig")
        elif n == 11:
            calls = open("/run/stubs/calls.log").read()
            assert "enable --now forge-node-agent.service" in calls and os.path.exists("/run/stubs/privd.pid")
            assert not os.path.exists("/tmp/fn.env") and not os.path.exists(f"/tmp/{nid}.csr") and not os.path.exists(f"/tmp/policy-{nid}.json")
        elif n == 12:
            log = open("/run/stubs/psql.log").read()
            assert "INSERT INTO node.nodes" in log and "'t0'" in log and re.search(r"[0-9a-f]{64}", log) and "ARG<forge>" in log and "ARG<-v>" in log
            assert not os.path.exists(f"/tmp/register-{nid}.sql")
        elif n == 14:
            assert "now() - last_seen" in open("/run/stubs/psql.log").read()
        elif n == 15:
            for d in ("/opt/forge-node", "/etc/forge-node", "/var/lib/forge-node", "/var/lib/forge-node-priv", "/var/log/forge-node-priv", "/var/log/forge-node-agent"):
                assert not os.path.exists(d), d
            assert subprocess.run(["id", "forgenode"], capture_output=True).returncode != 0
    except (AssertionError, OSError) as e:
        return f"{type(e).__name__}: {e}"
    return None


if __name__ == "__main__":
    sys.exit(main())
