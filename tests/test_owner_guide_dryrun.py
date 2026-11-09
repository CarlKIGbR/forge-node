"""Owner-guide dry run (N5-prep rework 2; Betriebsleiter class fix for carl-vs-forge permission findings M-3/M-4/M-5): executes EVERY bash block of docs/reports/N5PREP_OWNER_GUIDE.md in a throw-away
Ubuntu 24.04 container that mimics the host (forge 994/980, forgebox 981, secrets/ drwx--S--- forge, carl = sudo but not in forgebox, git 2.43, the same paths), as the user the block's
`<!-- run: mac|host -->` marker names, under `set -euo pipefail`. Needs the Docker daemon, therefore it is skipped inside scripts/run-tests.sh's test container; run it on the host:
    pytest tests/test_owner_guide_dryrun.py        or        tests/owner_guide_dryrun/run.sh [--host g2|g3|g1|g4] [--doctor-rc N]
What is stubbed is listed in the output and in tests/owner_guide_dryrun/run.sh."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "owner_guide_dryrun" / "run.sh"
GUIDE = ROOT / "docs" / "reports" / "N5PREP_OWNER_GUIDE.md"


def test_every_bash_block_of_the_guide_has_a_run_marker():
    """Runs everywhere: a block without `<!-- run: mac|host -->` would silently escape the dry run."""
    text = GUIDE.read_text()
    assert len(re.findall(r"<!-- run: (?:mac|host) -->\n```bash\n", text)) == len(re.findall(r"^```bash\n", text, re.M)) >= 16


def _docker_ok() -> bool:
    return shutil.which("docker") is not None and subprocess.run(["docker", "info"], capture_output=True).returncode == 0


needs_docker = pytest.mark.skipif(not _docker_ok(), reason="needs the Docker daemon (run on the host, not inside scripts/run-tests.sh)")


def _run(*args):
    r = subprocess.run([str(HARNESS), *args], capture_output=True, text=True, timeout=1500)
    return r.returncode, r.stdout + r.stderr


@needs_docker
def test_owner_guide_runs_end_to_end_as_carl_on_g2():
    rc, out = _run()
    assert rc == 0 and "RESULT host=g2: PASS (16/16 blocks)" in out, out[-3000:]


@needs_docker
def test_owner_guide_runs_end_to_end_with_the_g4_values():
    rc, out = _run("--host", "g4")
    assert rc == 0 and "RESULT host=g4: PASS (16/16 blocks)" in out, out[-3000:]


@needs_docker
def test_a_failing_doctor_stops_block_5_4_before_the_agent_is_enabled():
    rc, out = _run("--doctor-rc", "1")                      # the harness inverts its expectation for block 5.4: FEHLER, "Agent wird NICHT gestartet", agent unit never enabled
    assert rc == 0 and "[11] host PASS" in out and "RESULT host=g2: PASS (12/12 blocks)" in out, out[-3000:]


# ---------------------------------------------------------------------------------------------------------------- probefix: the 0.5.0 -> 0.5.1 upgrade of g2
UPGRADE = ROOT / "docs" / "reports" / "PROBEFIX_OWNER_UPGRADE.md"


def _upgrade_blocks():
    return re.findall(r"<!-- run: (mac|host) -->\n```bash\n(.*?)^```$", UPGRADE.read_text(), re.S | re.M)


def test_upgrade_doc_blocks_are_marked_valid_shell_and_the_mac_blocks_are_zsh_safe(tmp_path):
    """Runs everywhere. M-168: the Mac's interactive zsh does not take `#` comments, so a pasted Mac block must be a heredoc that WRITES a script and a `bash script` line - no comment and no
    `set -e`/subshell outside the heredoc. The script bodies and every host block must pass `bash -n`."""
    text = UPGRADE.read_text()
    blocks = _upgrade_blocks()
    assert len(blocks) == len(re.findall(r"^```bash\n", text, re.M)) == 5
    for i, (actor, b) in enumerate(blocks):
        f = tmp_path / f"b{i}.sh"
        f.write_text(b)
        assert subprocess.run(["bash", "-n", str(f)], capture_output=True, text=True).returncode == 0, (i, b[:200])
        if actor == "mac" or b.startswith("cat > "):                  # a host block may be a script too (U4: ~/fn-cn-check.sh)
            m = re.fullmatch(r"cat > (\S+) <<'FNEOF'\n(.*?)^FNEOF\nbash \1\nrc=\$\?; if .*\n", b, re.S | re.M)
            assert m, "a Mac block is: cat > script <<'FNEOF' ... FNEOF / bash script / rc line"
            assert not re.search(r"^\s*#", b[: m.start(2)] + b[m.end(2):], re.M)          # nothing zsh could mistake for a command outside the heredoc
            (tmp_path / f"s{i}.sh").write_text(m.group(2))
            assert subprocess.run(["bash", "-n", str(tmp_path / f"s{i}.sh")], capture_output=True, text=True).returncode == 0
        else:
            assert b.startswith("(\nset -euo pipefail\n") and "\n)\nrc=$?; if [ $rc = 0 ]" in b          # standalone subshell, rc check on its own line (guide rework 2)
    for i, (actor, b) in enumerate(blocks):                                                    # m-2/m-3: no `cmp && echo` guard, no pipe into head under pipefail
        assert not re.search(r"^cmp [^|\n]*&& echo", b, re.M) and not re.search(r"systemctl[^\n]*\|\s*head", b), i
    assert "if ! cmp -s /tmp/pol-050.json /tmp/pol-051.json; then" in text and "exit 1; fi" in text
    assert not re.search(r"systemctl[^\n]*\|\s*head", GUIDE.read_text())
    assert "forge-node-release switch $VER" in text and "privctl policy-apply" not in "\n".join(b for _, b in blocks)       # one upgrade command; the installed policy (serial 1) stays


@needs_docker
def test_upgrade_of_g2_after_the_failed_first_doctor_runs_end_to_end():
    """The real g2 state (0.5.0 installed, privd socket + policy, agent never started, doctor failed), then U1..U5 with the REAL switcher (stub systemd + stub doctor, listed in the output)."""
    rc, out = _run("--doctor-rc", "1", "--upgrade")
    assert rc == 0 and "[U5] host PASS" in out and "RESULT host=g2: PASS (17/17 blocks)" in out, out[-3000:]
