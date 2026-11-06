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
