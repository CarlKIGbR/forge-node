"""Op worker for the crash tests. FN_TEST_BLOCK selects where it parks (reading FN_TEST_FIFO, so the test decides when it goes on):
  before  - before taking the effect lock / checking the fence
  mid     - after the effect (marker written), before status.json
  none    - runs through
It is the real worker.run() with a wrapped effect, so lock, fence and status.json are the production code."""
import os
import sys

sys.path.insert(0, os.environ["FN_TEST_SRC"])
from forge_node.privd import ops, worker  # noqa: E402


def wait():
    with open(os.environ["FN_TEST_FIFO"], "rb") as f:
        f.read(1)


def effect(ctx):
    out = ops.noop_effect(ctx)
    if os.environ.get("FN_TEST_BLOCK") == "mid" and not ctx.dry_run:
        wait()
    return out


if __name__ == "__main__":
    if os.environ.get("FN_TEST_BLOCK") == "before":
        # announce that we are parked: a file in the work dir the test can poll
        open(os.path.join(sys.argv[2], "parked"), "w").close()
        wait()
    sys.exit(worker.run(sys.argv[2], {"selftest.noop": effect}, owner_uid=0))
