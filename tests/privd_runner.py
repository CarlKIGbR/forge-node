"""A separate privd PROCESS for the crash tests: `privd_runner.py <base> exec|recover|reconcile <json>`; prints the reply as one JSON line. The test kills it with SIGKILL.
Uses the same fixed test clock as the test (FN_TEST_NOW) and the blocking worker script when FN_TEST_WORKER is set."""
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.environ["FN_TEST_SRC"])
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import privd_helpers as H  # noqa: E402
from forge_node.privd import reconcile  # noqa: E402

if __name__ == "__main__":
    base, cmd, body = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
    clock = H.Clock(datetime.fromisoformat(os.environ["FN_TEST_NOW"]).replace(tzinfo=timezone.utc))
    env = H.attach(base, clock=clock, worker_script=os.environ.get("FN_TEST_WORKER") or None)
    if cmd == "recover":
        rep = reconcile.recover_all(env.ctx)
        env.ctx.join_monitors(60)
        print(json.dumps({"report": rep}, default=str))
    else:
        print(json.dumps(env.call(cmd, body)))
    sys.stdout.flush()
