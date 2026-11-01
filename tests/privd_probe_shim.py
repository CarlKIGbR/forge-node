"""Test stand-in for `forge-node.pyz probe`: runs t0.probe_main.main with relocated paths taken from FN_TEST_* (the production entry has fixed paths). Used as the program of a
LocalProcessBackend 'ro-probe unit' in the privd tests."""
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.environ["FN_TEST_SRC"])
from forge_node.t0 import probe_main  # noqa: E402

if __name__ == "__main__":
    sys.exit(probe_main.main(sys.argv[1:], sys.stdin, sys.stdout, node_id=os.environ["FORGE_NODE_NODE_ID"], policy_dir=os.environ["FN_TEST_POLICY_DIR"],
                             allowed_signers=os.environ["FN_TEST_SIGNERS"], fs_root=os.environ.get("FN_TEST_FS_ROOT", "/"), owner_uid=0, now=lambda: datetime.now(timezone.utc),
                             ssh_keygen=os.environ["FN_TEST_SSH_KEYGEN"]))
