"""python -m forge_node.hub : startet den Hub (Konfiguration aus FORGE_NODEHUB_*). Wird in N1 NICHT gestartet oder installiert."""
import signal
import sys
import threading

from .config import HubConfig
from .core import Hub, Signer
from .db import Db
from .server import make_server, make_ssl_context

VERIFY_INTERVAL_S = 60


def main() -> int:
    cfg = HubConfig.from_env()
    db = Db(cfg.db_dsn, cfg.db_password_file)
    hub = Hub(cfg, db, Signer(cfg.gate_key, cfg.gate_key_id, cfg.ssh_keygen))
    srv = make_server(hub, cfg.listen_host, cfg.listen_port, make_ssl_context(cfg.tls_cert, cfg.tls_key, cfg.tls_ca))
    stop = threading.Event()

    def verifier():
        while not stop.wait(VERIFY_INTERVAL_S):
            try:
                hub.run_verification()
            except Exception as e:  # noqa: BLE001
                print(f"nodehub verification error: {type(e).__name__}", file=sys.stderr, flush=True)

    threading.Thread(target=verifier, daemon=True, name="verifier").start()
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=srv.shutdown, daemon=True).start())
    print(f"forge-nodehub listening on {cfg.listen_host}:{cfg.listen_port}", flush=True)
    try:
        srv.serve_forever()
    finally:
        stop.set()
        srv.server_close()
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
