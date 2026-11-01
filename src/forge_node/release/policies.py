"""Policy templates shipped in the release (Design 13.C C5, 13.D, 7.4). The owner fills the two hub trust values, reads the file once, signs it. Every template is `observe` with
tier 0 only: gated features (Betriebsleiter decision) cannot be switched on by any signature until their gates are met in code. Unfilled placeholders make a template INVALID
(not a hex pin, not a key), so an unfilled template can never be applied."""
GATE_KEY_NOT_AFTER = "2027-10-31"
NODES = {
    "g1": {"profile": "t0", "forge_root": None, "logs": []},
    "g2": {"profile": "full", "forge_root": ("/srv/forge/node", 107374182400, 214748364800), "logs": ["forge-postbote.service", "forge-edge.service"]},
    "g3": {"profile": "full", "forge_root": ("/var/lib/forge-node/data", 53687091200, 161061273600), "logs": []},
    "g4": {"profile": "t0", "forge_root": None, "logs": []},
}
PROTECTED = {
    "paths": ["/opt/kmu-ai", "/srv/models", "/srv/kmu-ai", "/srv/tradebot", "/etc/ssh", "/etc/sudoers", "/etc/sudoers.d", "/etc/forge-node", "/root"],
    "units": ["kmu-*", "tradebot-*", "secmpro*", "nexus*", "ollama.service", "ssh.service", "docker.service", "containerd.service", "nginx.service", "postgresql@*", "redis-server.service"],
    "networks": ["tb-gate0", "tb-int0", "172.31.250.0/24", "172.31.251.0/24", "172.31.252.0/24"],
    "ports": [22, 80, 443, 5432, 6379, 8003, 8004, 8188, 9102, 9112, 11434],
}


def template(node_id: str) -> dict:
    n = NODES[node_id]
    doc = {"schema": 1, "serial": 1, "not_before": "2026-10-31T00:00:00Z", "node": node_id, "profile": n["profile"], "global_mode": "observe", "tiers_enabled": [0],
           "hub_tls_pins": ["__HUB_TLS_PIN__"], "hub_gate_keys": [{"id": "hub-gate-1", "pub": "__HUB_GATE_PUB__", "not_after": GATE_KEY_NOT_AFTER}],
           "protected": PROTECTED,
           "t0": {"units_for_logs": n["logs"], "cert_paths": [], "backup_units": ["kmu-sicherung-*"], "backup_dirs": [], "repos": [], "model_dirs": ["/srv/models"] if n["profile"] == "full" else []},
           "t1": {"workloads_enabled": False}, "t2": {"ops": []}, "t3": {"manifests_enabled": [], "opaque_enabled": False},
           "windows": {"blackout": "02:00-05:45", "sunday_open": "06:00"}, "redaction_version": 2, "circuit": {"fail_threshold": 3}}
    if n["forge_root"]:
        path, size, min_free = n["forge_root"]
        doc["forge_roots"] = [{"path": path, "quota_backend": "loop_fs", "backing_image": "/var/lib/forge-node-img/forge-root.img", "size_bytes": size, "log_budget_bytes": 2147483648,
                               "min_free_bytes": min_free}]
    return doc


def nodes_for(profile: str) -> list[str]:
    return sorted(k for k, v in NODES.items() if v["profile"] == profile)
