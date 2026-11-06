"""Policy templates shipped in the release (Design 13.C C5, 13.D, 7.4). The owner fills the two hub trust values, reads the file once, signs it. Every template is `observe` with
tier 0 only, profile `t0` on all four hosts (Betriebsleiter decision, N5-prep): gated features (Betriebsleiter decision) cannot be switched on by any signature until their gates are met in code. Unfilled placeholders make a template INVALID
(not a hex pin, not a key), so an unfilled template can never be applied. `inv.models` (Round 0, §14.1) reads `/srv/models` metadata on ALL four nodes: the second SSD is KMU model
storage everywhere (M-99), so `model_dirs` is in every template, T0-only nodes included."""
GATE_KEY_NOT_AFTER = "2027-10-31"
# Betriebsleiter decision (N5-prep): ALL four hosts install the `t0` profile for now - no forge-root loop volume, no op code (no `selftest.noop`), `observe`, tier 0 only. That the design's 13.D lists
# `full` for g2/g3 is the later T1 step: `FULL_LATER` keeps those values, `template(nid, "full")` still renders them (T0-only as well until the gates are met in code).
NODES = {
    "g1": {"profile": "t0", "forge_root": None, "logs": []},
    "g2": {"profile": "t0", "forge_root": None, "logs": ["forge-postbote.service", "forge-edge.service"]},
    "g3": {"profile": "t0", "forge_root": None, "logs": []},
    "g4": {"profile": "t0", "forge_root": None, "logs": []},
}
FULL_LATER = {
    "g2": {"forge_root": ("/srv/forge/node", 107374182400, 214748364800)},
    "g3": {"forge_root": ("/var/lib/forge-node/data", 53687091200, 161061273600)},
}
INSTALL_ORDER = ("g2", "g3", "g1", "g4")                                                  # design 13.D: g4 (live trading) last
PROTECTED = {
    "paths": ["/opt/kmu-ai", "/srv/models", "/srv/kmu-ai", "/srv/tradebot", "/etc/ssh", "/etc/sudoers", "/etc/sudoers.d", "/etc/forge-node", "/root"],
    "units": ["kmu-*", "tradebot-*", "secmpro*", "nexus*", "ollama.service", "ssh.service", "docker.service", "containerd.service", "nginx.service", "postgresql@*", "redis-server.service"],
    "networks": ["tb-gate0", "tb-int0", "172.31.250.0/24", "172.31.251.0/24", "172.31.252.0/24"],
    "ports": [22, 80, 443, 5432, 6379, 8003, 8004, 8188, 9102, 9112, 11434],
}


def template(node_id: str, profile: str | None = None) -> dict:
    """The unsigned policy template of a node. `profile` defaults to the node's install profile (`t0` everywhere today); `full` is only defined for the nodes in FULL_LATER and adds their forge root."""
    n = NODES[node_id]
    profile = profile or n["profile"]
    if profile not in ("t0", "full") or (profile == "full" and node_id not in FULL_LATER):
        raise KeyError(f"no {profile} template for {node_id}")
    doc = {"schema": 1, "serial": 1, "not_before": "2026-10-31T00:00:00Z", "node": node_id, "profile": profile, "global_mode": "observe", "tiers_enabled": [0],
           "hub_tls_pins": ["__HUB_TLS_PIN__"], "hub_gate_keys": [{"id": "hub-gate-1", "pub": "__HUB_GATE_PUB__", "not_after": GATE_KEY_NOT_AFTER}],
           "protected": PROTECTED,
           "t0": {"units_for_logs": n["logs"], "cert_paths": [], "backup_units": ["kmu-sicherung-*"], "backup_dirs": [], "repos": [], "model_dirs": ["/srv/models"]},
           "t1": {"workloads_enabled": False}, "t2": {"ops": []}, "t3": {"manifests_enabled": [], "opaque_enabled": False},
           "windows": {"blackout": "02:00-05:45", "sunday_open": "06:00"}, "redaction_version": 2, "circuit": {"fail_threshold": 3}}
    if profile == "full":
        path, size, min_free = FULL_LATER[node_id]["forge_root"]
        doc["forge_roots"] = [{"path": path, "quota_backend": "loop_fs", "backing_image": "/var/lib/forge-node-img/forge-root.img", "size_bytes": size, "log_budget_bytes": 2147483648,
                               "min_free_bytes": min_free}]
    return doc


def nodes_for(profile: str) -> list[str]:
    """Nodes whose policy templates go into the artifact of a profile: the t0 artifact carries every node (all hosts install t0), the full artifact only the nodes that can later become `full`."""
    if profile == "t0":
        return sorted(k for k, v in NODES.items() if v["profile"] == "t0")
    return sorted(FULL_LATER)
