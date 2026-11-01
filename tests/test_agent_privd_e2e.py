"""The whole chain, all production code: hub (mTLS, Postgres) -> agent -> privd (real socket) -> op worker unit, with gate D switched on in hub AND node (a test-only gate table;
production keeps every gate unmet). Checks the contract between the pieces: lease hand-over, job relay, results, open_jobs/audit heads in the poll, audit records on both sides."""
import json
import os
import threading
from pathlib import Path

import pytest
from privd_helpers import PrivdEnv, gates_with

from conftest import NOW as HUB_NOW  # noqa: F401
from forge_node import protocol
from forge_node.agent import __main__ as agent_main
from forge_node.agent.config import AgentConfig
from forge_node.agent.privlink import PrivLink
from forge_node.audit.log import Appender
from forge_node.hub.core import Hub, JobRequest, Signer
from forge_node.privd.client import PrivClient
from forge_node.privd.server import Server, listen
from test_agent_e2e import certs, rig as _rig  # noqa: F401 - fixtures

pytestmark = pytest.mark.db


@pytest.fixture
def hub(hubcfg, hubdb, gate, clock, adm):
    from conftest import add_node
    add_node(adm, "g2", "full", cert="a" * 64)
    add_node(adm, "g1", "t0", cert="b" * 64)
    return Hub(hubcfg, hubdb, Signer(gate["priv"], gate["id"]), clock=clock, sleep=lambda s: clock.advance(s), gate_set=gates_with("D"))


@pytest.fixture
def chain_rig(_rig, realfs, owner, gate, clock, monkeypatch):
    from forge_node.t0 import policy as t0policy
    # TEST ONLY: the agent's policy loader checks the gate rules against the production table, where gate D is unmet and a tier-1 policy cannot load. The agent has no way to be
    # handed a gate table, so for this one test the loader's default table is replaced.
    monkeypatch.setattr(t0policy.parse_policy, "__defaults__", (gates_with("D"),))
    r = _rig
    env = PrivdEnv(realfs, {"owner": owner, "gate": gate}, clock=clock)
    sock = listen(env.paths.socket, 1001)
    srv = Server(env.ctx)
    threading.Thread(target=srv.serve, args=(sock,), daemon=True).start()
    r.env = env
    r.install = lambda **kw: env.install(env.doc(hub_tls_pins=r.pins, gate_keys=gate["keys"], tiers=(0, 1), t1_ops=[{"op": "selftest.noop", "mode": "enforce"}], **kw))
    assert r.install(serial=1)["ok"]

    def make_agent(ship=False):
        cfg = AgentConfig("g2", "127.0.0.1", r.srv.server_address[1], str(r.certs["g2"][1]), str(r.certs["g2"][0]), str(r.pki.ca_crt), env.paths.policy_dir, env.paths.allowed_signers,
                          str(r.tmp / "state"), env.paths.socket, os.getuid(), os.getuid(), str(r.tmp / "root"))
        os.makedirs(r.tmp / "state", exist_ok=True)
        link = PrivLink(client=PrivClient(env.paths.socket, 0, 60), audit=Appender(env.specs["agent"], "g2", clock), log=r.logs.append)
        from forge_node.agent.shipper import AuditShipper
        shipper = AuditShipper(specs={"agent": env.specs["agent"], "priv": env.specs["priv"]}, node="g2", state_dir=str(r.tmp / "state"), log=r.logs.append) if ship else None
        return agent_main.build(cfg, runner=r.runner, clock=clock, log=r.logs.append, probe=r.probe, ssh_keygen="ssh-keygen", priv=link, shipper=shipper), link
    r.make_chain_agent = make_agent
    yield r
    srv.stop()
    sock.close()
    for log in (env.priv_log, env.agent_log):
        log.close()
    env.ledger.close()


def test_tier1_dry_run_and_apply_travel_hub_agent_privd_worker_and_back(chain_rig):
    r = chain_rig
    agent, link = r.make_chain_agent()
    jid = r.hub.enqueue_job(JobRequest(node="g2", tier=1, op="selftest.noop", params={"note": "chain"}, dry_run=True)).job_id
    assert agent.poll_once(wait_s=0) == "job"                                              # first poll: lease -> privd; job relayed; result posted
    j = r.hub.job_state(jid)
    assert j["state"] == "dry_run" and j["result_status"] == "dry_run", j
    # the plan hash the node computed is in privd's ledger (the hub stores status/output; the planner would carry the hash into the apply job)
    row = r.env.ledger.get(jid)
    assert row.state == "committed" and row.eff_dry_run and row.result["plan_hash"]
    jid2 = r.hub.enqueue_job(JobRequest(node="g2", tier=1, op="selftest.noop", params={"note": "chain"}, plan_hash=row.result["plan_hash"])).job_id
    r.clock.advance(61)
    assert agent.poll_once(wait_s=0) == "job"
    j2 = r.hub.job_state(jid2)
    assert j2["state"] == "committed" and j2["result_status"] == "committed", j2
    assert os.path.exists(f"{r.env.paths.work}/{jid2}-1/effect.mark")
    # audit on both sides: privd's intent/result pair and the agent's relay records
    assert [t for t in r.env.types(jid2)] == ["intent", "result"]
    agent_recs = []
    for g in sorted(os.listdir(r.env.specs["agent"].dir)):
        p = f"{r.env.specs['agent'].dir}/{g}"
        if os.path.isdir(p):
            for f in os.listdir(p):
                agent_recs += [json.loads(x) for x in open(f"{p}/{f}", "rb").read().split(b"\n") if x]
    assert [(x["type"], x.get("phase")) for x in agent_recs if x.get("job_id") == jid2] == [("relay", "relay"), ("relay", "result")]
    # the next poll carries the audit heads of both logs and an empty open_jobs list (the hub accepted the request shape)
    r.clock.advance(61)
    assert agent.poll_once(wait_s=0) == "idle"


def test_denials_at_privd_reach_the_hub_as_denied_with_their_code_and_stop_blocks_t1_not_t0(chain_rig):
    r = chain_rig
    agent, link = r.make_chain_agent()
    open(r.env.paths.local_stop, "w").close()                                              # LOCAL_STOP on the node: the hub does not know
    jid = r.hub.enqueue_job(JobRequest(node="g2", tier=1, op="selftest.noop", params={"note": "x"}, dry_run=True)).job_id
    agent.poll_once(wait_s=0)
    j = r.hub.job_state(jid)
    assert j["state"] == "denied_retryable" and j["result_reason"] == "DENY_LOCAL_STOP", j
    os.unlink(r.env.paths.local_stop)
    r.clock.advance(61)
    again = r.hub.enqueue_job(JobRequest(node="g2", tier=1, op="selftest.noop", params={"note": "x"}, dry_run=True, job_id=jid))          # the graph re-issues the same effect key
    assert again.requeued
    agent.poll_once(wait_s=0)                                                              # redelivered with the same job_id (delivery_seq + 1)
    j = r.hub.job_state(jid)
    assert j["state"] == "dry_run", j


def test_agent_without_audit_log_relays_nothing_above_t0(chain_rig):
    r = chain_rig
    agent, link = r.make_chain_agent()
    link.audit = None
    jid = r.hub.enqueue_job(JobRequest(node="g2", tier=1, op="selftest.noop", params={"note": "x"}, dry_run=True)).job_id
    agent.poll_once(wait_s=0)
    j = r.hub.job_state(jid)
    assert j["result_reason"] == "DENY_AUDIT_DOWN" and not r.env.ledger.open_rows()
    assert r.env.ledger.get(jid) is None                                                   # privd never saw it


def test_audit_travels_to_the_hub_chains_verify_across_rotation_and_the_crosscheck_matches_the_jobs(chain_rig):
    """The node's two logs are shipped; the hub recomputes both chains (incl. the chain_link after a rotation) and cross-checks every executed job against privd's intent/result."""
    r = chain_rig
    agent, link = r.make_chain_agent(ship=True)
    jid = r.hub.enqueue_job(JobRequest(node="g2", tier=1, op="selftest.noop", params={"note": "ship"}, dry_run=True)).job_id
    assert agent.poll_once(wait_s=0) == "job"
    plan = r.env.ledger.get(jid).result["plan_hash"]
    assert r.env.call("audit.rotate", {"log": "both"})["ok"]                                 # rotate both logs between the two jobs
    r.clock.advance(61)
    jid2 = r.hub.enqueue_job(JobRequest(node="g2", tier=1, op="selftest.noop", params={"note": "ship"}, plan_hash=plan)).job_id
    assert agent.poll_once(wait_s=0) == "job"
    r.clock.advance(61)
    agent.poll_once(wait_s=0)
    heads = {s: r.adm.execute("SELECT max(seq) AS m FROM node.audit WHERE node_id='g2' AND source=%s", (s,)).fetchone()["m"] for s in ("agent", "priv")}
    assert heads["agent"] >= 5 and heads["priv"] >= 8
    assert r.hub.verify_chains("g2", full=True) == []
    r.clock.advance(r.hub.cfg.crosscheck_grace_s + 5)
    assert r.hub.crosscheck("g2") == []
    types = {x["type"] for x in r.adm.execute("SELECT type FROM node.audit WHERE node_id='g2' AND source='priv'").fetchall()}
    assert {"intent", "result", "chain_link", "policy", "lease"} <= types
    n = r.adm.execute("SELECT status FROM node.nodes WHERE node_id='g2'").fetchone()["status"]
    assert n == "active"                                                                       # not quarantined


def test_the_crosscheck_does_not_quarantine_a_node_for_denials_the_agent_made_without_privd(chain_rig):
    """Review M3: the agent denies by itself when its audit log is down or privd is unreachable; no privd record exists for such a job and none is owed."""
    r = chain_rig
    agent, link = r.make_chain_agent()
    link.audit = None
    jid = r.hub.enqueue_job(JobRequest(node="g2", tier=1, op="selftest.noop", params={"note": "x"}, dry_run=True)).job_id
    agent.poll_once(wait_s=0)
    assert r.hub.job_state(jid)["result_reason"] == "DENY_AUDIT_DOWN"
    r.clock.advance(r.hub.cfg.crosscheck_grace_s + 5)
    assert r.hub.crosscheck("g2") == []
    assert r.adm.execute("SELECT quarantine FROM node.nodes WHERE node_id='g2'").fetchone()["quarantine"] is False


def test_a_failure_code_from_privd_is_posted_as_failed_not_as_an_invalid_denied_result(chain_rig):
    """Review: `denied` + FAIL_* is rejected by the hub, which left the job open for ever."""
    r = chain_rig
    agent, link = r.make_chain_agent()
    link.execute = lambda env: {"ok": False, "code": "FAIL_PRECHECK", "detail": "internal error: boom"}
    jid = r.hub.enqueue_job(JobRequest(node="g2", tier=1, op="selftest.noop", params={"note": "x"}, dry_run=True)).job_id
    agent.poll_once(wait_s=0)
    j = r.hub.job_state(jid)
    assert j["state"] == "failed" and j["result_reason"] == "FAIL_PRECHECK", j
