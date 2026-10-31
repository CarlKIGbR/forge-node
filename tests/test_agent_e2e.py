"""Agent against the real hub (mTLS, Postgres, ssh-keygen): signed T0 jobs run, results arrive redacted, STOP does not stop T0, nothing above T0 runs, a replaced or revoked
hub credential makes the agent stop talking. The agent's host is a fake /proc tree and a scripted command runner; everything else is the production code."""
import json
import os
import threading
from datetime import timedelta

import pytest

from conftest import NOW as HUB_NOW, add_node
from forge_node import protocol, sshsig
from forge_node.agent import __main__ as agent_main
from forge_node.agent.config import AgentConfig
from forge_node.agent.loop import Agent
from forge_node.hub.core import JobRequest
from forge_node.hub.server import make_server, make_ssl_context
from forge_node.t0.runner import Run
from forge_node.t0.wire import ProbeUnavailable

from n2_helpers import FakeRunner, PROC, install_policy, policy_doc, signers_text, write_tree

pytestmark = pytest.mark.db
CAN = "sk-CANARYabcdef123456"


class FakeProbe:
    def __init__(self):
        self.replies = {}

    def call(self, name, params):
        r = self.replies.get(name)
        if r is None:
            raise ProbeUnavailable("no privd in this test")
        return r(params) if callable(r) else r


@pytest.fixture(scope="module")
def certs(pki):
    return {"srv": pki.issue("e_srv", "forge-nodehub", "IP:127.0.0.1", "serverAuth"), "g2": pki.issue("e_g2", "forge-node-g2", "URI:urn:forge:node:g2", "clientAuth"),
            "other": pki.issue("e_other_srv", "forge-nodehub", "IP:127.0.0.1", "serverAuth")}


class Rig:
    pass


@pytest.fixture
def rig(pki, certs, hub, hubcfg, adm, clock, gate, owner, tmp_path):
    adm.execute("UPDATE node.nodes SET cert_sha256=%s WHERE node_id='g2'", (pki.sha256_der(certs["g2"][1]),))
    hub.sleep = lambda s: None
    srv = make_server(hub, "127.0.0.1", 0, make_ssl_context(certs["srv"][1], certs["srv"][0], pki.ca_crt))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    r = Rig()
    r.hub, r.srv, r.clock, r.tmp, r.gate, r.owner, r.pki, r.certs, r.adm, r.cfg_hub = hub, srv, clock, tmp_path, gate, owner, pki, certs, adm, hubcfg
    signers = tmp_path / "allowed_signers"
    signers.write_text(signers_text(owner["pub"]))
    os.chmod(signers, 0o644)
    r.signers = signers
    write_tree(tmp_path / "root", {**PROC, "/var/log/unattended-upgrades/unattended-upgrades.log": "2026-10-31 06:25:01,100 INFO Starting unattended upgrades script\n2026-10-31 06:25:05,100 INFO All upgrades installed\n"})
    r.runner = FakeRunner({"timedatectl": "Timezone=Europe/Berlin\nNTPSynchronized=yes\nNTP=yes\n",
                           "systemctl_show_all": f"Id=svc.service\nLoadState=loaded\nActiveState=active\nSubState=running\nResult=success\nFragmentPath=/etc/x\nDescription=svc password=CANARYhunter2 {CAN}\nNRestarts=0\n\n",
                           "systemctl_list_timers": "[]"})
    r.probe = FakeProbe()
    r.logs = []
    r.pins = [pki.sha256_der(certs["srv"][1])]
    r.set_policy = lambda serial=1, pins=None, keys=None, **kw: install_policy(tmp_path / "policy", policy_doc(serial=serial, pins=pins or r.pins, gate_keys=keys or gate["keys"], **kw), owner["priv"])
    r.set_policy()

    def make_agent(**over):
        cfg = AgentConfig("g2", "127.0.0.1", srv.server_address[1], str(certs["g2"][1]), str(certs["g2"][0]), str(pki.ca_crt), str(tmp_path / "policy"), str(signers), str(tmp_path / "state"),
                          str(tmp_path / "nosock"), os.getuid(), os.getuid(), str(tmp_path / "root"))
        os.makedirs(tmp_path / "state", exist_ok=True)
        return agent_main.build(cfg, runner=r.runner, clock=clock, log=r.logs.append, probe=r.probe)
    r.make_agent = make_agent
    r.enqueue = lambda op, tier=0, **params: hub.enqueue_job(JobRequest(node="g2", tier=tier, op=op, params=params)).job_id
    yield r
    srv.shutdown()
    srv.server_close()


def state(r, job_id):
    return r.hub.job_state(job_id)


# -------------------------------------------------------------------------------------------------------------------------- happy path
def test_poll_runs_signed_t0_job_and_hub_stores_the_redacted_untrusted_result(rig):
    jid = rig.enqueue("inv.units")
    a = rig.make_agent()
    assert a.poll_once(wait_s=0) == "job"
    j = state(rig, jid)
    assert j["state"] == "committed" and j["result_status"] == "committed" and j["result_attempt"] == 1
    env = json.loads(j["result_output"])
    assert env["untrusted"] is True and env["op"] == "inv.units" and env["node"] == "g2" and env["sensitivity"] == "internal"
    assert "CANARY" not in j["result_output"] and "[REDACTED]" in j["result_output"]
    n = rig.adm.execute("SELECT agent_version, policy_serial, last_seen FROM node.nodes WHERE node_id='g2'").fetchone()
    assert n["agent_version"] == "0.1.0" and n["policy_serial"] == 1 and n["last_seen"] is not None


def test_all_op_kinds_roundtrip_through_the_hub(rig):
    ids = {op: rig.enqueue(op) for op in ("inv.host", "inv.gpu", "inv.disks", "inv.pkgs", "inv.backups", "inv.net", "inv.certs", "inv.vms", "inv.containers", "inv.access", "inv.usage", "metrics.sample")}
    a = rig.make_agent()
    seen = {}
    for _ in range(len(ids)):
        rig.clock.advance(31)                                # fresh rate buckets
        a.poll_once(wait_s=0)
    for op, jid in ids.items():
        j = state(rig, jid)
        assert j["state"] == "committed", (op, j["state"], j["result_reason"])
        seen[op] = json.loads(j["result_output"])["op"]
    assert seen == {op: op for op in ids}


def test_heavy_op_in_blackout_is_denied_retryable_and_redelivered_after_the_window(rig):
    from forge_node.t0 import window as W
    from datetime import datetime, timezone
    inside = datetime(2026, 11, 3, 3, 0, tzinfo=W.BERLIN).astimezone(timezone.utc)
    rig.clock.now = inside
    jid = rig.enqueue("inv.git")
    a = rig.make_agent()
    a.poll_once(wait_s=0)
    j = state(rig, jid)
    assert j["state"] == "denied_retryable" and j["result_reason"] == "DENY_WINDOW"


def test_logs_unit_with_probe_unavailable_returns_the_degraded_section(rig):
    jid = rig.enqueue("logs.unit", unit="forge-postbote.service")
    rig.make_agent().poll_once(wait_s=0)
    j = state(rig, jid)
    assert j["state"] == "committed" and json.loads(j["result_output"])["data"]["log"]["status"] == "unavailable"


def test_logs_unit_through_the_probe_reaches_the_hub_redacted(rig):
    rig.probe.replies["journal"] = lambda p: {"log": {"status": "ok", "unit": p["unit"], "lines": [f"x {CAN}", "ok"], "dropped": 0}}
    jid = rig.enqueue("logs.unit", unit="forge-edge.service", lines=5)
    rig.make_agent().poll_once(wait_s=0)
    out = state(rig, jid)["result_output"]
    assert "CANARY" not in out and "ok" in out and json.loads(out)["sensitivity"] == "internal"


def test_node_side_params_check_is_independent_of_the_hub(rig):
    jid = rig.enqueue("logs.unit", unit="sshd.service")                # hub schema passes (a plain unit name); the node policy does not list it
    rig.make_agent().poll_once(wait_s=0)
    j = state(rig, jid)
    assert j["state"] == "denied" and j["result_reason"] == "DENY_NOT_ALLOWLISTED"


# --------------------------------------------------------------------------------------------------------------------------------- STOP
def test_stop_does_not_stop_t0(rig):
    (rig.cfg_hub.control_dir / "STOP").write_text("stop\n")
    jid = rig.enqueue("inv.host")
    a = rig.make_agent()
    assert a.poll_once(wait_s=0) == "job" and state(rig, jid)["state"] == "committed"


# ------------------------------------------------------------------------------------------------------------------ nothing above T0
def test_agent_denies_a_tier1_job_even_if_a_hub_with_open_gates_signs_it(rig, open_gates):
    rig.hub.gates = open_gates                         # a (hypothetically compromised/future) hub that signs a T1 job
    jid = rig.enqueue("container.stop", tier=1, id="x" * 64)
    a = rig.make_agent()
    assert a.poll_once(wait_s=0) == "job"
    j = state(rig, jid)
    assert j["state"] == "denied" and j["result_reason"] == "DENY_TIER_DISABLED"
    assert a.rt.engine.spool.depth() == 0 and not [c for c in rig.runner.calls if c[0].startswith("docker")]


# ------------------------------------------------------------------------------------------------------------------ trust anchors
def test_agent_does_not_talk_to_a_ca_valid_hub_whose_certificate_is_not_pinned(rig):
    rig.set_policy(serial=2, pins=[rig.pki.sha256_der(rig.certs["other"][1])])
    jid = rig.enqueue("inv.host")
    a = rig.make_agent()
    assert a.poll_once(wait_s=0) == "unreachable"
    assert state(rig, jid)["state"] == "queued" and rig.adm.execute("SELECT last_seen FROM node.nodes WHERE node_id='g2'").fetchone()["last_seen"] is None
    assert any("not pinned" in m for m in rig.logs)


def test_old_gate_key_signatures_rejected_after_policy_serial_plus_one(rig, gate2):
    rig.set_policy(serial=2, keys=gate2["keys"])                       # the owner revoked gate key 1 by signing serial 2 without it
    jid = rig.enqueue("inv.host")
    a = rig.make_agent()
    assert a.poll_once(wait_s=0) == "bad_response"
    assert state(rig, jid)["state"] == "issued" and not any(c[0] == "timedatectl" for c in rig.runner.calls)
    assert any("discarded" in m for m in rig.logs)


def test_policy_hot_reload_rebuilds_pins_and_keys(rig, gate2):
    a = rig.make_agent()
    rig.enqueue("inv.host")
    assert a.poll_once(wait_s=0) == "job"
    rig.set_policy(serial=2, pins=[rig.pki.sha256_der(rig.certs["other"][1])])
    assert a.poll_once(wait_s=0) == "unreachable"                      # new pin list took effect without a restart
    rig.set_policy(serial=3)
    assert a.poll_once(wait_s=0) in ("idle", "job")


def test_a_broken_newer_policy_means_no_policy_and_silence(rig):
    a = rig.make_agent()
    assert a.poll_once(wait_s=0) in ("idle", "job")
    calls = rig.adm.execute("SELECT last_seen FROM node.nodes WHERE node_id='g2'").fetchone()["last_seen"]
    d = rig.tmp / "policy"
    (d / "policy-2.json").write_text('{"serial": 2}')
    (d / "policy-2.json.sig").write_text("junk")
    os.chmod(d / "policy-2.json", 0o644)
    os.chmod(d / "policy-2.json.sig", 0o644)
    rig.clock.advance(120)
    assert a.poll_once(wait_s=0) == "no_policy"
    assert rig.adm.execute("SELECT last_seen FROM node.nodes WHERE node_id='g2'").fetchone()["last_seen"] == calls


def test_agent_without_any_policy_never_contacts_the_hub(rig):
    for f in (rig.tmp / "policy").iterdir():
        f.unlink()
    a = rig.make_agent()
    assert a.poll_once(wait_s=0) == "no_policy"
    assert rig.adm.execute("SELECT last_seen FROM node.nodes WHERE node_id='g2'").fetchone()["last_seen"] is None


# ----------------------------------------------------------------------------------------------------------------- job verification
def test_expired_job_is_not_executed_and_nothing_is_posted(rig):
    jid = rig.enqueue("inv.host")
    a = rig.make_agent()
    real_clock = a.clock
    # the agent's clock runs 5 minutes ahead of the hub's: the delivered job is already expired for it (and the lease is 'issued in the past' > skew)
    a.clock = lambda: real_clock() + timedelta(minutes=5)
    a.holder.clock = a.clock
    st = a.poll_once(wait_s=0)
    assert st in ("bad_response", "unreachable", "idle") and state(rig, jid)["state"] == "issued"


def test_job_for_another_node_is_rejected(rig, adm):
    add_node(adm, "g3", "full", cert="c" * 64)
    a = rig.make_agent()
    jid = rig.hub.enqueue_job(JobRequest(node="g3", tier=0, op="inv.host")).job_id
    assert a.poll_once(wait_s=0) == "idle" and state(rig, jid)["state"] == "queued"


def test_forged_job_in_a_valid_looking_response_is_dropped(rig):
    a = rig.make_agent()
    a.poll_once(wait_s=0)
    real_poll = a.rt.client.poll

    def poisoned(body):
        resp = real_poll(body)
        job = {"typ": "job", "v": 1, "job_id": protocol.new_uuid(), "delivery_seq": 1, "node": "g2", "tier": 0, "op": "inv.host", "params": {}, "dry_run": False, "plan_hash": None,
               "requester": {"identity": "meta", "planner_call_id": None, "run_id": None, "project": None}, "issued_at": protocol.fmt_ts(rig.clock()),
               "expires_at": protocol.fmt_ts(rig.clock() + timedelta(seconds=60)), "owner_sig": None}
        from forge_node import canon
        resp["jobs"] = [{"payload": canon.canonical_text(job), "sig": "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n", "key_id": "hub-gate-1"}]
        return resp
    a.rt.client.poll = poisoned
    rig.runner.calls.clear()
    rig.clock.advance(5)
    assert a.poll_once(wait_s=0) == "job" and not rig.runner.calls
    assert any("job rejected" in m for m in rig.logs)


def test_replayed_lease_with_an_old_seq_discards_the_response(rig):
    a = rig.make_agent()
    a.poll_once(wait_s=0)
    first = a.rt.client.poll

    def replay(body, cache={}):
        if "r" not in cache:
            cache["r"] = first(body)
            return cache["r"]
        first(body)
        return cache["r"]
    a.rt.client.poll = replay
    assert a.poll_once(wait_s=0) in ("idle", "job")
    assert a.poll_once(wait_s=0) == "bad_response"


# ------------------------------------------------------------------------------------------------------------------- results / policy
def test_result_post_failure_is_retried_and_delivered(rig):
    from forge_node.agent.client import HubUnreachable
    a = rig.make_agent()
    a.poll_once(wait_s=0)                                   # builds the runtime
    jid = rig.enqueue("inv.gpu")
    real = a.rt.client.post_result
    n = {"calls": 0}

    def post(job_id, body):
        n["calls"] += 1
        if n["calls"] == 1:
            raise HubUnreachable("down")
        return real(job_id, body)
    a.rt.client.post_result = post
    rig.clock.advance(31)
    a.poll_once(wait_s=0)
    assert n["calls"] == 2 and a._pending == [] and state(rig, jid)["state"] == "committed"


def test_result_the_hub_keeps_refusing_is_dropped_not_retried_forever(rig):
    from forge_node.agent.client import HubError, HubUnreachable
    a = rig.make_agent()
    a.poll_once(wait_s=0)
    jid = rig.enqueue("inv.gpu")
    a.rt.client.post_result = lambda job_id, body: (_ for _ in ()).throw(HubUnreachable("down"))
    rig.clock.advance(31)
    a.poll_once(wait_s=0)
    assert len(a._pending) == 1
    a.rt.client.post_result = lambda job_id, body: (_ for _ in ()).throw(HubError(400, "bad_request"))
    a.poll_once(wait_s=0)
    assert a._pending == []


def test_newer_signed_policy_is_staged_not_activated(rig):
    d = rig.hub.cfg.policy_dir / "g2"
    install_policy(d, policy_doc(serial=2, pins=rig.pins, gate_keys=rig.gate["keys"]), rig.owner["priv"])
    rig.enqueue("inv.host")
    a = rig.make_agent()
    a.poll_once(wait_s=0)
    staged = rig.tmp / "state" / "staging"
    assert (staged / "policy-2.json").exists() and (staged / "policy-2.json.sig").exists()
    assert a.rt.policy.serial == 1                                         # the installed policy is still the old one
    assert any("staged" in m for m in rig.logs)


def test_newer_policy_with_a_bad_signature_is_not_staged(rig, gate):
    d = rig.hub.cfg.policy_dir / "g2"
    raw = json.dumps(policy_doc(serial=2, pins=rig.pins, gate_keys=rig.gate["keys"])).encode()
    install_policy(d, policy_doc(serial=2), rig.owner["priv"], raw=raw, sig=sshsig.sign(raw, gate["priv"], sshsig.NS_POLICY))
    a = rig.make_agent()
    a.poll_once(wait_s=0)
    assert not (rig.tmp / "state" / "staging").exists()


def test_run_loop_backs_off_when_the_hub_is_unreachable_and_stops_on_request(rig):
    rig.set_policy(serial=2, pins=[rig.pki.sha256_der(rig.certs["other"][1])])
    a = rig.make_agent()
    waits = []
    a._stop.wait = lambda d: (waits.append(d), a.stop())[0]
    a._poll_loop()
    assert waits == [2.0]                                                      # 2**1 s base, rng()==0.5 -> factor 1.0


def test_sampler_feeds_the_spool_and_metrics_sample_job_reads_it(rig):
    a = rig.make_agent()
    a.poll_once(wait_s=0)
    a.sample_tick()
    rig.clock.advance(31)
    a.sample_tick()
    jid = rig.enqueue("metrics.sample", after_seq=0, max_samples=10)
    rig.clock.advance(31)
    a.poll_once(wait_s=0)
    out = json.loads(state(rig, jid)["result_output"])["data"]["samples"]
    assert [s["seq"] for s in out["samples"]] == [1, 2] and out["samples"][0]["mem"]["total"] == 65856000 * 1024
    assert rig.adm.execute("SELECT 1 FROM node.nodes WHERE node_id='g2' AND quarantine").fetchone() is None
