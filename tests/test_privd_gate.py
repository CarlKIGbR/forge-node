"""privd gate() pipeline (Design 3.3): the direct-socket bypass tests (T-GATE), denial order, audit of every denial, intent before effect, dry-run/plan flow, owner signature."""
import base64
import json
import os
import time

import pytest
from audit_helpers import AGENT_UID
from privd_helpers import NODE, PrivdEnv, gates_with, policy_doc

from forge_node import gates, protocol, sshsig
from forge_node.privd.core import Peer, Request
from forge_node.privd.gate import gate, owner_binding


def result(r):
    assert r["ok"] is True and "result" in r, r
    return r["result"]


def test_happy_path_dry_run_then_apply_with_plan_one_effect(privd_env):
    e = privd_env.ready()
    r, job = e.exec(dry_run=True, params={"note": "t"})
    res = result(r)
    assert res["status"] == "dry_run" and res["reason_code"] is None and len(res["plan_hash"]) == 64
    assert not os.path.exists(f"{e.paths.work}/{job['job_id']}-1/effect.mark")
    r2, job2 = e.exec(plan_hash=res["plan_hash"], params={"note": "t"})
    res2 = result(r2)
    assert res2["status"] == "committed" and res2["plan_hash"] == res["plan_hash"], res2
    assert os.path.exists(f"{e.paths.work}/{job2['job_id']}-1/effect.mark")
    row = e.ledger.get(job2["job_id"])
    assert row.state == "committed" and row.attempt == 1 and row.fence == 1 and row.worker_unit.startswith("forge-node-op-")
    recs = [x for x in e.priv_records() if x.get("job_id") == job2["job_id"]]
    assert [x["type"] for x in recs] == ["intent", "result"] and recs[0]["attempt"] == recs[1]["attempt"] == 1
    assert res2["audit_seq_range"] == [recs[0]["seq"], recs[1]["seq"]]
    assert protocol.validate_result({k: v for k, v in res2.items() if k != "job_id"})


def test_mutating_ops_denied_until_gate_d(realfs, owner, gate):
    """With the production gate table (all gates unmet) no op above T0 is accepted: the policy that enables one is refused at apply, and a signed job for it is denied."""
    e = PrivdEnv(realfs, {"owner": owner, "gate": gate}, gate_set=gates.GATES)
    assert not any(g.met for g in gates.GATES.values())
    r = e.install(t1_ops=[{"op": "selftest.noop"}])
    assert r["ok"] is False and r["code"] == "DENY_POLICY_INVALID" and "gate D" in r["detail"], r
    assert e.install(tiers=(0,))["ok"], "the T0-only policy is accepted"
    e.put_lease()
    res = result(e.exec()[0])
    assert res["status"] == "denied" and res["reason_code"] == "DENY_TIER_DISABLED" and "gate D" in res["output"]
    assert not os.listdir(e.paths.work)
    # the gate table cannot be opened by a request: there is no field in any request that reaches `gates`
    from forge_node.privd import gate as gate_mod
    assert gate_mod.gates.GATES is gates.GATES and not any(g.met for g in gates.GATES.values())


def test_direct_calls_in_the_design_order_each_denial_is_audited(privd_env):
    e = privd_env.ready()

    def denied(code, **kw):
        r, job = e.exec(**kw)
        res = result(r)
        assert res["status"] == "denied" and res["reason_code"] == code, res
        recs = [x for x in e.priv_records() if x.get("job_id") == job["job_id"]]
        assert recs and recs[-1]["type"] in ("denial", "result") and recs[-1]["reason_code"] == code, recs
        assert e.ledger.get(job["job_id"]).state in ("denied", "denied_retryable")
        return res
    # 4 LOCAL_STOP before everything that follows it
    open(e.paths.local_stop, "w").close()
    denied("DENY_LOCAL_STOP")
    os.unlink(e.paths.local_stop)
    # 3 lease: global stop, per-project stop, quarantine, expiry
    e.put_lease(seq=2, stop=True)
    denied("DENY_STOP")
    e.put_lease(seq=3, projects=("p1",))
    denied("DENY_STOP", project="p1")
    assert result(e.exec(project="p2", dry_run=True)[0])["status"] == "dry_run"
    e.put_lease(seq=4, quarantine=True)
    denied("DENY_QUARANTINE")
    e.put_lease(seq=5)
    e.clock.advance(seconds=61)
    denied("DENY_STALE_LEASE")
    e.put_lease(seq=6)
    # 5 clock skew: a clock that is 61 s BEHIND the lease's issued_at (the lease itself is still in its validity window)
    e.clock.advance(seconds=-62)
    denied("DENY_CLOCK")
    e.clock.advance(seconds=62)
    # 7 policy: tier / op not enabled
    e.install(t1_ops=[], serial=2)
    denied("DENY_TIER_DISABLED")
    e.install(t1_ops=[{"op": "selftest.noop", "mode": "enforce"}], serial=3)
    # 9 parameter schema
    denied("DENY_PARAM", params={"nope": 1}, dry_run=True)
    denied("DENY_PARAM", params={"note": "x" * 65}, dry_run=True)
    # unknown / unimplemented op, wrong tier
    denied("DENY_OP_UNKNOWN", op="container.stop", tier=1, params={})              # known to the design (gates.OPS), but NOT compiled into this release: no entry, no code path
    denied("DENY_OP_UNKNOWN", op="no.such.op", tier=1)
    denied("DENY_PARAM", op="selftest.noop", tier=2)
    # 12 window (Berlin blackout 02:00-05:45): 2026-11-01 03:00 Berlin = 02:00 UTC
    from datetime import datetime, timezone
    e.clock.t = datetime(2026, 11, 1, 2, 0, 0, tzinfo=timezone.utc)
    e.put_lease(seq=7)
    denied("DENY_WINDOW")


def test_denial_order_stop_before_policy(privd_env):
    """Everything that follows STOP is not even looked at: a job that is invalid in every later way is denied as STOP, with the same code for a direct call."""
    e = privd_env.ready()
    e.put_lease(seq=2, stop=True)
    r, job = e.exec(params={"bogus": 1}, op="no.such.op")
    assert result(r)["reason_code"] == "DENY_STOP"
    open(e.paths.local_stop, "w").close()
    r, job = e.exec(params={"bogus": 1}, op="no.such.op")
    assert result(r)["reason_code"] == "DENY_STOP"                                  # lease (3) comes before LOCAL_STOP (4)
    e.put_lease(seq=3)
    r, job = e.exec(params={"bogus": 1}, op="no.such.op")
    assert result(r)["reason_code"] == "DENY_LOCAL_STOP"


def test_unsigned_wrong_node_expired_and_foreign_key_jobs(privd_env, keys):
    e = privd_env.ready()
    env, job = e.job_env()
    forged = dict(env, payload=env["payload"].replace('"op":"selftest.noop"', '"op":"selftest.noop" '))
    for bad, code in ((forged, "DENY_JOB_SIGNATURE"), ({"payload": env["payload"], "sig": "x", "key_id": "hub-gate-1"}, "DENY_JOB_SIGNATURE"),
                      (dict(env, key_id="hub-gate-9"), "DENY_JOB_SIGNATURE"), ("junk", "DENY_JOB_SIGNATURE")):
        r = e.call("exec", {"job": bad})
        assert r["ok"] is False and r["code"] == code, (bad, r)
    other_priv, other_pub = keys.make("rogue-gate")
    env2, _ = e.job_env(key=type("K", (), {"__getitem__": lambda s, k: other_priv if k == "priv" else other_pub})())
    assert e.call("exec", {"job": env2})["code"] == "DENY_JOB_SIGNATURE"                       # signed by a key the policy does not list
    env3, _ = e.job_env(node="g3")
    assert e.call("exec", {"job": env3})["code"] == "DENY_JOB_SIGNATURE"
    env4, _ = e.job_env(ttl=10)
    e.clock.advance(seconds=11)
    assert e.call("exec", {"job": env4})["code"] == "DENY_JOB_EXPIRED"
    assert not e.ledger.open_rows()                                                          # nothing was claimed for an unauthenticated job
    assert not any(r.get("job_id") for r in e.priv_records() if r["type"] == "denial")       # and its id is never trusted into a job_id column (hub cross-check)
    assert any(r.get("claimed_job_id") or r.get("kind") == "exec" for r in e.priv_records() if r["type"] == "denial")


def test_other_callers_and_forged_leases_and_jobs_never_reach_anything(privd_env):
    e = privd_env.ready()
    for uid in (1, 1234, 65534):
        for kind in ("exec", "t0", "status", "lease.put", "policy.apply", "reconcile", "selfcheck"):
            r = e.call(kind, {}, uid=uid)
            assert r["ok"] is False and r["code"] == "DENY_JOB_SIGNATURE", (uid, kind, r)
    for kind in ("audit.rotate", "lockdown"):
        assert e.call(kind, {"log": "priv"}, uid=AGENT_UID)["code"] == "DENY_JOB_SIGNATURE"        # root only
    # a lease the agent made up
    forged = e.lease_env(seq=50)
    forged["payload"] = forged["payload"].replace('"stop":false', '"stop":true')
    r = e.call("lease.put", {"lease": forged}, uid=AGENT_UID)
    assert r["ok"] is False
    lease_payload_seq = e.call("status", {}, uid=AGENT_UID)["status"]["lease"]["seq"]
    assert lease_payload_seq == 1
    assert e.call("nonsense", {}) == {"ok": False, "code": "DENY_OP_UNKNOWN", "detail": "unknown request kind"}


def test_lease_seq_replay_and_wrong_key_and_node(privd_env):
    e = privd_env.ready()
    assert e.put_lease(seq=5)["ok"]
    for seq in (5, 4, 1):
        r = e.put_lease(seq=seq)
        assert r["ok"] is False and r["code"] == "DENY_STALE_LEASE", (seq, r)
    assert e.put_lease(seq=6)["ok"]
    # replay survives a privd restart: the highest seq is in the ledger, not in memory
    e2 = e.ctx.leases.__class__(path=e.paths.lease_file, ledger=e.ledger, node=NODE, ssh_keygen=e.ssh_keygen, clock=e.clock, owner_uid=0)
    with pytest.raises(protocol.ProtoError):
        e2.put(e.lease_env(seq=6), e.ctx.policies.current().view.hub_gate_keys)
    r = e.call("lease.put", {"lease": protocol.seal(__import__("privd_helpers").lease_payload(e.clock(), 9, node="g3"), e.gate_key["priv"], "hub-gate-1")})
    assert r["ok"] is False and r["code"] == "DENY_STALE_LEASE"


def test_reboot_clears_the_lease_and_fails_closed(privd_env):
    e = privd_env.ready()
    os.unlink(e.paths.lease_file)                                                     # /run is tmpfs: gone after a reboot
    res = result(e.exec(dry_run=True)[0])
    assert res["status"] == "denied" and res["reason_code"] == "DENY_STALE_LEASE"


def test_observe_forces_dry_run_and_dry_run_only_op_mode(privd_env):
    e = privd_env.ready(mode="observe", serial=2)
    r, job = e.exec(params={"note": "obs"})                                           # an APPLY job in observe mode
    res = result(r)
    assert res["status"] == "dry_run" and "forced dry run" in res["output"], res
    assert not os.path.exists(f"{e.paths.work}/{job['job_id']}-1/effect.mark")
    e.install(t1_ops=[{"op": "selftest.noop", "mode": "dry_run_only"}], serial=3)
    r, job = e.exec(params={"note": "dro"})
    assert result(r)["status"] == "dry_run" and not os.path.exists(f"{e.paths.work}/{job['job_id']}-1/effect.mark")
    row = e.ledger.get(job["job_id"])
    assert row.dry_run is False and row.eff_dry_run is True


def test_rate_limit_and_state_survives_restart(privd_env):
    e = privd_env.ready(t1_ops=[{"op": "selftest.noop", "mode": "enforce", "rate": [[2, 600]]}], serial=2)
    for _ in range(2):
        assert result(e.exec(dry_run=True)[0])["status"] == "dry_run"
    res = result(e.exec(dry_run=True)[0])
    assert res["status"] == "denied" and res["reason_code"] == "DENY_RATE"
    # "agent restart" / a new Context on the same ledger: the buckets are root state
    e.ctx = e.make_context()
    res = result(e.exec(dry_run=True)[0])
    assert res["reason_code"] == "DENY_RATE"
    e.clock.advance(minutes=11)
    e.put_lease(seq=9)
    assert result(e.exec(dry_run=True)[0])["status"] == "dry_run"


def test_node_wide_mutating_rate_bucket(privd_env):
    e = privd_env.ready()
    codes = [result(e.exec(dry_run=True)[0]) for _ in range(8)]
    assert [c["status"] for c in codes[:6]] == ["dry_run"] * 6
    assert codes[6]["reason_code"] == "DENY_RATE" and codes[7]["reason_code"] == "DENY_RATE"
    assert protocol.RETRYABLE_DENIALS >= {"DENY_RATE"}
    # a rate denial is retryable: the same job_id succeeds when delivered later
    env, job = e.job_env(dry_run=True)
    assert result(e.call("exec", {"job": env}))["reason_code"] == "DENY_RATE"
    assert e.ledger.get(job["job_id"]).state == "denied_retryable"
    e.clock.advance(seconds=61)
    e.put_lease(seq=10)
    env2, _ = e.job_env(dry_run=True, job_id=job["job_id"], delivery_seq=2)
    assert result(e.call("exec", {"job": env2}))["status"] == "dry_run"
    assert e.ledger.get(job["job_id"]).state == "committed"


def test_circuit_opens_after_three_failures_and_only_dry_runs_remain(privd_env, tmp_path):
    e = privd_env.ready()
    script = tmp_path / "failing_worker.py"
    script.write_text("import sys\nsys.path.insert(0, %r)\nfrom forge_node.privd import worker\n\n\ndef boom(ctx):\n    raise RuntimeError('disk on fire')\n\n\n"
                      "sys.exit(worker.run(sys.argv[2], {'selftest.noop': boom}, owner_uid=0))\n" % __import__("privd_helpers").SRC)

    def plan(note, seq):
        e.clock.advance(seconds=61)                                                    # keeps the node-wide bucket and the lease fresh
        e.put_lease(seq=seq)
        e.worker_script = None
        return result(e.exec(dry_run=True, params={"note": note})[0])
    results = []
    for i in range(3):
        p = plan(f"p{i}", 20 + 2 * i)
        e.worker_script = str(script)                                                  # the APPLY run fails in the worker
        results.append(result(e.exec(plan_hash=p["plan_hash"], params={"note": f"p{i}"})[0]))
    e.worker_script = None
    assert [r["status"] for r in results] == ["failed"] * 3 and results[0]["reason_code"] == "FAIL_EXEC"
    assert e.ledger.circuit("selftest.noop")["state"] == "open"
    p = plan("after", 30)
    assert p["status"] == "dry_run"                                                    # dry runs still work
    r = result(e.exec(plan_hash=p["plan_hash"], params={"note": "after"})[0])
    assert r["status"] == "denied" and r["reason_code"] == "DENY_CIRCUIT_OPEN"
    assert e.ledger.circuit_ack("selftest.noop", "betriebsleiter") and e.ledger.circuit("selftest.noop")["state"] == "closed"
    p = plan("again", 31)
    assert result(e.exec(plan_hash=p["plan_hash"], params={"note": "again"})[0])["status"] == "committed"


def test_plan_hash_mismatch_and_missing_plan(privd_env):
    e = privd_env.ready()
    plan = result(e.exec(dry_run=True, params={"note": "a"})[0])
    # no plan at all / unknown hash
    for ph in (None, "0" * 64):
        res = result(e.exec(plan_hash=ph, params={"note": "a"})[0])
        assert res["status"] == "denied" and res["reason_code"] == "DENY_STALE_PLAN", res
    # the approved plan, but the world changed between plan and apply (recomputed under the effect lock by the worker)
    with open(f"{e.paths.priv_state}/selftest.marker", "w") as f:
        f.write("changed\n")
    os.chmod(f"{e.paths.priv_state}/selftest.marker", 0o600)
    r, job = e.exec(plan_hash=plan["plan_hash"], params={"note": "a"})
    res = result(r)
    assert res["status"] == "denied" and res["reason_code"] == "DENY_STALE_PLAN", res
    assert not os.path.exists(f"{e.paths.work}/{job['job_id']}-1/effect.mark")
    assert e.ledger.get(job["job_id"]).state == "denied"
    # an expired plan
    os.unlink(f"{e.paths.priv_state}/selftest.marker")
    plan2 = result(e.exec(dry_run=True, params={"note": "b"})[0])
    e.clock.advance(minutes=31)
    e.put_lease(seq=40)
    assert result(e.exec(plan_hash=plan2["plan_hash"], params={"note": "b"})[0])["reason_code"] == "DENY_STALE_PLAN"


def test_missing_and_invalid_owner_signature(privd_env):
    e = privd_env.ready(t1_ops=[{"op": "selftest.noop", "mode": "enforce", "requires": "owner_signature"}], serial=2)
    res = result(e.exec(dry_run=True)[0])
    assert res["reason_code"] == "DENY_NEEDS_OWNER_SIG"
    assert e.ledger.get(res["job_id"]).state == "denied"                                 # terminal (not in the retryable list)
    # a signature in the POLICY namespace is not an approval
    env, job = e.job_env(dry_run=True)
    sig_policy = sshsig.sign(owner_binding(job), e.owner["priv"], sshsig.NS_POLICY)
    env, job = e.job_env(dry_run=True, owner_sig=sig_policy)
    assert result(e.call("exec", {"job": env}))["reason_code"] == "DENY_NEEDS_OWNER_SIG"
    # a signature over a different job
    other_env, other = e.job_env(dry_run=True)
    sig_other = sshsig.sign(owner_binding(other), e.owner["priv"], sshsig.NS_APPROVAL)
    env, job = e.job_env(dry_run=True, owner_sig=sig_other)
    assert result(e.call("exec", {"job": env}))["reason_code"] == "DENY_NEEDS_OWNER_SIG"
    # the right one: binding computed from the job that is sent
    jid = "11111111-1111-4111-8111-111111111111"
    _, probe_job = e.job_env(dry_run=True, job_id=jid)
    sig = sshsig.sign(owner_binding(probe_job), e.owner["priv"], sshsig.NS_APPROVAL)
    env, job = e.job_env(dry_run=True, job_id=jid, owner_sig=sig)
    assert result(e.call("exec", {"job": env}))["status"] == "dry_run"


def test_intent_fsynced_before_effect_else_refused(privd_env):
    """The intent record is on disk BEFORE the worker unit exists; and if the log cannot be appended the op is refused (DENY_AUDIT_DOWN, retryable) with no unit started."""
    e = privd_env.ready()
    seen = {}
    real_start = e.backend.start

    def spy(name, props, argv):
        seen["intent_on_disk_at_start"] = [r["type"] for r in e.priv_records() if r.get("job_id") == name.split("forge-node-op-")[1][:36]]
        seen["ledger_state_at_start"] = e.ledger.get(name.split("forge-node-op-")[1][:36]).state
        return real_start(name, props, argv)
    e.backend.start = spy
    assert result(e.exec(dry_run=True)[0])["status"] == "dry_run"
    assert seen["intent_on_disk_at_start"] == ["intent"] and seen["ledger_state_at_start"] == "started"
    e.backend.start = real_start
    # break the log: the file named by CURRENT is sealed (what a crashed rotation leaves) and this instance cannot heal it right now
    from forge_node.audit import fsflags
    spec = e.specs["priv"]
    fd = os.open(f"{spec.dir}/priv.000001/priv.000001.jsonl", os.O_RDONLY)
    fsflags.add_flags(fd, fsflags.IMMUTABLE)
    os.close(fd)
    e.priv_log._drop()
    e.priv_log._heal_depth = 99
    started = []
    e.backend.start = lambda *a: started.append(a) or real_start(*a)
    e.clock.advance(seconds=61)
    e.put_lease(seq=60)
    r, job = e.exec(dry_run=True)
    res = result(r) if r.get("ok") else r
    assert (res.get("reason_code") or res.get("code")) == "DENY_AUDIT_DOWN", res
    assert not started, "no unit may start when the intent cannot be recorded"
    row = e.ledger.get(job["job_id"])
    assert row is None or row.state in ("denied_retryable",)


def test_op_unit_properties_come_from_a_fixed_table_not_params(privd_env):
    from forge_node.privd import classes
    e = privd_env.ready()
    captured = []
    real_start = e.backend.start
    e.backend.start = lambda name, props, argv: captured.append(dict(props)) or real_start(name, props, argv)
    result(e.exec(dry_run=True, params={"note": "ProtectSystem no"})[0])
    assert captured and captured[0]["ProtectSystem"] == "strict" and captured[0]["NoNewPrivileges"] == "yes" and "no" != captured[0].get("ProtectSystem")
    # the same job parameters can only change the property set through nothing at all
    r1 = classes.op_unit_properties("selftest", work_dir="/w", priv_state="/p", timeout_s=30)
    r2 = classes.op_unit_properties("selftest", work_dir="/w", priv_state="/p", timeout_s=30)
    assert r1 == r2
    with pytest.raises(classes.ClassError):
        classes.op_unit_properties("no-such-class", work_dir="/w", priv_state="/p", timeout_s=30)
    for bad in (0, 3601, True, "30"):
        with pytest.raises(classes.ClassError):
            classes.op_unit_properties("selftest", work_dir="/w", priv_state="/p", timeout_s=bad)
    assert "ReadWritePaths" not in classes.op_unit_properties("t3-opaque", work_dir="/w", priv_state="/p", timeout_s=30)
    assert classes.op_unit_properties("dir-ops", work_dir="/w", priv_state="/p", forge_roots=("/srv/forge/node",), timeout_s=30)["ReadWritePaths"] == "/w /p/locks /srv/forge/node"


def test_status_reports_policy_lease_heads_open_jobs_and_gates(privd_env):
    e = privd_env.ready()
    s = e.call("status", {}, uid=AGENT_UID)["status"]
    assert s["policy"]["serial"] == 1 and s["lease"]["seq"] == 1 and s["local_stop"] is False
    assert s["gates"] == {"A": False, "B": False, "C": False, "D": True} and s["audit_heads"]["priv"]["seq"] >= 2 and s["open_jobs"] == []
    open(e.paths.local_stop, "w").close()
    assert e.call("status", {})["status"]["local_stop"] is True


def test_t0_probe_requires_lease_policy_and_a_known_probe_and_is_allowed_during_stop(privd_env):
    e = privd_env
    e.install(tiers=(0,))
    r = e.call("t0", {"probe": "uulog", "params": {}})
    assert r["code"] == "DENY_STALE_LEASE"                                               # no lease yet: fail closed
    e.put_lease()
    assert e.call("t0", {"probe": "no-such", "params": {}})["code"] == "DENY_OP_UNKNOWN"
    assert e.call("t0", {"probe": "uulog"})["code"] == "DENY_PARAM"
    r = e.call("t0", {"probe": "uulog", "params": {}})
    assert r["ok"] is True and r["probe"]["ok"] is True, r
    e.put_lease(seq=2, stop=True)
    open(e.paths.local_stop, "w").close()
    r = e.call("t0", {"probe": "uulog", "params": {}})                                   # STOP and LOCAL_STOP do not stop reads
    assert r["ok"] is True
    assert any(x["type"] == "t0" and x["probe"] == "uulog" for x in e.priv_records())


def test_t0_probe_rate_limit_is_authoritative_in_privd(privd_env):
    e = privd_env
    e.install(tiers=(0,))
    e.put_lease()
    codes = [e.call("t0", {"probe": "uulog", "params": {}}) for _ in range(5)]
    assert [c["ok"] for c in codes[:3]] == [True] * 3
    assert codes[3]["code"] == "DENY_RATE"
