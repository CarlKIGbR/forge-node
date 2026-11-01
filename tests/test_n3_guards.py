"""G27 (one guarded path: entry-point enumeration + behavioural guard tests) and G28 (fresh evidence: deterministic races) for the N3 code. The helpers are the pinned
forge-standards testkit (tests/g27_entrypoints.py, tests/g28_race.py). The static check is NECESSARY, NOT SUFFICIENT: every counted entry point also has a behavioural case that feeds it
input failing each check and demands a rejection without side effect."""
import base64
import dataclasses
import io
import json
import os
import shutil
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest
from audit_helpers import AGENT_GID, AGENT_UID
from g27_entrypoints import DROP, EntryCase, assert_fail_closed, assert_guard_failures_rejected, check_entry_points, find_entry_points
from g28_race import Interleaver, hook_after, hook_before
from privd_helpers import NODE, PrivdEnv, SRC

from forge_node import protocol, sshsig
from forge_node.privd import privctl, reconcile
from forge_node.privd.client import PrivUnavailable
from forge_node.privd.core import Context, Peer, Request
from forge_node.privd.gate import gate
from forge_node.privd.server import Server

PRIVD = Path(SRC) / "forge_node" / "privd"
RELEASE = Path(SRC) / "forge_node" / "release"
AGENT = Path(SRC) / "forge_node" / "agent"
GUARD_PARAMS = ("peer", "uid", "euid", "ctx", "req", "gates", "gates_map", "gate_set", "policy", "lease", "signature", "sig", "owner", "release")
EFFECTS = ("start", "append", "rotate", "recover", "purge", "apply", "mkdir", "unlink", "rename", "replace", "fchmod", "fchown", "fsync", "symlink", "write", "finish", "mark_started",
           "put", "flock", "kill", "stop", "run_pipe", "lock_target", "init")


class Rejected(Exception):
    pass


def reject_on_denial(reply: dict):
    """Adapter from privd's reply dicts to the testkit's 'raises on rejection' contract."""
    if reply.get("ok") is False:
        raise Rejected(reply.get("code"))
    if reply.get("in_progress"):
        raise Rejected("in_progress")                                  # not an acceptance either: nothing finished
    r = reply.get("result")
    if isinstance(r, dict) and r.get("status") in ("denied", "failed"):
        raise Rejected(r.get("reason_code"))
    return reply


# ============================================================================================================================ G27 static
def test_g27_every_privd_request_handler_is_counted_and_passes_gate_on_every_path():
    rep = check_entry_points(PRIVD, verbs=("handle",), guarded=("gate",), expected_count=9, exempt={}, guard_params=GUARD_PARAMS, effect_calls=EFFECTS)
    assert rep.ok, rep.render()
    names = sorted(e.qualname for e in rep.entry_points)
    assert names == sorted(f"privd.server.Server.handle_{k}" for k in ("exec", "lease_put", "t0", "status", "selfcheck", "reconcile", "policy_apply", "audit_rotate", "lockdown"))
    # the request set of the design (3.3) is closed: exec, lease.put, t0, status, selfcheck, reconcile, policy.apply, audit.rotate, lockdown
    from forge_node.privd.core import KINDS
    assert set(KINDS) == {"exec", "lease.put", "t0", "status", "selfcheck", "reconcile", "policy.apply", "audit.rotate", "lockdown"}


def test_g27_every_privctl_command_passes_require_root_first():
    rep = check_entry_points(PRIVD, verbs=("cmd",), guarded=("require_root",), expected_count=9, exempt={}, guard_params=GUARD_PARAMS, effect_calls=EFFECTS)
    assert rep.ok, rep.render()
    assert sorted(e.name for e in rep.entry_points) == sorted(f"cmd_{n}" for n in ("audit_init", "audit_verify", "audit_rotate", "audit_purge", "policy_apply", "status", "lockdown", "unit_closure",
                                                                                   "circuit_ack"))


def test_g27_every_switcher_command_passes_verify_release_first():
    rep = check_entry_points(RELEASE, verbs=("cmd",), guarded=("verify_release",), expected_count=4, exempt={}, guard_params=GUARD_PARAMS, effect_calls=EFFECTS)
    assert rep.ok, rep.render()
    assert sorted(e.name for e in rep.entry_points) == ["cmd_check", "cmd_install_first", "cmd_self_update", "cmd_switch"]


def test_g27_no_optional_parameter_can_switch_a_check_off_anywhere_in_privd_the_agent_link_or_the_audit_writer():
    """The helper reports optional parameters on counted entry points and the guarded function; this also scans every privd/audit/agent-link function for defaulted parameters whose
    names are guard inputs or bypass words (the T0 layer has its own scan in test_n2_scope)."""
    import ast
    import re
    bypass = re.compile(r"^(skip|bypass|no_check|unsafe|force|disable|trust)(_|$)|(^|_)(skip|bypass)$")
    allowed_defaults = {                                        # (file, function, param): why a default is harmless
        ("policy.py", "parse_policy", "gates_map"): "the T0 (agent-side) loader defaults to the PRODUCTION gate table gates.GATES; privd's PolicyStore passes it explicitly (asserted below) and tests pass "
                                                    "their own; the default can only be the strict one",
    }
    offenders = []
    for root in (PRIVD, Path(SRC) / "forge_node" / "audit", AGENT / "privlink.py", AGENT / "shipper.py", RELEASE / "switcher.py", RELEASE / "build.py", Path(SRC) / "forge_node" / "t0" / "policy.py"):
        files = [root] if root.is_file() else sorted(root.rglob("*.py"))
        for f in files:
            for n in ast.walk(ast.parse(f.read_text())):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    a = n.args
                    pos = a.posonlyargs + a.args
                    defaulted = {p.arg for p in pos[len(pos) - len(a.defaults):]} | {p.arg for p, d in zip(a.kwonlyargs, a.kw_defaults) if d is not None}
                    for p in defaulted:
                        if (bypass.search(p) or p in GUARD_PARAMS) and (f.name, n.name, p) not in allowed_defaults:
                            offenders.append((f.name, n.name, p))
    # the one reviewed exception: the release BUILDER's switcher_api/state_window/policy_schema are manifest VALUES, not guard inputs (the node's guard reads the signed manifest)
    assert not offenders, offenders


def test_g27_the_static_check_fails_on_a_new_unguarded_entry_point_even_a_conditional_one(tmp_path):
    """Mutation proof: copy the handlers into a scratch tree and add (a) an unguarded handler, (b) a handler that skips the guard on a condition, (c) one with an optional bypass
    parameter, (d) one that performs an effect before the guard. Each must be reported."""
    scratch = tmp_path / "privd"
    scratch.mkdir()
    shutil.copy(PRIVD / "server.py", scratch / "server.py")
    shutil.copy(PRIVD / "gate.py", scratch / "gate.py")
    (scratch / "__init__.py").write_text("")
    base = check_entry_points(scratch, verbs=("handle",), guarded=("gate",), expected_count=9, exempt={}, guard_params=GUARD_PARAMS, effect_calls=EFFECTS)
    assert base.ok, base.render()
    extra = {
        "unguarded": "    def handle_new(self, peer, body):\n        return {'ok': True}\n",
        "conditional": "    def handle_new(self, peer, body):\n        if peer.uid == 0:\n            return {'ok': True}\n        return gate(self.ctx, Request('status', peer, body))\n",
        "bypass param": "    def handle_new(self, peer, body, skip_checks=False):\n        return gate(self.ctx, Request('status', peer, body))\n",
        "effect first": "    def handle_new(self, peer, body):\n        self.ctx.backend.start('x', {}, [])\n        return gate(self.ctx, Request('status', peer, body))\n",
        "swallowed": "    def handle_new(self, peer, body):\n        try:\n            return gate(self.ctx, Request('status', peer, body))\n        except Exception:\n            return {'ok': True}\n",
    }
    src = (PRIVD / "server.py").read_text()
    for label, code in extra.items():
        (scratch / "server.py").write_text(src.replace("    # ---- transport", code + "\n    # ---- transport"))
        rep = check_entry_points(scratch, verbs=("handle",), guarded=("gate",), expected_count=10, exempt={}, guard_params=GUARD_PARAMS, effect_calls=EFFECTS)
        assert not rep.ok, f"{label}: the static check did not catch it"
    (scratch / "server.py").write_text(src.replace("    # ---- transport", "    def handle_extra(self, peer, body):\n        return gate(self.ctx, Request('status', peer, body))\n\n    # ---- transport"))
    rep = check_entry_points(scratch, verbs=("handle",), guarded=("gate",), expected_count=9, exempt={}, guard_params=GUARD_PARAMS, effect_calls=EFFECTS)
    assert not rep.ok and any("counted 10" in p for p in rep.problems)                      # a new guarded entry point still has to be counted by a reviewer


def _transport_effects(src: str) -> list:
    """Calls in the Server methods that are NOT the nine handlers (dispatch, serve_connection, serve, peer_of, stop) that could be an effect or could reach privd's state: the transport
    may parse, route to a handler by name and read the clock - nothing else."""
    import ast
    import re
    tree = ast.parse(src)
    out = []
    for cls in (n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Server"):
        for fn in (n for n in cls.body if isinstance(n, ast.FunctionDef) and not n.name.startswith("handle_")):
            for c in ast.walk(fn):
                if isinstance(c, ast.Call):
                    name = ast.unparse(c.func)
                    if name.rsplit(".", 1)[-1] in EFFECTS + ("gate",) and name not in ("self.stop", "self._stop.set") and not name.startswith("threading.Thread(") or re.match(r"self\.ctx\.(ledger|backend|priv_log|agent_log|policies|leases|paths|optable)\b", name):
                        out.append((fn.name, name))
    return out


def test_g27_the_transport_between_the_socket_and_the_handlers_has_no_effect_of_its_own(tmp_path):
    """Review M8: the counted entry points are the handle_* methods; dispatch/serve_connection sit between the socket and them and are not counted. They must contain no effect and no
    access to privd's state (a new branch in dispatch that starts a unit would otherwise pass the entry-point count). Mutation proof included."""
    src = (PRIVD / "server.py").read_text()
    assert _transport_effects(src) == []
    mutated = src.replace("            body = {k: v for k, v in doc.items() if k != \"req\"}", "            body = {k: v for k, v in doc.items() if k != \"req\"}\n            if kind == 'x':\n                self.ctx.backend.start('x', {}, [])")
    assert mutated != src and _transport_effects(mutated) == [("dispatch", "self.ctx.backend.start")]
    needle = "            return canon.canonical(getattr(self, name)(peer, body)) + b\"\\n\""
    mutated2 = src.replace(needle, "            self.ctx.ledger.finish('j', 1, 'failed', {}, None)\n" + needle)
    assert mutated2 != src and _transport_effects(mutated2)
    # startup recovery is not a request path: it is called from the daemon's main() before the socket exists, and from nowhere else in the package
    import re
    callers = sorted(f.name for f in PRIVD.glob("*.py") if re.search(r"\brecover_all\(", f.read_text()) and f.name != "reconcile.py")
    assert callers == ["main.py"]


def test_every_op_table_entry_dispatches_through_gate():
    """No code path from the socket to an op script that skips gate(): the only callers of the unit start for an op are in gate.py, and `reconcile.py` never starts a worker."""
    import ast
    starters = {}
    for f in sorted(PRIVD.rglob("*.py")):
        for n in ast.walk(ast.parse(f.read_text())):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("start", "run_pipe") and "backend" in ast.unparse(n.func.value):
                starters.setdefault(f.name, set()).add(n.func.attr)
    assert starters == {"gate.py": {"start", "run_pipe"}}, starters
    # and the op table is data: no entry carries a callable that starts anything itself
    from forge_node.privd import optable
    for e in optable.build_optable("full"):
        assert e.worker_cmd in (None, e.name) and e.unit_class in __import__("forge_node.privd.classes", fromlist=["x"]).CLASSES


def test_g27_static_check_of_the_production_wiring_uses_the_real_gate_table_and_backend():
    import ast
    src = (PRIVD / "main.py").read_text()
    assert "gates_map=gates.GATES" in src and "gates=gates.GATES" in src and "SystemdBackend(" in src and "LocalProcessBackend" not in src
    for f in PRIVD.rglob("*.py"):
        if f.name != "units.py":
            assert "LocalProcessBackend" not in f.read_text(), f.name
    for f in sorted((Path(SRC) / "forge_node").rglob("*.py")):
        t = f.read_text()
        if f.parts[-2] in ("agent", "t0", "hub"):
            assert "gates_map" not in t.replace("gates_map=gates.GATES", "") or f.name == "policy.py", f.name      # only the T0 policy loader takes a table, with the production default


# ========================================================================================================================== G27 behavioural
@pytest.fixture
def rig(privd_env):
    e = privd_env.ready()
    e.server = Server(e.ctx)
    return e


def units_started(e):
    return len(e.backend.list_op_units())


def side_effects(e):
    """Everything a guard-failing request must NOT change: units started, work directories, installed policies, rotated generations, LOCAL_STOP, ledger rows past `received`, leases."""
    n = units_started(e) + len(os.listdir(e.paths.work)) + sum(1 for x in os.listdir(e.paths.policy_dir) if x.endswith(".json"))
    n += sum(1 for g in os.listdir(e.specs["priv"].dir) if g.startswith("priv.")) * 100 + sum(1 for g in os.listdir(e.specs["agent"].dir) if g.startswith("audit.")) * 100
    n += int(os.path.exists(e.paths.local_stop)) * 1000 + sum(1 for r in e.ledger.open_rows() if r.state != "received") + int(e.ledger.meta_get("lease_seq", "0"))
    return n


def test_g27_behavioural_every_handler_rejects_input_failing_each_check_without_side_effect(rig, keys):
    e = rig
    rep = check_entry_points(PRIVD, verbs=("handle",), guarded=("gate",), expected_count=9, exempt={}, guard_params=GUARD_PARAMS, effect_calls=EFFECTS)
    srv = e.server
    agent, root, stranger = Peer(1, AGENT_UID, AGENT_GID), Peer(1, 0, 0), Peer(1, 1234, 1234)
    rogue_priv, rogue_pub = keys.make("rogue-hub")

    class K:
        def __getitem__(self, k):
            return rogue_priv if k == "priv" else rogue_pub

    good_job = e.job_env(dry_run=True)[0]
    forged_job = dict(good_job, sig=good_job["sig"][:-30] + "A" * 30)
    rogue_job = e.job_env(dry_run=True, key=K())[0]
    wrong_node = e.job_env(dry_run=True, node="g3")[0]
    e.clock.advance(seconds=1)
    lease_new = e.lease_env(seq=50)
    lease_replay = e.lease_env(seq=1)
    lease_rogue = protocol.seal(__import__("privd_helpers").lease_payload(e.clock(), 60), rogue_priv, "hub-gate-1")
    raw2, sig2 = e.sign(e.doc(tiers=(0, 1), serial=2, t1_ops=[{"op": "selftest.noop", "mode": "enforce"}]))
    raw_other, sig_other = e.sign(e.doc(tiers=(0, 1), serial=3, node="g3", t1_ops=[{"op": "selftest.noop"}]))
    raw_old, sig_old = e.sign(e.doc(tiers=(0, 1), serial=1, t1_ops=[{"op": "selftest.noop"}]))
    pb = lambda raw, sig: {"policy_b64": base64.b64encode(raw).decode(), "sig": sig}      # noqa: E731

    def call(name):
        def f(peer=None, body=None, **_):
            if peer is None or body is None:
                raise Rejected("missing guard state")                                    # a missing input must reject, not skip a check
            return reject_on_denial(getattr(srv, name)(peer, body))
        return f
    cases = {
        "privd.server.Server.handle_exec": EntryCase(call("handle_exec"), dict(peer=agent, body={"job": good_job}), {
            "stranger uid": dict(peer=stranger), "root-only fields do not help": dict(peer=stranger, body={"job": good_job, "uid": 0}), "forged signature": dict(body={"job": forged_job}),
            "unlisted gate key": dict(body={"job": rogue_job}), "other node": dict(body={"job": wrong_node}), "no job": dict(body={}), "no body": dict(body=DROP), "no peer": dict(peer=DROP)}),
        "privd.server.Server.handle_lease_put": EntryCase(call("handle_lease_put"), dict(peer=agent, body={"lease": lease_new}), {
            "stranger uid": dict(peer=stranger), "replayed seq": dict(body={"lease": lease_replay}), "unlisted key": dict(body={"lease": lease_rogue}), "no lease": dict(body={}),
            "garbage": dict(body={"lease": "x"})}),
        "privd.server.Server.handle_t0": EntryCase(call("handle_t0"), dict(peer=agent, body={"probe": "vms", "params": {}}), {
            "stranger uid": dict(peer=stranger), "unknown probe": dict(body={"probe": "rm", "params": {}}), "extra keys": dict(body={"probe": "vms", "params": {}, "sudo": 1}),
            "params not an object": dict(body={"probe": "vms", "params": []})}),
        "privd.server.Server.handle_status": EntryCase(call("handle_status"), dict(peer=agent, body={}), {"stranger uid": dict(peer=stranger)}),
        "privd.server.Server.handle_selfcheck": EntryCase(call("handle_selfcheck"), dict(peer=agent, body={"target": "probe:vms"}), {
            "stranger uid": dict(peer=stranger), "unknown target": dict(body={"target": "probe:nope"}), "path-like target": dict(body={"target": "op:../../etc/passwd"}),
            "no target": dict(body={})}),
        "privd.server.Server.handle_reconcile": EntryCase(call("handle_reconcile"), dict(peer=agent, body={"job_id": "00000000-0000-4000-8000-000000000000"}), {
            "stranger uid": dict(peer=stranger), "not a uuid": dict(body={"job_id": "../../x"}), "agent tries to resolve": dict(body={"job_id": "00000000-0000-4000-8000-000000000000", "resolve":
                                                                                                                              {"verdict": "committed", "inspection": "looked fine to me, honest"}})}),
        "privd.server.Server.handle_policy_apply": EntryCase(call("handle_policy_apply"), dict(peer=root, body=pb(raw2, sig2)), {
            "stranger uid": dict(peer=stranger), "forged signature": dict(body=pb(raw2, sig_old)), "another node's policy": dict(body=pb(raw_other, sig_other)),
            "serial not newer": dict(body=pb(raw_old, sig_old)), "not base64": dict(body={"policy_b64": "!!", "sig": "x"})}),
        "privd.server.Server.handle_audit_rotate": EntryCase(call("handle_audit_rotate"), dict(peer=root, body={"log": "priv"}), {
            "agent uid (root only)": dict(peer=agent), "stranger uid": dict(peer=stranger), "unknown log": dict(body={"log": "../etc"}), "no log": dict(body={})}),
        "privd.server.Server.handle_lockdown": EntryCase(call("handle_lockdown"), dict(peer=root, body={}), {"agent uid (root only)": dict(peer=agent), "stranger uid": dict(peer=stranger)}),
    }
    assert_guard_failures_rejected(cases, report=rep, rejects=(Rejected,), side_effects=lambda: side_effects(e))


def test_g27_fail_closed_gate_rejects_missing_state_without_side_effects(rig):
    e = rig
    valid = dict(ctx=e.ctx, req=Request("status", Peer(1, AGENT_UID, AGENT_GID), {}))
    assert_fail_closed(lambda **kw: reject_on_denial(gate(**kw)), valid, ["ctx", "req"], rejects=(Rejected,), side_effects=lambda: side_effects(e))
    assert gate(e.ctx, Request("exec", Peer(1, AGENT_UID, AGENT_GID), None)) ["ok"] is False             # a body that is not a mapping at all
    # review: the adapter rejected the "no body" / "no peer" cases itself - privd's own answer, with its own state untouched, is what counts
    before = side_effects(e)
    for kind in ("exec", "lease.put", "t0", "selfcheck", "reconcile", "policy.apply", "audit.rotate", "lockdown", "status"):
        for bad in (Request(kind, None, {}), Request(kind, Peer(1, AGENT_UID, AGENT_GID), None), Request(kind, Peer(1, 0, 0), None), Request(kind, "peer", "body")):
            r = gate(e.ctx, bad)
            assert r["ok"] is False and r["code"] in ("FAIL_PRECHECK", "DENY_PARAM", "DENY_JOB_SIGNATURE", "DENY_OP_UNKNOWN"), (kind, bad, r)
    assert side_effects(e) == before and not os.path.exists(e.paths.local_stop)


def test_g27_behavioural_privctl_commands_refuse_non_root_without_side_effect(rig, tmp_path):
    e = rig
    from test_privd_server import make_ctl
    ctl, out, calls = make_ctl(e, euid=1001)
    rep = check_entry_points(PRIVD, verbs=("cmd",), guarded=("require_root",), expected_count=9, exempt={}, guard_params=GUARD_PARAMS, effect_calls=EFFECTS)

    def call(fn):
        def f(**_):
            try:
                fn(ctl)
            except privctl.CtlError:
                raise Rejected("not root")
        return f
    ok_ctl, _, _ = make_ctl(e, euid=0)
    names = {"audit_init": lambda c: c.cmd_audit_init(), "audit_verify": lambda c: c.cmd_audit_verify(), "audit_rotate": lambda c: c.cmd_audit_rotate("both"), "audit_purge": lambda c: c.cmd_audit_purge(1, 1),
             "policy_apply": lambda c: c.cmd_policy_apply("/nonexistent", "/nonexistent"), "status": lambda c: c.cmd_status(), "lockdown": lambda c: c.cmd_lockdown(),
             "unit_closure": lambda c: c.cmd_unit_closure("a.service", "start"), "circuit_ack": lambda c: c.cmd_circuit_ack("selftest.noop", "me")}
    cases = {}
    for n, fn in names.items():
        def make(fn=fn):
            def f(as_root=False):
                c = ok_ctl if as_root else ctl
                try:
                    fn(c)
                except privctl.CtlError:
                    raise Rejected("not root")
                except (FileNotFoundError, PrivUnavailable):
                    if not as_root:                                                  # root got PAST the guard and failed on a file / on the (absent) socket - the guard did not stop it
                        raise
                return None
            return f
        cases[f"privd.privctl.Ctl.cmd_{n}"] = EntryCase(make(), dict(as_root=True), {"not root": dict(as_root=False)})
    assert_guard_failures_rejected(cases, report=rep, rejects=(Rejected,), side_effects=lambda: side_effects(e) + len(calls) + len(out.getvalue()))


def test_g27_behavioural_switcher_commands_reject_unverifiable_releases_without_side_effect(tmp_path, mkey_fixture):
    """Node A has a current release (check/switch/self-update). `install-first` needs a node WITHOUT one, and its valid call would use that state up, so every call of it gets a fresh
    node of its own - otherwise a tampered release would be refused as 'already current' even without the signature guard. On all of them release 0.3.2 was tampered with after signing."""
    from forge_node.release.switcher import Refused
    from test_release import Env
    (tmp_path / "a").mkdir()
    a = Env(tmp_path / "a", mkey_fixture)
    fresh: list = []

    def prepare(env):
        for v in ("0.3.0", "0.3.1", "0.3.2"):
            env.release(v, "full")
        (env.base / "releases" / "0.3.2" / "units" / "forge-node-agent.service").write_text("[Service]\nExecStart=/bin/sh\n")       # tampered after signing
    prepare(a)
    swa = a.switcher()
    swa.cmd_install_first("0.3.0")
    a.make_ledger()
    rep = check_entry_points(RELEASE, verbs=("cmd",), guarded=("verify_release",), expected_count=4, exempt={}, guard_params=GUARD_PARAMS, effect_calls=EFFECTS)

    def changes(env):
        calls = sum(1 for c in env.calls if not c[0].endswith("ssh-keygen"))              # ssh-keygen verifications do not count
        links = sum(1 for n in ("current", "previous", "profile") if os.path.lexists(env.base / n))
        return calls + links + (env.self_path.stat().st_size if env.self_path.exists() else 0) + (len(os.readlink(env.base / "current")) if os.path.islink(env.base / "current") else 0)

    def side():
        return changes(a) + sum(changes(e) for e in fresh)

    def mk(fn):
        def f(version, **_):
            try:
                fn(version)
            except Refused:
                raise Rejected("refused")
        return f

    def install_first(version):
        n = len(fresh)
        (tmp_path / f"n{n}").mkdir()
        env = Env(tmp_path / f"n{n}", mkey_fixture)
        prepare(env)
        fresh.append(env)
        try:
            env.switcher().cmd_install_first(version)
        finally:
            if version != "0.3.1":                                                       # a refusal leaves this node exactly as prepare() made it
                assert changes(env) == 0, "a refused install-first changed the node"
    failing = {"tampered release": dict(version="0.3.2"), "unknown release": dict(version="9.9.9"), "malformed version": dict(version="../x")}
    cases = {
        "release.switcher.Switcher.cmd_check": EntryCase(mk(swa.cmd_check), dict(version="0.3.1"), failing),
        "release.switcher.Switcher.cmd_switch": EntryCase(mk(lambda v: swa.cmd_switch(v, False)), dict(version="0.3.1"), failing),
        "release.switcher.Switcher.cmd_self_update": EntryCase(mk(swa.cmd_self_update), dict(version="0.3.1"), failing),
        "release.switcher.Switcher.cmd_install_first": EntryCase(mk(install_first), dict(version="0.3.1"), failing),
    }
    assert_guard_failures_rejected(cases, report=rep, rejects=(Rejected,), side_effects=side)
    assert len(fresh) == 4 and all(changes(e) == 0 for e in fresh[1:])                  # the valid call changed its node, none of the refused ones did


@pytest.fixture
def mkey_fixture(tmp_path_factory):
    d = tmp_path_factory.mktemp("g27key")
    os.chmod(d, 0o700)
    priv = d / "owner"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(priv)], check=True, capture_output=True)
    return priv, " ".join((d / "owner.pub").read_text().split()[:2])


# ======================================================================================================================== G28 races
def test_g28_reconcile_reobserves_the_world_after_the_fence_bump(privd_env, tmp_path):
    """A worker that is past its time budget but finishes between the decision to reconcile and the stop must be COMMITTED from its own status, not aborted/re-run: after the fence bump
    and the confirmed death, status.json is read again (the earlier look is not evidence)."""
    import uuid
    e = privd_env.ready()
    from forge_node.privd.units import op_unit_name
    jid = str(uuid.uuid4())
    e.ledger.claim(jid, 1, "selftest.noop", "selftest.noop", "0" * 64, False, "meta", e.clock())
    wd = Path(e.paths.work) / f"{jid}-1"
    wd.mkdir(mode=0o700)
    unit = op_unit_name(jid, 1)
    inv = e.backend.start(unit, {"ProtectSystem": "strict"}, [sys.executable, "-c", "import time; time.sleep(120)"])
    e.ledger.mark_started(jid, 1, unit, str(wd), None, None, False, False, e.clock())
    e.ledger.set_invocation(jid, 1, inv, e.clock())
    e.clock.advance(seconds=31)                                                                # past the op's budget: reconciliation is allowed to proceed
    il = Interleaver()
    hook_after(reconcile, "examine", il, "A.examined", only_thread="A")
    il.start("A", lambda: reconcile.reconcile_job(e.ctx, jid))
    il.wait_parked("A.examined")                                                              # A saw an active-but-late worker and decided to reconcile
    (wd / "effect.mark").write_text("applied\n")                                              # ... and the worker did its effect and reported, just now
    (wd / "request.json").write_text("{}")
    from forge_node.privd import worker
    worker.write_status(str(wd), {"job_id": jid, "attempt": 1, "fence": 1, "outcome": "done", "plan_hash": None, "output": "ok", "post_digest": None})
    il.release("A.examined")
    kind, res = il.join("A")
    assert kind == "committed" and res["status"] == "committed", (kind, res)
    assert e.ledger.get(jid).state == "committed" and e.ledger.get(jid).attempt == 1
    assert not e.backend.show(unit).is_active


def test_reconcile_and_retry_claims_serialized(privd_env):
    import uuid
    from forge_node.privd.units import op_unit_name
    e = privd_env.ready()
    jid = str(uuid.uuid4())
    e.ledger.claim(jid, 1, "selftest.noop", "selftest.noop", __import__("forge_node.canon", fromlist=["x"]).digest({"note": "r"}), False, "meta", e.clock())
    wd = Path(e.paths.work) / f"{jid}-1"
    wd.mkdir(mode=0o700)
    e.ledger.mark_started(jid, 1, op_unit_name(jid, 1), str(wd), None, None, False, False, e.clock())      # an interrupted row: no unit
    il = Interleaver()
    hook_after(e.ledger, "begin_reconcile", il, "A.bumped", only_thread="A")
    il.start("A", lambda: reconcile.reconcile_job(e.ctx, jid))
    il.wait_parked("A.bumped")                                                                 # A holds the job lock, the fence is already bumped
    assert e.ledger.get(jid).fence == 2 and e.ledger.get(jid).state == "reconciling"
    assert reconcile.reconcile_job(e.ctx, jid) == ("in_progress", None)                       # a second reconcile
    env2, _ = e.job_env(job_id=jid, params={"note": "r"}, delivery_seq=2)
    assert e.call("exec", {"job": env2}) == {"ok": True, "in_progress": True, "job_id": jid}      # a re-delivery
    assert e.call("reconcile", {"job_id": jid}, uid=AGENT_UID)["reconcile"] == "in_progress"       # the hub's reconcile[] through the agent
    il.release("A.bumped")
    kind, res = il.join("A")
    assert kind == "aborted_safe" and e.ledger.get(jid).state == "aborted_safe"
    # only now a retry claim may start attempt 2
    e.put_lease(seq=9)
    env3, _ = e.job_env(job_id=jid, params={"note": "r"}, dry_run=False, delivery_seq=3, plan_hash=None)
    assert e.ledger.claim(jid, 3, "selftest.noop", "selftest.noop", __import__("forge_node.canon", fromlist=["x"]).digest({"note": "r"}), False, "meta", e.clock()).kind == "retry"
    assert e.ledger.get(jid).attempt == 2


def test_g28_the_stop_recheck_test_fails_without_the_recheck(privd_env, monkeypatch):
    """The race test of the STOP re-observation must FAIL on the variant without it (the testkit's rule: a race test that cannot fail proves nothing)."""
    from forge_node.privd import gate as gate_mod
    e = privd_env.ready()
    monkeypatch.setattr(gate_mod, "_fresh_stop_check", lambda st: None)
    started = []
    real = e.backend.start
    e.backend.start = lambda *a: started.append(a) or real(*a)
    il = Interleaver()
    hook_after(e.ledger, "mark_started", il, "A.started", only_thread="A")
    env, job = e.job_env(dry_run=True)
    il.start("A", lambda: e.call("exec", {"job": env}))
    il.wait_parked("A.started")
    open(e.paths.local_stop, "w").close()
    il.release("A.started")
    il.join("A")
    assert started, "without the re-observation the unit starts although LOCAL_STOP appeared: the race test (test_stop_is_reobserved_immediately_before_the_unit_starts) detects exactly this"
