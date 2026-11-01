"""The two unit backends. SystemdBackend: argument vectors and parsing against a scripted command runner (no systemd in the test container - the real thing is proven by doctor/N4);
LocalProcessBackend: the double the other tests rely on, checked against the same interface contract."""
import os
import sys

import pytest

from forge_node.privd.units import (UNIT_RE, LocalProcessBackend, SystemdBackend, UnitError, op_unit_name, parse_show, prop_args, systemd_run_argv)

JOB = "0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b"
NAME = op_unit_name(JOB, 2)


class Script:
    """Scripted `run(argv, stdin, timeout)`: records every call, answers by the sub-command."""

    def __init__(self):
        self.calls, self.show_outputs, self.rc = [], [], {}

    def __call__(self, argv, stdin, timeout):
        self.calls.append((list(argv), stdin, timeout))
        if argv[0].endswith("systemd-run"):
            return self.rc.get("run", 0), b"", b"" if self.rc.get("run", 0) == 0 else b"Failed to start transient service unit"
        if argv[1] == "show":
            out = self.show_outputs.pop(0) if len(self.show_outputs) > 1 else self.show_outputs[0]
            return self.rc.get("show", 0), out, b""
        if argv[1] == "stop":
            return self.rc.get("stop", 0), b"", self.rc.get("stop_err", b"")
        if argv[1] == "list-units":
            return 0, b"forge-node-op-0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b-1.service loaded active running forge-node op\nnot-ours.service loaded active running x\n", b""
        return 0, b"", b""


def backend(script, clock=None):
    t = {"now": 0.0}

    def sleep(s):
        t["now"] += s
    return SystemdBackend(systemd_run="/usr/bin/systemd-run", systemctl="/usr/bin/systemctl", run=script, sleep=sleep, monotonic=lambda: t["now"])


def show(active="active", sub="running", inv="a1" * 16, result="success", cg="/system.slice/x.service"):
    return f"ActiveState={active}\nSubState={sub}\nInvocationID={inv}\nResult={result}\nControlGroup={cg}\n".encode()


def test_systemd_run_vector_has_no_collect_no_shell_and_sorted_properties():
    argv = systemd_run_argv("/usr/bin/systemd-run", NAME, {"ProtectSystem": "strict", "NoNewPrivileges": "yes", "ReadWritePaths": "/a /b"}, ["/usr/bin/python3", "-I", "/x.pyz", "opworker", "run", "/w"], pipe_wait=False)
    assert argv[:5] == ["/usr/bin/systemd-run", "--quiet", f"--unit={NAME}", "--description=forge-node op", "--no-block"]
    assert "--collect" not in argv and "-c" not in argv and "sh" not in argv and "bash" not in argv
    props = [argv[i + 1] for i, a in enumerate(argv) if a == "-p"]
    assert props == sorted(props) == ["NoNewPrivileges=yes", "ProtectSystem=strict", "ReadWritePaths=/a /b"]
    assert argv[argv.index("--") + 1:] == ["/usr/bin/python3", "-I", "/x.pyz", "opworker", "run", "/w"]
    piped = systemd_run_argv("/usr/bin/systemd-run", "forge-node-probe-" + "a" * 32 + ".service", {}, ["/usr/bin/python3", "x"], pipe_wait=True)
    assert "--pipe" in piped and "--wait" in piped and "--no-block" not in piped


@pytest.mark.parametrize("bad", ["x.service", "forge-node-op-../../x-1.service", NAME + ".d", "forge-node-op-" + JOB + "-0.service", "forge-node-op-" + JOB + "-10000.service",
                                 "forge-node-op-" + JOB.upper() + "-1.service", "forge-node-probe-xyz.service", ""])
def test_unit_names_outside_the_pattern_are_refused(bad):
    with pytest.raises(UnitError):
        systemd_run_argv("/usr/bin/systemd-run", bad, {}, ["/usr/bin/true"], pipe_wait=False)
    assert not UNIT_RE.match(bad)


def test_programs_and_properties_are_validated():
    for argv in ([], ["relative/path"], ["python3"]):
        with pytest.raises(UnitError):
            systemd_run_argv("/usr/bin/systemd-run", NAME, {}, argv, pipe_wait=False)
    for props in ({"Bad Key": "x"}, {"1abc": "x"}, {"Key": "line\nbreak"}, {"Key": "nul\x00"}, {"Key": 5}):
        with pytest.raises(UnitError):
            prop_args(props)


def test_start_returns_the_invocation_id_polling_until_the_job_has_begun():
    sc = Script()
    sc.show_outputs = [b"ActiveState=inactive\nSubState=dead\nInvocationID=\nResult=success\nControlGroup=\n", show(active="activating", sub="start", inv=""), show(inv="b2" * 16)]
    b = backend(sc)
    inv = b.start(NAME, {"ProtectSystem": "strict"}, ["/usr/bin/true"])
    assert inv == "b2" * 16
    shows = [c for c in sc.calls if c[0][1] == "show"]
    assert len(shows) == 3 and sc.calls[0][0][0].endswith("systemd-run")
    assert all(c[0][-1] == NAME and c[0][:3] == ["/usr/bin/systemctl", "show", "--no-pager"] for c in shows)


def test_start_fails_when_systemd_run_fails_or_the_job_never_begins():
    sc = Script()
    sc.rc["run"] = 1
    with pytest.raises(UnitError, match="systemd-run failed"):
        backend(sc).start(NAME, {}, ["/usr/bin/true"])
    sc = Script()
    sc.show_outputs = [b"ActiveState=inactive\nSubState=dead\nInvocationID=\nResult=success\nControlGroup=\n"]
    with pytest.raises(UnitError, match="no InvocationID"):
        backend(sc).start(NAME, {}, ["/usr/bin/true"])


def test_show_parses_states_and_treats_a_collected_unit_as_gone():
    sc = Script()
    b = backend(sc)
    sc.show_outputs = [show()]
    info = b.show(NAME)
    assert (info.active_state, info.sub_state, info.invocation_id, info.is_active) == ("active", "running", "a1" * 16, True)
    sc.show_outputs = [show(active="failed", sub="failed", result="exit-code")]
    info = b.show(NAME)
    assert not info.is_active and info.result == "exit-code"
    # a finished transient unit is garbage-collected: systemctl answers "inactive/dead" with no invocation id and no cgroup => None (status.json is the evidence then)
    sc.show_outputs = [b"ActiveState=inactive\nSubState=dead\nInvocationID=\nResult=success\nControlGroup=\n"]
    assert b.show(NAME) is None
    sc.rc["show"] = 1
    sc.show_outputs = [b""]
    assert b.show(NAME) is None
    with pytest.raises(UnitError):
        b.show("x.service")


def test_stop_and_list_op_units():
    sc = Script()
    b = backend(sc)
    b.stop(NAME)
    assert sc.calls[-1][0] == ["/usr/bin/systemctl", "stop", NAME]
    sc.rc["stop"], sc.rc["stop_err"] = 5, b"Unit forge-node-op-x.service not loaded."
    b.stop(NAME)                                                                                  # already gone: fine
    sc.rc["stop_err"] = b"Access denied"
    with pytest.raises(UnitError):
        b.stop(NAME)
    assert b.list_op_units() == [op_unit_name(JOB, 1)]                                           # only names that match the pattern


def test_parse_show_ignores_lines_without_equals():
    assert parse_show("A=1\nnoise\nB=\nC=x=y\n") == {"A": "1", "B": "", "C": "x=y"}


# -------------------------------------------------------------------------------------------------------------------- the local test double
def test_local_backend_follows_the_same_contract(tmp_path):
    b = LocalProcessBackend(str(tmp_path / "u"))
    inv = b.start(NAME, {"ProtectSystem": "strict"}, [sys.executable, "-c", "import time; time.sleep(30)"])
    info = b.show(NAME)
    assert info.is_active and info.invocation_id == inv and not info.cgroup_empty
    assert b.list_op_units() == [NAME]
    b.stop(NAME)
    info = b.show(NAME)
    assert not info.is_active and info.cgroup_empty and info.invocation_id == inv
    assert b.show(op_unit_name(JOB, 3)) is None
    code, out, err = b.run_pipe("forge-node-probe-" + "c" * 32 + ".service", {}, [sys.executable, "-c", "import sys; print(sys.stdin.read().upper())"], b"hello", 20)
    assert code == 0 and out.strip() == b"HELLO"
    code, _, _ = b.run_pipe("forge-node-probe-" + "d" * 32 + ".service", {}, [sys.executable, "-c", "import time; time.sleep(30)"], b"", 1)
    assert code == 124
