"""systemd transaction resolver (Design 4.3.1) incl. the gate C rejection of OnSuccess=/OnFailure=/isolate. A fake unit graph stands in for `systemctl show`; the parser of the live
provider is tested against real `systemctl show` output format."""
import pytest

from forge_node.privd import resolver as R

PU = ("kmu-*", "ollama.service", "postgresql@*")
PP = ("/opt/kmu-ai", "/srv/models")


def U(name, **kw):
    d = {k: "" for k in R.ALL_PROPS}
    d.update({"Id": name, "LoadState": "loaded", "ActiveState": "active", "FragmentPath": f"/etc/systemd/system/{name}", "Names": name})
    d.update(kw)
    return d


def graph(*units):
    g = {u["Id"]: u for u in units}
    return lambda n: g.get(n, {"LoadState": "not-found", **{k: "" for k in ("Id",)}})


def NOTEXT(name):
    return f"# /etc/systemd/system/{name}\n[Service]\nExecStart=/bin/true\n"


def res(g, unit="forge-x.service", action="start", mode="replace", text=NOTEXT):
    return R.resolve(g, text, unit, action, job_mode=mode, protected_units=PU, protected_paths=PP)


def hit_units(r):
    return {h.unit for h in r.hits}


def test_plain_unit_is_clean_and_hash_is_stable():
    g = graph(U("forge-x.service", Wants="network.target"), U("network.target"))
    r = res(g)
    assert not r.denied and r.F == {"network.target"}
    assert r.closure_sha256() == res(g).closure_sha256() and len(r.closure_sha256()) == 64


def test_t2_unit_start_conflicts_protected_denied():
    g = graph(U("forge-x.service", Conflicts="ollama.service"), U("ollama.service", ConflictedBy="forge-x.service", FragmentPath="/etc/systemd/system/ollama.service"))
    r = res(g)
    assert r.denied and "ollama.service" in hit_units(r)
    assert any("Conflicts" in h.edge for h in r.hits), [h.text() for h in r.hits]


def test_conflictedby_reverse_edge_detected():
    """The protected unit carries the Conflicts= that names ours."""
    g = graph(U("forge-x.service", ConflictedBy="kmu-core.service"), U("kmu-core.service", Conflicts="forge-x.service"))
    assert "kmu-core.service" in hit_units(res(g))


def test_t2_unit_start_requires_wants_bindsto_protected_dependency_denied():
    for key in ("Requires", "Wants", "BindsTo", "Requisite", "Upholds"):
        g = graph(U("forge-x.service", **{key: "kmu-db.service"}), U("kmu-db.service", ActiveState="inactive"))          # starting forge-x would START the protected unit
        assert "kmu-db.service" in hit_units(res(g)), key
    # transitively
    g = graph(U("forge-x.service", Requires="forge-y.service"), U("forge-y.service", Wants="forge-z.service"), U("forge-z.service", Requires="kmu-q.service"), U("kmu-q.service", ActiveState="inactive"))
    assert "kmu-q.service" in hit_units(res(g))


def test_an_active_protected_dependency_is_not_an_effect_but_is_bound_into_the_hash():
    """Starting forge-edge.service (Requires=docker.service) does nothing to a docker.service that is already active: no hit. Its data is still in closure_sha256, so the closure
    changing (a drop-in on docker.service, a new Conflicts=) invalidates the signed hash."""
    g = graph(U("forge-x.service", Requires="docker.service"), U("docker.service", FragmentPath="/usr/lib/systemd/system/docker.service"))
    r = res(g)
    assert not r.denied and r.F == {"docker.service"}
    h = r.closure_sha256()
    g2 = graph(U("forge-x.service", Requires="docker.service"), U("docker.service", FragmentPath="/usr/lib/systemd/system/docker.service", DropInPaths="/etc/systemd/system/docker.service.d/o.conf"))
    assert res(g2).closure_sha256() != h
    # a restart or a stop of docker itself is of course an effect on it
    g3 = graph(U("docker.service"))
    assert R.resolve(g3, NOTEXT, "docker.service", "restart", job_mode="replace", protected_units=("docker.service",), protected_paths=()).denied
    # ... and so is starting something that requires it when it is NOT running
    g4 = graph(U("forge-x.service", Requires="docker.service"), U("docker.service", ActiveState="failed"))
    assert R.resolve(g4, NOTEXT, "forge-x.service", "start", job_mode="replace", protected_units=("docker.service",), protected_paths=()).denied


def test_split_names_understands_systemctl_quoting():
    assert R.split_names('a.service "opt-kmu\\x2dai.mount" b.target') == ["a.service", "opt-kmu\\x2dai.mount", "b.target"]
    assert R.split_names('"a \\"q\\" b.service" c') == ['a "q" b.service', "c"]
    assert R.split_names("") == [] and R.split_names("   ") == []
    assert R.split_names('"open') == ["\x00unterminated"]                                       # malformed quoting never yields a plausible name
    g = graph(U("forge-x.service", Wants='"opt-kmu\\x2dai.mount"'), U("opt-kmu\\x2dai.mount"))
    p = R.systemctl_provider("/x", lambda *a: (0, b"Id=x\n", b""))
    assert p("opt-kmu\\x2dai.mount") == {"Id": "x"}                                           # an escaped mount unit name passes the name check
    assert "opt-kmu\\x2dai.mount" in res(g).F


def test_stop_closure_of_conflicted_unit_checked():
    """forge-x conflicts with forge-y; kmu-app Requires forge-y: stopping forge-y stops kmu-app."""
    g = graph(U("forge-x.service", Conflicts="forge-y.service"), U("forge-y.service", RequiredBy="kmu-app.service"), U("kmu-app.service", Requires="forge-y.service"))
    r = res(g)
    assert "kmu-app.service" in hit_units(r) and "kmu-app.service" in r.S


def test_stop_action_reverse_closure_is_checked():
    g = graph(U("forge-x.service", RequiredBy="kmu-a.service"), U("kmu-a.service"))
    assert "kmu-a.service" in hit_units(res(g, action="stop"))


def test_partof_restart_propagation_detected():
    g = graph(U("forge-x.service", ConsistsOf="kmu-part.service"), U("kmu-part.service", PartOf="forge-x.service"))
    r = res(g, action="restart")
    assert "kmu-part.service" in hit_units(r) and "kmu-part.service" in r.members


def test_reload_propagation_is_checked():
    g = graph(U("forge-x.service", PropagatesReloadTo="kmu-r.service"), U("kmu-r.service"))
    assert "kmu-r.service" in hit_units(res(g, action="reload"))


def test_enable_disable_wantedby_boot_effect_checked():
    g = graph(U("forge-x.service", WantedBy="kmu-boot.target"), U("kmu-boot.target"))
    for a in ("enable", "disable", "mask", "unmask"):
        assert "kmu-boot.target" in hit_units(res(g, action=a)), a
    g = graph(U("forge-x.service", RequiredBy="forge-y.service"), U("forge-y.service", RequiredBy="kmu-z.service"), U("kmu-z.service"))
    assert "kmu-z.service" in hit_units(res(g, action="disable"))          # running unit: its stop-closure
    assert "kmu-z.service" not in hit_units(res(g, action="enable"))


def test_socket_timer_triggers_included():
    g = graph(U("forge-x.timer", Triggers="forge-x.service"), U("forge-x.service", Requires="kmu-db.service", ActiveState="inactive"), U("kmu-db.service", ActiveState="inactive"))
    r = res(g, unit="forge-x.timer")
    assert "forge-x.service" in r.F and "kmu-db.service" in hit_units(r)


def test_protected_unit_fragmentpath_denied():
    g = graph(U("forge-x.service", Wants="odd.service"), U("odd.service", FragmentPath="/opt/kmu-ai/units/odd.service", ActiveState="inactive"))
    assert "odd.service" in hit_units(res(g))
    g = graph(U("forge-x.service", DropInPaths="/srv/models/override.conf"))
    assert "forge-x.service" in hit_units(res(g))


def test_resolver_incomplete_resolution_is_protected_hit():
    # provider error
    g = {"forge-x.service": U("forge-x.service", Requires="forge-y.service")}
    r = res(lambda n: g.get(n))
    assert r.denied and "forge-y.service" in hit_units(r)
    # missing property in systemctl show output
    broken = U("forge-x.service")
    del broken["ConflictedBy"]
    assert res(graph(broken)).denied
    # loaded unit without a fragment cannot be enumerated
    assert res(graph(U("forge-x.service", FragmentPath=""))).denied
    # provider raising
    def boom(n):
        raise RuntimeError("x")
    assert res(boom).denied
    # strong edge to a unit that is not loaded is a hit; a weak edge to one is skipped
    assert res(graph(U("forge-x.service", Requires="gone.service"))).denied
    assert not res(graph(U("forge-x.service", Wants="gone.service"))).denied
    # an oversized closure is a hit
    units = [U("forge-x.service", Wants=" ".join(f"w{i}.service" for i in range(450)))] + [U(f"w{i}.service") for i in range(450)]
    assert res(graph(*units)).denied


def test_unknown_action_and_unloaded_requested_unit():
    assert res(graph(U("forge-x.service")), action="frobnicate").denied
    assert res(graph(U("other.service"))).denied


# ------------------------------------------------------------------------------------------------------------------------------ gate C
def test_t2_unit_with_onsuccess_in_closure_denied():
    g = graph(U("forge-x.service", OnSuccess="forge-after.service"), U("forge-after.service"))
    r = res(g)
    assert r.denied and any("OnSuccess" in h.reason for h in r.hits)
    assert any("OnSuccess" in h.edge and "forge-after.service" in h.edge for h in r.hits)
    # buried in the closure rather than on the requested unit
    g = graph(U("forge-x.service", Requires="forge-y.service"), U("forge-y.service", OnSuccess="forge-after.service", ActiveState="inactive"), U("forge-after.service"))
    assert any(h.unit == "forge-y.service" and "OnSuccess" in h.reason for h in res(g).hits)
    # ... but an ACTIVE dependency that merely has OnFailure= (sysinit.target, local-fs.target: every real unit reaches them) is not changed by the transaction: it cannot fail because of it
    g = graph(U("forge-x.service", Requires="local-fs.target"), U("local-fs.target", OnFailure="emergency.target"), U("emergency.target"))
    assert not res(g).denied
    g = graph(U("forge-x.service", Requires="local-fs.target"), U("local-fs.target", OnFailure="emergency.target", ActiveState="inactive"), U("emergency.target"))
    assert res(g).denied


def test_t2_unit_with_onfailure_in_closure_denied():
    g = graph(U("forge-x.service", OnFailure="kmu-notify.service"), U("kmu-notify.service"))
    r = res(g)
    assert r.denied and any("OnFailure" in h.reason for h in r.hits)
    for action in ("start", "stop", "restart", "try-restart", "reload", "reload-or-restart", "enable", "disable", "mask", "unmask"):
        assert res(g, action=action).denied, action
    g = graph(U("forge-x.service", ConsistsOf="forge-p.service"), U("forge-p.service", OnFailure="a.service"), U("a.service"))
    assert res(g, action="restart").denied                                  # reached through restart propagation / the stop closure


def test_t2_unit_isolate_job_mode_denied():
    g = graph(U("forge-x.service"))
    for mode in ("isolate", "replace-irreversibly", "flush", "ignore-dependencies", "ignore-requirements", "triggering", "restart-dependencies", ""):
        r = res(g, mode=mode)
        assert r.denied, mode
    assert not res(g, mode="replace").denied and not res(g, mode="fail").denied
    g = graph(U("forge-x.service", OnFailureJobMode="isolate"))
    assert res(g).denied
    g = graph(U("forge-x.service", OnSuccessJobMode="isolate"))
    assert any("isolate" in h.reason for h in res(g).hits)
    g = graph(U("forge-x.service", OnFailureJobMode="replace"))
    assert not res(g).denied                                              # a job-mode value alone, without OnFailure=, is harmless


def test_resolver_rejects_instead_of_following_onsuccess_onfailure_recursively():
    """Gate C stays unmet: the resolver does not follow On*= edges (and so cannot bind them into closure_sha256); it rejects. The positive test the gate names for opening it
    (test_resolver_follows_onsuccess_onfailure_recursively_and_binds_closure_sha256) belongs to N6/N7."""
    g = graph(U("forge-x.service", OnFailure="forge-a.service"), U("forge-a.service", OnFailure="forge-b.service"), U("forge-b.service"))
    r = res(g)
    assert r.denied and "forge-b.service" not in r.members and "forge-a.service" not in r.members


def test_closure_hash_changes_with_dropin_conflict_and_member_set():
    base = graph(U("forge-x.service", Wants="forge-w.service"), U("forge-w.service"))
    h0 = res(base).closure_sha256()
    assert res(graph(U("forge-x.service", Wants="forge-w.service", DropInPaths="/etc/systemd/system/forge-x.service.d/o.conf"), U("forge-w.service"))).closure_sha256() != h0
    assert res(graph(U("forge-x.service", Wants="forge-w.service", Conflicts="forge-c.service"), U("forge-w.service"), U("forge-c.service"))).closure_sha256() != h0
    assert res(graph(U("forge-x.service", Wants="forge-w.service"), U("forge-w.service", FragmentPath="/etc/systemd/system/other.service"))).closure_sha256() != h0
    assert res(base, action="restart").closure_sha256() != h0               # the action is part of the hash


SHOW_SAMPLE = b"""Requires=sysinit.target system.slice
Requisite=
BindsTo=
Wants=network-online.target
Upholds=
Conflicts=shutdown.target
ConflictedBy=
RequiredBy=
BoundBy=
ConsistsOf=
PropagatesStopTo=
PropagatesReloadTo=
PartOf=
Triggers=
TriggeredBy=
WantedBy=multi-user.target
UpheldBy=
OnSuccess=
OnFailure=
OnSuccessJobMode=fail
OnFailureJobMode=replace
Id=forge-edge.service
LoadState=loaded
ActiveState=active
FragmentPath=/etc/systemd/system/forge-edge.service
DropInPaths=/etc/systemd/system/forge-edge.service.d/10.conf /etc/systemd/system/forge-edge.service.d/20.conf
Names=forge-edge.service
RequisiteOf=
StopWhenUnneeded=no
"""


def test_live_provider_parses_systemctl_show_and_validates_the_unit_name():
    calls = []

    def run(argv, stdin, timeout):
        calls.append(argv)
        return 0, SHOW_SAMPLE, b""
    p = R.systemctl_provider("/usr/bin/systemctl", run)
    d = p("forge-edge.service")
    assert d["Id"] == "forge-edge.service" and d["WantedBy"] == "multi-user.target"
    assert calls[0][:3] == ["/usr/bin/systemctl", "show", "--no-pager"] and calls[0][-1] == "forge-edge.service" and "-p" in calls[0]
    for bad in ("../x.service", "a b.service", "x;y.service", "-p.service", "x.service\n", "", "x.sh", "a" * 300 + ".service"):
        assert p(bad) is None, bad
    assert len(calls) == 1                                                  # nothing invalid reached the command
    assert R.systemctl_provider("/usr/bin/systemctl", lambda *a: (1, b"", b"err"))("forge-edge.service") is None


def test_resolver_on_a_realistic_unit_has_no_false_hit():
    r = R.resolve(lambda n: {k: v for k, v in (line.partition("=")[::2] for line in SHOW_SAMPLE.decode().splitlines())} if n == "forge-edge.service" else
                  U(n), NOTEXT, "forge-edge.service", "restart", job_mode="replace", protected_units=PU, protected_paths=PP)
    assert not r.denied, [h.text() for h in r.hits]


def test_real_systemctl_show_output_of_this_systemd_has_every_property_the_resolver_needs():
    """Fixtures captured read-only with `systemctl show` (systemd 255, carlgpu2): no property is missing for a normal unit (else the fail-closed rule would deny everything), a unit that
    does not exist reports LoadState=not-found, and the protected hit for docker.service is found through the real relations (Requires=docker.socket, ConsistsOf=...)."""
    import os
    here = os.path.join(os.path.dirname(__file__), "fixtures")
    parse = lambda n: dict(line.partition("=")[::2] for line in open(os.path.join(here, n)).read().splitlines() if "=" in line)      # noqa: E731
    real = parse("systemctl_show_docker_service.txt")
    assert set(R.ALL_PROPS) <= set(real), set(R.ALL_PROPS) - set(real)
    assert parse("systemctl_show_not_found.txt")["LoadState"] == "not-found"
    r = R.resolve(lambda n: real if n == "docker.service" else U(n), NOTEXT, "docker.service", "stop", job_mode="replace", protected_units=("docker.service",), protected_paths=())
    assert r.denied and "docker.service" in hit_units(r)
    r = R.resolve(lambda n: real if n == "docker.service" else U(n, FragmentPath=f"/usr/lib/systemd/system/{n}"), NOTEXT, "docker.service", "stop", job_mode="replace", protected_units=(), protected_paths=())
    assert not r.denied and "forge-docker-user.service" in r.S and "forge-edge.service" in r.S         # the stop closure follows RequiredBy/ConsistsOf


# ================================================================================================================= review findings
def test_try_restart_and_reload_or_restart_resolve_like_a_restart():
    """Review M1: on an ACTIVE unit systemd restarts the units that require it; the start-only sets missed that."""
    g = graph(U("forge-x.service", RequiredBy="kmu-app.service"), U("kmu-app.service"))
    for action in ("restart", "try-restart", "reload-or-restart", "stop"):
        r = res(g, action=action)
        assert "kmu-app.service" in hit_units(r), action
    g = graph(U("forge-x.service", PropagatesReloadTo="kmu-r.service"), U("kmu-r.service"))
    assert "kmu-r.service" in hit_units(res(g, action="reload-or-restart"))
    g = graph(U("forge-x.service", ConsistsOf="kmu-part.service"), U("kmu-part.service"))
    assert "kmu-part.service" in hit_units(res(g, action="try-restart"))


def test_requisite_of_is_a_stop_edge():
    """Review M2: Requisite= propagates a stop like Requires= does; systemd reports the reverse edge as RequisiteOf=, not under RequiredBy=."""
    g = graph(U("forge-x.service", RequisiteOf="kmu-app.service"), U("kmu-app.service"))
    for action in ("stop", "restart", "disable"):
        r = res(g, action=action)
        assert "kmu-app.service" in hit_units(r) and "kmu-app.service" in r.S, action
    assert "RequisiteOf" in R.ALL_PROPS and "RequisiteOf" in R.REVERSE_STOP


def test_the_restart_stop_closure_is_tested():
    """Review: removing the restart's reverse closure passed every resolver test."""
    g = graph(U("forge-x.service", RequiredBy="forge-y.service"), U("forge-y.service", RequiredBy="kmu-deep.service"), U("kmu-deep.service"))
    r = res(g, action="restart")
    assert r.S >= {"forge-y.service", "kmu-deep.service"} and "kmu-deep.service" in hit_units(r)


def test_enable_reads_the_install_section_not_only_the_symlinks_that_exist():
    """Review M3: for a unit that is not enabled yet, the live WantedBy= is empty - the [Install] section says what `enable` will do."""
    def text(body):
        return lambda n: f"# /etc/systemd/system/{n}\n[Service]\nExecStart=/bin/true\n\n[Install]\n{body}\n"
    g = graph(U("forge-x.service"), U("kmu-stack.target", ActiveState="inactive"))
    r = res(g, action="enable", text=text("WantedBy=kmu-stack.target"))
    assert "kmu-stack.target" in hit_units(r) and "kmu-stack.target" in r.X
    # the target does not even exist (not loaded): the NAME is protected anyway
    g = graph(U("forge-x.service"))
    assert "kmu-future.target" in hit_units(res(g, action="enable", text=text("WantedBy=kmu-future.target")))
    # an alias under a protected name
    assert "ollama.service" in hit_units(res(g, action="enable", text=text("Alias=ollama.service")))
    # Also= pulls another unit in; its own [Install] counts
    g = graph(U("forge-x.service"), U("forge-y.service"), U("kmu-stack.target"))
    def two(n):
        return {"forge-x.service": "[Install]\nAlso=forge-y.service\n", "forge-y.service": "[Install]\nWantedBy=kmu-stack.target\n"}.get(n, "")
    r = res(g, action="enable", text=two)
    assert "kmu-stack.target" in hit_units(r)
    # a harmless install is clean, a line continuation is joined, comments are ignored
    g = graph(U("forge-x.service"), U("multi-user.target"))
    assert not res(g, action="enable", text=text("# WantedBy=kmu-stack.target\nWantedBy=multi-user.target")).denied
    r = res(graph(U("forge-x.service")), action="enable", text=text("WantedBy=multi-user.target \\\n kmu-late.target"))
    assert "kmu-late.target" in hit_units(r)
    # the install data is bound into the hash
    a = res(g, action="enable", text=text("WantedBy=multi-user.target")).closure_sha256()
    b = res(g, action="enable", text=text("WantedBy=multi-user.target\nAlias=forge-z.service")).closure_sha256()
    assert a != b


def test_a_protected_conflict_is_a_hit_whether_or_not_it_is_active_now():
    """Review M4: with ollama inactive the result was 'allowed' (and the hash the same as when it is active); it can be started between the check and the action."""
    for state in ("active", "inactive", "failed"):
        g = graph(U("forge-x.service", Conflicts="ollama.service"), U("ollama.service", ActiveState=state, FragmentPath="/etc/systemd/system/ollama.service"))
        assert "ollama.service" in hit_units(res(g)), state
    # same for the stop-closure of a conflict and for restart propagation
    g = graph(U("forge-x.service", Conflicts="forge-y.service"), U("forge-y.service", RequiredBy="kmu-app.service"), U("kmu-app.service", ActiveState="inactive"))
    assert "kmu-app.service" in hit_units(res(g))
    g = graph(U("forge-x.service", ConsistsOf="kmu-part.service"), U("kmu-part.service", ActiveState="inactive"))
    assert "kmu-part.service" in hit_units(res(g, action="restart"))
    # the start side keeps its relaxation: an ACTIVE protected dependency is left alone
    g = graph(U("forge-x.service", Requires="docker.service"), U("docker.service"))
    assert not R.resolve(g, NOTEXT, "forge-x.service", "start", job_mode="replace", protected_units=("docker.service",), protected_paths=()).denied


def test_mount_units_of_protected_paths_are_hits_by_what_they_mount():
    """Review M5: srv-models.mount comes from a generator: no name pattern, no fragment path under a protected path matched it."""
    mount = U("srv-models.mount", Where="/srv/models", FragmentPath="/run/systemd/generator/srv-models.mount")
    g = graph(U("forge-x.service", Conflicts="srv-models.mount"), mount)
    assert "srv-models.mount" in hit_units(res(g))
    assert "srv-models.mount" in hit_units(res(graph(mount), unit="srv-models.mount", action="stop"))
    # a mount UNDER a protected path, and one that contains it
    for where in ("/srv/models/cache", "/srv", "/"):
        m = U("x.mount", Where=where)
        assert "x.mount" in hit_units(res(graph(m), unit="x.mount", action="stop")), where
    assert not res(graph(U("x.mount", Where="/srv/other")), unit="x.mount", action="stop").denied
    # a mount unit without Where= cannot be judged
    assert res(graph(U("x.mount")), unit="x.mount", action="stop").denied


def test_dependencies_that_stop_when_unneeded_are_part_of_a_stop():
    """Review: user-runtime-dir@.service, user-.slice and several targets set StopWhenUnneeded=yes; stopping the last thing that needs them stops them too."""
    g = graph(U("forge-x.service", Requires="kmu-tmp.target"), U("kmu-tmp.target", StopWhenUnneeded="yes"))
    r = res(g, action="stop")
    assert "kmu-tmp.target" in hit_units(r) and "kmu-tmp.target" in r.S
    g = graph(U("forge-x.service", Requires="kmu-tmp.target"), U("kmu-tmp.target"))
    assert not res(g, action="stop").denied


def test_the_hash_binds_the_text_of_what_the_transaction_changes():
    """Review: the hash bound paths, not content - an edit of the fragment in place did not invalidate a signed hash."""
    g = graph(U("forge-x.service"))
    a = res(g, text=lambda n: "[Service]\nExecStart=/bin/true\n").closure_sha256()
    b = res(g, text=lambda n: "[Service]\nExecStart=/bin/false\n").closure_sha256()
    assert a != b
    assert res(g, text=lambda n: None).denied                                    # text that cannot be read cannot be bound


def test_the_text_provider_reads_systemctl_cat_by_exact_name_only():
    calls = []

    def run(argv, stdin, timeout):
        calls.append(argv)
        return 0, b"# /etc/systemd/system/forge-x.service\n[Service]\n", b""
    p = R.systemctl_text_provider("/usr/bin/systemctl", run)
    assert p("forge-x.service").startswith("# /etc")
    assert calls == [["/usr/bin/systemctl", "cat", "--no-pager", "--", "forge-x.service"]]
    assert p("../x") is None and p("a b.service") is None and len(calls) == 1
    assert R.systemctl_text_provider("/usr/bin/systemctl", lambda *a: (1, b"", b"err"))("forge-x.service") is None


def test_real_mount_unit_output_of_this_systemd():
    import os
    here = os.path.join(os.path.dirname(__file__), "fixtures")
    real = dict(line.partition("=")[::2] for line in open(os.path.join(here, "systemctl_show_srv_models_mount.txt")).read().splitlines() if "=" in line)
    assert real["Where"] == "/srv/models" and real["FragmentPath"].startswith("/run/systemd/generator/") and set(R.ALL_PROPS) <= set(real)
    r = R.resolve(lambda n: real if n == "srv-models.mount" else U(n), NOTEXT, "srv-models.mount", "stop", job_mode="replace", protected_units=(), protected_paths=("/srv/models",))
    assert any("mounts /srv/models" in h.reason for h in r.hits)                  # found through Where=, with no unit-name pattern and no fragment path to help
    p = R.systemctl_provider("/usr/bin/systemctl", lambda argv, *a: (0, f"Id={argv[-1]}\n".encode(), b""))
    seen = []
    R.systemctl_provider("/usr/bin/systemctl", lambda argv, *a: seen.append(argv) or (0, b"Id=x\n", b""))("srv-models.mount")
    assert "Where" in seen[0][seen[0].index("-p") + 1].split(",")
