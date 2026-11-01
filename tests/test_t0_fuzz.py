"""Property / fuzz level (class kritisch): the parsers and verifiers that read data from the host, from privd or from a policy file must never raise anything but their documented error on arbitrary input."""
import inspect
import json
import os
import tempfile

from hypothesis import HealthCheck, given, settings, strategies as st

from forge_node import canon
from forge_node.t0 import parse, policy as P, probes, sanitize, wire
from forge_node.t0.spool import Spool

from n2_helpers import FakeRunner, NOW, make_env, policy_doc, view

text = st.text(max_size=600)
lines = st.lists(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=120), max_size=30).map("\n".join)
PARSERS = [(n, f) for n, f in inspect.getmembers(parse, inspect.isfunction) if f.__module__ == parse.__name__ and list(inspect.signature(f).parameters)[:1] == ["text"]
           and len(inspect.signature(f).parameters) == 1]


def test_there_are_parsers_to_fuzz():
    assert len(PARSERS) >= 25


structured = st.text(alphabet="0123456789.:-_ \t\n\"'[]{}(),=#$*/\\ABCDEFabcdef", max_size=120)           # token-ish soup finds the parsers' int()/split() assumptions


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.one_of(text, lines, structured))
def test_property_no_parser_raises_on_arbitrary_text(s):
    for name, fn in PARSERS:
        try:
            fn(s)
        except Exception as e:  # noqa: BLE001
            raise AssertionError(f"parse.{name} raised {type(e).__name__}: {e}") from e


@settings(max_examples=60, deadline=None)
@given(st.text(max_size=400), st.sampled_from([("docker", "sudo", "adm"), ("x",)]))
def test_property_group_parser_and_cgroup_helpers(s, names):
    parse.etc_group(s, names)
    parse.cgroup_v2_path(s)


@settings(max_examples=300, deadline=None)
@given(st.one_of(st.text(max_size=500), st.text(alphabet="\t[]\"'= \\#;abcdefgilmnopsrtuyz.\n\r\x0b\x0c\x85\u2028\ufeff", max_size=200)))
def test_property_snapshot_config_is_always_the_fixed_inert_shape(s):
    """Whatever the repository config contains, what git will read is generated: only `[core]`, only the inert keys, only simple values, each on its own line."""
    cfg, dropped = probes.filter_git_config(s)
    lines = cfg.split("\n")
    assert lines[0] == "[core]" and lines[1] == "\trepositoryformatversion = 0" and lines[-1] == ""
    for l in lines[2:-1]:
        k, _, v = l.strip().partition(" = ")
        assert k in probes._INERT_CORE and probes._INERT_VALUE.match(v), l
    low = cfg.lower()
    for bad in ("fsmonitor", "hookspath", "filter", "textconv", "include", "sshcommand", "pager", "editor", "alias", "credential", "extensions", "attributesfile", "askpass", "diff", "worktree"):
        assert bad not in low, (bad, s)
    assert len(dropped) <= 20


@settings(max_examples=100, deadline=None)
@given(st.text(max_size=300))
def test_property_inspect_line_parser(s):
    assert probes.parse_inspect_line(s) is None or isinstance(probes.parse_inspect_line(s), dict)


@settings(max_examples=100, deadline=None)
@given(st.binary(max_size=2000))
def test_property_handle_request_never_raises_on_arbitrary_bytes(b):
    with tempfile.TemporaryDirectory() as td:
        env = make_env(__import__("pathlib").Path(td), FakeRunner({}))
        out = wire.handle_request(b, env)
        r = json.loads(out)
        assert out.endswith(b"\n") and isinstance(r["ok"], bool)


json_scalar = st.none() | st.booleans() | st.integers(-5, 10**7) | st.text(max_size=40)
json_tree = st.recursive(json_scalar, lambda c: st.lists(c, max_size=5) | st.dictionaries(st.text(max_size=12), c, max_size=6), max_leaves=30)


@settings(max_examples=200, deadline=None)
@given(st.dictionaries(st.sampled_from(["schema", "serial", "not_before", "node", "profile", "global_mode", "tiers_enabled", "hub_tls_pins", "hub_gate_keys", "protected", "t0", "windows", "t1", "t2", "t3"]), json_tree, max_size=15))
def test_property_policy_parser_only_ever_raises_policy_error(doc):
    base = policy_doc()
    merged = {**base, **doc}
    try:
        P.parse_policy(json.dumps(merged).encode(), "g2", merged.get("serial") if isinstance(merged.get("serial"), int) else 1, NOW)
    except P.PolicyError as e:
        assert e.code in ("DENY_POLICY_INVALID",)


@settings(max_examples=100, deadline=None)
@given(st.binary(max_size=3000))
def test_property_policy_parser_on_arbitrary_bytes(b):
    try:
        P.parse_policy(b, "g2", 1, NOW)
    except P.PolicyError:
        pass


@settings(max_examples=60, deadline=None)
@given(st.lists(st.binary(max_size=200), max_size=20))
def test_property_spool_reader_survives_arbitrary_segment_content(chunks):
    with tempfile.TemporaryDirectory() as td:
        d = os.path.join(td, "s")
        os.mkdir(d)
        with open(os.path.join(d, "seg-000000000001.jsonl"), "wb") as f:
            f.write(b"\n".join(chunks))
        s = Spool(d, os.getuid(), 1 << 16)
        r = s.read_after(0, 50, 10**6)
        assert all(isinstance(x["seq"], int) for x in r["samples"])
        n = s.append({"ts": "2026-10-31T00:00:00Z"})
        assert n >= 1 and s.read_after(n - 1, 5)["samples"][-1]["seq"] == n


@settings(max_examples=100, deadline=None)
@given(json_tree, st.sampled_from(["internal", "customer"]), st.booleans())
def test_property_finalize_always_yields_a_bounded_untrusted_envelope(body, sens, full):
    t = sanitize.finalize("g2", "inv.host", "2026-10-31T13:40:10Z", sens, {"x": body}, full_redaction=full)
    e = json.loads(t)
    assert e["untrusted"] is True and e["sensitivity"] == sens and len(t.encode()) <= sanitize.MAX_ENVELOPE_BYTES
    canon.canonical(e)


@settings(max_examples=250, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(json_tree)
def test_property_json_consuming_parsers_survive_any_json_shape(doc):
    s = json.dumps(doc)
    for fn in (parse.lsblk, parse.findmnt, parse.list_units_json, parse.ip_routes):
        fn(s)
    wrapped = json.dumps({"blockdevices": doc, "filesystems": doc})
    parse.lsblk(wrapped)
    parse.findmnt(wrapped)


def test_inputs_the_fuzzer_found_are_pinned_as_regressions():
    """Each of these once raised: float('INFINITY') in milli(), a bare 'cpu ' line, a superscript digit that str.isdigit() accepts but int() rejects, 'MODEL NAME' without a colon,
    csv with a stray CR, JSON of the wrong shape."""
    assert parse.uptime("INFINITY") is None and parse.milli("nan") is None and parse.milli("1e999") is None and parse.milli("1e30") == 2**53 - 1
    assert parse.cpu_times("cpu \n") is None and parse.cpu_times("cpu a b c d\n") is None
    assert parse.kv_file("0 \u00b2\n1 \u00b9\nok 7\n") == {"ok": 7}
    assert parse.cpuinfo("MODEL NAME\nprocessor\n") == {"threads": 1, "model": None}
    assert parse.nvidia_apps("a\r,b\n") == []
    assert parse.diskstats("1 2 sda x y z w q r s t u v\n") == {} and parse.net_dev("h\nh\n e: a b c d e f g h i\n") == {}
    assert parse.ip_routes("0") == {"routes": [], "default_gateways": []} and parse.lsblk('{"blockdevices": [null, 1, {"children": 5}]}')[0]["name"] is None


@settings(max_examples=2000, deadline=None)
@given(st.one_of(st.text(max_size=120), st.text(alphabet="/.abc-_@{}~^:?*[\\ \x00\n", max_size=40)))
def test_property_an_accepted_ref_name_can_never_select_a_path_outside_its_base(name):
    """Whatever string a repository owner puts in HEAD: if valid_branch() accepts it, joining it below a base stays inside that base, and the confined writer creates exactly one file
    below the base; if it refuses it, nothing is written."""
    import posixpath
    base = "/snap/refs/heads"
    if probes.valid_branch(name):
        joined = posixpath.normpath(posixpath.join(base, name))
        assert joined.startswith(base + "/") and ".." not in name.split("/") and not name.startswith("/")
        assert all(c and c not in (".", "..") for c in name.split("/"))
    with tempfile.TemporaryDirectory() as td:
        from forge_node.t0 import confined
        os.mkdir(os.path.join(td, "inside"))
        fd = confined.open_dir(os.path.join(td, "inside"))
        try:
            try:
                confined.write_new_at(fd, ["refs", "heads", *name.split("/")], b"x")
            except (confined.ConfinementError, OSError):
                pass
        finally:
            os.close(fd)
        created = [os.path.join(d, f) for d, _, fs in os.walk(td) for f in fs]
        assert all(c.startswith(os.path.join(td, "inside") + "/") for c in created)
