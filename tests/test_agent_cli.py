"""Agent analysis subcommands: profiles, orgs, catalogs, datastores, scan, plan.

JSON documents validate against schemas/, stdout is pure JSON, names resolve to exactly
one object (else exit 2 with candidates), template filters, offline plans with a
recomputable hash, secrets only from stdin, exit codes 0/2/3/4, and no DELETE anywhere.
"""
import hashlib
import io
import json
import os
import random
import socket
import stat
import sys

import pytest
import requests

from helpers import ORG_A, ORG_B, S, T, Resp, paged
from schema_check import validate

CAT_A = {"name": "Gold", "href": "https://vcd.example/api/catalog/A", "orgName": "OrgA", "org": ORG_A}
CAT_B = {"name": "Gold", "href": "https://vcd.example/api/catalog/B", "orgName": "OrgB", "org": ORG_B}
DS1 = {"name": "ds1", "href": "https://vcd.example/api/admin/extension/datastore/1", "vcName": "vc1",
       "vc": "https://vcd.example/api/admin/extension/vimServer/1"}
DS2 = {"name": "ds1", "href": "https://vcd.example/api/admin/extension/datastore/2", "vcName": "vc2",
       "vc": "https://vcd.example/api/admin/extension/vimServer/2"}
ORGS = {"org": [{"name": "OrgA", "href": ORG_A}, {"name": "OrgB", "href": ORG_B}]}


def tpl(name, n, cat=CAT_A):
    return {"name": name, "href": T + n, "catalogName": cat["name"], "catalog": cat["href"],
            "org": cat["org"], "orgName": cat["orgName"]}


TEMPLATES = [tpl("web", "3"), tpl("web-v2", "4")]


def shadow(name, sid, parent=None, ds=DS1):
    rec = {"name": name, "href": S + sid, "datastoreName": ds["name"], "datastore": ds["href"],
           "vcName": ds["vcName"]}
    if parent:
        rec["primaryVAppTemplate"] = T + parent
    return rec


SHADOWS = [
    shadow("web-a", "e1", "3"),            # exact web
    shadow("web-b", "e2", "3"),            # exact web
    shadow("web-v2-a", "e3", "4"),         # exact web-v2
    shadow("web-v2-old", "w1"),            # name prefix -> web-v2 (longest wins)
    shadow("prod_web", "w2"),              # substring -> web
    shadow("other-1", "o1", "999"),        # other template
    shadow("cobweb-1", "u1"),              # unmatched
]


def routes(shadows=SHADOWS, templates=TEMPLATES, catalogs=(CAT_A,), datastores=(DS1,), **extra):
    r = {
        "POST": lambda call: Resp(200, {"access_token": "x"}),
        "GET /api/org": lambda call: Resp(200, ORGS),
        "adminCatalog": paged(list(catalogs)),
        "datastore": paged(list(datastores)),
        "adminVAppTemplate": paged(list(templates)),
        "adminShadowVM": paged(list(shadows)),
    }
    r.update(extra)
    return r


SRV = ["--server", "vcd.example", "--token-stdin"]
SCAN = ["scan"] + SRV + ["--catalog", "Gold", "--datastore", "ds1"]


def no_deletes(session):
    """The only DELETE an analysis subcommand may send is its own session logout."""
    bad = [c for c in session.calls if c.method == "DELETE" and c.path != "/api/session"]
    assert bad == [], bad
    assert not any(c.method not in ("GET", "POST", "DELETE") for c in session.calls)
    assert all(c.path.startswith(("/oauth/", "/cloudapi/1.0.0/sessions", "/api/sessions"))
               for c in session.calls if c.method == "POST")


def doc_of(out, schema):
    doc = json.loads(out)          # the whole of stdout is one JSON document
    assert doc["schema"] == schema
    validate(doc)
    return doc


def run(run_main, argv, r=None, stdin="tok\n"):
    return run_main(argv, r or routes(), stdin=stdin)


def write_profiles(vsc, profiles):
    os.makedirs(vsc._CONFIG_DIR, exist_ok=True)
    with open(vsc._SERVERS_FILE, "w") as f:
        json.dump(profiles, f)


# ---------------------------------------------------------------- help, dispatch

@pytest.mark.parametrize("argv", [["--help"], ["profiles", "--help"], ["orgs", "--help"],
                                  ["catalogs", "--help"], ["datastores", "--help"],
                                  ["scan", "--help"], ["plan", "--help"]])
def test_help_exits_0(run_main, argv):
    rc, out, err, s = run_main(argv, {})
    assert rc == 0
    prog = "vcd_shadow_cleaner.py" + (f" {argv[0]}" if argv[0] != "--help" else "")
    assert out.startswith(f"usage: {prog} ")
    if argv[0] != "--help":
        assert "Exit codes: 0 success" in out
    assert s.calls == []


def test_top_level_help_lists_subcommands(run_main):
    rc, out, err, s = run_main(["--help"], {})
    assert rc == 0 and "profiles list" in out and "plan  --scan" in out


def test_no_args_still_opens_gui(vsc, run_main, monkeypatch):
    opened = []
    monkeypatch.setattr(vsc, "run_gui", lambda: opened.append(1) or 0)
    rc, out, err, s = run_main([], {})
    assert opened == [1] and rc == 0


# ---------------------------------------------------------------- profiles

def test_profiles_list(vsc, run_main, fake_keyring):
    write_profiles(vsc, [
        {"id": "p1", "name": "lab", "server": "https://vcd.example/", "auth_type": "token", "org": "OrgA"},
        {"id": "p2", "name": "lab2", "server": "vcd2.example", "auth_type": "password", "username": "admin",
         "_credential_b64": "c2VjcmV0LXZhbHVl"},
    ])
    fake_keyring.store[("vcd-shadow-cleaner", "p1")] = "keyring-secret-value"
    rc, out, err, s = run(run_main, ["profiles", "list"])
    assert rc == 0
    doc = doc_of(out, "vcd-shadow-cleaner.profiles/1")
    assert [p["name"] for p in doc["profiles"]] == ["lab", "lab2"]
    assert doc["profiles"][0]["server"] == "vcd.example"
    assert "c2VjcmV0LXZhbHVl" not in out + err and "keyring-secret-value" not in out + err
    assert s.calls == []


# ---------------------------------------------------------------- discovery

def test_orgs_discovery(run_main):
    rc, out, err, s = run(run_main, ["orgs"] + SRV)
    assert rc == 0, err
    doc = doc_of(out, "vcd-shadow-cleaner.discovery/1")
    assert doc["kind"] == "orgs" and doc["complete"] is True and doc["server"] == "vcd.example"
    assert [o["name"] for o in doc["items"]] == ["OrgA", "OrgB"]
    assert doc["items"][0]["id"] == ORG_A
    no_deletes(s)


def test_catalogs_discovery_keeps_stdout_pure(run_main):
    rc, out, err, s = run(run_main, ["catalogs"] + SRV, routes(catalogs=(CAT_A, CAT_B)))
    assert rc == 0, err
    doc = doc_of(out, "vcd-shadow-cleaner.discovery/1")
    assert {(c["name"], c["org"], c["id"]) for c in doc["items"]} == {
        ("Gold", "OrgA", CAT_A["href"]), ("Gold", "OrgB", CAT_B["href"])}
    assert "Found 2 catalogs" in err and "Found" not in out
    no_deletes(s)


def test_catalogs_with_org(run_main):
    rc, out, err, s = run(run_main, ["catalogs"] + SRV + ["--org", "OrgA"],
                          routes(catalogs=(CAT_A, CAT_B)))
    assert rc == 0, err
    doc = doc_of(out, "vcd-shadow-cleaner.discovery/1")
    assert doc["org"] == "OrgA"
    assert [c["org"] for c in doc["items"]] == ["OrgA"]


def test_catalogs_unknown_org_exits_2(run_main):
    rc, out, err, s = run(run_main, ["catalogs"] + SRV + ["--org", "Nope"])
    assert rc == 2
    doc = doc_of(out, "vcd-shadow-cleaner.discovery/1")
    assert doc["complete"] is False
    assert doc["errors"][0]["type"] == "ResolutionError" and doc["errors"][0]["reason"] == "not_found"
    assert not s.of("GET", "adminCatalog")


def test_datastores_discovery_shows_vcenters(run_main):
    rc, out, err, s = run(run_main, ["datastores"] + SRV, routes(datastores=(DS1, DS2)))
    assert rc == 0, err
    doc = doc_of(out, "vcd-shadow-cleaner.discovery/1")
    assert {(d["name"], d["vcenter"], d["id"]) for d in doc["items"]} == {
        ("ds1", "vc1", DS1["href"]), ("ds1", "vc2", DS2["href"])}


def test_discovery_vcd_error_exits_4(run_main, sleeps):
    rc, out, err, s = run(run_main, ["datastores"] + SRV, routes(datastore=lambda call: Resp(503)))
    assert rc == 4
    doc = doc_of(out, "vcd-shadow-cleaner.discovery/1")
    assert doc["complete"] is False and doc["errors"][0]["http_status"] == 503


# ---------------------------------------------------------------- scan

def by_id(doc):
    return {sh["id"]: sh for sh in doc["shadows"]}


def test_scan_unique_names_ok_with_evidence(run_main):
    rc, out, err, s = run(run_main, SCAN)
    assert rc == 0, err
    doc = doc_of(out, "vcd-shadow-cleaner.scan/1")
    assert doc["complete"] is True and doc["errors"] == []
    assert doc["scope"]["catalogs"][0]["id"] == CAT_A["href"]
    assert doc["scope"]["datastores"][0] == {"id": DS1["href"], "name": "ds1", "href": DS1["href"],
                                             "vcenter": "vc1", "vc": DS1["vc"]}
    c = doc["counts"]
    assert (c["exact"], c["name"], c["substring"], c["other_template"], c["unmatched"]) == (3, 1, 1, 1, 1)
    assert c["listed"] == 5 and c["templates"] == 2
    got = by_id(doc)
    e1 = got["e1"]["match"]
    assert e1["strength"] == "exact"
    assert e1["template"]["id"] == T + "3" and e1["template"]["name"] == "web"
    assert e1["evidence"] == {"rule": "parent_ref", "field": "primaryVAppTemplate", "value": T + "3",
                              "template_href": T + "3"}
    assert got["e1"]["record"]["primaryVAppTemplate"] == T + "3"
    assert got["e1"]["datastore"]["id"] == DS1["href"]
    assert got["w1"]["match"]["strength"] == "name"
    assert got["w1"]["match"]["template"]["name"] == "web-v2"
    assert got["w1"]["match"]["evidence"] == {"rule": "name_prefix", "field": "name", "value": "web-v2-old",
                                              "token": "web-v2"}
    assert got["w2"]["match"]["strength"] == "substring"
    assert "o1" not in got and "u1" not in got
    no_deletes(s)


def test_scan_include_unmatched(run_main):
    rc, out, err, s = run(run_main, SCAN + ["--include-unmatched"])
    assert rc == 0
    got = by_id(doc_of(out, "vcd-shadow-cleaner.scan/1"))
    assert got["o1"]["match"]["strength"] == "other_template"
    assert got["o1"]["match"]["template"] is None
    assert got["o1"]["match"]["evidence"]["value"] == T + "999"
    assert got["u1"]["match"] == {"strength": "unmatched", "template": None, "evidence": {"rule": "none"},
                                  "ambiguous_with": []}


def test_scan_ambiguous_catalog_exits_2_with_candidates(run_main):
    rc, out, err, s = run(run_main, SCAN, routes(catalogs=(CAT_A, CAT_B)))
    assert rc == 2
    doc = doc_of(out, "vcd-shadow-cleaner.scan/1")
    assert doc["complete"] is False and doc["shadows"] == []
    e = doc["errors"][0]
    assert (e["type"], e["kind"], e["reason"], e["query"]) == ("ResolutionError", "catalog", "ambiguous", "Gold")
    assert {(c["id"], c["org"]) for c in e["candidates"]} == {(CAT_A["href"], "OrgA"), (CAT_B["href"], "OrgB")}
    assert CAT_A["href"] in err and "--catalog-id" in err
    assert not s.of("GET", "adminShadowVM") and not s.of("GET", "adminVAppTemplate")


def test_scan_catalog_id_resolves_the_ambiguity(run_main):
    argv = ["scan"] + SRV + ["--catalog-id", CAT_B["href"], "--datastore", "ds1"]
    tb = [tpl("web", "3", CAT_B)]
    rc, out, err, s = run(run_main, argv, routes(catalogs=(CAT_A, CAT_B), templates=tb))
    assert rc == 0, err
    doc = doc_of(out, "vcd-shadow-cleaner.scan/1")
    assert [c["org"] for c in doc["scope"]["catalogs"]] == ["OrgB"]
    assert {sh["match"]["template"]["org"] for sh in doc["shadows"]} == {"OrgB"}


def test_scan_org_scopes_catalog_name(run_main):
    rc, out, err, s = run(run_main, SCAN + ["--org", "OrgA"], routes(catalogs=(CAT_A, CAT_B)))
    assert rc == 0, err
    doc = doc_of(out, "vcd-shadow-cleaner.scan/1")
    assert doc["scope"]["org"] == "OrgA" and [c["org"] for c in doc["scope"]["catalogs"]] == ["OrgA"]


def test_scan_ambiguous_datastore_and_datastore_id(run_main):
    shadows = SHADOWS + [shadow("web-c", "x2", "3", ds=DS2)]
    r = routes(shadows=shadows, datastores=(DS1, DS2))
    rc, out, err, s = run(run_main, SCAN, r)
    assert rc == 2
    e = doc_of(out, "vcd-shadow-cleaner.scan/1")["errors"][0]
    assert e["kind"] == "datastore" and {c["vcenter"] for c in e["candidates"]} == {"vc1", "vc2"}

    argv = ["scan"] + SRV + ["--catalog", "Gold", "--datastore-id", DS2["href"]]
    rc, out, err, s = run(run_main, argv, routes(shadows=shadows, datastores=(DS1, DS2)))
    assert rc == 0, err
    doc = doc_of(out, "vcd-shadow-cleaner.scan/1")
    assert [d["vcenter"] for d in doc["scope"]["datastores"]] == ["vc2"]
    assert list(by_id(doc)) == ["x2"]
    assert by_id(doc)["x2"]["datastore"]["id"] == DS2["href"]


def test_scan_id_by_bare_uuid(run_main):
    ds = dict(DS1, href="https://vcd.example/api/admin/extension/datastore/0f0f0f0f-0000-0000-0000-000000000001")
    shadows = [dict(shadow("web-a", "e1", "3"), datastore=ds["href"])]
    argv = ["scan"] + SRV + ["--catalog", "Gold", "--datastore-id", "0f0f0f0f-0000-0000-0000-000000000001"]
    rc, out, err, s = run(run_main, argv, routes(shadows=shadows, datastores=(ds,)))
    assert rc == 0, err
    assert list(by_id(doc_of(out, "vcd-shadow-cleaner.scan/1"))) == ["e1"]


def test_scan_unknown_names_exit_2(run_main):
    argv = ["scan"] + SRV + ["--catalog", "Nope", "--datastore", "dsX", "--catalog-id", "urn:x"]
    rc, out, err, s = run(run_main, argv)
    assert rc == 2
    errs = doc_of(out, "vcd-shadow-cleaner.scan/1")["errors"]
    assert {(e["kind"], e["by"], e["reason"]) for e in errs} == {
        ("catalog", "name", "not_found"), ("catalog", "id", "not_found"), ("datastore", "name", "not_found")}
    assert all(e["candidates"] == [] for e in errs)


def test_scan_case_insensitive_name_only_when_unique(run_main):
    rc, out, err, s = run(run_main, ["scan"] + SRV + ["--catalog", "gold", "--datastore", "DS1"])
    assert rc == 0, err


@pytest.mark.parametrize("flags, expected", [
    (["--template", "web"], {"e1", "e2", "w2"}),                 # web-v2-old stays with web-v2
    (["--template", "web-*"], {"e3", "w1"}),
    (["--template", "web*", "--exclude-template", "web-v2"], {"e1", "e2", "w2"}),
    (["--exclude-template", "web"], {"e3", "w1"}),
    (["--template", "w?b"], {"e1", "e2", "w2"}),
])
def test_scan_template_filters(run_main, flags, expected):
    rc, out, err, s = run(run_main, SCAN + flags)
    assert rc == 0, err
    doc = doc_of(out, "vcd-shadow-cleaner.scan/1")
    assert set(by_id(doc)) == expected
    assert doc["counts"]["filtered_out"] == 5 - len(expected)
    assert doc["scope"]["template_filter"]["include"] == [f for i, f in enumerate(flags)
                                                          if i and flags[i - 1] == "--template"]


def test_scan_template_typo_warns(run_main):
    rc, out, err, s = run(run_main, SCAN + ["--exclude-template", "wbe"])
    doc = doc_of(out, "vcd-shadow-cleaner.scan/1")
    assert any("--exclude-template 'wbe' matches no template" in w for w in doc["warnings"])


def test_scan_incomplete_exits_4(run_main, sleeps):
    many = [shadow(f"web-{i}", f"m{i}", "3") for i in range(60)]
    r = routes(shadows=many, adminShadowVM=paged(many, cap=25, fail_pages=(2,)))
    rc, out, err, s = run(run_main, SCAN, r)
    assert rc == 4
    doc = doc_of(out, "vcd-shadow-cleaner.scan/1")
    assert doc["complete"] is False and doc["errors"][0]["http_status"] == 503
    no_deletes(s)


def test_scan_out_file(run_main, tmp_path):
    path = tmp_path / "scan.json"
    rc, out, err, s = run(run_main, SCAN + ["--out", str(path)])
    assert rc == 0, err
    assert out == ""
    doc = json.loads(path.read_text())
    validate(doc)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


# ---------------------------------------------------------------- auth and secrets

def test_auth_failure_exits_3(run_main):
    rc, out, err, s = run(run_main, SCAN, routes(POST=lambda call: Resp(401, {"message": "bad token"})))
    assert rc == 3
    doc = doc_of(out, "vcd-shadow-cleaner.scan/1")
    assert doc["complete"] is False and doc["errors"][0]["type"] == "VCDAuthError"
    assert not s.of("GET", "adminShadowVM")


def test_token_stdin_keeps_secret_out_of_argv_and_output(run_main):
    secret = "tok-SECRET-1234567890"
    rc, out, err, s = run(run_main, ["orgs"] + SRV, stdin=secret + "\n")
    assert rc == 0, err
    post = s.of("POST")[0]
    assert post.data["refresh_token"] == secret
    assert secret not in " ".join(sys.argv)
    assert secret not in out + err


def test_password_stdin_keeps_secret_out_of_argv_and_output(run_main):
    import base64
    secret = "pw-SECRET-0987654321"
    r = routes(**{"POST /cloudapi/1.0.0/sessions/provider":
                  lambda call: Resp(200, {}, headers={"X-VMWARE-VCLOUD-ACCESS-TOKEN": "x"})})
    argv = ["orgs", "--server", "vcd.example", "--username", "admin", "--password-stdin"]
    rc, out, err, s = run(run_main, argv, r, stdin=secret + "\n")
    assert rc == 0, err
    basic = s.of("POST")[0].headers["Authorization"].split(" ", 1)[1]
    assert base64.b64decode(basic).decode() == f"admin@system:{secret}"
    assert secret not in " ".join(sys.argv) and secret not in out + err


def test_wrong_password_exits_3_without_echo(run_main):
    secret = "pw-WRONG-555"
    argv = ["scan", "--server", "vcd.example", "--username", "admin", "--password-stdin",
            "--catalog", "Gold", "--datastore", "ds1"]
    rc, out, err, s = run(run_main, argv, routes(POST=lambda call: Resp(401, {"message": "no"})),
                          stdin=secret + "\n")
    assert rc == 3 and secret not in out + err


@pytest.mark.parametrize("argv", [
    ["orgs", "--server", "vcd.example", "--token", "argv-SECRET-1"],
    ["orgs", "--server", "vcd.example", "--username", "u", "--password", "argv-SECRET-1"],
    ["orgs", "--server", "vcd.example", "--tok", "argv-SECRET-1"],
])
def test_secret_on_argv_is_refused_without_echo(run_main, argv):
    rc, out, err, s = run(run_main, argv)
    assert rc == 2
    assert "argv-SECRET-1" not in out + err
    assert "never read from argv" in err or "not shown, in case one is a secret" in err
    assert s.calls == []


def test_empty_stdin_secret_exits_2(run_main):
    rc, out, err, s = run(run_main, ["orgs"] + SRV, stdin="")
    assert rc == 2
    assert doc_of(out, "vcd-shadow-cleaner.discovery/1")["errors"][0]["type"] == "UsageError"
    assert s.calls == []


@pytest.mark.parametrize("argv", [
    ["orgs"],                                                   # no connection
    ["orgs", "--profile", "lab", "--server", "vcd.example"],    # both
    ["orgs", "--server", "vcd.example"],                        # no secret source
    ["orgs", "--server", "vcd.example", "--password-stdin"],    # no username
    ["orgs", "--profile", "lab", "--token-stdin"],
    ["scan", "--server", "vcd.example", "--token-stdin", "--catalog", "Gold"],   # no datastore
    ["plan", "--scan", "x.json", "--limit", "0"],
])
def test_usage_errors_exit_2(run_main, argv):
    rc, out, err, s = run(run_main, argv)
    assert rc == 2 and out == "" and s.calls == []
    assert f"vcd_shadow_cleaner.py {argv[0]}: error:" in err


def test_profile_token_from_keyring(vsc, run_main, fake_keyring):
    write_profiles(vsc, [{"id": "p1", "name": "lab", "server": "vcd.example", "auth_type": "token",
                          "skip_ssl_verify": True}])
    fake_keyring.store[("vcd-shadow-cleaner", "p1")] = "kr-SECRET-42"
    rc, out, err, s = run_main(["orgs", "--profile", "lab"], routes())
    assert rc == 0, err
    assert s.of("POST")[0].data["refresh_token"] == "kr-SECRET-42"
    assert "kr-SECRET-42" not in out + err
    assert doc_of(out, "vcd-shadow-cleaner.discovery/1")["server"] == "vcd.example"


def test_profile_ambiguous_and_unknown_exit_2(vsc, run_main):
    write_profiles(vsc, [{"id": "p1", "name": "lab", "server": "vcd.example", "auth_type": "token"},
                         {"id": "p2", "name": "LAB", "server": "vcd2.example", "auth_type": "token"}])
    rc, out, err, s = run_main(["orgs", "--profile", "lab"], routes())
    assert rc == 2
    e = doc_of(out, "vcd-shadow-cleaner.discovery/1")["errors"][0]
    assert e["reason"] == "ambiguous" and {c["id"] for c in e["candidates"]} == {"p1", "p2"}
    assert s.calls == []
    rc, out, err, s = run_main(["orgs", "--profile", "p2"], routes())
    assert rc == 3  # resolved by id; no stored credential
    rc, out, err, s = run_main(["orgs", "--profile", "nope"], routes())
    assert rc == 2


def test_profile_without_credential_exits_3(vsc, run_main):
    write_profiles(vsc, [{"id": "p1", "name": "lab", "server": "vcd.example", "auth_type": "token"}])
    rc, out, err, s = run_main(["scan", "--profile", "lab", "--catalog", "Gold", "--datastore", "ds1"],
                               routes())
    assert rc == 3 and s.calls == []
    assert doc_of(out, "vcd-shadow-cleaner.scan/1")["errors"][0]["type"] == "VCDAuthError"


def test_subcommands_ignore_vcd_env_and_dotenv(run_main, monkeypatch, tmp_path):
    (tmp_path / ".env").write_text("VCD_TOKEN=env-SECRET\nVCD_SERVER=vcd.example\n")
    monkeypatch.setenv("VCD_TOKEN", "env-SECRET")
    rc, out, err, s = run(run_main, ["orgs", "--server", "vcd.example"])
    assert rc == 2 and s.calls == []
    assert "with --server give --token-stdin" in err


# ---------------------------------------------------------------- plan

def make_scan(run_main, tmp_path, extra=(), name="scan.json", r=None):
    path = tmp_path / name
    rc, out, err, s = run(run_main, SCAN + list(extra) + ["--out", str(path)], r)
    assert rc in (0, 4), err
    return path


def plan(run_main, argv):
    rc, out, err, s = run_main(["plan"] + argv, {})
    return rc, (doc_of(out, "vcd-shadow-cleaner.plan/1") if out else None), err, s


def recompute(server, items):
    canon = {"server": server.lower(),
             "items": sorted(({k: i[k] for k in ("shadow_id", "datastore_id", "template_id", "match_strength")}
                              for i in items), key=lambda i: i["shadow_id"])}
    return hashlib.sha256(json.dumps(canon, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_plan_default_excludes_weak_with_reasons(run_main, tmp_path):
    path = make_scan(run_main, tmp_path, ["--include-unmatched"])
    rc, doc, err, s = plan(run_main, ["--scan", str(path)])
    assert rc == 0, err
    assert [i["shadow_id"] for i in doc["items"]] == ["e1", "e2", "e3"]
    assert all(i["match_strength"] == "exact" for i in doc["items"])
    reasons = {x["shadow_id"]: x["reasons"] for x in doc["excluded"]}
    assert reasons == {"w1": ["weak_match"], "w2": ["weak_match"], "o1": ["other_template"],
                       "u1": ["unmatched"]}
    assert doc["counts"]["by_reason"] == {"weak_match": 2, "other_template": 1, "unmatched": 1}
    assert doc["source_scan_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert doc["plan_sha256"] == recompute("vcd.example", doc["items"])
    assert doc["items"][0] == {"shadow_id": "e1", "datastore_id": DS1["href"], "template_id": T + "3",
                               "match_strength": "exact", "shadow_name": "web-a", "shadow_href": S + "e1",
                               "template_name": "web", "datastore_name": "ds1", "ambiguous": False}
    assert s.calls == []


def test_plan_include_weak(run_main, tmp_path):
    path = make_scan(run_main, tmp_path)
    rc, doc, err, s = plan(run_main, ["--scan", str(path), "--include-weak"])
    assert rc == 0
    assert [i["shadow_id"] for i in doc["items"]] == ["e1", "e2", "e3", "w1", "w2"]
    assert doc["counts"]["weak"] == 2 and doc["excluded"] == []


def test_plan_hash_stable_across_input_order(run_main, tmp_path):
    path = make_scan(run_main, tmp_path)
    scan_doc = json.loads(path.read_text())
    shuffled = dict(scan_doc, shadows=list(reversed(scan_doc["shadows"])))
    random.Random(7).shuffle(shuffled["shadows"])
    p2 = tmp_path / "scan2.json"
    p2.write_text(json.dumps(shuffled, indent=4))
    rc1, d1, _, _ = plan(run_main, ["--scan", str(path), "--include-weak", "--limit", "4"])
    rc2, d2, _, _ = plan(run_main, ["--scan", str(p2), "--include-weak", "--limit", "4"])
    assert rc1 == rc2 == 0
    assert d1["plan_sha256"] == d2["plan_sha256"]
    assert d1["items"] == d2["items"] and d1["excluded"] == d2["excluded"]
    assert d1["source_scan_sha256"] != d2["source_scan_sha256"]


def test_plan_hash_ignores_names_but_not_ids(run_main, tmp_path):
    path = make_scan(run_main, tmp_path)
    scan_doc = json.loads(path.read_text())
    renamed = json.loads(json.dumps(scan_doc))
    for sh in renamed["shadows"]:
        sh["name"] = "renamed-" + sh["name"]
        sh["match"]["template"]["name"] = "renamed"
    (tmp_path / "r.json").write_text(json.dumps(renamed))
    other_ds = json.loads(json.dumps(scan_doc))
    other_ds["shadows"][0]["datastore"]["id"] = DS2["href"]
    (tmp_path / "d.json").write_text(json.dumps(other_ds))
    base = plan(run_main, ["--scan", str(path)])[1]["plan_sha256"]
    assert plan(run_main, ["--scan", str(tmp_path / "r.json")])[1]["plan_sha256"] == base
    assert plan(run_main, ["--scan", str(tmp_path / "d.json")])[1]["plan_sha256"] != base


def test_plan_limit_takes_exact_first(run_main, tmp_path):
    path = make_scan(run_main, tmp_path)
    rc, doc, err, s = plan(run_main, ["--scan", str(path), "--include-weak", "--limit", "2"])
    assert rc == 0
    assert [i["shadow_id"] for i in doc["items"]] == ["e1", "e2"]
    assert {x["shadow_id"]: x["reasons"] for x in doc["excluded"]} == {
        "e3": ["limit"], "w1": ["limit"], "w2": ["limit"]}
    assert doc["filters"]["limit"] == 2


def test_plan_template_filters(run_main, tmp_path):
    path = make_scan(run_main, tmp_path)
    rc, doc, err, s = plan(run_main, ["--scan", str(path), "--template", "web-*"])
    assert [i["shadow_id"] for i in doc["items"]] == ["e3"]
    reasons = {x["shadow_id"]: x["reasons"] for x in doc["excluded"]}
    assert reasons["e1"] == ["template_not_included"]
    assert reasons["w1"] == ["weak_match"]
    assert reasons["w2"] == ["weak_match", "template_not_included"]
    rc, doc, err, s = plan(run_main, ["--scan", str(path), "--exclude", "web-v2"])
    assert [i["shadow_id"] for i in doc["items"]] == ["e1", "e2"]


def test_plan_from_incomplete_scan_exits_4(run_main, tmp_path, sleeps):
    ds2 = {"name": "ds2", "href": "https://vcd.example/api/admin/extension/datastore/22", "vcName": "vc1"}
    ok = paged(SHADOWS)

    def shadows(call):  # ds1 answers, ds2 fails: a partial, incomplete scan
        return Resp(503, {"message": "unavailable"}) if "ds2" in call.query.get("filter", "") else ok(call)

    r = routes(datastores=(DS1, ds2), adminShadowVM=shadows)
    path = make_scan(run_main, tmp_path, ["--datastore", "ds2"], r=r)
    assert json.loads(path.read_text())["shadows"]
    rc, doc, err, s = plan(run_main, ["--scan", str(path)])
    assert rc == 4
    assert doc["complete"] is False and doc["items"] == [] and doc["plan_sha256"] is None
    assert doc["excluded"] and all("source_scan_incomplete" in x["reasons"] for x in doc["excluded"])
    assert doc["errors"][0]["type"] == "IncompleteScan"


@pytest.mark.parametrize("content", ["not json", json.dumps({"schema": "something/1"}),
                                     json.dumps({"schema": "vcd-shadow-cleaner.scan/1"})])
def test_plan_rejects_bad_scan_files(run_main, tmp_path, content):
    p = tmp_path / "bad.json"
    p.write_text(content)
    rc, doc, err, s = plan(run_main, ["--scan", str(p)])
    assert rc == 2 and doc["complete"] is False and doc["plan_sha256"] is None


def test_plan_missing_file_exits_2(run_main, tmp_path):
    rc, doc, err, s = plan(run_main, ["--scan", str(tmp_path / "nope.json")])
    assert rc == 2
    assert doc["errors"][0]["type"] == "UsageError" and "cannot read --scan file" in doc["errors"][0]["message"]


def test_plan_makes_no_http_calls(vsc, run_main, tmp_path, monkeypatch):
    path = make_scan(run_main, tmp_path)

    def boom(*a, **k):
        raise AssertionError("plan opened a connection")

    rc, out, err, s = run_main(["plan", "--scan", str(path), "--include-weak"], {})
    assert rc == 0 and s.calls == []
    monkeypatch.setattr(requests.sessions.Session, "request", boom)
    monkeypatch.setattr(requests, "Session", boom)
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(sys, "argv", ["vcd_shadow_cleaner.py", "plan", "--scan", str(path), "--out",
                                      str(tmp_path / "plan.json")])
    assert vsc.main() == 0
    validate(json.loads((tmp_path / "plan.json").read_text()))
    assert s.calls == []


# ---------------------------------------------------------------- no DELETE anywhere

def test_no_subcommand_sends_a_delete(vsc, run_main, tmp_path, sleeps):
    write_profiles(vsc, [{"id": "p1", "name": "lab", "server": "vcd.example", "auth_type": "token"}])
    vsc.keyring.store[("vcd-shadow-cleaner", "p1")] = "t"
    scan_path = tmp_path / "s.json"
    every = [
        ["profiles", "list"],
        ["orgs"] + SRV, ["orgs", "--profile", "lab"],
        ["catalogs"] + SRV, ["catalogs"] + SRV + ["--org", "OrgA"],
        ["datastores"] + SRV,
        SCAN, SCAN + ["--include-unmatched", "--template", "web"],
        ["scan", "--profile", "lab", "--catalog", "Gold", "--datastore", "ds1", "--out", str(scan_path)],
        ["plan", "--scan", str(scan_path), "--include-weak"],
        SCAN + ["--catalog", "Nope"],
    ]
    seen = set()
    for argv in every:
        rc, out, err, s = run(run_main, argv)
        seen.add(rc)
        no_deletes(s)
        assert not any(S in c.prepared for c in s.calls if c.method != "GET"), argv
    assert seen == {0, 2}


def test_read_only_client_refuses_deletes(vsc):
    from helpers import FakeSession
    c = vsc.ReadOnlyVCDClient("vcd.example")
    c.session = FakeSession({"DELETE": lambda call: Resp(204)})
    c.access_token = "t"
    sh = vsc.ShadowVM("x", S + "1", "", "", "ds1", "1", "")
    with pytest.raises(RuntimeError):
        c.delete_shadow_vm(sh)
    with pytest.raises(RuntimeError):
        c._request("DELETE", S + "1", stage="delete", target="x")
    with pytest.raises(RuntimeError):
        c._request("POST", S + "1", stage="other", target="x")
    with pytest.raises(RuntimeError):
        vsc.delete_shadow_vms(c, [sh])
    assert c.session.calls == []


# ---------------------------------------------------------------- legacy --cli template filter

LEGACY = ["--cli", "--server", "vcd.example", "--token", "tok", "--catalog", "Gold", "--datastore", "ds1"]


def test_legacy_cli_template_filter_dry_run(run_main):
    rc, out, err, s = run_main(LEGACY + ["--template", "web", "--dry-run", "--json"], routes())
    assert rc == 0, err
    doc = json.loads(out)
    assert {d["id"] for d in doc["shadow_vms"]} == {"e1", "e2", "w2"}
    assert doc["delete_candidates"] == 2
    assert doc["counts"]["exact"] == 2 and doc["counts"]["weak"] == 1
    assert doc["template_filter"] == {"include": ["web"], "exclude": [], "filtered_out": 2}


def test_legacy_cli_glob_and_exclude(run_main):
    rc, out, err, s = run_main(LEGACY + ["--template", "web*", "--exclude-template", "web", "--dry-run",
                                         "--json"], routes())
    assert {d["id"] for d in json.loads(out)["shadow_vms"]} == {"e3", "w1"}


def test_legacy_cli_without_filter_is_unchanged(run_main):
    rc, out, err, s = run_main(LEGACY + ["--dry-run", "--json"], routes())
    doc = json.loads(out)
    assert "template_filter" not in doc and doc["delete_candidates"] == 3


def test_legacy_cli_deletes_only_the_selected_template(vsc, run_main, monkeypatch):
    """Two template versions in one catalog and datastore: delete only web-v2's shadows."""
    import io as _io
    w = _io.StringIO()
    w.close = lambda: None
    monkeypatch.setattr(vsc, "_open_tty", lambda: (_io.StringIO("yes\n"), w), raising=False)
    r = routes(DELETE=lambda call: Resp(204))
    rc, out, err, s = run_main(LEGACY + ["--template", "web-v2"], r)
    assert rc == 0, err
    deleted = [c.path.rsplit("/", 1)[-1] for c in s.calls if c.method == "DELETE" and c.path != "/api/session"]
    assert deleted == ["e3"]
