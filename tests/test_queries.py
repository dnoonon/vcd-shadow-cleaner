"""Queries: encoding (I6), typed errors (I4), timeouts/retry (I8), paging (I14),
auth (I4, I15), host normalization (I16), and org/datastore scoping (I3)."""
import base64

import pytest
import requests

from helpers import ORG_A, ORG_B, S, T, FakeSession, Resp, by_name, make_client, paged, shadows_of


# ---- I6: encoding ----

def test_names_with_ampersand_and_hash_reach_the_server_intact(vsc):
    c = make_client(vsc, {"adminVAppTemplate": paged([]), "adminShadowVM": paged([])})
    c.get_vapp_templates_in_catalog("R&D Templates")
    c.get_shadow_vms_on_datastore("ds#2")
    tpl_call, ds_call = c.session.calls
    assert tpl_call.query["filter"] == "catalogName==R&D Templates"
    assert tpl_call.query["type"] == "adminVAppTemplate"
    assert ds_call.query["filter"] == "datastoreName==ds#2"
    assert ds_call.fragment == ""
    assert ds_call.query["page"] == "1" and "pageSize" in ds_call.query
    assert "%20" in tpl_call.raw_query  # spaces encoded as %20


@pytest.mark.parametrize("name", ["*", "ds1;isDeleted==true", "a,b", "x(1)"])
def test_filter_syntax_characters_never_reach_the_filter(vsc, name):
    recs = [{"name": "a", "href": S + "a", "datastoreName": "ds1"},
            {"name": "b", "href": S + "b", "datastoreName": name}]
    c = make_client(vsc, {"adminShadowVM": paged(recs)})
    got = c.get_shadow_vms_on_datastore(name)
    assert [s.name for s in got] == ["b"]
    for call in c.session.calls:
        assert name not in call.query.get("filter", "")


def test_tenant_token_url_and_body_are_encoded(vsc):
    c = make_client(vsc, {"POST": lambda call: Resp(200, {"access_token": "x"})})
    c.authenticate_with_token("tok&en=1", "R&D/x")
    call = c.session.calls[0]
    assert call.path == "/oauth/tenant/R%26D%2Fx/token"
    assert call.data == {"grant_type": "refresh_token", "refresh_token": "tok&en=1"}


# ---- I8: timeouts and retry ----

def test_every_request_has_a_timeout(vsc, sleeps):
    c = make_client(vsc, {
        "POST": lambda call: Resp(200, {"access_token": "x"}),
        "adminVAppTemplate": paged([{"name": "t", "href": T + "1", "catalogName": "Gold"}]),
        "adminShadowVM": paged([{"name": "t-1", "href": S + "1", "datastoreName": "ds1"}]),
        "DELETE": lambda call: Resp(204),
    })
    c.authenticate_with_token("tok")
    res = vsc.scan_shadow_vms(c, ["Gold"], ["ds1"], debug=False)
    c.delete_shadow_vm(shadows_of(res)[0])
    assert len(c.session.calls) >= 4
    assert all(call.timeout == (10, 60) for call in c.session.calls)


def test_get_retried_on_503_then_succeeds(vsc, sleeps):
    c = make_client(vsc, {"datastore": [Resp(503), Resp(502), paged([{"name": "ds1", "href": "h"}])]})
    got = c.get_datastores()
    assert [d["name"] for d in got] == ["ds1"]
    assert len(c.session.calls) == 3
    assert len(sleeps) == 2


def test_post_and_delete_are_not_retried(vsc, sleeps):
    c = make_client(vsc, {"POST": lambda call: Resp(503), "DELETE": lambda call: Resp(503)})
    with pytest.raises(vsc.VCDQueryError):
        c.authenticate_with_token("tok")
    shadow = vsc.ShadowVM("s", S + "1", "", "", "ds1", "1", "")
    r = c.delete_shadow_vm(shadow)
    assert r.status == "failed" and r.http_status == 503
    assert [call.method for call in c.session.calls] == ["POST", "DELETE"]


# ---- I14: paging ----

ALL60 = [{"name": f"s{i:02d}", "href": S + str(i), "datastoreName": "ds1"} for i in range(60)]


def test_paging_continues_past_short_pages(vsc):
    c = make_client(vsc, {"adminShadowVM": paged(ALL60, cap=25)})
    got = c.get_shadow_vms_on_datastore("ds1")
    assert len(got) == 60
    assert [call.query["page"] for call in c.session.calls] == ["1", "2", "3"]
    assert all(call.query.get("sortAsc") == "name" for call in c.session.calls)


def test_failure_mid_paging_raises(vsc, sleeps):
    c = make_client(vsc, {"adminShadowVM": paged(ALL60, cap=25, fail_pages=(2,))})
    with pytest.raises(vsc.VCDQueryError) as ei:
        c.get_shadow_vms_on_datastore("ds1")
    assert ei.value.status == 503
    assert ei.value.stage == "shadow VMs"


def test_empty_page_before_total_raises(vsc):
    c = make_client(vsc, {"adminShadowVM": paged(ALL60[:10], total=60)})
    with pytest.raises(vsc.VCDQueryError, match="paging stopped"):
        c.get_shadow_vms_on_datastore("ds1")


# ---- I4: typed errors instead of empty lists ----

@pytest.mark.parametrize("call_name,route,status", [
    ("get_organizations", "GET /api/org", 500),
    ("get_datastores", "datastore", 401),
    ("get_templates", "adminVAppTemplate", 401),
    ("get_shadows", "adminShadowVM", 403),
])
def test_query_errors_raise_typed_exceptions(vsc, sleeps, call_name, route, status):
    c = make_client(vsc, {route: lambda call: Resp(status, {"message": "nope"})})
    fn = {
        "get_organizations": lambda: c.get_organizations(),
        "get_datastores": lambda: c.get_datastores(),
        "get_templates": lambda: c.get_vapp_templates_in_catalog("Gold"),
        "get_shadows": lambda: c.get_shadow_vms_on_datastore("ds1"),
    }[call_name]
    with pytest.raises(vsc.VCDQueryError) as ei:
        fn()
    assert ei.value.status == status
    assert ei.value.to_dict()["http_status"] == status


def test_network_error_raises_query_error(vsc):
    c = make_client(vsc, {"datastore": requests.exceptions.ConnectionError("refused")})
    with pytest.raises(vsc.VCDQueryError) as ei:
        c.get_datastores()
    assert ei.value.status is None


def test_catalogs_fall_back_on_403_and_raise_when_both_forbidden(vsc):
    c = make_client(vsc, {"adminCatalog": lambda call: Resp(403),
                          "catalog": paged([{"name": "Gold", "href": "c1", "orgName": "OrgA"}])})
    assert [x["name"] for x in c.get_catalogs()] == ["Gold"]
    c = make_client(vsc, {"adminCatalog": lambda call: Resp(403), "catalog": lambda call: Resp(403)})
    with pytest.raises(vsc.VCDQueryError):
        c.get_catalogs()


def test_scan_collects_errors_and_marks_incomplete(vsc, sleeps):
    c = make_client(vsc, {"adminVAppTemplate": lambda call: Resp(401),
                          "adminShadowVM": paged([{"name": "web-1", "href": S + "1", "datastoreName": "ds1"}])})
    res = vsc.scan_shadow_vms(c, ["Gold"], ["ds1"], debug=False)
    assert res.complete is False
    assert res.errors[0]["http_status"] == 401 and res.errors[0]["stage"] == "templates"


# ---- auth (I4, I15) ----

def test_token_auth_without_access_token_fails(vsc):
    c = make_client(vsc, {"POST": lambda call: Resp(200, {})})
    c.access_token = None
    with pytest.raises(vsc.VCDAuthError):
        c.authenticate_with_token("tok")
    assert c.access_token is None


def test_legacy_auth_without_token_fails(vsc):
    c = make_client(vsc, {
        "POST /cloudapi/1.0.0/sessions/provider": lambda call: Resp(404),
        "POST /api/sessions": lambda call: Resp(200, {}, headers={}),
    })
    c.access_token = None
    with pytest.raises(vsc.VCDAuthError):
        c.authenticate_with_credentials("admin", "pw")


def test_cloudapi_auth_succeeds_with_header_token(vsc):
    c = make_client(vsc, {"POST /cloudapi/1.0.0/sessions/provider":
                          lambda call: Resp(200, {}, headers={"X-VMWARE-VCLOUD-ACCESS-TOKEN": "abc"})})
    assert c.authenticate_with_credentials("admin", "pw") is True
    assert c.access_token == "abc"


@pytest.mark.parametrize("user,org,expected", [
    ("alice@OrgA", "system", "alice@OrgA"),
    ("alice", "system", "alice@system"),
    ("alice", "OrgB", "alice@OrgB"),
])
def test_username_with_org_is_not_doubled(vsc, user, org, expected):
    c = make_client(vsc, {"POST": lambda call: Resp(200, {}, headers={"X-VMWARE-VCLOUD-ACCESS-TOKEN": "abc"})})
    c.authenticate_with_credentials(user, "pw", org)
    auth = c.session.calls[0].headers["Authorization"]
    assert base64.b64decode(auth.split()[1]).decode() == f"{expected}:pw"


def test_legacy_username_with_org_is_not_doubled(vsc):
    c = make_client(vsc, {
        "POST /cloudapi/1.0.0/sessions/provider": lambda call: Resp(404),
        "POST /api/sessions": lambda call: Resp(200, {}, headers={"X-VMWARE-VCLOUD-ACCESS-TOKEN": "abc"}),
    })
    c.authenticate_with_credentials("alice@OrgA", "pw")
    assert c.session.calls[-1].auth == ("alice@OrgA", "pw")


# ---- I16: host normalization ----

@pytest.mark.parametrize("raw", ["https://vcd.example/", "HTTPS://vcd.example", "vcd.example//", " http://vcd.example "])
def test_host_scheme_and_trailing_slash_stripped(vsc, raw):
    c = vsc.VCDClient(raw)
    assert c.host == "vcd.example"
    c.session = FakeSession({"GET /api/org": lambda call: Resp(200, {"org": []})})
    c.get_organizations()
    assert c.session.calls[0].prepared.startswith("https://vcd.example/api/org")


# ---- I3: scoping by identity ----

TWO_ORG_TEMPLATES = [
    {"name": "tA", "href": T + "A", "catalogName": "Gold", "org": ORG_A},
    {"name": "tB", "href": T + "B", "catalogName": "Gold", "org": ORG_B},
]


def test_templates_scoped_to_catalog_org(vsc):
    c = make_client(vsc, {"adminVAppTemplate": paged(TWO_ORG_TEMPLATES)})
    warnings = []
    got = c.get_vapp_templates_in_catalog({"name": "Gold", "href": "cA", "org": ORG_A, "orgName": "OrgA"},
                                          warnings=warnings)
    assert [(t.name, t.org_name) for t in got] == [("tA", "OrgA")]
    assert warnings == []


def test_templates_without_scope_fields_kept_with_warning(vsc):
    recs = [{"name": "tX", "href": T + "X", "catalogName": "Gold"}]
    c = make_client(vsc, {"adminVAppTemplate": paged(recs)})
    warnings = []
    got = c.get_vapp_templates_in_catalog({"name": "Gold", "href": "cA", "org": ORG_A, "orgName": "OrgA"},
                                          warnings=warnings)
    assert [t.name for t in got] == ["tX"]
    assert len(warnings) == 1 and "could not be scoped" in warnings[0]


def test_scan_does_not_match_other_orgs_template_and_stamps_real_org(vsc):
    shadows = [{"name": "x", "href": S + "x", "datastoreName": "ds1", "primaryVAppTemplate": T + "B"},
               {"name": "y", "href": S + "y", "datastoreName": "ds1", "primaryVAppTemplate": T + "A"}]
    c = make_client(vsc, {"adminVAppTemplate": paged(TWO_ORG_TEMPLATES), "adminShadowVM": paged(shadows)})
    res = vsc.scan_shadow_vms(c, [{"name": "Gold", "href": "cA", "org": ORG_A, "orgName": "OrgA"}], ["ds1"],
                              vcd_server="vcd.example")
    got = by_name(res)
    assert set(got) == {"y"}
    assert got["y"].org_name == "OrgA" and got["y"].match_strength == "exact"
    assert res.counts["other_template"] == 1


def test_shadows_scoped_to_datastore_identity(vsc):
    vc_a, vc_b = "https://vcd.example/api/admin/extension/vimServer/vcA", "https://vcd.example/api/admin/extension/vimServer/vcB"
    ds_a, ds_b = "https://vcd.example/api/admin/extension/datastore/dsA", "https://vcd.example/api/admin/extension/datastore/dsB"
    recs = [{"name": "a", "href": S + "a", "datastoreName": "ds1", "datastore": ds_a, "vc": vc_a},
            {"name": "b", "href": S + "b", "datastoreName": "ds1", "datastore": ds_b, "vc": vc_b}]
    c = make_client(vsc, {"adminShadowVM": paged(recs)})
    got = c.get_shadow_vms_on_datastore({"name": "ds1", "href": ds_a, "vc": vc_a, "vcName": "vcA"})
    assert [s.name for s in got] == ["a"]


def test_shadows_without_datastore_fields_kept_with_warning(vsc):
    recs = [{"name": "a", "href": S + "a", "datastoreName": "ds1"}]
    c = make_client(vsc, {"adminShadowVM": paged(recs)})
    warnings = []
    got = c.get_shadow_vms_on_datastore({"name": "ds1", "href": "dsA", "vcName": "vcA"}, warnings=warnings)
    assert [s.name for s in got] == ["a"]
    assert len(warnings) == 1


def test_get_catalogs_keeps_identity(vsc):
    c = make_client(vsc, {"adminCatalog": paged([
        {"name": "Gold", "href": "https://vcd.example/api/catalog/1", "orgName": "OrgA", "org": ORG_A},
    ])})
    cat = c.get_catalogs()[0]
    assert cat["href"] == "https://vcd.example/api/catalog/1"
    assert cat["org"] == ORG_A and cat["orgName"] == "OrgA"


# ---- I25: one session's failure keeps the others' results ----

def test_scan_sessions_keeps_partial_results(vsc):
    good = make_client(vsc, {
        "adminVAppTemplate": paged([{"name": "web", "href": T + "1", "catalogName": "Gold"}]),
        "adminShadowVM": paged([{"name": "s1", "href": S + "1", "datastoreName": "ds1",
                                 "primaryVAppTemplate": T + "1"}]),
    })

    class Broken:
        def get_vapp_templates_in_catalog(self, *a, **k):
            raise RuntimeError("boom")

        def get_shadow_vms_on_datastore(self, *a, **k):
            raise RuntimeError("boom")

    sessions = [{"server": "good", "client": good, "catalogs": ["Gold"], "datastores": ["ds1"]},
                {"server": "bad", "client": Broken(), "catalogs": ["Gold"], "datastores": ["ds1"]}]
    res = vsc.scan_sessions(sessions)
    assert [s.name for s in res.shadows] == ["s1"]
    assert res.complete is False
    assert res.errors and res.errors[0]["server"] == "bad"


def test_get_catalogs_scoped_to_org_client_side(vsc):
    recs = [{"name": "Gold", "href": "https://vcd.example/api/catalog/A", "orgName": "OrgA", "org": ORG_A},
            {"name": "Gold", "href": "https://vcd.example/api/catalog/B", "orgName": "OrgB", "org": ORG_B}]
    c = make_client(vsc, {"adminCatalog": paged(recs, honor_filter=False)})
    got = c.get_catalogs("orga")
    assert [x["orgName"] for x in got] == ["OrgA"]
