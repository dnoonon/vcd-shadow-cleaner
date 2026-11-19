"""Matching: strength and evidence, other_template, token boundaries, empty names,
determinism, ambiguity, and the container_name precedence fix (I2, I10, I11)."""
import json
import os
import subprocess
import sys
from pathlib import Path

from helpers import S, T, by_name, make_client, paged, shadows_of


def scan(vsc, tpls, shadows, catalogs=("Gold",), datastores=("ds1",)):
    c = make_client(vsc, {"adminVAppTemplate": paged(tpls), "adminShadowVM": paged(shadows)})
    return vsc.scan_shadow_vms(c, list(catalogs), list(datastores), debug=False)


GOLD = [
    {"name": "ubuntu", "href": T + "1", "catalogName": "Gold"},
    {"name": "ubuntu-22.04", "href": T + "2", "catalogName": "Gold"},
    {"name": "web", "href": T + "3", "catalogName": "Gold"},
]


def test_web_does_not_match_cobweb(vsc):
    shadows = [{"name": f"cobweb-{i}", "href": S + str(i), "datastoreName": "ds1"} for i in range(5)]
    res = scan(vsc, GOLD, shadows)
    assert shadows_of(res) == []
    assert res.counts["unmatched"] == 5


def test_substring_only_on_token_boundaries(vsc):
    shadows = [
        {"name": "prod_web_01", "href": S + "a", "datastoreName": "ds1"},
        {"name": "web-frontend (abc)", "href": S + "b", "datastoreName": "ds1"},
        {"name": "webserver", "href": S + "c", "datastoreName": "ds1"},
        {"name": "x.web", "href": S + "d", "datastoreName": "ds1"},
    ]
    got = by_name(scan(vsc, GOLD, shadows))
    assert set(got) == {"prod_web_01", "web-frontend (abc)", "x.web"}
    assert got["prod_web_01"].match_strength == "substring"
    assert got["prod_web_01"].match_rule == "name_token"
    assert got["web-frontend (abc)"].match_strength == "name"
    assert got["web-frontend (abc)"].match_rule == "name_prefix"
    assert got["x.web"].match_strength == "substring"


def test_parent_ref_to_unselected_template_is_other_template(vsc):
    shadows = [
        {"name": "web-frontend-prod (abc)", "href": S + "a", "datastoreName": "ds1",
         "primaryVAppTemplate": T + "999"},
    ]
    res = scan(vsc, GOLD, shadows)
    assert shadows_of(res) == []
    assert res.counts["other_template"] == 1
    assert res.counts["weak"] == 0


def test_exact_match_records_strength_rule_and_parent(vsc):
    shadows = [{"name": "x", "href": S + "d", "datastoreName": "ds1", "primaryVAppTemplate": T + "1"}]
    s = by_name(scan(vsc, GOLD, shadows))["x"]
    assert s.match_strength == "exact"
    assert s.match_rule == "parent_ref"
    assert s.parent_ref == T + "1"
    assert s.template_href == T + "1"
    assert s.container_name == "ubuntu"
    assert s.catalog_name == "Gold"
    assert s.ambiguous_with == []


def test_exact_match_tolerates_urn_vs_href(vsc):
    uid = "12345678-1234-1234-1234-123456789abc"
    tpls = [{"name": "base", "href": f"https://vcd.example/api/vAppTemplate/vappTemplate-{uid}",
             "catalogName": "Gold"}]
    shadows = [{"name": "zzz", "href": S + "u", "datastoreName": "ds1",
                "primaryVAppTemplate": f"urn:vcloud:vapptemplate:{uid}"}]
    s = by_name(scan(vsc, tpls, shadows))["zzz"]
    assert s.match_strength == "exact"


def test_empty_template_name_matches_nothing(vsc):
    tpls = [{"href": T + "7", "catalogName": "Gold"}, {"name": "", "href": T + "8", "catalogName": "Gold"},
            {"name": "   ", "href": T + "9", "catalogName": "Gold"}]
    shadows = [{"name": n, "href": S + n, "datastoreName": "ds1"} for n in ("anything", "prod-db-01", "zzz")]
    res = scan(vsc, tpls, shadows)
    assert shadows_of(res) == []


def test_ambiguous_longest_template_wins_and_is_recorded(vsc):
    shadows = [{"name": "ubuntu-22.04-shadow", "href": S + "c", "datastoreName": "ds1"}]
    s = by_name(scan(vsc, GOLD, shadows))["ubuntu-22.04-shadow"]
    assert s.container_name == "ubuntu-22.04"
    assert s.match_strength == "name"
    assert [a["template"] for a in s.ambiguous_with] == ["ubuntu"]
    res = scan(vsc, GOLD, shadows)
    assert res.counts["ambiguous"] == 1


_SEED_SCRIPT = r"""
import importlib.util, json, sys
sys.path.insert(0, sys.argv[2])
spec = importlib.util.spec_from_file_location("vsc", sys.argv[1])
vsc = importlib.util.module_from_spec(spec); spec.loader.exec_module(vsc)
from helpers import T, S, make_client, paged, shadows_of
import io, contextlib
tpls = [{"name": n, "href": T + str(i), "catalogName": "Gold"} for i, n in enumerate(
    ["ubuntu", "ubuntu-22.04", "ubuntu-22", "22.04", "shadow", "u"])]
shadows = [{"name": "ubuntu-22.04-shadow", "href": S + "c", "datastoreName": "ds1"},
           {"name": "x-ubuntu-22.04-shadow", "href": S + "d", "datastoreName": "ds1"}]
c = make_client(vsc, {"adminVAppTemplate": paged(tpls), "adminShadowVM": paged(shadows)})
with contextlib.redirect_stdout(io.StringIO()):
    res = vsc.scan_shadow_vms(c, ["Gold"], ["ds1"], debug=False)
print(json.dumps(sorted((s.name, s.container_name) for s in shadows_of(res))))
"""


def test_name_matching_is_deterministic_across_hash_seeds(vsc, tmp_path):
    script = tmp_path / "seed_check.py"
    script.write_text(_SEED_SCRIPT)
    tests_dir = str(Path(__file__).resolve().parent)
    outputs = set()
    for seed in range(1, 7):
        env = dict(os.environ, PYTHONHASHSEED=str(seed))
        out = subprocess.run([sys.executable, str(script), vsc.__file__, tests_dir], env=env,
                             capture_output=True, text=True, check=True).stdout.strip()
        outputs.add(out)
    assert len(outputs) == 1, outputs
    result = dict(json.loads(outputs.pop()))
    assert result == {"ubuntu-22.04-shadow": "ubuntu-22.04", "x-ubuntu-22.04-shadow": "ubuntu-22.04"}


def test_container_name_precedence(vsc):
    recs = [{"name": "nospace", "href": S + "1", "containerName": "GoldTpl", "datastoreName": "ds1"},
            {"name": "Ubuntu (uuid-1)", "href": S + "2", "datastoreName": "ds1"},
            {"name": "plain", "href": S + "3", "datastoreName": "ds1"}]
    c = make_client(vsc, {"adminShadowVM": paged(recs)})
    got = {s.name: s.container_name for s in c.get_shadow_vms_on_datastore("ds1")}
    assert got == {"nospace": "GoldTpl", "Ubuntu (uuid-1)": "Ubuntu", "plain": ""}


def test_container_name_field_match_is_name_strength(vsc):
    shadows = [{"name": "zz-123", "href": S + "1", "containerName": "web", "datastoreName": "ds1"}]
    s = by_name(scan(vsc, GOLD, shadows))["zz-123"]
    assert s.match_strength == "name"
    assert s.match_rule == "container_name"
    assert s.container_name == "web"


def test_same_template_name_in_two_catalogs_is_ambiguous(vsc):
    tpls = [{"name": "web", "href": T + "g", "catalogName": "Gold"},
            {"name": "web", "href": T + "s", "catalogName": "Silver"}]
    shadows = [{"name": "web (x)", "href": S + "1", "datastoreName": "ds1"}]
    s = by_name(scan(vsc, tpls, shadows, catalogs=("Gold", "Silver")))["web (x)"]
    assert s.catalog_name == "Gold"
    assert [(a["template"], a["catalog"]) for a in s.ambiguous_with] == [("web", "Silver")]


def test_counts_summary(vsc):
    shadows = [
        {"name": "x", "href": S + "1", "datastoreName": "ds1", "primaryVAppTemplate": T + "1"},
        {"name": "web-1", "href": S + "2", "datastoreName": "ds1"},
        {"name": "a_web", "href": S + "3", "datastoreName": "ds1"},
        {"name": "other", "href": S + "4", "datastoreName": "ds1", "primaryVAppTemplate": T + "404"},
        {"name": "nothing", "href": S + "5", "datastoreName": "ds1"},
    ]
    res = scan(vsc, GOLD, shadows)
    assert res.counts == {"exact": 1, "name": 1, "substring": 1, "weak": 2, "ambiguous": 0,
                          "other_template": 1, "unmatched": 1}
    assert res.complete is True
