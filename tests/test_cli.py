"""CLI: exit codes and JSON completeness (I4), terminal-only confirmation (I1),
exact-only deletes and --include-weak, stop rules and pause (I7), scoping (I3), host (I16)."""
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import requests

from helpers import ORG_A, ORG_B, S, T, Resp, paged

BASE = ["--cli", "--server", "vcd.example", "--token", "tok", "--catalog", "Gold", "--datastore", "ds1"]
CATALOGS = [{"name": "Gold", "href": "https://vcd.example/api/catalog/A", "orgName": "OrgA", "org": ORG_A}]
DATASTORES = [{"name": "ds1", "href": "https://vcd.example/api/admin/extension/datastore/1", "vcName": "vc1"}]
TEMPLATES = [{"name": "web", "href": T + "3", "catalogName": "Gold"}]


def routes(shadows, templates=TEMPLATES, delete=None, catalogs=CATALOGS, **extra):
    r = {
        "POST": lambda call: Resp(200, {"access_token": "x"}),
        "adminCatalog": paged(catalogs),
        "datastore": paged(DATASTORES),
        "adminVAppTemplate": paged(templates),
        "adminShadowVM": paged(shadows),
        "DELETE": delete or (lambda call: Resp(204)),
    }
    r.update(extra)
    return r


def deletes(session):
    return [c for c in session.calls if c.method == "DELETE" and "/api/session" not in c.path]


EXACT = [{"name": f"web-{i}", "href": S + f"e{i}", "datastoreName": "ds1", "primaryVAppTemplate": T + "3"}
         for i in range(3)]
WEAK = [{"name": "web (copy)", "href": S + "w1", "datastoreName": "ds1"},
        {"name": "prod_web", "href": S + "w2", "datastoreName": "ds1"}]


class _Writer(io.StringIO):
    """A terminal stand-in whose text stays readable after the code closes it."""

    def close(self):
        self.closed_by_code = True


def fake_tty(vsc, monkeypatch, answer="yes\n"):
    written = _Writer()
    monkeypatch.setattr(vsc, "_open_tty", lambda: (io.StringIO(answer), written), raising=False)
    return written


# ---- I4: failures are failures ----

def test_template_query_401_exits_4_with_incomplete_json(run_main):
    shadows = [{"name": "web-1", "href": S + "1", "datastoreName": "ds1"}]
    rc, out, err, s = run_main(BASE + ["--dry-run", "--json"],
                               routes(shadows, adminVAppTemplate=lambda call: Resp(401)))
    assert rc == 4
    doc = json.loads(out)
    assert doc["complete"] is False
    assert doc["errors"] and doc["errors"][0]["http_status"] == 401
    assert not deletes(s)


def test_incomplete_scan_never_deletes(vsc, run_main, monkeypatch):
    fake_tty(vsc, monkeypatch)
    rc, out, err, s = run_main(BASE, routes(EXACT, adminShadowVM=paged(EXACT * 40, cap=25, fail_pages=(2,))))
    assert rc == 4
    assert not deletes(s)


def test_token_without_access_token_exits_3(run_main):
    rc, out, err, s = run_main(BASE + ["--dry-run", "--json"], routes([], POST=lambda call: Resp(200, {})))
    assert rc == 3
    doc = json.loads(out)
    assert doc["complete"] is False and doc["errors"][0]["type"] == "VCDAuthError"
    assert "Connected successfully" not in out + err


def test_network_error_on_auth_exits_4(run_main):
    rc, out, err, s = run_main(BASE + ["--dry-run"],
                               routes([], POST=requests.exceptions.ConnectionError("refused")))
    assert rc == 4


def test_discovery_error_exits_4(run_main, sleeps):
    rc, out, err, s = run_main(["--cli", "--server", "vcd.example", "--token", "tok", "--list-datastores", "--json"],
                               routes([], datastore=lambda call: Resp(503)))
    assert rc == 4
    assert json.loads(out)["complete"] is False


def test_dry_run_json_complete_and_no_delete(run_main):
    rc, out, err, s = run_main(BASE + ["--dry-run", "--json"], routes(EXACT + WEAK))
    assert rc == 0
    doc = json.loads(out)
    assert doc["complete"] is True and doc["errors"] == []
    assert doc["counts"]["exact"] == 3 and doc["counts"]["weak"] == 2
    assert {d["match_strength"] for d in doc["shadow_vms"]} == {"exact", "name", "substring"}
    assert doc["delete_candidates"] == 3
    assert not deletes(s)


def test_catalog_not_found_exits_2(run_main):
    rc, out, err, s = run_main(["--cli", "--server", "vcd.example", "--token", "tok", "--catalog", "Nope",
                                "--datastore", "ds1", "--dry-run"], routes(EXACT))
    assert rc == 2
    assert "catalog 'Nope'" in err


# ---- I1: confirmation only from a terminal ----

def test_piped_yes_without_terminal_does_not_delete(run_main):
    rc, out, err, s = run_main(BASE, routes(EXACT), stdin="yes\n")
    assert deletes(s) == []
    assert rc == 5
    assert "REFUSED" in err


_NO_TTY_SCRIPT = r"""
import importlib.util, sys
sys.path.insert(0, sys.argv[2])
spec = importlib.util.spec_from_file_location("vsc", sys.argv[1])
vsc = importlib.util.module_from_spec(spec); spec.loader.exec_module(vsc)
from helpers import FakeSession, Resp, paged, S, T
import time
time.sleep = lambda s: None
shadows = [{"name": "web-1", "href": S + "1", "datastoreName": "ds1", "primaryVAppTemplate": T + "3"}]
sess = FakeSession({
    "POST": lambda c: Resp(200, {"access_token": "x"}),
    "adminCatalog": paged([{"name": "Gold", "href": "c", "orgName": "OrgA"}]),
    "datastore": paged([{"name": "ds1", "href": "d"}]),
    "adminVAppTemplate": paged([{"name": "web", "href": T + "3", "catalogName": "Gold"}]),
    "adminShadowVM": paged(shadows),
    "DELETE": lambda c: Resp(204),
})
vsc.requests.Session = lambda: sess
sys.argv = ["x", "--cli", "--server", "vcd.example", "--token", "t", "--catalog", "Gold", "--datastore", "ds1"]
rc = vsc.main()
n = sum(1 for c in sess.calls if c.method == "DELETE" and "/api/session" not in c.path)
print("DELETES", n, file=sys.stderr)
sys.exit(rc)
"""


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX setsid")
def test_piped_yes_with_no_controlling_terminal_subprocess(vsc, tmp_path):
    """End to end: a new session has no controlling terminal; stdin says 'yes'."""
    script = tmp_path / "no_tty.py"
    script.write_text(_NO_TTY_SCRIPT)
    tests_dir = str(Path(__file__).resolve().parent)
    proc = subprocess.run([sys.executable, str(script), vsc.__file__, tests_dir], input="yes\n",
                          capture_output=True, text=True, start_new_session=True, timeout=60,
                          cwd=str(tmp_path))
    assert "DELETES 0" in proc.stderr, proc.stderr
    assert proc.returncode == 5, proc.stderr


def test_terminal_yes_deletes_only_exact_by_default(vsc, run_main, monkeypatch):
    prompt = fake_tty(vsc, monkeypatch)
    rc, out, err, s = run_main(BASE, routes(EXACT + WEAK))
    assert rc == 0
    assert sorted(c.prepared for c in deletes(s)) == sorted(r["href"] for r in EXACT)
    assert "--include-weak" in out
    assert "Exact matches" in prompt.getvalue()


def test_terminal_no_cancels(vsc, run_main, monkeypatch):
    fake_tty(vsc, monkeypatch, answer="no\n")
    rc, out, err, s = run_main(BASE, routes(EXACT))
    assert rc == 0 and deletes(s) == []


def test_include_weak_deletes_weak_and_lists_them_separately(vsc, run_main, monkeypatch):
    prompt = fake_tty(vsc, monkeypatch)
    rc, out, err, s = run_main(BASE + ["--include-weak"], routes(EXACT + WEAK))
    assert rc == 0
    assert len(deletes(s)) == 5
    text = prompt.getvalue()
    assert "WEAK matches" in text
    assert "web (copy)" in text and "prod_web" in text


# ---- I7: stop rules and pause ----

def test_stops_after_three_consecutive_failures(vsc, run_main, monkeypatch):
    fake_tty(vsc, monkeypatch)
    many = [{"name": f"web-{i}", "href": S + f"f{i}", "datastoreName": "ds1", "primaryVAppTemplate": T + "3"}
            for i in range(6)]
    rc, out, err, s = run_main(BASE + ["--json"], routes(many, delete=lambda call: Resp(500)))
    assert len(deletes(s)) == 3
    assert rc == 7
    doc = json.loads(out)
    assert doc["failed"] == 3 and doc["skipped"] == 3
    assert "consecutive" in doc["stopped_reason"]


def test_stops_on_first_401(vsc, run_main, monkeypatch):
    fake_tty(vsc, monkeypatch)
    rc, out, err, s = run_main(BASE, routes(EXACT, delete=lambda call: Resp(401)))
    assert len(deletes(s)) == 1
    assert rc == 7


def test_pause_between_deletes(vsc, run_main, monkeypatch, sleeps):
    fake_tty(vsc, monkeypatch)
    rc, out, err, s = run_main(BASE, routes(EXACT))
    assert rc == 0
    assert sleeps.count(3) == 2


def test_accepted_without_task_is_reported_unverified(vsc, run_main, monkeypatch):
    fake_tty(vsc, monkeypatch)
    rc, out, err, s = run_main(BASE + ["--json"], routes(EXACT[:1], delete=lambda call: Resp(202)))
    doc = json.loads(out)
    assert rc == 0
    assert doc["deleted"] == 0 and doc["accepted_unverified"] == 1
    assert doc["deletion_results"][0]["status"] == "accepted_unverified"


# ---- I3: --tenant scopes results ----

def test_tenant_scopes_results_to_its_catalog(run_main):
    catalogs = [
        {"name": "Gold", "href": "https://vcd.example/api/catalog/A", "orgName": "OrgA", "org": ORG_A},
        {"name": "Gold", "href": "https://vcd.example/api/catalog/B", "orgName": "OrgB", "org": ORG_B},
    ]
    templates = [{"name": "tA", "href": T + "A", "catalogName": "Gold", "org": ORG_A},
                 {"name": "tB", "href": T + "B", "catalogName": "Gold", "org": ORG_B}]
    shadows = [{"name": "x", "href": S + "x", "datastoreName": "ds1", "primaryVAppTemplate": T + "B"},
               {"name": "y", "href": S + "y", "datastoreName": "ds1", "primaryVAppTemplate": T + "A"}]
    rc, out, err, s = run_main(BASE + ["--tenant", "OrgA", "--dry-run", "--json"],
                               routes(shadows, templates=templates, catalogs=catalogs))
    assert rc == 0
    doc = json.loads(out)
    assert [(d["name"], d["org"]) for d in doc["shadow_vms"]] == [("y", "OrgA")]
    assert doc["counts"]["other_template"] == 1


# ---- I16: server address normalized ----

def test_https_server_argument_is_normalized(run_main):
    argv = ["--cli", "--server", "https://vcd.example/", "--token", "tok", "--catalog", "Gold",
            "--datastore", "ds1", "--dry-run"]
    rc, out, err, s = run_main(argv, routes(EXACT))
    assert rc == 0
    assert all(c.host == "vcd.example" for c in s.calls), [c.prepared for c in s.calls]
