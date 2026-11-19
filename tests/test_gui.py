"""Offscreen GUI smoke test: match-strength column, exact-only bulk select, and
hidden rows excluded from deletion (I2/I10 GUI part, I13)."""
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6", exc_type=ImportError)
pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication, QMessageBox  # noqa: E402

COL_CHECK, COL_TEMPLATE, COL_CATALOG, COL_MATCH = 0, 1, 2, 7


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def mk(vsc, name, tpl, catalog, strength, ds="ds1"):
    s = vsc.ShadowVM(name=name, href=f"https://vcd.example/api/shadow/{name}", container_name=tpl,
                     container_id="", datastore_name=ds, vm_id=name, primary_vm_href="",
                     catalog_name=catalog, vcd_server="vcd.example", org_name="OrgA")
    s.match_strength = strength
    s.match_rule = {"exact": "parent_ref", "name": "name_prefix", "substring": "name_token"}[strength]
    return s


@pytest.fixture
def window(vsc, app):
    classes = vsc.run_gui(build_only=True)
    w = classes["MainWindow"]()
    w.vcd_sessions = [{"server": "vcd.example", "org": "OrgA", "client": None, "catalogs": [], "datastores": []}]
    shadows = [
        mk(vsc, "web-1", "web", "Gold", "exact"),
        mk(vsc, "web-2", "web", "Gold", "exact"),
        mk(vsc, "web (copy)", "web", "Gold", "name"),
        mk(vsc, "db-1", "db", "Silver", "exact"),
        mk(vsc, "x_cache", "cache", "Gold", "substring"),
    ]
    w._on_scan_finished(vsc.ScanResult(shadows=shadows))
    yield w
    w.close()


def groups(w):
    m = w._tree_model
    out = {}
    for r in range(m.rowCount()):
        out[m.item(r, COL_TEMPLATE).text()] = m.item(r, COL_CHECK)
    return out


def children(group_item):
    out = {}
    for r in range(group_item.rowCount()):
        shadow = group_item.child(r, COL_CATALOG).data(Qt.ItemDataRole.UserRole + 1)
        out[shadow.name] = group_item.child(r, COL_CHECK)
    return out


def checked_names(w):
    names = set()
    for g in groups(w).values():
        for n, chk in children(g).items():
            if chk.checkState() == Qt.CheckState.Checked:
                names.add(n)
    return names


def test_match_column_shows_strength(window):
    g = groups(window)
    m = window._tree_model
    labels = {m.item(r, COL_TEMPLATE).text(): m.item(r, COL_MATCH).text() for r in range(m.rowCount())}
    assert labels == {"web": "mixed", "db": "exact", "cache": "weak"}
    web = g["web"]
    child_match = {web.child(r, COL_TEMPLATE).text().strip(): web.child(r, COL_MATCH).text()
                   for r in range(web.rowCount())}
    assert child_match == {"web-1": "exact", "web-2": "exact", "web (copy)": "name"}


def test_nothing_checked_after_scan(window):
    assert checked_names(window) == set()


def test_header_select_all_checks_only_exact(window):
    window._on_header_select_all_clicked()
    assert checked_names(window) == {"web-1", "web-2", "db-1"}
    window._on_header_select_all_clicked()  # all eligible checked -> clears
    assert checked_names(window) == set()


def test_group_checkbox_checks_only_exact_children(window):
    g = groups(window)
    g["web"].setCheckState(Qt.CheckState.Checked)  # emits itemChanged like a user click
    assert checked_names(window) == {"web-1", "web-2"}
    g["web"].setCheckState(Qt.CheckState.Checked)  # second click on a partial group clears it
    assert checked_names(window) == set()
    g["cache"].setCheckState(Qt.CheckState.Checked)  # weak-only group: nothing to bulk-check
    assert checked_names(window) == set()


def test_weak_child_can_be_checked_individually(window):
    children(groups(window)["web"])["web (copy)"].setCheckState(Qt.CheckState.Checked)
    assert checked_names(window) == {"web (copy)"}


def test_include_weak_toggle(window):
    window.include_weak_check.setChecked(True)
    window._on_header_select_all_clicked()
    assert checked_names(window) == {"web-1", "web-2", "web (copy)", "db-1", "x_cache"}


def test_hidden_rows_excluded_from_deletion(window, monkeypatch):
    window._on_header_select_all_clicked()
    window._active_filters[COL_CATALOG] = {"Gold"}  # hides the Silver group (db-1, checked)
    window._apply_filters()
    visible, hidden = window._collect_delete_selection()
    assert sorted(s.name for s in visible) == ["web-1", "web-2"]
    assert hidden == 1

    asked = {}

    def fake_question(parent, title, text, *a, **k):
        asked["text"] = text
        return QMessageBox.StandardButton.No

    monkeypatch.setattr(QMessageBox, "question", staticmethod(fake_question))
    window.cleanup_shadows()
    text = asked["text"]
    assert "delete 2 selected" in text
    assert "Exact matches (parent template reference): 2" in text
    assert "WEAK matches (name/substring only): 0" in text
    assert "1 checked row(s) hidden by the current filters will be skipped" in text
    assert getattr(window, "delete_worker", None) is None


def test_confirmation_counts_weak(window, monkeypatch):
    children(groups(window)["web"])["web (copy)"].setCheckState(Qt.CheckState.Checked)
    window._on_header_select_all_clicked()
    visible, hidden = window._collect_delete_selection()
    text = window._delete_confirmation_text(visible, hidden)
    assert "Exact matches (parent template reference): 3" in text
    assert "WEAK matches (name/substring only): 1" in text
    assert "web (copy)" in text


def test_delete_worker_uses_shared_loop_with_stop_rule(vsc, app, sleeps):
    from helpers import Resp, make_client

    classes = vsc.run_gui(build_only=True)
    client = make_client(vsc, {"DELETE": lambda call: Resp(500)})
    shadows = [mk(vsc, f"web-{i}", "web", "Gold", "exact") for i in range(5)]
    worker = classes["MainWindow"].DeleteWorker(None, [{"server": "vcd.example", "client": client}], shadows)
    results, summaries = [], []
    worker.item_done.connect(results.append)
    worker.finished.connect(summaries.append)
    worker.run()  # synchronously, on this thread
    app.processEvents()  # item_done is emitted from pool threads, so it is queued
    assert [r.status for r in results] == ["failed"] * 3 + ["skipped"] * 2
    assert summaries[0]["failed"] == 3 and summaries[0]["skipped"] == 2
    assert summaries[0]["stopped"]
    assert sleeps.count(3) == 2
    assert len([c for c in client.session.calls if c.method == "DELETE"]) == 3


def test_incomplete_scan_shows_partial_results_and_error(vsc, app, monkeypatch):
    shown = {}
    monkeypatch.setattr(QMessageBox, "warning",
                        staticmethod(lambda parent, title, text, *a, **k: shown.update(title=title, text=text)))
    classes = vsc.run_gui(build_only=True)
    w = classes["MainWindow"]()
    res = vsc.ScanResult(shadows=[mk(vsc, "web-1", "web", "Gold", "exact")],
                         errors=[{"message": "templates failed for catalog 'Silver': HTTP 503", "server": "vcd2"}])
    w._on_scan_finished(res)
    assert w._tree_model.rowCount() == 1
    assert shown["title"] == "Scan Incomplete" and "HTTP 503" in shown["text"]
    assert "INCOMPLETE" in w.summary_label.text()
    w.close()
