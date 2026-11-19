"""Credential storage: keyring-first, base64 fallback warnings, delete-both, and
--migrate-credentials. Uses the in-memory FakeKeyring from conftest; never the real keychain."""
import base64
import glob
import json
import os
import stat
import sys

import pytest

SVC = "vcd-shadow-cleaner"
SECRET = "Sup3r-S3cret-Pa55word-xyzzy!"
SECRET_B64 = base64.b64encode(SECRET.encode()).decode()


def _b64(value):
    return base64.b64encode(value.encode()).decode()


def _write_servers(vsc, servers, mode=0o600):
    os.makedirs(vsc._CONFIG_DIR, exist_ok=True)
    with open(vsc._SERVERS_FILE, "w") as f:
        json.dump(servers, f)
    os.chmod(vsc._SERVERS_FILE, mode)


def _read_servers(vsc):
    with open(vsc._SERVERS_FILE) as f:
        return json.load(f)


def _entry(vsc, sid):
    return next(s for s in _read_servers(vsc) if s["id"] == sid)


def _backups(vsc):
    return glob.glob(vsc._SERVERS_FILE + ".bak-*")


def _srv(sid, name, secret=None, host=None):
    e = {"id": sid, "name": name, "server": host or f"{name}.example", "auth_type": "token"}
    if secret is not None:
        e["_credential_b64"] = _b64(secret)
    return e


# ---------------------------------------------------------------- A1: write


def test_keyring_write_removes_leftover_base64(vsc, fake_keyring):
    _write_servers(vsc, [_srv("a", "lab", "old"), _srv("b", "other", "keepme")])
    result = vsc._set_credential("a", "new")
    assert fake_keyring.store[(SVC, "a")] == "new"
    assert "_credential_b64" not in _entry(vsc, "a")
    assert result == "keyring"
    assert _entry(vsc, "b")["_credential_b64"] == _b64("keepme")  # other servers untouched
    assert vsc._get_credential("a") == "new"


def test_keyring_write_failure_falls_back_to_base64(vsc, fake_keyring):
    _write_servers(vsc, [_srv("a", "lab")])
    fake_keyring.fail_set = True
    result = vsc._set_credential("a", "tok")
    assert _entry(vsc, "a")["_credential_b64"] == _b64("tok")
    assert vsc._get_credential("a") == "tok"
    assert result == "base64"  # the caller needs this to warn the user


# ------------------------------------------------------- A2: user warnings


def test_base64_warning_is_shown_once(vsc, capsys):
    assert vsc._warn_base64_once() is True
    assert vsc._warn_base64_once() is False
    err = capsys.readouterr().err
    assert err.count("WARNING:") == 1
    assert "base64-encoded (NOT encrypted)" in err
    assert vsc._SERVERS_FILE in err


def test_warning_text_says_how_to_fix(vsc, monkeypatch):
    monkeypatch.setattr(vsc, "_KEYRING_AVAILABLE", False)
    text = vsc._base64_warning_text()
    assert "pip install keyring" in text and "--migrate-credentials" in text
    monkeypatch.setattr(vsc, "_KEYRING_AVAILABLE", True)
    assert "--migrate-credentials" in vsc._base64_warning_text()


def test_reads_do_not_print_warnings(vsc, monkeypatch, capsys):
    monkeypatch.setattr(vsc, "_KEYRING_AVAILABLE", False)
    _write_servers(vsc, [_srv("a", "lab", SECRET)])
    for _ in range(3):
        assert vsc._get_credential("a") == SECRET
    assert capsys.readouterr().err == ""


def test_cli_saved_server_base64_warns_on_stderr_without_secret(vsc, run_main, monkeypatch):
    from helpers import Resp, paged
    monkeypatch.setattr(vsc, "_KEYRING_AVAILABLE", False)
    _write_servers(vsc, [_srv("a", "lab", SECRET, host="vcd.example")])
    routes = {
        "POST": lambda call: Resp(200, {"access_token": "x"}),
        "adminCatalog": paged([{"name": "Gold", "href": "c", "orgName": "OrgA"}]),
        "datastore": paged([{"name": "ds1", "href": "d"}]),
        "adminVAppTemplate": paged([]),
        "adminShadowVM": paged([]),
    }
    rc, out, err, _ = run_main(["--saved-server", "lab", "--catalog", "Gold", "--datastore", "ds1",
                                "--dry-run"], routes)
    assert rc == 0, err
    assert err.count("base64-encoded (NOT encrypted)") == 1
    assert "pip install keyring" in err
    assert SECRET not in out + err and SECRET_B64 not in out + err


@pytest.fixture
def gui_app():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6.QtWidgets", exc_type=ImportError)
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def test_gui_save_with_base64_fallback_warns_once(vsc, gui_app, monkeypatch):
    from PySide6.QtWidgets import QMessageBox
    shown = []
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: shown.append(a)))
    monkeypatch.setattr(vsc, "_KEYRING_AVAILABLE", False)
    Dialog = vsc.run_gui(build_only=True)["EditSavedServerDialog"]
    for i in range(2):
        dlg = Dialog(None, server_data={"id": "a", "name": f"lab{i}", "server": "vcd.example",
                                        "auth_type": "token"}, prefill_credential=SECRET)
        dlg._on_save()
    assert len(shown) == 1
    title, text = shown[0][1], shown[0][2]
    assert "not encrypted" in title.lower()
    assert "base64-encoded (NOT encrypted)" in text and "pip install keyring" in text
    assert SECRET not in text
    assert _entry(vsc, "a")["_credential_b64"] == _b64(SECRET)


def test_gui_save_with_keyring_does_not_warn(vsc, gui_app, monkeypatch, fake_keyring):
    from PySide6.QtWidgets import QMessageBox
    shown = []
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: shown.append(a)))
    _write_servers(vsc, [_srv("a", "lab", "old")])
    Dialog = vsc.run_gui(build_only=True)["EditSavedServerDialog"]
    dlg = Dialog(None, server_data={"id": "a", "name": "lab", "server": "vcd.example",
                                    "auth_type": "token"}, prefill_credential=SECRET)
    dlg._on_save()
    assert shown == []
    assert fake_keyring.store[(SVC, "a")] == SECRET
    assert "_credential_b64" not in _entry(vsc, "a")


# ------------------------------------------------------------ A3: delete


def test_delete_removes_keyring_and_base64(vsc, fake_keyring):
    _write_servers(vsc, [_srv("a", "lab", "b64val")])
    fake_keyring.store[(SVC, "a")] = "kval"
    vsc._delete_credential("a")
    assert (SVC, "a") not in fake_keyring.store
    assert "_credential_b64" not in _entry(vsc, "a")
    assert vsc._get_credential("a") == ""


def test_delete_removes_base64_when_keyring_has_nothing(vsc, fake_keyring):
    _write_servers(vsc, [_srv("a", "lab", "b64val")])
    vsc._delete_credential("a")  # keyring delete raises "not found"; must not stop the b64 removal
    assert "_credential_b64" not in _entry(vsc, "a")
    assert vsc._get_credential("a") == ""


def test_delete_without_keyring_removes_base64(vsc, monkeypatch):
    monkeypatch.setattr(vsc, "_KEYRING_AVAILABLE", False)
    _write_servers(vsc, [_srv("a", "lab", "b64val")])
    vsc._delete_credential("a")
    assert "_credential_b64" not in _entry(vsc, "a")


# ----------------------------------------------------- A4: read compatibility


def test_read_without_keyring_uses_base64(vsc, monkeypatch):
    monkeypatch.setattr(vsc, "_KEYRING_AVAILABLE", False)
    _write_servers(vsc, [_srv("a", "lab", "fromb64")])
    assert vsc._get_credential("a") == "fromb64"


def test_read_prefers_keyring_then_base64(vsc, fake_keyring):
    _write_servers(vsc, [_srv("a", "lab", "fromb64"), _srv("b", "other", "onlyb64")])
    fake_keyring.store[(SVC, "a")] = "fromkeyring"
    assert vsc._get_credential("a") == "fromkeyring"
    assert vsc._get_credential("b") == "onlyb64"


# --------------------------------------------------- B: --migrate-credentials


def _migrate(run_main, *extra):
    return run_main(["--migrate-credentials", *extra], {})


def test_migrate_dry_run_changes_nothing(vsc, run_main, fake_keyring):
    _write_servers(vsc, [_srv("a", "lab", SECRET), _srv("b", "other")])
    before = open(vsc._SERVERS_FILE, "rb").read()
    rc, out, err, _ = _migrate(run_main, "--dry-run", "--json")
    assert rc == 0, err
    doc = json.loads(out)
    assert doc["dry_run"] is True and doc["backup"] is None
    assert [(r["id"], r["outcome"]) for r in doc["results"]] == [("a", "would_migrate")]
    assert open(vsc._SERVERS_FILE, "rb").read() == before
    assert fake_keyring.store == {}
    assert _backups(vsc) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_migrate_moves_credentials_and_backs_up(vsc, run_main, fake_keyring):
    _write_servers(vsc, [_srv("a", "lab", SECRET), _srv("b", "other", "tok2"), _srv("c", "nocred")])
    original = open(vsc._SERVERS_FILE, "rb").read()
    rc, out, err, _ = _migrate(run_main)
    assert rc == 0, out + err
    assert fake_keyring.store == {(SVC, "a"): SECRET, (SVC, "b"): "tok2"}
    assert all("_credential_b64" not in s for s in _read_servers(vsc))
    assert [s["id"] for s in _read_servers(vsc)] == ["a", "b", "c"]
    backups = _backups(vsc)
    assert len(backups) == 1
    assert open(backups[0], "rb").read() == original
    assert stat.S_IMODE(os.stat(backups[0]).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(vsc._SERVERS_FILE).st_mode) == 0o600
    assert "migrated" in out and "lab" in out and "lab.example" in out
    assert vsc._get_credential("a") == SECRET


def test_migrate_writes_servers_file_once(vsc, run_main, monkeypatch):
    _write_servers(vsc, [_srv("a", "lab", "x1"), _srv("b", "other", "x2"), _srv("c", "third", "x3")])
    writes = []
    real = vsc._persist_saved_servers
    monkeypatch.setattr(vsc, "_persist_saved_servers", lambda s: (writes.append(1), real(s)))
    rc, out, err, _ = _migrate(run_main)
    assert rc == 0, err
    assert len(writes) == 1


def test_migrate_readback_mismatch_keeps_base64(vsc, run_main, fake_keyring):
    _write_servers(vsc, [_srv("a", "lab", SECRET)])
    fake_keyring.readback = "something-else"
    rc, out, err, _ = _migrate(run_main, "--json")
    assert rc == 1
    doc = json.loads(out)
    assert doc["results"][0]["outcome"] == "failed"
    assert _entry(vsc, "a")["_credential_b64"] == SECRET_B64
    # the bad keyring write is removed so reads still reach the good base64 copy
    assert (SVC, "a") not in fake_keyring.store
    fake_keyring.readback = None
    assert vsc._get_credential("a") == SECRET


def test_migrate_keyring_write_error_is_failed(vsc, run_main, fake_keyring):
    _write_servers(vsc, [_srv("a", "lab", SECRET)])
    fake_keyring.fail_set = True
    rc, out, err, _ = _migrate(run_main, "--json")
    assert rc == 1
    assert json.loads(out)["results"][0]["outcome"] == "failed"
    assert _entry(vsc, "a")["_credential_b64"] == SECRET_B64


def test_migrate_conflict_leaves_both(vsc, run_main, fake_keyring):
    _write_servers(vsc, [_srv("a", "lab", SECRET), _srv("b", "other", "tok2")])
    fake_keyring.store[(SVC, "a")] = "different-keyring-value"
    rc, out, err, _ = _migrate(run_main, "--json")
    assert rc == 1
    outcomes = {r["id"]: r["outcome"] for r in json.loads(out)["results"]}
    assert outcomes == {"a": "conflict", "b": "migrated"}
    assert fake_keyring.store[(SVC, "a")] == "different-keyring-value"
    assert _entry(vsc, "a")["_credential_b64"] == SECRET_B64
    assert "_credential_b64" not in _entry(vsc, "b")
    assert "different-keyring-value" not in out + err


def test_migrate_already_in_keyring_same_drops_base64(vsc, run_main, fake_keyring):
    _write_servers(vsc, [_srv("a", "lab", SECRET)])
    fake_keyring.store[(SVC, "a")] = SECRET
    rc, out, err, _ = _migrate(run_main, "--json")
    assert rc == 0, err
    assert json.loads(out)["results"][0]["outcome"] == "already_in_keyring_same"
    assert "_credential_b64" not in _entry(vsc, "a")


def test_migrate_nothing_to_do(vsc, run_main):
    _write_servers(vsc, [_srv("a", "lab")])
    before = open(vsc._SERVERS_FILE, "rb").read()
    rc, out, err, _ = _migrate(run_main)
    assert rc == 0, err
    assert "nothing to migrate" in out.lower()
    assert open(vsc._SERVERS_FILE, "rb").read() == before
    assert _backups(vsc) == []


def test_migrate_without_keyring_exits_1(vsc, run_main, monkeypatch):
    monkeypatch.setattr(vsc, "_KEYRING_AVAILABLE", False)
    _write_servers(vsc, [_srv("a", "lab", SECRET)])
    before = open(vsc._SERVERS_FILE, "rb").read()
    rc, out, err, _ = _migrate(run_main)
    assert rc == 1
    assert "keyring" in err.lower()
    assert open(vsc._SERVERS_FILE, "rb").read() == before
    assert _backups(vsc) == []


def test_migrate_with_fail_backend_exits_1(vsc, run_main, fake_keyring, monkeypatch):
    fail_cls = type("Keyring", (), {"__module__": "keyring.backends.fail"})
    monkeypatch.setattr(fake_keyring, "get_keyring", lambda: fail_cls())
    _write_servers(vsc, [_srv("a", "lab", SECRET)])
    rc, out, err, _ = _migrate(run_main)
    assert rc == 1
    assert fake_keyring.store == {}


@pytest.mark.parametrize("extra", [[], ["--json"], ["--dry-run"], ["--dry-run", "--json"]])
def test_migrate_output_never_contains_secret(vsc, run_main, fake_keyring, caplog, extra):
    import logging
    caplog.set_level(logging.DEBUG)
    fake_keyring.store[(SVC, "c")] = "conflicting-" + SECRET
    _write_servers(vsc, [_srv("a", "lab", SECRET), _srv("c", "clash", SECRET)])
    rc, out, err, _ = _migrate(run_main, *extra)
    assert rc == 1, err  # the "clash" entry is a conflict
    assert "lab.example" in out and "clash.example" in out  # per-server rows were printed
    blob = out + err + caplog.text
    for needle in (SECRET, SECRET_B64, "conflicting-"):
        assert needle not in blob
    if "--json" in extra:
        doc = json.loads(out)
        keys = {k for r in doc["results"] for k in r}
        assert keys == {"id", "name", "server", "outcome", "detail"}
        assert all(len(SECRET) not in (v,) for r in doc["results"] for v in r.values())


def test_help_mentions_migrate_flag(vsc, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["vcd_shadow_cleaner.py", "--help"])
    with pytest.raises(SystemExit) as e:
        vsc.main()
    assert e.value.code == 0
    assert "--migrate-credentials" in capsys.readouterr().out
