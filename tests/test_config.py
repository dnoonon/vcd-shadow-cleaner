"""Saved-server store: keyring fallback (I17), 0600 atomic writes (I18-lite), host (I16)."""
import base64
import json
import os
import stat
import types

import pytest

from helpers import S, T, Resp, paged


def _write_servers(vsc, servers, mode=0o644):
    os.makedirs(vsc._CONFIG_DIR, exist_ok=True)
    with open(vsc._SERVERS_FILE, "w") as f:
        json.dump(servers, f)
    os.chmod(vsc._SERVERS_FILE, mode)


def test_keyring_miss_falls_back_to_base64_store(vsc, monkeypatch):
    _write_servers(vsc, [{"id": "abc", "name": "lab", "server": "vcd.example",
                          "_credential_b64": base64.b64encode(b"s3cret").decode()}])
    fake_keyring = types.SimpleNamespace(get_password=lambda service, sid: None)
    monkeypatch.setattr(vsc, "_KEYRING_AVAILABLE", True)
    monkeypatch.setattr(vsc, "keyring", fake_keyring, raising=False)
    assert vsc._get_credential("abc") == "s3cret"


def test_keyring_value_wins(vsc, monkeypatch):
    _write_servers(vsc, [{"id": "abc", "_credential_b64": base64.b64encode(b"old").decode()}])
    monkeypatch.setattr(vsc, "_KEYRING_AVAILABLE", True)
    monkeypatch.setattr(vsc, "keyring", types.SimpleNamespace(get_password=lambda s, i: "fromkeyring"),
                        raising=False)
    assert vsc._get_credential("abc") == "fromkeyring"


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_persist_writes_0600_and_fixes_existing_mode(vsc):
    _write_servers(vsc, [{"id": "old"}], mode=0o644)
    vsc._persist_saved_servers([{"id": "new", "name": "x"}])
    mode = stat.S_IMODE(os.stat(vsc._SERVERS_FILE).st_mode)
    assert mode == 0o600
    with open(vsc._SERVERS_FILE) as f:
        assert json.load(f) == [{"id": "new", "name": "x"}]
    leftovers = [n for n in os.listdir(vsc._CONFIG_DIR) if n != "servers.json"]
    assert leftovers == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_persist_new_file_is_0600(vsc):
    vsc._persist_saved_servers([])
    assert stat.S_IMODE(os.stat(vsc._SERVERS_FILE).st_mode) == 0o600


def test_persist_is_atomic_on_failure(vsc):
    _write_servers(vsc, [{"id": "keep"}])

    class Unserializable:
        pass

    with pytest.raises(TypeError):
        vsc._persist_saved_servers([{"id": Unserializable()}])
    with open(vsc._SERVERS_FILE) as f:
        assert json.load(f) == [{"id": "keep"}]
    assert [n for n in os.listdir(vsc._CONFIG_DIR) if n != "servers.json"] == []


def test_saved_server_with_scheme_is_normalized(vsc, run_main):
    _write_servers(vsc, [{"id": "abc", "name": "lab", "server": "https://vcd.example/", "auth_type": "token",
                          "_credential_b64": base64.b64encode(b"tok").decode()}])
    routes = {
        "POST": lambda call: Resp(200, {"access_token": "x"}),
        "adminCatalog": paged([{"name": "Gold", "href": "c", "orgName": "OrgA"}]),
        "datastore": paged([{"name": "ds1", "href": "d"}]),
        "adminVAppTemplate": paged([]),
        "adminShadowVM": paged([]),
    }
    rc, out, err, s = run_main(["--saved-server", "lab", "--catalog", "Gold", "--datastore", "ds1",
                                "--dry-run"], routes)
    assert rc == 0, err
    assert s.calls and all(c.host == "vcd.example" for c in s.calls)
