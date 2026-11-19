"""Shared fixtures.

The module under test is loaded from VSC_MODULE_PATH when set (used to run the suite
against an older copy of vcd_shadow_cleaner.py), else from the repo root.
"""
import importlib.util
import io
import json
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = os.environ.get("VSC_MODULE_PATH") or str(ROOT / "vcd_shadow_cleaner.py")

_module = None


def load_module():
    global _module
    if _module is None:
        spec = importlib.util.spec_from_file_location("vcd_shadow_cleaner", MODULE_PATH)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["vcd_shadow_cleaner"] = mod
        spec.loader.exec_module(mod)
        _module = mod
    return _module


@pytest.fixture(scope="session")
def vsc():
    return load_module()


@pytest.fixture(autouse=True)
def _isolate(vsc, monkeypatch, tmp_path):
    """No real terminal, no real sleeping, no real config dir, no VCD_* env vars."""
    for var in ("VCD_SERVER", "VCD_TOKEN", "VCD_USER", "VCD_PASSWORD", "VCD_TENANT",
                "VCD_CATALOG", "VCD_DATASTORE", "VCD_SKIP_SSL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)
    cfg = tmp_path / "config"
    monkeypatch.setattr(vsc, "_CONFIG_DIR", str(cfg))
    monkeypatch.setattr(vsc, "_SERVERS_FILE", str(cfg / "servers.json"))
    monkeypatch.setattr(vsc, "_open_tty", lambda: None, raising=False)
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))


@pytest.fixture
def sleeps(monkeypatch):
    """Record every time.sleep() instead of waiting."""
    calls = []
    monkeypatch.setattr(time, "sleep", lambda s: calls.append(s))
    return calls


@pytest.fixture
def run_main(vsc, monkeypatch, capsys, sleeps):
    """Run vsc.main() with argv against a FakeSession; returns (rc, stdout, stderr, session)."""
    from helpers import FakeSession

    def _run(argv, routes, stdin=None):
        session = FakeSession(routes)
        monkeypatch.setattr(vsc.requests, "Session", lambda: session)
        monkeypatch.setattr(sys, "argv", ["vcd_shadow_cleaner.py"] + list(argv))
        if stdin is not None:
            monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
        try:
            rc = vsc.main()
        except SystemExit as e:
            rc = e.code
        out, err = capsys.readouterr()
        return rc, out, err, session

    return _run


def parse_json(out):
    return json.loads(out)
