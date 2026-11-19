#!/usr/bin/env python3
"""
VMware Cloud Director Shadow VM Cleanup Tool
Author: Burke Azbill
Last Update: 2025-12-16
Description:
A cross-platform GUI application for managing Shadow VMs in VMware Cloud Director.
Supports system tenant (provider) login with the ability to switch to specific tenants.

Requirements:
    - Python 3.8+
    - PySide6
    - requests

Usage:
    GUI Mode:   python vcd_shadow_cleaner.py
    CLI Mode:   python vcd_shadow_cleaner.py --cli --server <vcd_host> --token <api_token>
                    --tenant <tenant_name> --catalog <catalog_name> --datastore <datastore_name>
                    [--dry-run] [--json]
                python vcd_shadow_cleaner.py --cli --saved-server <name> \
                    --catalog <catalog_name> --datastore <datastore_name>
                python vcd_shadow_cleaner.py --cli --list-servers
                python vcd_shadow_cleaner.py --migrate-credentials [--dry-run] [--json]
                python vcd_shadow_cleaner.py --cli --saved-server <name> \
                    [--list-tenants] [--list-catalogs] [--list-datastores]
"""

import argparse
import contextlib
import sys
import json
import logging
import re
import tempfile
import urllib3
import os
import time
import uuid
import base64
from urllib.parse import quote, urlencode, urljoin

try:
    import keyring
    _KEYRING_AVAILABLE = True
except ImportError:
    _KEYRING_AVAILABLE = False

_CONFIG_DIR = os.path.expanduser("~/.vcd-shadow-cleaner")
_SERVERS_FILE = os.path.join(_CONFIG_DIR, "servers.json")
_KEYRING_SERVICE = "vcd-shadow-cleaner"

from dataclasses import dataclass, field
from typing import Optional, List, Set, Tuple, Callable
from datetime import datetime, timezone

import requests

# Suppress SSL warnings for development (should be removed in production)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_logger = logging.getLogger("vcd_shadow_cleaner")

# ---- HTTP behaviour ----
HTTP_TIMEOUT = (10, 60)                      # (connect, read) seconds, on every request
RETRY_STATUSES = frozenset({429, 502, 503, 504})
GET_MAX_ATTEMPTS = 3                         # GETs only; never retried for POST/DELETE
RETRY_BACKOFF_SECONDS = 1.0                  # 1 s, 2 s, ... (Retry-After honoured, capped)
PAGE_SIZE = 100
MAX_PAGES = 10000

# ---- Delete behaviour ----
DELETE_DELAY_SECONDS = 3                     # pause between deletes (VCD rate limits)
MAX_CONSECUTIVE_DELETE_FAILURES = 3
TASK_POLL_INTERVAL_SECONDS = 2.0
TASK_TIMEOUT_SECONDS = 300.0
_TASK_FAILED_STATES = {"error", "aborted", "canceled", "cancelled"}

# ---- CLI exit codes ----
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_AUTH = 3            # authentication failed
EXIT_VCD = 4             # VCD or network error; results incomplete
EXIT_NO_TERMINAL = 5     # delete refused: no terminal to confirm on
EXIT_DELETE_FAILED = 7   # some deletes failed, timed out, or were skipped after a stop

MATCH_EXACT = "exact"
MATCH_NAME = "name"
MATCH_SUBSTRING = "substring"
WEAK_MATCHES = (MATCH_NAME, MATCH_SUBSTRING)


def _sleep(seconds: float) -> None:
    """Indirection so tests can skip real waiting."""
    time.sleep(seconds)


def _monotonic() -> float:
    return time.monotonic()


def normalize_host(host: Optional[str]) -> str:
    """Strip whitespace, an http(s):// scheme and trailing slashes from a server address."""
    h = (host or "").strip()
    low = h.lower()
    for scheme in ("https://", "http://"):
        if low.startswith(scheme):
            h = h[len(scheme):]
            break
    return h.rstrip("/")


class VCDError(Exception):
    """Base error for VCD calls. Carries the stage, the target and the HTTP status."""

    def __init__(self, message: str, *, stage: str = "", target: str = "", status: Optional[int] = None):
        super().__init__(message)
        self.stage = stage
        self.target = target
        self.status = status

    def to_dict(self) -> dict:
        return {
            "type": type(self).__name__,
            "stage": self.stage,
            "target": self.target,
            "http_status": self.status,
            "message": str(self),
        }


class VCDAuthError(VCDError):
    """Authentication failed (bad credentials, or no access token returned)."""


class VCDQueryError(VCDError):
    """A VCD request failed: HTTP error, network error, bad response, or incomplete paging."""


# Characters that VCD's query filter syntax may interpret. A name containing one is
# never sent in a server-side filter; the records are filtered client-side instead.
_FIQL_SPECIAL = set(';,()=!<>~*"\'\\')
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# Token boundaries for name/substring matching.
_NAME_BOUNDARY = set("-_ .()")


def _fiql_safe(value: str) -> bool:
    return bool(value) and not any(c in _FIQL_SPECIAL for c in value)


def _ref_key(value) -> str:
    """Comparable key for an href/urn/name: the embedded UUID if any, else the lower-cased string."""
    s = str(value or "").strip().lower().rstrip("/")
    m = _UUID_RE.search(s)
    return m.group(0) if m else s


def _looks_like_ref(value) -> bool:
    return isinstance(value, str) and (
        value.startswith("http://") or value.startswith("https://")
        or value.startswith("urn:") or "/api/" in value
    )


def _scope_check(record: dict, ident: dict, pairs) -> Optional[bool]:
    """Compare a record with a discovered identity.

    pairs: (record_field, identity_field) tuples. Returns True when every comparable
    pair matches, False when one differs, None when no pair could be compared.
    """
    compared = False
    for rec_key, ident_key in pairs:
        rv = record.get(rec_key)
        iv = ident.get(ident_key)
        if not rv or not iv or iv == "N/A":
            continue
        if rec_key.endswith("Name") and _looks_like_ref(iv):
            continue  # display fallback holds an href, not a name
        compared = True
        if _ref_key(rv) != _ref_key(iv):
            return False
    return True if compared else None


def load_env_file(env_path: str = ".env"):
    """
    Load environment variables from a .env file if it exists.
    Simple implementation to avoid external dependencies.
    """
    if not os.path.exists(env_path):
        return

    try:
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Split on first =
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip()

                    # Remove quotes if present
                    if (value.startswith('"') and value.endswith('"')) or \
                       (value.startswith("'") and value.endswith("'")):
                        value = value[1:-1]

                    # Set env var if not already set
                    if key not in os.environ:
                        os.environ[key] = value
    except Exception as e:
        print(f"Warning: Failed to load .env file: {e}", file=sys.stderr)


def _load_saved_servers() -> list:
    if not os.path.exists(_SERVERS_FILE):
        return []
    try:
        with open(_SERVERS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


def _persist_saved_servers(servers: list) -> None:
    """Write servers.json atomically (temp file + rename) with mode 0600."""
    os.makedirs(_CONFIG_DIR, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=_CONFIG_DIR, prefix=".servers.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(servers, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, _SERVERS_FILE)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise
    with contextlib.suppress(OSError):
        os.chmod(_SERVERS_FILE, 0o600)


def _base64_warning_text() -> str:
    """User-facing explanation of the base64 fallback and how to fix it."""
    if _KEYRING_AVAILABLE:
        fix = ("The system keyring could not be used. Fix the keyring backend, then run "
               "'python vcd_shadow_cleaner.py --migrate-credentials' to move stored credentials into it.")
    else:
        fix = ("Install the keyring package ('pip install keyring'), then run "
               "'python vcd_shadow_cleaner.py --migrate-credentials' to move stored credentials into "
               "the system keyring.")
    return (f"Saved-server credentials are stored base64-encoded (NOT encrypted) in {_SERVERS_FILE}. "
            f"Anyone who can read that file can recover them. {fix}")


# One warning per process, whichever path (read or write) hits the fallback first.
_base64_warning_shown = False


def _warn_base64_once(show: Optional[Callable[[str], None]] = None) -> bool:
    """Show the base64-fallback warning once per process. Returns True if shown now.

    `show` receives the message (the GUI passes a dialog); the default prints to stderr.
    """
    global _base64_warning_shown
    if _base64_warning_shown:
        return False
    _base64_warning_shown = True
    text = _base64_warning_text()
    if show is None:
        print(f"WARNING: {text}", file=sys.stderr)
    else:
        show(text)
    return True


def _b64_entry_credential(server_id: str) -> Optional[str]:
    """Decode the base64 credential stored for server_id, or None if there is none."""
    for s in _load_saved_servers():
        if s.get("id") == server_id:
            raw = s.get("_credential_b64", "")
            if raw:
                try:
                    return base64.b64decode(raw.encode()).decode()
                except Exception:
                    return None
            return None
    return None


def _remove_b64_credential(server_id: str) -> bool:
    """Drop any `_credential_b64` for server_id from servers.json. Returns True if removed."""
    servers = _load_saved_servers()
    changed = False
    for s in servers:
        if s.get("id") == server_id and "_credential_b64" in s:
            s.pop("_credential_b64", None)
            changed = True
    if changed:
        _persist_saved_servers(servers)
    return changed


def _get_credential_with_source(server_id: str) -> Tuple[str, str]:
    """Return (credential, source) where source is "keyring", "base64" or "" (none found).

    Tries the keyring first and falls back to the base64 store in servers.json when
    the keyring is unavailable, fails, or has nothing for this server.
    """
    if _KEYRING_AVAILABLE:
        try:
            result = keyring.get_password(_KEYRING_SERVICE, server_id)
            if result:
                return result, "keyring"
        except Exception:
            pass
    value = _b64_entry_credential(server_id)
    if value:
        return value, "base64"
    return "", ""


def _get_credential(server_id: str) -> str:
    """Return stored password/token for a saved server, or empty string (keyring, then base64)."""
    return _get_credential_with_source(server_id)[0]


def _set_credential(server_id: str, credential: str) -> str:
    """Store password/token for a saved server. Returns the store used: "keyring" or "base64".

    On a successful keyring write any leftover base64 copy in servers.json is removed.
    """
    if _KEYRING_AVAILABLE:
        try:
            keyring.set_password(_KEYRING_SERVICE, server_id, credential)
        except Exception:
            pass
        else:
            _remove_b64_credential(server_id)
            return "keyring"
    # fallback: base64 in JSON
    servers = _load_saved_servers()
    for s in servers:
        if s.get("id") == server_id:
            s["_credential_b64"] = base64.b64encode(credential.encode()).decode()
            break
    _persist_saved_servers(servers)
    return "base64"


def _delete_credential(server_id: str) -> None:
    """Remove the stored credential for a saved server from the keyring and servers.json."""
    if _KEYRING_AVAILABLE:
        try:
            keyring.delete_password(_KEYRING_SERVICE, server_id)
        except Exception:
            pass
    _remove_b64_credential(server_id)


def _gui_warn_base64_once(parent) -> bool:
    """GUI flavour of _warn_base64_once: a warning dialog, once per process."""
    from PySide6.QtWidgets import QMessageBox
    return _warn_base64_once(
        lambda text: QMessageBox.warning(parent, "Credentials not encrypted", text))


def _keyring_usable() -> bool:
    """True when the keyring module is importable and has a real (non-"fail") backend."""
    if not _KEYRING_AVAILABLE:
        return False
    get_keyring = getattr(keyring, "get_keyring", None)
    if get_keyring is None:
        return True
    try:
        backend = get_keyring()
    except Exception:
        return False
    return "keyring.backends.fail" not in type(backend).__module__


def _backup_servers_file() -> str:
    """Copy servers.json to servers.json.bak-<UTC timestamp> with mode 0600; return the path."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    with open(_SERVERS_FILE, "rb") as f:
        data = f.read()
    base = f"{_SERVERS_FILE}.bak-{stamp}"
    path, n = base, 0
    while True:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            break
        except FileExistsError:
            n += 1
            path = f"{base}-{n}"
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)
    return path


def migrate_credentials(dry_run: bool = False) -> dict:
    """Move base64 credentials from servers.json into the system keyring.

    Per server with `_credential_b64`: if the keyring already holds the same value the base64
    copy is dropped (already_in_keyring_same); if it holds a different value nothing changes
    (conflict); otherwise the value is written, read back, and the base64 copy dropped only
    when the read-back matches (migrated), else kept (failed). servers.json is backed up first
    and written once at the end. The result never contains a credential value or its length.
    """
    servers = _load_saved_servers()
    results = []
    candidates = [s for s in servers if isinstance(s, dict) and s.get("_credential_b64")]
    skipped = len(servers) - len(candidates)
    backup = None
    if candidates and not dry_run:
        backup = _backup_servers_file()
    changed = False
    for s in candidates:
        sid = s.get("id", "")
        row = {"id": sid, "name": s.get("name", ""), "server": s.get("server", ""),
               "outcome": "", "detail": ""}
        results.append(row)
        try:
            value = base64.b64decode(str(s["_credential_b64"]).encode()).decode()
        except Exception:
            value = ""
        if not value:
            row["outcome"], row["detail"] = "failed", "stored base64 value could not be decoded"
            continue
        if not sid:
            row["outcome"], row["detail"] = "failed", "entry has no id"
            continue
        try:
            existing = keyring.get_password(_KEYRING_SERVICE, sid)
        except Exception as e:
            row["outcome"], row["detail"] = "failed", f"keyring read failed ({type(e).__name__})"
            continue
        if existing:
            if existing == value:
                row["outcome"] = "already_in_keyring_same"
                if not dry_run:
                    s.pop("_credential_b64", None)
                    changed = True
                    row["detail"] = "base64 copy removed"
                else:
                    row["detail"] = "base64 copy would be removed"
            else:
                row["outcome"] = "conflict"
                row["detail"] = "keyring holds a different value; both left unchanged"
            continue
        if dry_run:
            row["outcome"] = "would_migrate"
            continue
        try:
            keyring.set_password(_KEYRING_SERVICE, sid, value)
            readback = keyring.get_password(_KEYRING_SERVICE, sid)
        except Exception as e:
            row["outcome"], row["detail"] = "failed", f"keyring write failed ({type(e).__name__})"
            continue
        if readback == value:
            s.pop("_credential_b64", None)
            changed = True
            row["outcome"] = "migrated"
        else:
            # Don't leave a wrong keyring value in front of the good base64 copy.
            with contextlib.suppress(Exception):
                keyring.delete_password(_KEYRING_SERVICE, sid)
            row["outcome"] = "failed"
            row["detail"] = "keyring read-back did not match; base64 copy kept"
    if changed:
        _persist_saved_servers(servers)
    ok = all(r["outcome"] in ("migrated", "already_in_keyring_same", "would_migrate") for r in results)
    return {"servers_file": _SERVERS_FILE, "dry_run": dry_run, "backup": backup,
            "results": results, "skipped_without_base64": skipped, "ok": ok}


def _find_saved_server(name_or_id: str) -> Optional[dict]:
    """Look up a saved server profile by id, display name, or hostname."""
    servers = _load_saved_servers()
    for s in servers:
        if s.get("id") == name_or_id:
            return s
    needle = name_or_id.strip().lower()
    for s in servers:
        if s.get("name", "").strip().lower() == needle:
            return s
    host_needle = normalize_host(name_or_id).lower()
    for s in servers:
        if normalize_host(s.get("server", "")).lower() == host_needle:
            return s
    return None


@dataclass
class ShadowVM:
    """Represents a Shadow VM in VCD."""
    name: str
    href: str
    container_name: str  # Parent vApp Template name (if resolved)
    container_id: str    # Parent vApp Template ID/HREF (any reference field the record carries)
    datastore_name: str
    vm_id: str
    primary_vm_href: str # Link to the primary VM
    catalog_name: str = ""
    vcd_server: str = ""
    org_name: str = ""
    # Authoritative parent template reference (primaryVAppTemplate / vAppTemplate), if any
    parent_ref: str = ""
    # True when container_name came from a record field rather than the shadow's name
    container_name_from_field: bool = False
    datastore_href: str = ""
    vc_name: str = ""
    # Match evidence, filled in by scan_shadow_vms
    match_strength: str = ""     # exact | name | substring
    match_rule: str = ""         # parent_ref | container_name | name_prefix | name_token
    template_href: str = ""      # href of the matched template
    ambiguous_with: List[dict] = field(default_factory=list)

    @property
    def is_weak(self) -> bool:
        return self.match_strength in WEAK_MATCHES


@dataclass
class VAppTemplate:
    """Represents a vApp Template in VCD."""
    name: str
    href: str
    id: str
    catalog_name: str
    org_href: str = ""
    org_name: str = ""
    catalog_href: str = ""


@dataclass
class DeleteResult:
    """Outcome of one shadow VM delete.

    status: deleted (VCD confirmed: 204 or task success), accepted_unverified (accepted,
    no task to confirm), failed, timeout (task did not finish in time), skipped (not tried).
    """
    shadow: ShadowVM
    status: str
    message: str
    http_status: Optional[int] = None
    task_href: str = ""
    task_status: str = ""

    @property
    def ok(self) -> bool:
        return self.status in ("deleted", "accepted_unverified")

    def to_dict(self) -> dict:
        return {
            "name": self.shadow.name,
            "href": self.shadow.href,
            "status": self.status,
            "success": self.ok,
            "message": self.message,
            "http_status": self.http_status,
            "task": {"href": self.task_href, "status": self.task_status} if self.task_href else None,
        }


@dataclass
class DeleteRun:
    results: List[DeleteResult] = field(default_factory=list)
    stopped_reason: str = ""

    def count(self, *statuses) -> int:
        return sum(1 for r in self.results if r.status in statuses)

    @property
    def deleted(self) -> int:
        return self.count("deleted")

    @property
    def unverified(self) -> int:
        return self.count("accepted_unverified")

    @property
    def failed(self) -> int:
        return self.count("failed", "timeout")

    @property
    def skipped(self) -> int:
        return self.count("skipped")


@dataclass
class ScanResult:
    """Result of scan_shadow_vms: matched shadows plus the scan's completeness."""
    shadows: List[ShadowVM] = field(default_factory=list)   # exact + weak matches
    other_template: int = 0       # parent reference set, pointing at an unselected template
    unmatched: int = 0            # no parent reference and no name match
    errors: List[dict] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.errors

    @property
    def counts(self) -> dict:
        exact = sum(1 for s in self.shadows if s.match_strength == MATCH_EXACT)
        name = sum(1 for s in self.shadows if s.match_strength == MATCH_NAME)
        sub = sum(1 for s in self.shadows if s.match_strength == MATCH_SUBSTRING)
        return {
            "exact": exact,
            "name": name,
            "substring": sub,
            "weak": name + sub,
            "ambiguous": sum(1 for s in self.shadows if s.ambiguous_with),
            "other_template": self.other_template,
            "unmatched": self.unmatched,
        }

    def extend(self, other: "ScanResult") -> None:
        self.shadows.extend(other.shadows)
        self.other_template += other.other_template
        self.unmatched += other.unmatched
        self.errors.extend(other.errors)
        self.warnings.extend(other.warnings)


def format_error(err) -> str:
    if isinstance(err, dict):
        prefix = f"[{err['server']}] " if err.get("server") else ""
        return prefix + str(err.get("message", err))
    return str(err)


class VCDClient:
    """VMware Cloud Director API Client."""

    def __init__(self, host: str, verify_ssl: bool = False):
        self.host = normalize_host(host)
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.access_token: Optional[str] = None
        self.api_version = "38.0"  # VCD API version
        self.current_org: Optional[str] = None

    def _url(self, path: str) -> str:
        return f"https://{self.host}{path}"

    def _get_headers(self) -> dict:
        """Get common API headers."""
        headers = {
            "Accept": f"application/*+json;version={self.api_version}",
            "Content-Type": "application/json"
        }
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        return headers

    # ---- low-level HTTP ----

    def _request(self, method: str, url: str, *, stage: str, target: str, params=None,
                 headers: Optional[dict] = None, retry: Optional[bool] = None, **kwargs):
        """Send one request with a timeout. GETs are retried on 429/502/503/504.

        Returns the response (any status). Network errors raise VCDQueryError.
        """
        if headers is None:
            headers = self._get_headers()
        if isinstance(params, dict):
            # Encode every value (spaces as %20, & and # escaped); keep '==' readable.
            params = urlencode(params, quote_via=quote, safe="=")
        method = method.upper()
        retryable = (method == "GET") if retry is None else retry
        attempts = GET_MAX_ATTEMPTS if retryable else 1
        for attempt in range(1, attempts + 1):
            try:
                resp = self.session.request(method, url, params=params, headers=headers,
                                            timeout=HTTP_TIMEOUT, **kwargs)
            except requests.exceptions.RequestException as e:
                raise VCDQueryError(f"{stage} failed for {target}: {type(e).__name__}: {e}",
                                    stage=stage, target=target) from e
            if resp.status_code in RETRY_STATUSES and attempt < attempts:
                delay = RETRY_BACKOFF_SECONDS * (2 ** (attempt - 1))
                retry_after = (getattr(resp, "headers", None) or {}).get("Retry-After")
                if retry_after and str(retry_after).isdigit():
                    delay = min(float(retry_after), 30.0)
                _logger.debug("%s %s -> HTTP %s; retry %d/%d in %.1fs",
                              method, url, resp.status_code, attempt, attempts - 1, delay)
                _sleep(delay)
                continue
            return resp
        return resp  # pragma: no cover - loop always returns

    @staticmethod
    def _body_snippet(resp, limit: int = 300) -> str:
        try:
            text = resp.text or ""
        except Exception:
            text = ""
        text = " ".join(str(text).split())
        return text[:limit]

    def _raise_for_status(self, resp, stage: str, target: str) -> None:
        if resp.status_code >= 400:
            snippet = self._body_snippet(resp)
            raise VCDQueryError(
                f"{stage} failed for {target}: HTTP {resp.status_code}" + (f": {snippet}" if snippet else ""),
                stage=stage, target=target, status=resp.status_code,
            )

    def _get_json(self, url: str, *, stage: str, target: str, params=None) -> dict:
        resp = self._request("GET", url, stage=stage, target=target, params=params)
        self._raise_for_status(resp, stage, target)
        try:
            data = resp.json()
        except ValueError as e:
            raise VCDQueryError(f"{stage} failed for {target}: response is not JSON",
                                stage=stage, target=target, status=resp.status_code) from e
        if not isinstance(data, dict):
            raise VCDQueryError(f"{stage} failed for {target}: unexpected response shape",
                                stage=stage, target=target, status=resp.status_code)
        return data

    def _query_records(self, query_type: str, *, stage: str, target: str,
                       filters: Optional[List[Tuple[str, str]]] = None) -> List[dict]:
        """Fetch every record of a typed query, page by page, sorted by name.

        Paging continues while fetched < total. A failure on any page raises; a partial
        list is never returned. Filter values with filter-syntax characters are not sent
        (callers filter those records client-side).
        """
        params = {"type": query_type, "format": "records", "pageSize": PAGE_SIZE, "sortAsc": "name"}
        fiql = [f"{fld}=={val}" for fld, val in (filters or []) if _fiql_safe(val)]
        if fiql:
            params["filter"] = ";".join(fiql)
        skipped = [val for _, val in (filters or []) if not _fiql_safe(val)]
        if skipped:
            _logger.debug("query %s: not sending filter values %r server-side; filtering client-side",
                          query_type, skipped)
        url = self._url("/api/query")
        records: List[dict] = []
        page = 1
        while True:
            params["page"] = page
            data = self._get_json(url, stage=stage, target=f"{target} (page {page})", params=params)
            page_records = data.get("record") or []
            if not isinstance(page_records, list):
                raise VCDQueryError(f"{stage} failed for {target}: 'record' is not a list",
                                    stage=stage, target=target)
            records.extend(page_records)
            try:
                total = int(data["total"])
            except (KeyError, TypeError, ValueError):
                total = None
            if total is None:
                if not page_records:
                    break
            else:
                if len(records) >= total:
                    break
                if not page_records:
                    raise VCDQueryError(
                        f"{stage} failed for {target}: paging stopped at page {page} with "
                        f"{len(records)} of {total} records",
                        stage=stage, target=target,
                    )
            page += 1
            if page > MAX_PAGES:
                raise VCDQueryError(f"{stage} failed for {target}: more than {MAX_PAGES} pages",
                                    stage=stage, target=target)
        return records

    # ---- authentication ----

    @staticmethod
    def _auth_user(username: str, org: str) -> str:
        if "@" in username:
            return username
        return f"{username}@{'system' if org.lower() == 'system' else org}"

    def authenticate_with_token(self, api_token: str, org: str = "system") -> bool:
        """
        Authenticate to VCD using an API token (refresh token).

        Returns True on success. Raises VCDAuthError when VCD rejects the token or
        returns no access_token, VCDQueryError on network/server errors.
        """
        if org.lower() == "system":
            uri = self._url("/oauth/provider/token")
        else:
            uri = self._url(f"/oauth/tenant/{quote(org, safe='')}/token")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        resp = self._request("POST", uri, stage="auth", target="token", headers=headers,
                             data={"grant_type": "refresh_token", "refresh_token": api_token})
        if resp.status_code in (400, 401, 403):
            raise VCDAuthError(f"Token authentication failed: HTTP {resp.status_code}",
                               stage="auth", target="token", status=resp.status_code)
        self._raise_for_status(resp, "auth", "token")
        try:
            data = resp.json()
        except ValueError:
            data = {}
        token = data.get("access_token") if isinstance(data, dict) else None
        if not token:
            raise VCDAuthError("Token authentication failed: the server returned no access_token",
                               stage="auth", target="token", status=resp.status_code)
        self.access_token = token
        self.current_org = org
        return True

    def authenticate_with_credentials(self, username: str, password: str, org: str = "system") -> bool:
        """
        Authenticate to VCD using username and password.

        Tries CloudAPI sessions (VCD 10.x+), then legacy /api/sessions. Returns True on
        success; raises VCDAuthError if both fail, VCDQueryError on network errors.
        """
        failures = []
        try:
            return self._authenticate_cloudapi(username, password, org)
        except VCDAuthError as e:
            failures.append(str(e))
        try:
            return self._authenticate_legacy(username, password, org)
        except VCDAuthError as e:
            failures.append(str(e))
        raise VCDAuthError("All authentication methods failed: " + "; ".join(failures), stage="auth",
                           target="credentials")

    def _authenticate_cloudapi(self, username: str, password: str, org: str = "system") -> bool:
        """
        Modern CloudAPI authentication using /cloudapi/1.0.0/sessions.
        Works with VCD 10.x and later.
        """
        if org.lower() == "system":
            uri = self._url("/cloudapi/1.0.0/sessions/provider")
        else:
            uri = self._url("/cloudapi/1.0.0/sessions")
        credentials = base64.b64encode(f"{self._auth_user(username, org)}:{password}".encode()).decode()
        headers = {
            "Accept": f"application/json;version={self.api_version}",
            "Content-Type": "application/json",
            "Authorization": f"Basic {credentials}",
        }
        resp = self._request("POST", uri, stage="auth", target="cloudapi session", headers=headers)
        if resp.status_code >= 400:
            raise VCDAuthError(f"CloudAPI authentication failed: HTTP {resp.status_code}",
                               stage="auth", target="cloudapi session", status=resp.status_code)
        token = (resp.headers or {}).get("X-VMWARE-VCLOUD-ACCESS-TOKEN")
        if not token:
            try:
                data = resp.json()
                if isinstance(data, dict):
                    token = data.get("accessToken") or data.get("token")
            except ValueError:
                pass
        if not token:
            raise VCDAuthError("CloudAPI authentication failed: no access token in response",
                               stage="auth", target="cloudapi session", status=resp.status_code)
        self.access_token = token
        self.current_org = org
        return True

    def _authenticate_legacy(self, username: str, password: str, org: str = "system") -> bool:
        """
        Legacy authentication using /api/sessions (for older VCD versions).
        """
        uri = self._url("/api/sessions")
        headers = {"Accept": f"application/*+json;version={self.api_version}"}
        resp = self._request("POST", uri, stage="auth", target="legacy session", headers=headers,
                             auth=(self._auth_user(username, org), password))
        if resp.status_code in (400, 401, 403):
            raise VCDAuthError(f"Legacy authentication failed: HTTP {resp.status_code}",
                               stage="auth", target="legacy session", status=resp.status_code)
        self._raise_for_status(resp, "auth", "legacy session")
        token = (resp.headers or {}).get("X-VMWARE-VCLOUD-ACCESS-TOKEN")
        if not token:
            raise VCDAuthError("Legacy authentication failed: no access token in response",
                               stage="auth", target="legacy session", status=resp.status_code)
        self.access_token = token
        self.current_org = org
        return True

    # ---- discovery ----

    def get_organizations(self) -> List[dict]:
        """Get list of organizations (tenants) visible to the authenticated user."""
        data = self._get_json(self._url("/api/org"), stage="organizations", target="/api/org")
        orgs = []
        for org in data.get("org", []) or []:
            orgs.append({
                "name": org.get("name"),
                "href": org.get("href")
            })
        return sorted(orgs, key=lambda x: x.get("name") or "")

    def switch_to_org(self, org_name: str) -> bool:
        """Record the selected organization. Scoping is done by catalog identity in the scan."""
        self.current_org = org_name
        return True

    @staticmethod
    def _catalog_entry(record: dict, shared: Optional[bool] = None) -> dict:
        href = record.get("href", "")
        return {
            "name": record.get("name"),
            "href": href,
            "id": record.get("id") or href,
            "org": record.get("org", "") if _looks_like_ref(record.get("org", "")) else "",
            "orgName": record.get("orgName", record.get("org", "N/A")),
            "isShared": True if shared else record.get("isShared", False),
            "isPublished": True if shared else record.get("isPublished", False),
        }

    def get_catalogs(self, org_name: Optional[str] = None) -> List[dict]:
        """
        Get list of catalogs visible to the authenticated user, with their identity
        (href/id, owning org href and name).

        Args:
            org_name: Optional organization name to filter catalogs by.
                      If provided, only returns catalogs belonging to or shared with that org.

        Raises VCDQueryError on failure (a 403 on adminCatalog falls back to catalog).
        """
        catalogs = []
        scoped = bool(org_name) and org_name.lower() != "system"
        filters = [("orgName", org_name)] if scoped else []

        last_403 = None
        any_succeeded = False
        for query_type in ("adminCatalog", "catalog"):
            try:
                records = self._query_records(query_type, stage="catalogs",
                                              target=f"{query_type} query", filters=filters)
            except VCDQueryError as e:
                if e.status == 403:
                    last_403 = e
                    continue
                raise
            any_succeeded = True
            for record in records:
                if scoped and record.get("orgName") and record.get("orgName").lower() != org_name.lower():
                    continue
                entry = self._catalog_entry(record)
                if not any(
                    (entry["href"] and c["href"] == entry["href"])
                    or (c["name"] == entry["name"] and c["orgName"] == entry["orgName"])
                    for c in catalogs
                ):
                    catalogs.append(entry)
            if catalogs:
                break
        if not any_succeeded and last_403 is not None:
            raise last_403

        # If org filter was applied but we also need shared catalogs, fetch those too
        if scoped:
            shared_catalogs = self._get_shared_catalogs_for_org(org_name)
            for cat in shared_catalogs:
                if not any(c["name"] == cat["name"] for c in catalogs):
                    catalogs.append(cat)

        print(f"Found {len(catalogs)} catalogs for org '{org_name or 'all'}'")
        return sorted(catalogs, key=lambda x: (x.get("orgName") or "", x.get("name") or ""))

    def _get_shared_catalogs_for_org(self, org_name: str) -> List[dict]:
        """Get catalogs that are shared/published and accessible to the specified org.

        A 403 (no rights to the admin query) returns []; other errors raise.
        """
        try:
            records = self._query_records("adminCatalog", stage="catalogs",
                                          target="published catalogs",
                                          filters=[("isPublished", "true")])
        except VCDQueryError as e:
            if e.status == 403:
                return []
            raise
        return [self._catalog_entry(r, shared=True) for r in records]

    def get_datastores(self) -> List[dict]:
        """Get list of datastores with their identity (href, vCenter). Requires provider access."""
        records = self._query_records("datastore", stage="datastores", target="datastore query")
        datastores = []
        for record in records:
            href = record.get("href", "")
            datastores.append({
                "name": record.get("name"),
                "href": href,
                "id": record.get("id") or href,
                "vc": record.get("vc", ""),
                "vcName": record.get("vcName", ""),
                "datastoreType": record.get("datastoreType", "")
            })
        return sorted(datastores, key=lambda x: x.get("name") or "")

    def get_vapp_templates_in_catalog(self, catalog, warnings: Optional[List[str]] = None) -> List[VAppTemplate]:
        """Get all vApp templates in a catalog.

        catalog: a catalog name, or a catalog dict from get_catalogs() (name, href, org,
        orgName). With a dict, template records are kept only if their catalog/org
        reference matches; records without those fields are kept and a warning is added.
        Raises VCDQueryError on failure.
        """
        ident = catalog if isinstance(catalog, dict) else {"name": catalog}
        name = ident.get("name") or ""
        records = self._query_records("adminVAppTemplate", stage="templates",
                                      target=f"catalog '{name}'", filters=[("catalogName", name)])
        has_identity = any(ident.get(k) for k in ("href", "org")) or (
            ident.get("orgName") not in (None, "", "N/A"))
        templates = []
        unscoped = 0
        for record in records:
            if "catalogName" in record and record.get("catalogName") != name:
                continue
            verdict = _scope_check(record, ident, (("catalog", "href"), ("org", "org"),
                                                   ("orgName", "orgName")))
            if verdict is False:
                continue
            if verdict is None:
                unscoped += 1
            org_name = record.get("orgName") or ""
            if not org_name and ident.get("orgName") not in (None, "N/A") \
                    and not _looks_like_ref(ident.get("orgName")):
                org_name = ident.get("orgName") or ""
            templates.append(VAppTemplate(
                name=record.get("name", "") or "",
                href=record.get("href", "") or "",
                id=record.get("id", "") or record.get("href", "") or "",
                catalog_name=record.get("catalogName", "") or name,
                org_href=record.get("org", "") or "",
                org_name=org_name,
                catalog_href=record.get("catalog", "") or ident.get("href", "") or "",
            ))
        if warnings is not None:
            if not has_identity:
                warnings.append(f"catalog '{name}' was given by name only; its templates are not "
                                f"scoped to one org")
            elif unscoped:
                warnings.append(f"catalog '{name}': {unscoped} template record(s) carry no catalog/org "
                                f"reference, so they could not be scoped to this catalog's org; kept")
        return templates

    @staticmethod
    def _shadow_from_record(record: dict) -> ShadowVM:
        name = record.get("name", "") or ""
        # Parent template NAME: a record field (never an href), else the first word of the name.
        field_name = ""
        for key in ("containerName", "container", "vappTemplate", "catalogItem"):
            val = record.get(key)
            if val and isinstance(val, str) and not _looks_like_ref(val):
                field_name = val
                break
        container_name = field_name or (name.split(" ")[0] if " " in name else "")

        # Authoritative parent reference: primaryVAppTemplate / vAppTemplate, or a
        # container/entity reference that points at a vAppTemplate.
        parent_ref = ""
        for key in ("primaryVAppTemplate", "vAppTemplate"):
            val = record.get(key)
            if val and isinstance(val, str):
                parent_ref = val
                break
        container_id = parent_ref
        if not parent_ref:
            for key in ("container", "entity"):
                val = record.get(key)
                if val and _looks_like_ref(val):
                    container_id = container_id or val
                    if "vapptemplate" in val.lower():
                        parent_ref = val
                        container_id = val
                        break
        href = record.get("href", "") or ""
        return ShadowVM(
            name=name,
            href=href,
            container_name=container_name,
            container_id=container_id,
            datastore_name=record.get("datastoreName", "") or "",
            vm_id=href.split("/")[-1] if href else "",
            primary_vm_href=record.get("primaryVM", "") or "",
            parent_ref=parent_ref,
            container_name_from_field=bool(field_name),
            datastore_href=record.get("datastore", "") or "",
            vc_name=record.get("vcName", "") or "",
        )

    def get_shadow_vms_on_datastore(self, datastore, debug: bool = False,
                                    warnings: Optional[List[str]] = None) -> List[ShadowVM]:
        """Get all Shadow VMs on a datastore.

        datastore: a datastore name, or a datastore dict from get_datastores() (name,
        href, vc, vcName). With a dict, records are kept only if their datastore/vCenter
        reference matches; records without those fields are kept and a warning is added.
        Raises VCDQueryError on failure.
        """
        ident = datastore if isinstance(datastore, dict) else {"name": datastore}
        name = ident.get("name") or ""
        records = self._query_records("adminShadowVM", stage="shadow VMs",
                                      target=f"datastore '{name}'", filters=[("datastoreName", name)])
        if debug and records:
            print(f"DEBUG: Sample Shadow VM record fields: {list(records[0].keys())}")
            print(f"DEBUG: Sample Shadow VM record: {records[0]}")
        has_identity = any(ident.get(k) for k in ("href", "vc", "vcName"))
        shadows = []
        unscoped = 0
        for record in records:
            if "datastoreName" in record and record.get("datastoreName") != name:
                continue
            if has_identity:
                verdict = _scope_check(record, ident, (("datastore", "href"), ("vc", "vc"),
                                                       ("vcName", "vcName")))
                if verdict is False:
                    continue
                if verdict is None:
                    unscoped += 1
            shadow = self._shadow_from_record(record)
            if not shadow.datastore_href:
                shadow.datastore_href = ident.get("href", "") or ""
            if not shadow.vc_name:
                shadow.vc_name = ident.get("vcName", "") or ""
            shadows.append(shadow)
        if warnings is not None and unscoped:
            warnings.append(f"datastore '{name}': {unscoped} shadow VM record(s) carry no datastore/"
                            f"vCenter reference, so they could not be scoped to one vCenter; kept")
        return shadows

    # ---- delete ----

    def _task_href_from_response(self, resp) -> str:
        headers = getattr(resp, "headers", None) or {}
        location = headers.get("Location") or headers.get("location")
        if location:
            return urljoin(self._url("/"), location)
        try:
            body = resp.json()
        except Exception:
            body = None
        if isinstance(body, dict):
            for cand in (body, body.get("task") if isinstance(body.get("task"), dict) else None):
                if not cand:
                    continue
                href = cand.get("href") or ""
                ctype = str(cand.get("type") or "").lower()
                if href and ("/task/" in href.lower() or "task" in ctype):
                    return href
        try:
            text = resp.text or ""
        except Exception:
            text = ""
        m = re.search(r"<(?:\w+:)?Task\b[^>]*\shref=\"([^\"]+)\"", str(text))
        return m.group(1) if m else ""

    def _wait_for_task(self, shadow: ShadowVM, task_href: str, http_status: int) -> DeleteResult:
        deadline = _monotonic() + TASK_TIMEOUT_SECONDS
        last = ""
        while True:
            try:
                data = self._get_json(task_href, stage="task", target=f"delete task for {shadow.name}")
            except VCDQueryError as e:
                return DeleteResult(shadow, "accepted_unverified",
                                    f"delete accepted (HTTP {http_status}) but the task could not be "
                                    f"read: {e}", http_status=e.status if e.status in (401, 403) else http_status,
                                    task_href=task_href, task_status=last)
            last = str(data.get("status", "")).strip()
            _logger.debug("task %s status=%r", task_href, last)
            low = last.lower()
            if low == "success":
                return DeleteResult(shadow, "deleted", f"Deleted {shadow.name} (task succeeded)",
                                    http_status=http_status, task_href=task_href, task_status=last)
            if low in _TASK_FAILED_STATES:
                err = data.get("error") if isinstance(data.get("error"), dict) else {}
                detail = err.get("message") or data.get("details") or ""
                return DeleteResult(shadow, "failed",
                                    f"Delete task for {shadow.name} ended '{last}'" + (f": {detail}" if detail else ""),
                                    http_status=http_status, task_href=task_href, task_status=last)
            if _monotonic() >= deadline:
                return DeleteResult(shadow, "timeout",
                                    f"Delete task for {shadow.name} still '{last}' after "
                                    f"{int(TASK_TIMEOUT_SECONDS)} s",
                                    http_status=http_status, task_href=task_href, task_status=last)
            _sleep(TASK_POLL_INTERVAL_SECONDS)

    def delete_shadow_vm(self, shadow_vm: ShadowVM) -> DeleteResult:
        """Delete a Shadow VM and report the real outcome.

        A returned Task (Location header, or a task href in the body) is polled until it
        finishes or TASK_TIMEOUT_SECONDS passes. 204 counts as deleted. 200/202 without a
        task reference is reported as accepted_unverified.
        """
        if not shadow_vm.href:
            return DeleteResult(shadow_vm, "failed", f"Cannot delete {shadow_vm.name}: no href")
        try:
            resp = self._request("DELETE", shadow_vm.href, stage="delete", target=shadow_vm.name,
                                 retry=False)
        except VCDQueryError as e:
            return DeleteResult(shadow_vm, "failed", f"Error deleting {shadow_vm.name}: {e}")
        headers = getattr(resp, "headers", None) or {}
        _logger.debug("DELETE %s -> HTTP %s Location=%r Content-Type=%r body=%r",
                      shadow_vm.href, resp.status_code, headers.get("Location"),
                      headers.get("Content-Type"), self._body_snippet(resp, 500))
        status = resp.status_code
        if status >= 400:
            snippet = self._body_snippet(resp)
            return DeleteResult(shadow_vm, "failed",
                                f"Failed to delete {shadow_vm.name}: HTTP {status}" + (f": {snippet}" if snippet else ""),
                                http_status=status)
        task_href = self._task_href_from_response(resp)
        if task_href:
            return self._wait_for_task(shadow_vm, task_href, status)
        if status == 204:
            return DeleteResult(shadow_vm, "deleted", f"Deleted {shadow_vm.name}", http_status=status)
        return DeleteResult(shadow_vm, "accepted_unverified",
                            f"Delete of {shadow_vm.name} accepted (HTTP {status}), not verified: "
                            f"no task returned", http_status=status)

    def disconnect(self):
        """Disconnect from VCD (best effort; a failed logout is not an error)."""
        try:
            if self.access_token:
                self.session.request("DELETE", self._url("/api/session"), headers=self._get_headers(),
                                     timeout=HTTP_TIMEOUT)
        except Exception:
            pass
        finally:
            self.access_token = None
            self.current_org = None


def delete_shadow_vms(client: VCDClient, shadows: List[ShadowVM], *,
                      delay_seconds: float = DELETE_DELAY_SECONDS,
                      max_consecutive_failures: int = MAX_CONSECUTIVE_DELETE_FAILURES,
                      on_start: Optional[Callable[[int, ShadowVM], None]] = None,
                      on_result: Optional[Callable[[DeleteResult], None]] = None) -> DeleteRun:
    """Delete shadow VMs one by one (shared by the CLI and the GUI).

    Pauses delay_seconds between deletes, stops after max_consecutive_failures failures
    in a row or on any 401/403; the remaining items are reported as skipped.
    """
    run = DeleteRun()
    consecutive = 0
    attempted = 0
    for shadow in shadows:
        if run.stopped_reason:
            result = DeleteResult(shadow, "skipped", f"Not attempted: {run.stopped_reason}")
            run.results.append(result)
            if on_result:
                on_result(result)
            continue
        if attempted:
            _sleep(delay_seconds)
        if on_start:
            on_start(attempted, shadow)
        attempted += 1
        result = client.delete_shadow_vm(shadow)
        run.results.append(result)
        if on_result:
            on_result(result)
        if result.http_status in (401, 403):
            run.stopped_reason = (f"stopped after HTTP {result.http_status} (not authorized); "
                                  f"remaining deletes skipped")
        elif result.ok:
            consecutive = 0
        else:
            consecutive += 1
            if consecutive >= max_consecutive_failures:
                run.stopped_reason = (f"stopped after {consecutive} consecutive failures; "
                                      f"remaining deletes skipped")
    return run


def _match_templates(shadow: ShadowVM, ordered: List[VAppTemplate]):
    """Return (strength, rule, winner, others) for name/substring matching, or None.

    ordered: templates sorted longest name first (ties by name, then catalog order),
    empty names already removed. Matches only on token boundaries.
    """
    def boundary_pos(text: str, sub: str) -> int:
        i = text.find(sub)
        while i != -1:
            end = i + len(sub)
            if (i == 0 or text[i - 1] in _NAME_BOUNDARY) and (end == len(text) or text[end] in _NAME_BOUNDARY):
                return i
            i = text.find(sub, i + 1)
        return -1

    if shadow.container_name_from_field and shadow.container_name:
        hits = [t for t in ordered if t.name == shadow.container_name]
        if hits:
            others = hits[1:] + [t for t in ordered
                                 if all(t is not h for h in hits) and boundary_pos(shadow.name, t.name) >= 0]
            return MATCH_NAME, "container_name", hits[0], others

    prefix, inner = [], []
    for t in ordered:
        pos = boundary_pos(shadow.name, t.name)
        if pos == 0:
            prefix.append(t)
        elif pos > 0:
            inner.append(t)
    if prefix:
        return MATCH_NAME, "name_prefix", prefix[0], prefix[1:] + inner
    if inner:
        return MATCH_SUBSTRING, "name_token", inner[0], inner[1:]
    return None


def scan_shadow_vms(client: VCDClient, catalogs, datastores, vcd_server: str = "",
                    debug: bool = False) -> ScanResult:
    """
    Scan for Shadow VMs on one or more datastores that belong to templates in one or more catalogs.

    Args:
        client: Authenticated VCDClient
        catalogs: catalog names or catalog dicts from get_catalogs() (a single item is accepted)
        datastores: datastore names or datastore dicts from get_datastores()
        vcd_server: VCD server hostname to stamp on results (for multi-VCD consolidation)
        debug: Enable debug output

    Matching, in priority order:
      1. exact: the shadow's parent reference is one of the selected templates.
         A parent reference that points at any other template makes the shadow
         'other_template': it is never matched by name.
      2. name: the record's container name equals a template name, or the shadow's
         name starts with a template name at a token boundary.
      3. substring: a template name appears inside the shadow's name on token
         boundaries (-, _, space, dot, parentheses).
    Longest template name wins; other fitting templates are recorded in ambiguous_with.
    Query failures are collected in result.errors (result.complete is then False).
    """
    if isinstance(catalogs, (str, dict)):
        catalogs = [catalogs]
    if isinstance(datastores, (str, dict)):
        datastores = [datastores]
    cat_idents = [c if isinstance(c, dict) else {"name": c} for c in catalogs]
    ds_idents = [d if isinstance(d, dict) else {"name": d} for d in datastores]

    result = ScanResult()

    def record_error(e: VCDError):
        err = e.to_dict()
        err["server"] = vcd_server
        result.errors.append(err)
        print(f"  ERROR: {e}")

    print(f"\nScanning for Shadow VMs...")
    print(f"  Catalogs: {', '.join(str(c.get('name')) for c in cat_idents)}")
    print(f"  Datastores: {', '.join(str(d.get('name')) for d in ds_idents)}")

    # Collect templates across catalogs (deduplicated by href, catalog order kept)
    all_templates: List[VAppTemplate] = []
    seen_tpl = set()
    for ident in cat_idents:
        cat_name = ident.get("name") or ""
        try:
            templates = client.get_vapp_templates_in_catalog(ident, warnings=result.warnings)
        except VCDError as e:
            record_error(e)
            continue
        print(f"  Found {len(templates)} templates in catalog '{cat_name}'")
        if debug and templates:
            print(f"  DEBUG: Sample template names ({cat_name}): {[t.name for t in templates[:5]]}")
        for t in templates:
            key = _ref_key(t.href) if t.href else ("name", t.name, cat_name)
            if key in seen_tpl:
                continue
            seen_tpl.add(key)
            if not t.catalog_name:
                t.catalog_name = cat_name
            all_templates.append(t)

    template_by_ref: dict = {}
    for t in all_templates:
        for ref in (t.href, t.id):
            if ref:
                template_by_ref.setdefault(ref, t)
                template_by_ref.setdefault(_ref_key(ref), t)
    order = {id(t): i for i, t in enumerate(all_templates)}
    named = [t for t in all_templates if t.name and t.name.strip()]
    skipped_empty = len(all_templates) - len(named)
    if skipped_empty:
        result.warnings.append(f"{skipped_empty} template(s) with an empty name ignored for name matching")
    ordered = sorted(named, key=lambda t: (-len(t.name), t.name, order[id(t)]))

    all_shadows: List[ShadowVM] = []
    for ident in ds_idents:
        ds_name = ident.get("name") or ""
        try:
            ds_shadows = client.get_shadow_vms_on_datastore(ident, debug=debug, warnings=result.warnings)
        except VCDError as e:
            record_error(e)
            continue
        print(f"  Found {len(ds_shadows)} Shadow VMs on datastore '{ds_name}'")
        all_shadows.extend(ds_shadows)
    print(f"  Found {len(all_shadows)} Shadow VMs across {len(ds_idents)} datastore(s)")

    if debug and all_shadows:
        print(f"  DEBUG: Sample Shadow VM container_names: {[s.container_name for s in all_shadows[:5]]}")
        print(f"  DEBUG: Sample Shadow VM container_ids: {[s.container_id for s in all_shadows[:5]]}")
        print(f"  DEBUG: Sample Shadow VM names: {[s.name for s in all_shadows[:5]]}")

    def amb(ts):
        return [{"template": t.name, "catalog": t.catalog_name, "href": t.href} for t in ts]

    seen_hrefs = set()
    for shadow in all_shadows:
        dedup_key = shadow.href or id(shadow)
        if dedup_key in seen_hrefs:
            continue
        seen_hrefs.add(dedup_key)

        tpl = None
        for ref in (shadow.parent_ref, shadow.container_id):
            if ref:
                tpl = template_by_ref.get(ref) or template_by_ref.get(_ref_key(ref))
                if tpl:
                    break
        if tpl is not None:
            shadow.match_strength, shadow.match_rule = MATCH_EXACT, "parent_ref"
        elif shadow.parent_ref:
            result.other_template += 1
            continue
        else:
            hit = _match_templates(shadow, ordered)
            if hit is None:
                result.unmatched += 1
                continue
            shadow.match_strength, shadow.match_rule, tpl, others = hit
            shadow.ambiguous_with = amb(others)

        shadow.container_name = tpl.name
        shadow.catalog_name = tpl.catalog_name
        shadow.template_href = tpl.href
        shadow.org_name = tpl.org_name
        shadow.vcd_server = vcd_server
        result.shadows.append(shadow)

    c = result.counts
    print(f"  Matched {len(result.shadows)} Shadow VMs to catalog templates "
          f"({c['exact']} exact, {c['weak']} weak); {c['other_template']} belong to other templates, "
          f"{c['unmatched']} unmatched")
    if not result.complete:
        print(f"  Scan INCOMPLETE: {len(result.errors)} error(s)")
    return result


def scan_sessions(sessions: list) -> ScanResult:
    """Scan several VCD sessions in parallel (GUI multi-VCD scan).

    Each session dict has 'client', 'server', 'catalogs' and 'datastores'. One session's
    failure is recorded in errors and never discards the other sessions' results.
    """
    from concurrent.futures import ThreadPoolExecutor

    combined = ScanResult()

    def scan_one(session):
        return scan_shadow_vms(session["client"], session["catalogs"], session["datastores"],
                               vcd_server=session["server"], debug=False)

    with ThreadPoolExecutor(max_workers=max(1, len(sessions))) as executor:
        futures = [(s, executor.submit(scan_one, s)) for s in sessions]
        for session, future in futures:
            try:
                combined.extend(future.result())
            except Exception as e:
                combined.errors.append({
                    "type": type(e).__name__, "stage": getattr(e, "stage", "scan") or "scan",
                    "target": getattr(e, "target", "") or "", "http_status": getattr(e, "status", None),
                    "message": str(e), "server": session.get("server", ""),
                })
    return combined


def print_shadow_vm_table(shadows: List[ShadowVM]):
    """Print Shadow VMs in ASCII table format."""
    if not shadows:
        print("\nNo Shadow VMs found matching the criteria.")
        return

    def match_label(s: ShadowVM) -> str:
        return (s.match_strength or "?") + (" (ambiguous)" if s.ambiguous_with else "")

    cols = [
        ("Shadow VM Name", lambda s: s.name),
        ("Parent Template", lambda s: s.container_name),
        ("Match", match_label),
        ("Catalog", lambda s: s.catalog_name),
        ("Org", lambda s: s.org_name),
        ("Datastore", lambda s: s.datastore_name),
    ]
    widths = [max(len(title), max(len(str(fn(s) or "")) for s in shadows)) for title, fn in cols]
    total_width = sum(widths) + 3 * len(cols) + 1

    print("\n" + "=" * total_width)
    print("| " + " | ".join(f"{title:<{w}}" for (title, _), w in zip(cols, widths)) + " |")
    print("|" + "|".join("-" * (w + 2) for w in widths) + "|")
    for shadow in shadows:
        print("| " + " | ".join(f"{str(fn(shadow) or ''):<{w}}" for (_, fn), w in zip(cols, widths)) + " |")
    print("=" * total_width)
    print(f"\nTotal Shadow VMs: {len(shadows)}")


def _open_tty():
    """Open the controlling terminal as (reader, writer); None when there is none.

    The delete confirmation is read here, never from stdin, so piping 'yes' into the
    tool cannot confirm a delete.
    """
    try:
        if os.name == "nt":
            reader = open("CONIN$", "r")
            writer = open("CONOUT$", "w")
        else:
            reader = open("/dev/tty", "r")
            writer = open("/dev/tty", "w")
    except OSError:
        return None
    return reader, writer


def _confirm_on_terminal(prompt: str, expected: str = "yes") -> Optional[bool]:
    """Ask on the controlling terminal. None = no terminal; True/False = answer."""
    tty = _open_tty()
    if tty is None:
        return None
    reader, writer = tty
    try:
        writer.write(prompt)
        writer.flush()
        answer = reader.readline()
    except (OSError, EOFError):
        answer = ""
    finally:
        for f in (reader, writer):
            with contextlib.suppress(Exception):
                f.close()
    return answer.strip().lower() == expected


def _resolve_scope(client: VCDClient, catalog_names: List[str], datastore_names: List[str],
                   tenant: Optional[str], warnings: List[str]):
    """Resolve names to discovered catalog/datastore identities. Returns (cats, dss, missing)."""
    catalogs = client.get_catalogs(tenant if tenant and tenant.lower() != "system" else None)
    datastores = client.get_datastores()
    missing = []

    def pick(name, items, kind, describe):
        hits = [i for i in items if i.get("name") == name]
        if not hits:
            hits = [i for i in items if (i.get("name") or "").lower() == name.lower()]
        if not hits:
            missing.append(f"{kind} '{name}'")
        elif len(hits) > 1:
            warnings.append(f"{kind} name '{name}' matches {len(hits)} {kind}s "
                            f"({', '.join(describe(h) for h in hits)}); scanning all of them")
        return hits

    cats, dss = [], []
    for n in catalog_names:
        cats.extend(pick(n, catalogs, "catalog", lambda c: f"org {c.get('orgName')}"))
    for n in datastore_names:
        dss.extend(pick(n, datastores, "datastore", lambda d: f"vCenter {d.get('vcName') or d.get('vc') or '?'}"))
    return cats, dss, missing


def _shadow_json(s: ShadowVM) -> dict:
    return {
        "name": s.name,
        "id": s.vm_id,
        "href": s.href,
        "parent_template": s.container_name,
        "template_href": s.template_href,
        "catalog": s.catalog_name,
        "org": s.org_name,
        "datastore": s.datastore_name,
        "datastore_href": s.datastore_href,
        "vcenter": s.vc_name,
        "match_strength": s.match_strength,
        "match_rule": s.match_rule,
        "parent_ref": s.parent_ref,
        "ambiguous_with": s.ambiguous_with,
    }


def _run_migrate_credentials(args, emit_json) -> int:
    """CLI front end for migrate_credentials(); prints outcomes, never credential values."""
    if not _keyring_usable():
        msg = ("--migrate-credentials needs a working system keyring. Install the keyring package "
               "('pip install keyring') and make sure it has a backend (macOS Keychain, Windows "
               "Credential Manager, or Secret Service on Linux).")
        if args.json:
            emit_json({"ok": False, "error": msg})
        print(f"ERROR: {msg}", file=sys.stderr)
        return 1
    try:
        report = migrate_credentials(dry_run=args.dry_run)
    except Exception as e:
        msg = f"Credential migration failed: {type(e).__name__}"
        if args.json:
            emit_json({"ok": False, "error": msg})
        print(f"ERROR: {msg}", file=sys.stderr)
        return 1
    if args.json:
        emit_json(report)
    else:
        mode = " (dry run: nothing changed)" if report["dry_run"] else ""
        print(f"Credential migration for {report['servers_file']}{mode}")
        if report["backup"]:
            print(f"Backup written: {report['backup']} (it still holds the base64 credentials; "
                  f"delete it once you have checked the migration)")
        if not report["results"]:
            print("No base64-stored credentials found; nothing to migrate.")
        for r in report["results"]:
            detail = f"  ({r['detail']})" if r["detail"] else ""
            label = r["name"] or "?"
            print(f"  {r['id']:<36}  {label:<30} {r['server']:<40} {r['outcome']}{detail}")
        if report["skipped_without_base64"]:
            print(f"Servers without a base64 credential (left as is): {report['skipped_without_base64']}")
    return 0 if report["ok"] else 1


def run_cli(args):
    """Run in CLI mode."""
    as_json = args.json
    # In JSON mode all progress/informational output goes to stderr so stdout
    # stays pure machine-readable JSON.
    info = sys.stderr if as_json else sys.stdout
    include_weak = bool(getattr(args, "include_weak", False))
    if getattr(args, "debug", False):
        logging.basicConfig(level=logging.DEBUG, stream=sys.stderr,
                            format="DEBUG %(name)s: %(message)s")

    def emit_json(payload):
        print(json.dumps(payload, indent=2))

    # --migrate-credentials only touches the local profile store and the keyring.
    if getattr(args, "migrate_credentials", False):
        return _run_migrate_credentials(args, emit_json)

    # --list-servers needs no connection at all.
    if args.list_servers:
        servers = _load_saved_servers()
        if as_json:
            emit_json({"saved_servers": [
                {
                    "name": s.get("name", ""),
                    "server": s.get("server", ""),
                    "auth_type": s.get("auth_type", ""),
                    "username": s.get("username", ""),
                    "default_org": s.get("org", ""),
                    "skip_ssl_verify": s.get("skip_ssl_verify", True),
                }
                for s in servers
            ]})
        elif not servers:
            print("No saved servers found. Add one in the GUI (Manage Saved Servers).")
        else:
            print(f"Saved servers ({_SERVERS_FILE}):")
            for s in servers:
                auth = "token" if s.get("auth_type") == "token" else f"password ({s.get('username', '')})"
                org = s.get("org") or "system"
                print(f"  {s.get('name', '?'):<30} {s.get('server', ''):<40} auth={auth}  default org={org}")
        return 0

    print("=" * 60, file=info)
    print("VMware Cloud Director Shadow VM Cleanup Tool", file=info)
    print("=" * 60, file=info)

    # Resolve a saved-server profile. The stored credential is used only to
    # authenticate this shadow-VM scan/cleanup session; it is never printed.
    token = args.token
    username = args.username
    password = args.password
    if args.saved_server:
        profile = _find_saved_server(args.saved_server)
        if not profile:
            names = ", ".join(s.get("name", "?") for s in _load_saved_servers()) or "(none)"
            print(f"ERROR: No saved server matches '{args.saved_server}'. Saved servers: {names}", file=sys.stderr)
            return 1
        args.server = profile.get("server") or args.server
        if profile.get("skip_ssl_verify", True):
            args.skip_ssl_verify = True
        if not args.tenant:
            args.tenant = profile.get("org") or None
        credential, cred_source = _get_credential_with_source(profile.get("id", ""))
        if cred_source == "base64":
            _warn_base64_once()
        if credential:
            if profile.get("auth_type") == "token":
                token, username, password = credential, None, None
            else:
                token, username, password = None, profile.get("username", ""), credential
        elif not (token or (username and password)):
            print(f"ERROR: No stored credential found for saved server '{profile.get('name')}'. "
                  f"Re-save it in the GUI (Manage Saved Servers) or pass --token / --username/--password.",
                  file=sys.stderr)
            return 1

    if not (token or (username and password)):
        print("ERROR: Provide --token, --username/--password, or --saved-server.", file=sys.stderr)
        return 1

    args.server = normalize_host(args.server)

    def fail(code: int, errors: list, extra: Optional[dict] = None):
        for e in errors:
            print(f"ERROR: {format_error(e)}", file=sys.stderr)
        if as_json:
            doc = {"server": args.server, "complete": False, "errors": errors}
            doc.update(extra or {})
            emit_json(doc)
        return code

    if args.dry_run:
        print("\n*** DRY RUN MODE - No changes will be made ***\n", file=info)

    client = VCDClient(args.server, verify_ssl=not args.skip_ssl_verify)

    print(f"\nConnecting to {args.server}...", file=info)
    try:
        with contextlib.redirect_stdout(info):
            if token:
                client.authenticate_with_token(token, "system")
            else:
                client.authenticate_with_credentials(username, password, "system")
    except VCDAuthError as e:
        return fail(EXIT_AUTH, [e.to_dict()])
    except VCDError as e:
        return fail(EXIT_VCD, [e.to_dict()])
    print("Connected successfully!", file=info)

    try:
        # Discovery actions: list resources and exit without scanning.
        if args.list_tenants or args.list_catalogs or args.list_datastores:
            result = {}
            try:
                with contextlib.redirect_stdout(info):
                    if args.list_tenants:
                        result["tenants"] = [o.get("name", "") for o in client.get_organizations()]
                    if args.list_catalogs:
                        result["catalogs"] = [
                            {"name": c.get("name", ""), "org": c.get("orgName", ""), "href": c.get("href", "")}
                            for c in client.get_catalogs(args.tenant)
                        ]
                    if args.list_datastores:
                        result["datastores"] = [d.get("name", "") for d in client.get_datastores()]
            except VCDError as e:
                return fail(EXIT_VCD, [e.to_dict()], result)
            result["complete"] = True
            result["errors"] = []
            if as_json:
                emit_json(result)
            else:
                if "tenants" in result:
                    print("\nTenants/Organizations:")
                    for name in result["tenants"]:
                        print(f"  {name}")
                if "catalogs" in result:
                    print(f"\nCatalogs{' (org: ' + args.tenant + ')' if args.tenant else ''}:")
                    for c in result["catalogs"]:
                        print(f"  {c['name']}  (org: {c['org']})")
                if "datastores" in result:
                    print("\nDatastores:")
                    for name in result["datastores"]:
                        print(f"  {name}")
            return 0

        tenant = args.tenant if args.tenant and args.tenant.lower() != "system" else None
        if tenant:
            print(f"Scoping to tenant: {tenant}", file=info)
            client.switch_to_org(tenant)

        # Scan for Shadow VMs (support comma-separated catalog and datastore names from CLI)
        catalog_names = [c.strip() for c in args.catalog.split(",") if c.strip()]
        datastore_names = [d.strip() for d in args.datastore.split(",") if d.strip()]

        warnings: List[str] = []
        try:
            with contextlib.redirect_stdout(info):
                cats, dss, missing = _resolve_scope(client, catalog_names, datastore_names, tenant, warnings)
        except VCDError as e:
            return fail(EXIT_VCD, [e.to_dict()])
        if missing:
            print(f"ERROR: Not found{' in tenant ' + tenant if tenant else ''}: {', '.join(missing)}. "
                  f"Use --list-catalogs / --list-datastores to see the names.", file=sys.stderr)
            if as_json:
                emit_json({"server": args.server, "complete": False,
                           "errors": [{"type": "UsageError", "message": f"not found: {m}"} for m in missing]})
            return EXIT_USAGE

        with contextlib.redirect_stdout(info):
            scan = scan_shadow_vms(client, cats, dss, vcd_server=args.server, debug=args.debug)
        scan.warnings[:0] = warnings
        shadows = scan.shadows
        for w in scan.warnings:
            print(f"WARNING: {w}", file=sys.stderr)

        exact = [s for s in shadows if s.match_strength == MATCH_EXACT]
        weak = [s for s in shadows if s.is_weak]
        to_delete = exact + (weak if include_weak else [])

        payload = {
            "server": args.server,
            "tenant": args.tenant or "system",
            "catalogs": catalog_names,
            "datastores": datastore_names,
            "scope": {
                "catalogs": [{"name": c.get("name"), "href": c.get("href"), "org": c.get("orgName")} for c in cats],
                "datastores": [{"name": d.get("name"), "href": d.get("href"), "vcenter": d.get("vcName")}
                               for d in dss],
            },
            "dry_run": bool(args.dry_run),
            "include_weak": include_weak,
            "complete": scan.complete,
            "errors": scan.errors,
            "warnings": scan.warnings,
            "counts": scan.counts,
            "count": len(shadows),
            "delete_candidates": len(to_delete),
            "shadow_vms": [_shadow_json(s) for s in shadows],
        }

        if not as_json:
            print_shadow_vm_table(shadows)
            c = scan.counts
            print(f"Matches: {c['exact']} exact, {c['weak']} weak (name/substring); "
                  f"{c['other_template']} shadow VM(s) belong to other templates; {c['unmatched']} unmatched")

        if not scan.complete:
            for e in scan.errors:
                print(f"ERROR: {format_error(e)}", file=sys.stderr)
            print("ERROR: Scan incomplete; results may be missing. Nothing will be deleted.", file=sys.stderr)
            if as_json:
                emit_json(payload)
            return EXIT_VCD

        if weak and not include_weak:
            print(f"\n{len(weak)} weak (name/substring) match(es) are excluded from deletion; "
                  f"pass --include-weak to include them.", file=info)

        if not to_delete:
            if as_json:
                emit_json(payload)
            return 0

        if args.dry_run:
            print(f"\n*** DRY RUN COMPLETE - would delete {len(to_delete)} Shadow VM(s) "
                  f"({len(exact)} exact, {len(to_delete) - len(exact)} weak). Nothing was deleted ***", file=info)
            if as_json:
                emit_json(payload)
            return 0

        # Safety gate: deleting Shadow VMs is permanent. The confirmation is read from
        # the controlling terminal, never stdin, so `echo yes |` cannot confirm it.
        # There is deliberately no --yes/--force flag. Use --dry-run for unattended analysis.
        lines = [f"\nWARNING: About to PERMANENTLY delete {len(to_delete)} Shadow VM(s) from {args.server}. "
                 f"This cannot be undone.",
                 f"  Exact matches (parent template reference): {len(exact)}"]
        if include_weak and weak:
            lines.append(f"  WEAK matches (name/substring only), included by --include-weak: {len(weak)}")
            for s in weak:
                lines.append(f"    - {s.name}  -> {s.container_name} [{s.match_strength}"
                             f"{', ambiguous' if s.ambiguous_with else ''}]")
        prompt = "\n".join(lines) + "\nAre you sure? Type 'yes' to confirm, anything else to cancel: "
        answer = _confirm_on_terminal(prompt)
        if answer is None:
            print("\nREFUSED: deleting needs a person to confirm at a terminal, and no terminal is "
                  "available (the confirmation is never read from stdin). No Shadow VMs were deleted. "
                  "Run from an interactive terminal, or use --dry-run.", file=sys.stderr)
            if as_json:
                payload["confirmed"] = False
                payload["refused"] = "no terminal for confirmation"
                emit_json(payload)
            return EXIT_NO_TERMINAL
        if not answer:
            print("Operation cancelled. No Shadow VMs were deleted.", file=info)
            if as_json:
                payload["confirmed"] = False
                emit_json(payload)
            return 0

        # Delete Shadow VMs
        print("\nDeleting Shadow VMs...", file=info)

        def on_start(i, shadow):
            print(f"  [{i + 1}/{len(to_delete)}] Deleting {shadow.name}...", end=" ", file=info, flush=True)

        def on_result(r: DeleteResult):
            if r.status == "skipped":
                return
            label = {"deleted": "OK", "accepted_unverified": "ACCEPTED (not verified)"}.get(r.status)
            print(label if label else f"FAILED - {r.message}", file=info)

        run = delete_shadow_vms(client, to_delete, on_start=on_start, on_result=on_result)
        if run.stopped_reason:
            print(f"\nSTOPPED: {run.stopped_reason} ({run.skipped} not attempted)", file=sys.stderr)
        print(f"\nDeletion complete: {run.deleted} deleted, {run.unverified} accepted (not verified), "
              f"{run.failed} failed, {run.skipped} skipped", file=info)
        if as_json:
            payload["confirmed"] = True
            payload["succeeded"] = run.deleted + run.unverified
            payload["deleted"] = run.deleted
            payload["accepted_unverified"] = run.unverified
            payload["failed"] = run.failed
            payload["skipped"] = run.skipped
            payload["stopped_reason"] = run.stopped_reason
            payload["deletion_results"] = [r.to_dict() for r in run.results]
            emit_json(payload)

        return 0 if (run.failed == 0 and run.skipped == 0) else EXIT_DELETE_FAILED
    finally:
        client.disconnect()


def run_gui(build_only: bool = False):
    """Run in GUI mode with PySide6.

    build_only=True returns the GUI classes (for tests) without creating the
    QApplication or entering the event loop.
    """
    try:
        from PySide6.QtWidgets import (
            QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
            QLabel, QLineEdit, QPushButton, QComboBox, QTreeView,
            QGroupBox, QFormLayout, QProgressBar,
            QMessageBox, QCheckBox, QTextEdit, QHeaderView,
            QFrame, QListWidget, QListWidgetItem,
            QDialog, QDialogButtonBox, QAbstractItemView, QMenu,
            QFileDialog, QSizePolicy
        )
        from PySide6.QtCore import (
            Qt, QThread, Signal, QSortFilterProxyModel, QModelIndex
        )
        from PySide6.QtGui import (
            QFont, QPalette, QColor, QIcon, QStandardItemModel, QStandardItem,
            QAction
        )
    except ImportError:
        print("ERROR: PySide6 is required for GUI mode.")
        print("Install it with: pip install PySide6")
        return 1

    SHADOW_VM_ROLE = Qt.ItemDataRole.UserRole + 1
    IS_GROUP_ROLE = Qt.ItemDataRole.UserRole + 2
    COL_CHECK = 0
    COL_TEMPLATE = 1
    COL_CATALOG = 2
    COL_VMNAME = 3
    COL_DATASTORE = 4
    COL_VCD = 5
    COL_ORG = 6
    COL_MATCH = 7
    COLUMN_HEADERS = ["", "Parent Template", "Catalog", "Shadow VMs", "Datastore", "VCD Instance", "Org",
                      "Match"]
    FILTERABLE_COLUMNS = {COL_CATALOG, COL_TEMPLATE, COL_DATASTORE, COL_VCD, COL_ORG, COL_MATCH}

    class ColumnFilterProxyModel(QSortFilterProxyModel):
        """Proxy that filters rows based on per-column allowed-value sets."""

        def __init__(self, parent=None):
            super().__init__(parent)
            self._filters: dict[int, set[str]] = {}

        def set_column_filter(self, col: int, allowed: Optional[Set[str]]):
            if allowed is None:
                self._filters.pop(col, None)
            else:
                self._filters[col] = allowed
            self.invalidateFilter()

        def clear_all_filters(self):
            self._filters.clear()
            self.invalidateFilter()

        def active_filters(self) -> dict[int, set[str]]:
            return dict(self._filters)

        def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
            model = self.sourceModel()
            for col, allowed in self._filters.items():
                idx = model.index(source_row, col)
                value = model.data(idx, Qt.ItemDataRole.DisplayRole) or ""
                if value not in allowed:
                    return False
            return True

    class FilterPopupDialog(QDialog):
        """Excel-style multi-select filter popup for a column."""

        def __init__(self, parent, title: str, all_values: list[str], checked_values: Optional[Set[str]]):
            super().__init__(parent)
            self.setWindowTitle(f"Filter: {title}")
            self.setMinimumSize(280, 350)
            self.result_set: Optional[Set[str]] = None

            layout = QVBoxLayout(self)

            btn_row = QHBoxLayout()
            select_all_btn = QPushButton("Select All")
            select_all_btn.clicked.connect(self._select_all)
            deselect_all_btn = QPushButton("Deselect All")
            deselect_all_btn.clicked.connect(self._deselect_all)
            clear_filter_btn = QPushButton("Clear Filter")
            clear_filter_btn.clicked.connect(self._clear_filter)
            btn_row.addWidget(select_all_btn)
            btn_row.addWidget(deselect_all_btn)
            btn_row.addWidget(clear_filter_btn)
            layout.addLayout(btn_row)

            self._list = QListWidget()
            self._list.setSelectionMode(QListWidget.SelectionMode.NoSelection)
            sorted_values = sorted(set(all_values))
            for val in sorted_values:
                item = QListWidgetItem(val)
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                if checked_values is None or val in checked_values:
                    item.setCheckState(Qt.CheckState.Checked)
                else:
                    item.setCheckState(Qt.CheckState.Unchecked)
                self._list.addItem(item)
            layout.addWidget(self._list)

            buttons = QDialogButtonBox(
                QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
            )
            buttons.accepted.connect(self._on_ok)
            buttons.rejected.connect(self.reject)
            layout.addWidget(buttons)

        def _select_all(self):
            for i in range(self._list.count()):
                self._list.item(i).setCheckState(Qt.CheckState.Checked)

        def _deselect_all(self):
            for i in range(self._list.count()):
                self._list.item(i).setCheckState(Qt.CheckState.Unchecked)

        def _clear_filter(self):
            self.result_set = None
            self.accept()

        def _on_ok(self):
            self.result_set = set()
            for i in range(self._list.count()):
                item = self._list.item(i)
                if item.checkState() == Qt.CheckState.Checked:
                    self.result_set.add(item.text())
            self.accept()

    SORTABLE_COLUMNS = {COL_TEMPLATE, COL_CATALOG, COL_VMNAME, COL_DATASTORE, COL_VCD, COL_ORG, COL_MATCH}
    NUMERIC_COLUMNS = {COL_VMNAME}

    class FilterHeaderView(QHeaderView):
        """Header view with a select-all checkbox in col 0, left-click sort, and right-click filters."""
        filter_requested = Signal(int)
        select_all_clicked = Signal()
        sort_requested = Signal(int)  # emits logical column index

        def __init__(self, orientation, parent=None):
            super().__init__(orientation, parent)
            self.setSectionsClickable(True)
            self._filtered_columns: set[int] = set()
            self._check_state = Qt.CheckState.Unchecked  # header checkbox state
            self._sort_col = -1
            self._sort_asc = True

        def set_sort_indicator(self, col: int, ascending: bool):
            self._sort_col = col
            self._sort_asc = ascending
            self.viewport().update()

        def set_filtered(self, col: int, is_filtered: bool):
            if is_filtered:
                self._filtered_columns.add(col)
            else:
                self._filtered_columns.discard(col)
            self.viewport().update()

        def set_check_state(self, state: Qt.CheckState):
            if self._check_state != state:
                self._check_state = state
                self.viewport().update()

        def _checkbox_rect(self, logical_index: int):
            """Return the bounding rect for the checkbox drawn in the given section."""
            from PySide6.QtCore import QRect
            x = self.sectionViewportPosition(logical_index)
            w = self.sectionSize(logical_index)
            h = self.height()
            cb_size = 14
            cx = x + (w - cb_size) // 2
            cy = (h - cb_size) // 2
            return QRect(cx, cy, cb_size, cb_size)

        def paintSection(self, painter, rect, logical_index):
            super().paintSection(painter, rect, logical_index)
            if logical_index == COL_CHECK:
                from PySide6.QtWidgets import QStyleOptionButton, QStyle
                opt = QStyleOptionButton()
                opt.rect = self._checkbox_rect(logical_index)
                if self._check_state == Qt.CheckState.Checked:
                    opt.state = QStyle.StateFlag.State_Enabled | QStyle.StateFlag.State_On
                elif self._check_state == Qt.CheckState.PartiallyChecked:
                    opt.state = QStyle.StateFlag.State_Enabled | QStyle.StateFlag.State_NoChange
                else:
                    opt.state = QStyle.StateFlag.State_Enabled | QStyle.StateFlag.State_Off
                self.style().drawControl(QStyle.ControlElement.CE_CheckBox, opt, painter)
            elif logical_index in SORTABLE_COLUMNS and logical_index == self._sort_col:
                from PySide6.QtCore import QRect
                arrow = "\u25B2" if self._sort_asc else "\u25BC"
                x = self.sectionViewportPosition(logical_index)
                w = self.sectionSize(logical_index)
                h = self.height()
                painter.save()
                painter.setPen(self.palette().color(self.palette().ColorRole.HighlightedText
                                                    if self.currentIndex() == logical_index
                                                    else self.palette().ColorRole.WindowText))
                painter.drawText(QRect(x + w - 18, 0, 16, h),
                                 Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
                                 arrow)
                painter.restore()

        def mousePressEvent(self, event):
            logical = self.logicalIndexAt(event.pos())
            if event.button() == Qt.MouseButton.LeftButton:
                if logical == COL_CHECK:
                    cb_rect = self._checkbox_rect(logical)
                    if cb_rect.contains(event.pos()):
                        self.select_all_clicked.emit()
                        return
                elif logical in SORTABLE_COLUMNS:
                    self.sort_requested.emit(logical)
                    return
            if event.button() == Qt.MouseButton.RightButton:
                if logical in FILTERABLE_COLUMNS:
                    menu = QMenu(self)
                    col = logical
                    action = QAction("Filter...", self)
                    action.triggered.connect(lambda checked=False, c=col: self.filter_requested.emit(c))
                    menu.addAction(action)
                    if col in self._filtered_columns:
                        clear_action = QAction("Clear this filter", self)
                        clear_action.triggered.connect(lambda checked=False, c=col: self.filter_requested.emit(-c))
                        menu.addAction(clear_action)
                    menu.exec(event.globalPosition().toPoint())
                    return
            super().mousePressEvent(event)

    class EditSavedServerDialog(QDialog):
        """Create or edit a saved VCD server entry."""

        def __init__(self, parent=None, server_data: dict = None, prefill_credential: str = ""):
            super().__init__(parent)
            self._is_edit = server_data is not None
            self._server_data = dict(server_data) if server_data else {}
            self.setWindowTitle("Edit Saved Server" if self._is_edit else "Add Saved Server")
            self.setMinimumWidth(420)

            layout = QVBoxLayout(self)
            form = QFormLayout()
            form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

            self._name_input = QLineEdit(self._server_data.get("name", ""))
            self._name_input.setPlaceholderText("e.g. Production VCD")
            form.addRow("Display Name:", self._name_input)

            self._server_input = QLineEdit(self._server_data.get("server", ""))
            self._server_input.setPlaceholderText("e.g. vcd.example.com")
            form.addRow("VCD Server:", self._server_input)

            self._token_check = QCheckBox("Use API Token")
            self._token_check.setChecked(self._server_data.get("auth_type") == "token")
            self._token_check.stateChanged.connect(self._toggle_auth)
            form.addRow("", self._token_check)

            self._token_label = QLabel("API Token:")
            self._token_input = QLineEdit()
            self._token_input.setEchoMode(QLineEdit.EchoMode.Password)
            self._token_input.setPlaceholderText("Enter token (leave blank to keep existing)")
            form.addRow(self._token_label, self._token_input)

            self._username_label = QLabel("Username:")
            self._username_input = QLineEdit(self._server_data.get("username", ""))
            form.addRow(self._username_label, self._username_input)

            self._password_label = QLabel("Password:")
            self._password_input = QLineEdit()
            self._password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self._password_input.setPlaceholderText("Enter password (leave blank to keep existing)")
            pwd_row = QHBoxLayout()
            self._show_pwd = QCheckBox("Show")
            self._show_pwd.stateChanged.connect(
                lambda s: self._password_input.setEchoMode(
                    QLineEdit.EchoMode.Normal if s else QLineEdit.EchoMode.Password
                )
            )
            pwd_row.addWidget(self._password_input)
            pwd_row.addWidget(self._show_pwd)
            form.addRow(self._password_label, pwd_row)

            self._org_input = QLineEdit(
                self._server_data.get("org", self._server_data.get("tenant", ""))
            )
            self._org_input.setPlaceholderText("Leave blank for system/provider")
            self._org_input.textChanged.connect(self._on_org_changed)
            form.addRow("Default Org:", self._org_input)

            self._auto_select_catalogs_check = QCheckBox("Select all catalogs by default")
            self._auto_select_catalogs_check.setChecked(
                self._server_data.get("auto_select_all_catalogs", False)
            )
            form.addRow("", self._auto_select_catalogs_check)

            self._auto_select_datastores_check = QCheckBox("Select all datastores by default")
            self._auto_select_datastores_check.setChecked(
                self._server_data.get("auto_select_all_datastores", False)
            )
            form.addRow("", self._auto_select_datastores_check)

            self._skip_ssl = QCheckBox("Skip SSL Verification")
            self._skip_ssl.setChecked(self._server_data.get("skip_ssl_verify", True))
            form.addRow("", self._skip_ssl)

            if prefill_credential:
                if self._token_check.isChecked():
                    self._token_input.setText(prefill_credential)
                else:
                    self._password_input.setText(prefill_credential)

            if not _KEYRING_AVAILABLE:
                warn = QLabel("Warning: keyring not installed — credentials will be stored base64-encoded (NOT encrypted) "
                              "in servers.json. Install keyring (pip install keyring) to use the system keychain.")
                warn.setStyleSheet("color: #ffb74d; font-size: 11px;")
                warn.setWordWrap(True)
                layout.addWidget(warn)

            layout.addLayout(form)

            btn_box = QDialogButtonBox(
                QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
            )
            btn_box.accepted.connect(self._on_save)
            btn_box.rejected.connect(self.reject)
            layout.addWidget(btn_box)

            self._toggle_auth()
            self._on_org_changed(self._org_input.text())

        def _on_org_changed(self, text: str):
            has_org = bool(text.strip())
            self._auto_select_catalogs_check.setEnabled(has_org)
            self._auto_select_datastores_check.setEnabled(has_org)
            if not has_org:
                self._auto_select_catalogs_check.setChecked(False)
                self._auto_select_datastores_check.setChecked(False)

        def _toggle_auth(self):
            use_token = self._token_check.isChecked()
            self._token_label.setVisible(use_token)
            self._token_input.setVisible(use_token)
            self._username_label.setVisible(not use_token)
            self._username_input.setVisible(not use_token)
            self._password_label.setVisible(not use_token)
            self._password_input.setVisible(not use_token)
            try:
                self._show_pwd.setVisible(not use_token)
            except Exception:
                pass

        def _on_save(self):
            name = self._name_input.text().strip()
            server = normalize_host(self._server_input.text())
            if not name or not server:
                QMessageBox.warning(self, "Required", "Display Name and VCD Server are required.")
                return
            use_token = self._token_check.isChecked()
            new_credential = (
                self._token_input.text().strip()
                if use_token
                else self._password_input.text()
            )
            server_id = self._server_data.get("id") or str(uuid.uuid4())
            org = self._org_input.text().strip()
            entry = {
                "id": server_id,
                "name": name,
                "server": server,
                "auth_type": "token" if use_token else "password",
                "username": "" if use_token else self._username_input.text().strip(),
                "org": org,
                "auto_select_all_catalogs": bool(org) and self._auto_select_catalogs_check.isChecked(),
                "auto_select_all_datastores": bool(org) and self._auto_select_datastores_check.isChecked(),
                "skip_ssl_verify": self._skip_ssl.isChecked(),
            }
            servers = _load_saved_servers()
            existing_idx = next((i for i, s in enumerate(servers) if s.get("id") == server_id), -1)
            if existing_idx >= 0:
                servers[existing_idx] = entry
            else:
                servers.append(entry)
            _persist_saved_servers(servers)
            if new_credential:
                if _set_credential(server_id, new_credential) == "base64":
                    _gui_warn_base64_once(self)
            self._saved_entry = entry
            self.accept()

        def get_saved_entry(self) -> dict:
            return getattr(self, "_saved_entry", {})

    class ManageSavedServersDialog(QDialog):
        """List, add, edit, and delete saved VCD server entries."""

        def __init__(self, parent=None):
            super().__init__(parent)
            self.setWindowTitle("Manage Saved VCD Servers")
            self.setMinimumSize(500, 360)

            layout = QVBoxLayout(self)

            lbl = QLabel("Saved VCD Servers:")
            layout.addWidget(lbl)

            self._list = QListWidget()
            self._list.setAlternatingRowColors(True)
            self._list.currentRowChanged.connect(self._on_selection_changed)
            layout.addWidget(self._list)

            btn_row = QHBoxLayout()
            self._add_btn = QPushButton("Add")
            self._add_btn.clicked.connect(self._do_add)
            self._edit_btn = QPushButton("Edit")
            self._edit_btn.setEnabled(False)
            self._edit_btn.clicked.connect(self._do_edit)
            self._del_btn = QPushButton("Delete")
            self._del_btn.setEnabled(False)
            self._del_btn.setStyleSheet("color: #ef5350;")
            self._del_btn.clicked.connect(self._do_delete)
            btn_row.addWidget(self._add_btn)
            btn_row.addWidget(self._edit_btn)
            btn_row.addWidget(self._del_btn)
            btn_row.addStretch()
            layout.addLayout(btn_row)

            close_row = QHBoxLayout()
            close_row.addStretch()
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(self.accept)
            close_row.addWidget(close_btn)
            layout.addLayout(close_row)

            self._refresh_list()

        def _refresh_list(self):
            self._list.clear()
            for s in _load_saved_servers():
                auth = "Token" if s.get("auth_type") == "token" else f"Password ({s.get('username', '')})"
                org = s.get("org", s.get("tenant", ""))
                org_part = f"  ·  Org: {org}" if org else "  ·  Org: system"
                auto_bits = []
                if org and s.get("auto_select_all_catalogs"):
                    auto_bits.append("all catalogs")
                if org and s.get("auto_select_all_datastores"):
                    auto_bits.append("all datastores")
                auto_part = f"  ·  Auto-select: {', '.join(auto_bits)}" if auto_bits else ""
                item = QListWidgetItem(
                    f"{s['name']}  —  {s['server']}  [{auth}]{org_part}{auto_part}"
                )
                item.setData(Qt.ItemDataRole.UserRole, s["id"])
                self._list.addItem(item)

        def _on_selection_changed(self, row):
            has = row >= 0
            self._edit_btn.setEnabled(has)
            self._del_btn.setEnabled(has)

        def _current_server(self):
            item = self._list.currentItem()
            if not item:
                return None
            sid = item.data(Qt.ItemDataRole.UserRole)
            return next((s for s in _load_saved_servers() if s.get("id") == sid), None)

        def _do_add(self):
            dlg = EditSavedServerDialog(self)
            if dlg.exec() == QDialog.DialogCode.Accepted:
                self._refresh_list()

        def _do_edit(self):
            entry = self._current_server()
            if not entry:
                return
            dlg = EditSavedServerDialog(self, server_data=entry)
            if dlg.exec() == QDialog.DialogCode.Accepted:
                self._refresh_list()

        def _do_delete(self):
            entry = self._current_server()
            if not entry:
                return
            reply = QMessageBox.question(
                self,
                "Delete Saved Server",
                f"Delete '{entry['name']}'?\nThis cannot be undone.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                _delete_credential(entry["id"])
                servers = [s for s in _load_saved_servers() if s.get("id") != entry["id"]]
                _persist_saved_servers(servers)
                self._refresh_list()

    class WorkerThread(QThread):
        """Background worker thread for long-running operations."""
        finished = Signal(object)
        progress = Signal(int, str)
        error = Signal(str)

        def __init__(self, func, *args, **kwargs):
            super().__init__()
            self.func = func
            self.args = args
            self.kwargs = kwargs

        def run(self):
            try:
                result = self.func(*self.args, **self.kwargs)
                self.finished.emit(result)
            except Exception as e:
                self.error.emit(str(e))

    class VCDInstanceDialog(QDialog):
        """Dialog for connecting to an additional VCD instance and choosing its scan targets."""

        def __init__(self, parent=None, default_org="", auto_select_catalogs=False,
                     auto_select_datastores=False):
            super().__init__(parent)
            self.setWindowTitle("Add VCD Instance")
            self.setMinimumWidth(520)
            self._client = None
            self._session = None
            self._connect_worker = None
            self._catalog_worker = None
            self._pending_default_org = default_org
            self._auto_select_all_catalogs = auto_select_catalogs
            self._auto_select_all_datastores = auto_select_datastores

            main_layout = QVBoxLayout(self)

            # ---- Connection form ----
            conn_form = QFormLayout()
            conn_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

            # Saved servers row
            self._dlg_saved_row_widget = QWidget()
            saved_dlg_inner = QHBoxLayout(self._dlg_saved_row_widget)
            saved_dlg_inner.setContentsMargins(0, 0, 0, 0)
            self._dlg_saved_combo = QComboBox()
            self._dlg_saved_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            self._dlg_saved_combo.currentIndexChanged.connect(self._on_dlg_saved_selected)
            saved_dlg_inner.addWidget(self._dlg_saved_combo)
            dlg_manage_btn = QPushButton("Manage...")
            dlg_manage_btn.setMaximumHeight(26)
            dlg_manage_btn.setStyleSheet("font-size: 11px; padding: 2px 8px;")
            dlg_manage_btn.clicked.connect(self._open_dlg_manage_saved_servers)
            saved_dlg_inner.addWidget(dlg_manage_btn)
            conn_form.addRow("Saved Server:", self._dlg_saved_row_widget)

            self._server_input = QLineEdit()
            self._server_input.setPlaceholderText("e.g. vcd.example.com")
            conn_form.addRow("VCD Server:", self._server_input)

            self._skip_ssl = QCheckBox("Skip SSL Verification")
            conn_form.addRow("", self._skip_ssl)

            self._token_check = QCheckBox("Use API Token")
            self._token_check.stateChanged.connect(self._on_auth_toggle)
            conn_form.addRow("", self._token_check)

            self._token_input = QLineEdit()
            self._token_input.setPlaceholderText("API Token")
            self._token_input.setEchoMode(QLineEdit.EchoMode.Password)
            self._token_row_label = QLabel("Token:")
            conn_form.addRow(self._token_row_label, self._token_input)
            self._token_row_label.setVisible(False)
            self._token_input.setVisible(False)

            self._username_input = QLineEdit()
            self._username_input.setPlaceholderText("Username")
            self._username_label = QLabel("Username:")
            conn_form.addRow(self._username_label, self._username_input)

            self._password_input = QLineEdit()
            self._password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self._password_input.setPlaceholderText("Password")
            self._password_label = QLabel("Password:")
            conn_form.addRow(self._password_label, self._password_input)

            main_layout.addLayout(conn_form)

            connect_row = QHBoxLayout()
            self._connect_btn = QPushButton("Connect")
            self._connect_btn.clicked.connect(self._do_connect)
            connect_row.addWidget(self._connect_btn)
            self._save_conn_btn = QPushButton("Save Connection")
            self._save_conn_btn.setToolTip("Save these connection details for future use")
            self._save_conn_btn.clicked.connect(self._save_dlg_connection)
            connect_row.addWidget(self._save_conn_btn)
            main_layout.addLayout(connect_row)

            self._progress = QProgressBar()
            self._progress.setRange(0, 0)
            self._progress.setVisible(False)
            main_layout.addWidget(self._progress)

            self._status_label = QLabel("")
            self._status_label.setStyleSheet("font-style: italic; color: #aaa;")
            main_layout.addWidget(self._status_label)

            # ---- Selection (enabled after connect) ----
            sel_form = QFormLayout()
            sel_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

            self._tenant_combo = QComboBox()
            self._tenant_combo.setEnabled(False)
            self._tenant_combo.currentTextChanged.connect(self._on_tenant_changed)
            sel_form.addRow("Tenant:", self._tenant_combo)

            # Catalog list
            cat_container = QVBoxLayout()
            cat_btn_row = QHBoxLayout()
            cat_btn_row.setSpacing(4)
            self._cat_select_all = QPushButton("Select All")
            self._cat_select_all.setMaximumHeight(22)
            self._cat_select_all.setEnabled(False)
            self._cat_select_all.clicked.connect(self._catalog_select_all)
            self._cat_deselect_all = QPushButton("Deselect All")
            self._cat_deselect_all.setMaximumHeight(22)
            self._cat_deselect_all.setEnabled(False)
            self._cat_deselect_all.clicked.connect(self._catalog_deselect_all)
            cat_btn_row.addWidget(self._cat_select_all)
            cat_btn_row.addWidget(self._cat_deselect_all)
            cat_btn_row.addStretch()
            cat_container.addLayout(cat_btn_row)
            self._catalog_list = QListWidget()
            self._catalog_list.setEnabled(False)
            self._catalog_list.setSelectionMode(QListWidget.SelectionMode.NoSelection)
            self._catalog_list.setMaximumHeight(100)
            self._catalog_list.itemChanged.connect(self._check_ok_enabled)
            cat_container.addWidget(self._catalog_list)
            cat_widget = QWidget()
            cat_widget.setLayout(cat_container)
            sel_form.addRow("Catalog(s):", cat_widget)

            # Datastore list
            ds_container = QVBoxLayout()
            ds_btn_row = QHBoxLayout()
            ds_btn_row.setSpacing(4)
            self._ds_select_all = QPushButton("Select All")
            self._ds_select_all.setMaximumHeight(22)
            self._ds_select_all.setEnabled(False)
            self._ds_select_all.clicked.connect(self._ds_select_all_fn)
            self._ds_deselect_all = QPushButton("Deselect All")
            self._ds_deselect_all.setMaximumHeight(22)
            self._ds_deselect_all.setEnabled(False)
            self._ds_deselect_all.clicked.connect(self._ds_deselect_all_fn)
            ds_btn_row.addWidget(self._ds_select_all)
            ds_btn_row.addWidget(self._ds_deselect_all)
            ds_btn_row.addStretch()
            ds_container.addLayout(ds_btn_row)
            self._ds_list = QListWidget()
            self._ds_list.setEnabled(False)
            self._ds_list.setSelectionMode(QListWidget.SelectionMode.NoSelection)
            self._ds_list.setMaximumHeight(100)
            self._ds_list.itemChanged.connect(self._check_ok_enabled)
            ds_container.addWidget(self._ds_list)
            ds_widget = QWidget()
            ds_widget.setLayout(ds_container)
            sel_form.addRow("Datastore(s):", ds_widget)

            main_layout.addLayout(sel_form)

            self._populate_dlg_saved_combo()

            # ---- Dialog buttons ----
            self._btn_box = QDialogButtonBox(
                QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
            )
            self._btn_box.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)
            self._btn_box.accepted.connect(self._on_accept)
            self._btn_box.rejected.connect(self.reject)
            main_layout.addWidget(self._btn_box)

        def _on_auth_toggle(self):
            use_token = self._token_check.isChecked()
            self._token_row_label.setVisible(use_token)
            self._token_input.setVisible(use_token)
            self._username_label.setVisible(not use_token)
            self._username_input.setVisible(not use_token)
            self._password_label.setVisible(not use_token)
            self._password_input.setVisible(not use_token)

        def _populate_dlg_saved_combo(self, select_id=None):
            self._dlg_saved_combo.blockSignals(True)
            self._dlg_saved_combo.clear()
            self._dlg_saved_combo.addItem("-- New Connection --", userData=None)
            select_index = 0
            for s in _load_saved_servers():
                label = f"{s['name']}  ({s['server']})"
                self._dlg_saved_combo.addItem(label, userData=s["id"])
                if select_id and s["id"] == select_id:
                    select_index = self._dlg_saved_combo.count() - 1
            self._dlg_saved_combo.setCurrentIndex(select_index)
            self._dlg_saved_combo.blockSignals(False)

        def _open_dlg_manage_saved_servers(self):
            dlg = ManageSavedServersDialog(self)
            dlg.exec()
            self._populate_dlg_saved_combo()

        def _save_dlg_connection(self):
            server = normalize_host(self._server_input.text())
            if not server:
                QMessageBox.warning(self, "Error", "Please enter a VCD server address.")
                return
            use_token = self._token_check.isChecked()
            username = "" if use_token else self._username_input.text().strip()
            credential = (
                self._token_input.text().strip() if use_token else self._password_input.text()
            )

            servers = _load_saved_servers()
            existing = next(
                (s for s in servers
                 if normalize_host(s.get("server", "")) == server
                 and s.get("auth_type") == ("token" if use_token else "password")
                 and s.get("username", "") == username),
                None
            )

            # Derive defaults from the current dialog state: the selected org, and
            # whether the catalog/datastore lists are fully checked ("select all").
            current_org = self._tenant_combo.currentText()
            if current_org.startswith("--"):
                current_org = existing.get("org", "") if existing else ""
            all_catalogs_checked = self._catalog_list.count() > 0 and all(
                self._catalog_list.item(i).checkState() == Qt.CheckState.Checked
                for i in range(self._catalog_list.count())
            )
            all_ds_checked = self._ds_list.count() > 0 and all(
                self._ds_list.item(i).checkState() == Qt.CheckState.Checked
                for i in range(self._ds_list.count())
            )

            prefill = {
                "id": existing.get("id") if existing else None,
                "name": existing.get("name") if existing else server,
                "server": server,
                "auth_type": "token" if use_token else "password",
                "username": username,
                "org": current_org,
                "auto_select_all_catalogs": all_catalogs_checked if current_org else (
                    existing.get("auto_select_all_catalogs", False) if existing else False
                ),
                "auto_select_all_datastores": all_ds_checked if current_org else (
                    existing.get("auto_select_all_datastores", False) if existing else False
                ),
                "skip_ssl_verify": self._skip_ssl.isChecked(),
            }

            dlg = EditSavedServerDialog(self, server_data=prefill, prefill_credential=credential)
            if dlg.exec() == QDialog.DialogCode.Accepted:
                saved = dlg.get_saved_entry()
                self._populate_dlg_saved_combo(select_id=saved.get("id"))

        def _on_dlg_saved_selected(self, index):
            if index <= 0:
                self._pending_default_org = ""
                self._auto_select_all_catalogs = False
                self._auto_select_all_datastores = False
                return
            server_id = self._dlg_saved_combo.itemData(index)
            if not server_id:
                return
            entry = next((s for s in _load_saved_servers() if s.get("id") == server_id), None)
            if not entry:
                return
            self._server_input.setText(entry.get("server", ""))
            self._skip_ssl.setChecked(entry.get("skip_ssl_verify", True))
            use_token = entry.get("auth_type") == "token"
            self._token_check.setChecked(use_token)
            self._on_auth_toggle()
            cred, cred_source = _get_credential_with_source(server_id)
            if cred_source == "base64":
                _gui_warn_base64_once(self)
            if use_token:
                self._token_input.setText(cred)
            else:
                self._username_input.setText(entry.get("username", ""))
                self._password_input.setText(cred)
            self._pending_default_org = entry.get("org", entry.get("tenant", ""))
            self._auto_select_all_catalogs = entry.get("auto_select_all_catalogs", False)
            self._auto_select_all_datastores = entry.get("auto_select_all_datastores", False)

        def _do_connect(self):
            server = self._server_input.text().strip()
            if not server:
                return
            verify_ssl = not self._skip_ssl.isChecked()

            if self._token_check.isChecked():
                token = self._token_input.text().strip()
                if not token:
                    return
                auth_method = "token"
                auth_args = {"token": token}
            else:
                username = self._username_input.text().strip()
                password = self._password_input.text()
                if not username or not password:
                    return
                auth_method = "credentials"
                auth_args = {"username": username, "password": password}

            self._status_label.setText("Connecting...")
            self._connect_btn.setEnabled(False)
            self._progress.setVisible(True)

            client = VCDClient(server, verify_ssl=verify_ssl)

            def do_auth_and_load():
                if auth_method == "token":
                    ok = client.authenticate_with_token(auth_args["token"], "system")
                else:
                    ok = client.authenticate_with_credentials(
                        auth_args["username"], auth_args["password"], "system"
                    )
                if not ok:
                    raise Exception("Authentication failed — check credentials.")
                return {
                    "client": client,
                    "orgs": client.get_organizations(),
                    "catalogs": client.get_catalogs(),
                    "datastores": client.get_datastores(),
                }

            self._connect_worker = WorkerThread(do_auth_and_load)
            self._connect_worker.finished.connect(self._on_connected)
            self._connect_worker.error.connect(self._on_connect_error)
            self._connect_worker.start()

        def _on_connected(self, data):
            self._progress.setVisible(False)
            self._client = data["client"]
            self._status_label.setText("Connected.")
            self._status_label.setStyleSheet("color: #66bb6a;")

            self._tenant_combo.blockSignals(True)
            self._tenant_combo.clear()
            self._tenant_combo.addItem("-- Select Tenant --")
            for org in data["orgs"]:
                self._tenant_combo.addItem(org["name"])
            self._tenant_combo.setEnabled(True)
            self._tenant_combo.blockSignals(False)

            self._populate_catalog_list(data["catalogs"])
            self._populate_ds_list(data["datastores"])

            # Auto-select the default org from a saved server, if one was chosen.
            if self._pending_default_org:
                idx = self._tenant_combo.findText(self._pending_default_org)
                if idx >= 0:
                    self._tenant_combo.setCurrentIndex(idx)

        def _on_connect_error(self, error_message: str):
            self._progress.setVisible(False)
            self._connect_btn.setEnabled(True)
            self._status_label.setText(f"Failed: {error_message}")
            self._status_label.setStyleSheet("color: #ef5350;")

        def _on_tenant_changed(self, tenant_name: str):
            if not self._client or tenant_name.startswith("--"):
                return
            self._client.switch_to_org(tenant_name)
            self._catalog_list.setEnabled(False)
            self._cat_select_all.setEnabled(False)
            self._cat_deselect_all.setEnabled(False)
            self._progress.setVisible(True)
            self._status_label.setText(f"Loading catalogs for '{tenant_name}'...")

            self._catalog_worker = WorkerThread(self._client.get_catalogs, org_name=tenant_name)
            self._catalog_worker.finished.connect(self._populate_catalog_list)
            self._catalog_worker.error.connect(
                lambda e: (self._progress.setVisible(False),
                           self._status_label.setText(f"Failed to load catalogs: {e}"))
            )
            self._catalog_worker.start()

        def _populate_catalog_list(self, catalogs: list):
            self._progress.setVisible(False)
            self._status_label.setText("")
            self._catalog_list.clear()
            for catalog in catalogs:
                flags = []
                if catalog.get("isShared"):
                    flags.append("Shared")
                if catalog.get("isPublished"):
                    flags.append("Published")
                flag_str = f" [{', '.join(flags)}]" if flags else ""
                display = f"{catalog['name']} ({catalog.get('orgName', 'N/A')}){flag_str}"
                item = QListWidgetItem(display)
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                item.setCheckState(Qt.CheckState.Unchecked)
                # Keep the full catalog identity (href, owning org) so the scan can scope by it
                item.setData(Qt.ItemDataRole.UserRole, dict(catalog))
                self._catalog_list.addItem(item)
            self._catalog_list.setEnabled(True)
            self._cat_select_all.setEnabled(True)
            self._cat_deselect_all.setEnabled(True)
            self._check_ok_enabled()

            # Only auto-select once this population reflects the chosen default org
            # (the initial, unfiltered population before org selection is skipped).
            if (
                self._auto_select_all_catalogs
                and self._pending_default_org
                and self._tenant_combo.currentText() == self._pending_default_org
            ):
                self._catalog_select_all()

        def _populate_ds_list(self, datastores: list):
            self._ds_list.clear()
            for ds in datastores:
                vc_name = ds.get("vcName", "")
                display = f"{ds['name']} ({vc_name})" if vc_name else ds["name"]
                item = QListWidgetItem(display)
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                item.setCheckState(Qt.CheckState.Unchecked)
                # Keep the full datastore identity (href, vCenter) so the scan can scope by it
                item.setData(Qt.ItemDataRole.UserRole, dict(ds))
                self._ds_list.addItem(item)
            self._ds_list.setEnabled(True)
            self._ds_select_all.setEnabled(True)
            self._ds_deselect_all.setEnabled(True)
            self._check_ok_enabled()

            if self._auto_select_all_datastores:
                self._ds_select_all_fn()

        def _catalog_select_all(self):
            for i in range(self._catalog_list.count()):
                self._catalog_list.item(i).setCheckState(Qt.CheckState.Checked)

        def _catalog_deselect_all(self):
            for i in range(self._catalog_list.count()):
                self._catalog_list.item(i).setCheckState(Qt.CheckState.Unchecked)

        def _ds_select_all_fn(self):
            for i in range(self._ds_list.count()):
                self._ds_list.item(i).setCheckState(Qt.CheckState.Checked)

        def _ds_deselect_all_fn(self):
            for i in range(self._ds_list.count()):
                self._ds_list.item(i).setCheckState(Qt.CheckState.Unchecked)

        def _check_ok_enabled(self):
            has_catalogs = any(
                self._catalog_list.item(i).checkState() == Qt.CheckState.Checked
                for i in range(self._catalog_list.count())
            )
            has_ds = any(
                self._ds_list.item(i).checkState() == Qt.CheckState.Checked
                for i in range(self._ds_list.count())
            )
            self._btn_box.button(QDialogButtonBox.StandardButton.Ok).setEnabled(
                self._client is not None and has_catalogs and has_ds
            )

        def _on_accept(self):
            catalogs = [
                self._catalog_list.item(i).data(Qt.ItemDataRole.UserRole)
                for i in range(self._catalog_list.count())
                if self._catalog_list.item(i).checkState() == Qt.CheckState.Checked
            ]
            datastores = [
                self._ds_list.item(i).data(Qt.ItemDataRole.UserRole)
                for i in range(self._ds_list.count())
                if self._ds_list.item(i).checkState() == Qt.CheckState.Checked
            ]
            org = self._tenant_combo.currentText()
            if org.startswith("--"):
                org = "system"
            self._session = {
                "server": normalize_host(self._server_input.text()),
                "org": org,
                "client": self._client,
                "catalogs": catalogs,
                "datastores": datastores,
            }
            self.accept()

        def get_session(self):
            return self._session

        def closeEvent(self, event):
            for w in (self._connect_worker, self._catalog_worker):
                if w is not None and w.isRunning():
                    w.wait()
            event.accept()

    class MainWindow(QMainWindow):
        class DeleteWorker(QThread):
            """Deletes shadow VMs, running each VCD instance's sequential loop in parallel.

            Each loop is the shared delete_shadow_vms() routine: a pause between deletes,
            task polling, and a stop after repeated failures or a 401/403.
            """
            progress = Signal(int, int, str)        # current, total, name
            item_done = Signal(object)              # DeleteResult
            finished = Signal(object)               # summary dict

            def __init__(self, parent, sessions, shadows, delay_seconds=DELETE_DELAY_SECONDS):
                super().__init__(parent)
                self.sessions = sessions    # list of session dicts with 'client'/'server'
                self.shadows = shadows
                self.delay_seconds = delay_seconds

            def run(self):
                import threading
                from concurrent.futures import ThreadPoolExecutor, as_completed
                from collections import defaultdict

                # Map server → client
                server_to_client = {s["server"]: s["client"] for s in self.sessions}

                # Group shadows by vcd_server so each VCD runs its own sequential loop
                groups = defaultdict(list)
                for shadow in self.shadows:
                    groups[shadow.vcd_server].append(shadow)

                # Shared counter so progress reflects overall completion across all
                # VCD instances running in parallel, not each group's own local count.
                total_items = len(self.shadows)
                progress_lock = threading.Lock()
                completed_count = 0

                def delete_group(server, group_shadows):
                    nonlocal completed_count
                    client = server_to_client.get(server)
                    if client is None:
                        run = DeleteRun()
                        for shadow in group_shadows:
                            r = DeleteResult(shadow, "failed", f"No client for server '{server}'")
                            run.results.append(r)
                            self.item_done.emit(r)
                        return server, run

                    def on_start(_i, shadow):
                        nonlocal completed_count
                        with progress_lock:
                            completed_count += 1
                            current = completed_count
                        self.progress.emit(current, total_items, f"[{server}] {shadow.name}")

                    run = delete_shadow_vms(client, group_shadows, delay_seconds=self.delay_seconds,
                                            on_start=on_start, on_result=self.item_done.emit)
                    return server, run

                summary = {"deleted": 0, "unverified": 0, "failed": 0, "skipped": 0, "stopped": []}
                with ThreadPoolExecutor(max_workers=max(1, len(groups))) as executor:
                    futs = [
                        executor.submit(delete_group, srv, shds)
                        for srv, shds in groups.items()
                    ]
                    for fut in as_completed(futs):
                        try:
                            server, run = fut.result()
                        except Exception as e:  # unexpected bug in one group: report, keep others
                            summary["stopped"].append(f"delete loop error: {e}")
                            continue
                        summary["deleted"] += run.deleted
                        summary["unverified"] += run.unverified
                        summary["failed"] += run.failed
                        summary["skipped"] += run.skipped
                        if run.stopped_reason:
                            summary["stopped"].append(f"{server}: {run.stopped_reason}")

                self.finished.emit(summary)

        def __init__(self):
            super().__init__()
            self.shadow_vms: List[ShadowVM] = []
            self.worker: Optional[WorkerThread] = None
            self._select_all_state = False
            self._active_filters: dict[int, set[str]] = {}
            self._sort_col = -1
            self._sort_asc = True
            self.vcd_sessions: list = []  # connected VCD instances for multi-VCD scans

            self.init_ui()
            self._refresh_sessions_ui()

        def init_ui(self):
            self.setWindowTitle("VMware Cloud Director Shadow VM Cleanup")
            self.setWindowIcon(QIcon("vcd_shadow_cleaner.svg"))
            self.setMinimumSize(1000, 700)

            central_widget = QWidget()
            self.setCentralWidget(central_widget)

            main_layout = QVBoxLayout(central_widget)
            main_layout.setSpacing(10)
            main_layout.setContentsMargins(15, 15, 15, 15)

            # --- VCD Instances panel ---
            instances_frame = QFrame()
            instances_frame.setFrameShape(QFrame.Shape.StyledPanel)
            instances_outer = QVBoxLayout(instances_frame)
            instances_outer.setContentsMargins(8, 6, 8, 8)
            instances_outer.setSpacing(6)

            # Header row: "VCD Instances" title + Connect/Add button
            instances_header = QHBoxLayout()
            instances_title = QLabel("VCD Instances")
            instances_title.setStyleSheet("font-weight: bold; font-size: 13px;")
            instances_header.addWidget(instances_title)
            instances_header.addStretch()
            self._add_instance_btn = QPushButton("Connect to VCD")
            self._add_instance_btn.setMinimumHeight(32)
            self._add_instance_btn.setStyleSheet(
                "font-size: 13px; font-weight: bold; padding: 4px 16px;"
                "background-color: #2e7d32; color: white;"
            )
            self._add_instance_btn.clicked.connect(self._add_vcd_instance)
            instances_header.addWidget(self._add_instance_btn)
            instances_outer.addLayout(instances_header)

            self._sessions_list_container = QWidget()
            self._sessions_list_layout = QVBoxLayout(self._sessions_list_container)
            self._sessions_list_layout.setContentsMargins(0, 0, 0, 0)
            self._sessions_list_layout.setSpacing(2)
            instances_outer.addWidget(self._sessions_list_container)

            main_layout.addWidget(instances_frame)

            # --- Scan / Cleanup buttons ---
            btn_layout = QHBoxLayout()
            self.scan_btn = QPushButton("Scan for Shadow VMs")
            self.scan_btn.clicked.connect(self.scan_shadow_vms)
            self.scan_btn.setEnabled(False)
            self.scan_btn.setMinimumHeight(35)
            btn_layout.addWidget(self.scan_btn)

            self.cleanup_btn = QPushButton("Cleanup Shadows")
            self.cleanup_btn.clicked.connect(self.cleanup_shadows)
            self.cleanup_btn.setEnabled(False)
            self.cleanup_btn.setMinimumHeight(35)
            self.cleanup_btn.setStyleSheet("background-color: #d32f2f; color: white;")
            btn_layout.addWidget(self.cleanup_btn)
            main_layout.addLayout(btn_layout)

            # --- Results Group ---
            results_group = QGroupBox("Shadow VMs Found")
            results_layout = QVBoxLayout()

            self.summary_label = QLabel("No scan performed yet.")
            self.summary_label.setStyleSheet("font-weight: bold; padding: 5px;")
            results_layout.addWidget(self.summary_label)

            # Filter button row
            filter_row = QHBoxLayout()
            filter_row.setSpacing(6)
            filter_label = QLabel("Filters:")
            filter_label.setStyleSheet("font-weight: bold; padding-right: 4px;")
            filter_row.addWidget(filter_label)

            self._filter_buttons: dict[int, QPushButton] = {}
            for col in sorted(FILTERABLE_COLUMNS):
                btn = QPushButton(f"{COLUMN_HEADERS[col]} \u25BC")
                btn.setMaximumHeight(24)
                btn.setStyleSheet("font-size: 11px; padding: 2px 8px;")
                btn.clicked.connect(lambda checked=False, c=col: self._on_filter_requested(c))
                filter_row.addWidget(btn)
                self._filter_buttons[col] = btn

            clear_all_btn = QPushButton("Clear All Filters")
            clear_all_btn.setMaximumHeight(24)
            clear_all_btn.setStyleSheet("font-size: 11px; padding: 2px 8px;")
            clear_all_btn.clicked.connect(self._clear_all_filters)
            filter_row.addWidget(clear_all_btn)

            # Bulk selection (header and group checkboxes) picks only exact matches unless
            # this is on. Weak (name/substring) matches can always be checked one by one.
            self.include_weak_check = QCheckBox("Include weak matches in bulk select")
            self.include_weak_check.setToolTip(
                "Off: the header and group checkboxes select only exact matches (the shadow VM's "
                "parent template reference is a selected template).\nOn: they also select weak "
                "matches, found only by name or substring."
            )
            self.include_weak_check.setStyleSheet("font-size: 11px;")
            filter_row.addWidget(self.include_weak_check)

            filter_row.addStretch()

            expand_all_btn = QPushButton("Expand All")
            expand_all_btn.setMaximumHeight(24)
            expand_all_btn.setStyleSheet("font-size: 11px; padding: 2px 8px;")
            expand_all_btn.clicked.connect(lambda: self.results_table.expandAll())
            filter_row.addWidget(expand_all_btn)

            collapse_all_btn = QPushButton("Collapse All")
            collapse_all_btn.setMaximumHeight(24)
            collapse_all_btn.setStyleSheet("font-size: 11px; padding: 2px 8px;")
            collapse_all_btn.clicked.connect(lambda: self.results_table.collapseAll())
            filter_row.addWidget(collapse_all_btn)

            export_btn = QPushButton("Export to CSV")
            export_btn.setMaximumHeight(24)
            export_btn.setStyleSheet("font-size: 11px; padding: 2px 8px;")
            export_menu = QMenu(export_btn)
            export_menu.addAction(
                "Export Templates & Shadow VMs",
                lambda: self._export_csv(include_shadows=True),
            )
            export_menu.addAction(
                "Export Templates Only",
                lambda: self._export_csv(include_shadows=False),
            )
            export_btn.setMenu(export_menu)
            filter_row.addWidget(export_btn)

            results_layout.addLayout(filter_row)

            # Tree model (tree structure: group rows = templates, child rows = shadow VMs)
            self._tree_model = QStandardItemModel(0, len(COLUMN_HEADERS))
            self._tree_model.setHorizontalHeaderLabels(COLUMN_HEADERS)

            # Tree view
            self.results_table = QTreeView()
            self.results_table.setModel(self._tree_model)
            self.results_table.setAlternatingRowColors(True)
            self.results_table.setSortingEnabled(False)
            self.results_table.setUniformRowHeights(True)
            self.results_table.setItemsExpandable(True)
            self.results_table.setRootIsDecorated(True)
            self.results_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            self.results_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)

            # Custom header with select-all checkbox in col 0
            header = FilterHeaderView(Qt.Orientation.Horizontal, self.results_table)
            self.results_table.setHeader(header)
            header.setSectionsClickable(True)
            header.filter_requested.connect(self._on_filter_requested)
            header.select_all_clicked.connect(self._on_header_select_all_clicked)
            header.sort_requested.connect(self._on_sort_requested)

            header.setSectionResizeMode(COL_CHECK, QHeaderView.ResizeMode.Fixed)
            self.results_table.setColumnWidth(COL_CHECK, 40)
            for c in (COL_TEMPLATE, COL_CATALOG, COL_VMNAME, COL_DATASTORE, COL_VCD, COL_ORG):
                header.setSectionResizeMode(c, QHeaderView.ResizeMode.Stretch)
            header.setSectionResizeMode(COL_MATCH, QHeaderView.ResizeMode.ResizeToContents)

            self._tree_model.itemChanged.connect(self._on_item_changed)

            results_layout.addWidget(self.results_table)
            results_group.setLayout(results_layout)
            main_layout.addWidget(results_group, stretch=1)

            # --- Progress bar ---
            self.progress_bar = QProgressBar()
            self.progress_bar.setVisible(False)
            main_layout.addWidget(self.progress_bar)

            # --- Log area ---
            log_group = QGroupBox("Log")
            log_layout = QVBoxLayout()
            self.log_text = QTextEdit()
            self.log_text.setReadOnly(True)
            self.log_text.setMaximumHeight(100)
            self.log_text.setStyleSheet("font-family: \"Courier New\";")
            log_layout.addWidget(self.log_text)
            log_group.setLayout(log_layout)
            main_layout.addWidget(log_group)

            self.statusBar().showMessage("Ready")

        # ---- helpers ----

        def log(self, message: str):
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.log_text.append(f"[{timestamp}] {message}")

        def _get_all_column_values(self, col: int) -> list[str]:
            """Collect unique values for a filterable column.
            Template/Catalog/Datastore filters operate at the group level."""
            values = []
            for group_row in range(self._tree_model.rowCount()):
                cell = self._tree_model.item(group_row, col)
                if cell:
                    values.append(cell.text())
            return values

        def _iter_visible_child_check_items(self):
            """Yield check items (col 0) for child rows that pass active filters."""
            for group_row in range(self._tree_model.rowCount()):
                group_item = self._tree_model.item(group_row, 0)
                if group_item is None:
                    continue
                if not self.results_table.isRowHidden(group_row, self._tree_model.invisibleRootItem().index()):
                    for child_row in range(group_item.rowCount()):
                        child_chk = group_item.child(child_row, COL_CHECK)
                        if child_chk and not self.results_table.isRowHidden(
                            child_row, group_item.index()
                        ):
                            yield child_chk

        def _shadow_for_check_item(self, chk_item: QStandardItem):
            parent = chk_item.parent()
            if parent is None:
                return None
            cat_cell = parent.child(chk_item.row(), COL_CATALOG)
            return cat_cell.data(SHADOW_VM_ROLE) if cat_cell else None

        def _bulk_eligible(self, chk_item: QStandardItem) -> bool:
            """Bulk select picks exact matches, and weak ones only with the toggle on."""
            shadow = self._shadow_for_check_item(chk_item)
            if shadow is None:
                return False
            return shadow.match_strength == MATCH_EXACT or self.include_weak_check.isChecked()

        def _bulk_toggle(self, chk_items: list) -> None:
            """Check the eligible items; if they are all checked already, uncheck every item."""
            eligible = [c for c in chk_items if self._bulk_eligible(c)]
            if eligible and any(c.checkState() != Qt.CheckState.Checked for c in eligible):
                for c in eligible:
                    c.setCheckState(Qt.CheckState.Checked)
            else:
                for c in chk_items:
                    c.setCheckState(Qt.CheckState.Unchecked)

        def _on_header_select_all_clicked(self):
            """Toggle visible child rows when the header checkbox is clicked (exact only by default)."""
            root_idx = self._tree_model.invisibleRootItem().index()
            visible_groups = []
            for group_row in range(self._tree_model.rowCount()):
                group_item = self._tree_model.item(group_row, 0)
                if group_item is None or self.results_table.isRowHidden(group_row, root_idx):
                    continue
                visible_groups.append(group_item)
            self._tree_model.blockSignals(True)
            self._bulk_toggle(list(self._iter_visible_child_check_items()))
            for group_item in visible_groups:
                self._update_group_checkbox(group_item)
            self._tree_model.blockSignals(False)
            self._update_selected_count()
            self._update_header_check_state()
            # blockSignals suppressed dataChanged, so force the view to repaint
            # the checkboxes it just silently updated.
            self.results_table.viewport().update()

        def _on_group_checkbox_clicked(self, group_item: QStandardItem):
            """A group-row click checks its exact children (weak too with the toggle on);
            when those are all checked already, it unchecks every child."""
            children = [
                group_item.child(r, COL_CHECK) for r in range(group_item.rowCount())
                if group_item.child(r, COL_CHECK) is not None
            ]
            self._tree_model.blockSignals(True)
            self._bulk_toggle(children)
            self._update_group_checkbox(group_item)
            self._tree_model.blockSignals(False)
            self._update_selected_count()
            self._update_header_check_state()
            self.results_table.viewport().update()

        def _update_group_checkbox(self, group_item: QStandardItem):
            """Sync group row checkbox to reflect its children's checked state."""
            total = 0
            checked = 0
            for child_row in range(group_item.rowCount()):
                child_chk = group_item.child(child_row, COL_CHECK)
                if child_chk:
                    total += 1
                    if child_chk.checkState() == Qt.CheckState.Checked:
                        checked += 1
            if total == 0:
                group_item.setCheckState(Qt.CheckState.Unchecked)
            elif checked == total:
                group_item.setCheckState(Qt.CheckState.Checked)
            elif checked > 0:
                group_item.setCheckState(Qt.CheckState.PartiallyChecked)
            else:
                group_item.setCheckState(Qt.CheckState.Unchecked)

        def _on_sort_requested(self, col: int):
            """Sort top-level group rows by the given column; toggle asc/desc on repeat click."""
            if self._sort_col == col:
                self._sort_asc = not self._sort_asc
            else:
                self._sort_col = col
                self._sort_asc = True
            self._sort_groups()
            self.results_table.header().set_sort_indicator(self._sort_col, self._sort_asc)

        def _sort_groups(self):
            """Re-order top-level rows in the tree model by the current sort column/direction."""
            if self._sort_col < 0:
                return
            model = self._tree_model
            tree = self.results_table

            # Remember which groups were expanded (by their template name text)
            expanded = set()
            for r in range(model.rowCount()):
                idx = model.index(r, 0)
                if tree.isExpanded(idx):
                    item = model.item(r, COL_TEMPLATE)
                    if item:
                        expanded.add(item.text())

            # Collapse all so takeRow is safe (children stay on their QStandardItem parent)
            tree.collapseAll()

            model.blockSignals(True)
            num_rows = model.rowCount()
            # takeRow removes the row from the model but children remain attached to the
            # QStandardItem (col-0 item) which travels with the row list.
            all_rows = [model.takeRow(0) for _ in range(num_rows)]
            col = self._sort_col
            if col in NUMERIC_COLUMNS:
                def sort_key(row_items):
                    text = row_items[col].text() if row_items[col] else ""
                    try:
                        return int(text)
                    except (ValueError, TypeError):
                        return -1
            else:
                def sort_key(row_items):
                    return row_items[col].text().lower() if row_items[col] else ""
            all_rows.sort(key=sort_key, reverse=not self._sort_asc)
            for row_items in all_rows:
                model.appendRow(row_items)
            model.blockSignals(False)
            # blockSignals suppressed the row-move notifications the view needs to
            # keep its internal layout in sync; force a full resync so checkboxes
            # and other cell state render against their new, correct rows.
            model.layoutChanged.emit()

            # Re-expand any groups that were open before the sort
            for r in range(model.rowCount()):
                item = model.item(r, COL_TEMPLATE)
                if item and item.text() in expanded:
                    tree.expand(model.index(r, 0))

            # Re-apply filters so hidden state matches the new row order
            self._apply_filters()

        def _export_csv(self, include_shadows: bool):
            """Export the currently visible results to a CSV file.

            include_shadows=True  -> one row per shadow VM (Parent Template, VM Name, Catalog, Datastore)
            include_shadows=False -> one row per template group (Parent Template, Catalog, Shadow VMs, Datastore)
            Honors active filters: hidden (filtered-out) groups are skipped.
            """
            import csv

            if self._tree_model.rowCount() == 0:
                QMessageBox.information(
                    self, "No Data", "There are no results to export. Run a scan first."
                )
                return

            default_name = "shadow_vms.csv" if include_shadows else "shadow_templates.csv"
            path, _ = QFileDialog.getSaveFileName(
                self, "Export to CSV", default_name, "CSV Files (*.csv);;All Files (*)"
            )
            if not path:
                return
            if not path.lower().endswith(".csv"):
                path += ".csv"

            root_idx = self._tree_model.invisibleRootItem().index()
            rows_written = 0
            try:
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    if include_shadows:
                        writer.writerow(
                            ["Parent Template", "VM Name", "Catalog", "Datastore",
                             "VCD Instance", "Org"]
                        )
                    else:
                        writer.writerow(
                            ["Parent Template", "Catalog", "Shadow VMs", "Datastore",
                             "VCD Instance", "Org"]
                        )

                    for group_row in range(self._tree_model.rowCount()):
                        if self.results_table.isRowHidden(group_row, root_idx):
                            continue
                        grp_chk = self._tree_model.item(group_row, COL_CHECK)
                        template_name = self._tree_model.item(group_row, COL_TEMPLATE).text()
                        catalog_name = self._tree_model.item(group_row, COL_CATALOG).text()
                        vm_count = self._tree_model.item(group_row, COL_VMNAME).text()
                        datastore_name = self._tree_model.item(group_row, COL_DATASTORE).text()
                        vcd_name = self._tree_model.item(group_row, COL_VCD).text()
                        org_name = self._tree_model.item(group_row, COL_ORG).text()

                        if include_shadows:
                            for child_row in range(grp_chk.rowCount()):
                                cat_item = grp_chk.child(child_row, COL_CATALOG)
                                shadow = cat_item.data(SHADOW_VM_ROLE) if cat_item else None
                                if shadow is not None:
                                    vm_name = shadow.name
                                    ds = shadow.datastore_name or datastore_name
                                else:
                                    tpl_item = grp_chk.child(child_row, COL_TEMPLATE)
                                    vm_name = tpl_item.text().strip() if tpl_item else ""
                                    ds = datastore_name
                                writer.writerow(
                                    [template_name, vm_name, catalog_name, ds,
                                     vcd_name, org_name]
                                )
                                rows_written += 1
                        else:
                            writer.writerow(
                                [template_name, catalog_name, vm_count, datastore_name,
                                 vcd_name, org_name]
                            )
                            rows_written += 1
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", f"Failed to write CSV file:\n{e}")
                self.log(f"CSV export failed: {e}")
                return

            self.log(f"Exported {rows_written} row(s) to {path}")
            self.statusBar().showMessage(f"Exported {rows_written} row(s) to {path}")
            QMessageBox.information(
                self, "Export Complete", f"Exported {rows_written} row(s) to:\n{path}"
            )

        def _on_filter_requested(self, col_signal: int):
            header = self.results_table.header()
            if col_signal <= 0:
                col = -col_signal
                self._active_filters.pop(col, None)
                header.set_filtered(col, False)
                self._update_filter_button(col, False)
                self._apply_filters()
                self._update_summary()
                return

            col = col_signal
            all_values = self._get_all_column_values(col)
            current_checked = self._active_filters.get(col)

            dlg = FilterPopupDialog(self, COLUMN_HEADERS[col], all_values, current_checked)
            if dlg.exec() == QDialog.DialogCode.Accepted:
                result = dlg.result_set
                if result is None:
                    self._active_filters.pop(col, None)
                    header.set_filtered(col, False)
                    self._update_filter_button(col, False)
                else:
                    all_unique = set(all_values)
                    is_filtered = result != all_unique
                    self._active_filters[col] = result
                    header.set_filtered(col, is_filtered)
                    self._update_filter_button(col, is_filtered)
                self._apply_filters()
                self._update_summary()

        def _apply_filters(self):
            """Show/hide group rows based on active filters (filters operate at group level)."""
            root_idx = self._tree_model.invisibleRootItem().index()
            for group_row in range(self._tree_model.rowCount()):
                group_visible = True
                for col, allowed in self._active_filters.items():
                    cell = self._tree_model.item(group_row, col)
                    val = cell.text() if cell else ""
                    if val not in allowed:
                        group_visible = False
                        break
                self.results_table.setRowHidden(group_row, root_idx, not group_visible)
            self._update_header_check_state()

        def _clear_all_filters(self):
            self._active_filters.clear()
            header = self.results_table.header()
            for c in FILTERABLE_COLUMNS:
                header.set_filtered(c, False)
                self._update_filter_button(c, False)
            self._apply_filters()
            self._update_summary()

        def _update_filter_button(self, col: int, is_filtered: bool):
            btn = self._filter_buttons.get(col)
            if btn:
                name = COLUMN_HEADERS[col]
                if is_filtered:
                    btn.setText(f"{name} \u25BC *")
                    btn.setStyleSheet("font-size: 11px; padding: 2px 8px; color: #4fc3f7; font-weight: bold;")
                else:
                    btn.setText(f"{name} \u25BC")
                    btn.setStyleSheet("font-size: 11px; padding: 2px 8px;")

        def _on_item_changed(self, item: QStandardItem):
            if item.column() != COL_CHECK:
                return
            is_group = item.data(IS_GROUP_ROLE)
            if is_group:
                self._on_group_checkbox_clicked(item)
            else:
                # Child checkbox changed: update parent group checkbox
                parent = item.parent()
                if parent:
                    self._tree_model.blockSignals(True)
                    self._update_group_checkbox(parent)
                    self._tree_model.blockSignals(False)
                    self.results_table.viewport().update()
                self._update_selected_count()
                self._update_header_check_state()

        def _update_selected_count(self):
            visible, hidden = self._collect_delete_selection()
            msg = f"Selected Shadow VMs: {len(visible)}"
            if hidden:
                msg += f" ({hidden} more checked but hidden by filters; they will not be deleted)"
            self.statusBar().showMessage(msg)

        def _update_header_check_state(self):
            """Sync the header checkbox in col 0 to reflect visible child row states."""
            total_visible = 0
            total_checked = 0
            root_idx = self._tree_model.invisibleRootItem().index()
            for group_row in range(self._tree_model.rowCount()):
                if self.results_table.isRowHidden(group_row, root_idx):
                    continue
                group_item = self._tree_model.item(group_row, 0)
                if group_item is None:
                    continue
                for child_row in range(group_item.rowCount()):
                    child_chk = group_item.child(child_row, COL_CHECK)
                    if child_chk:
                        total_visible += 1
                        if child_chk.checkState() == Qt.CheckState.Checked:
                            total_checked += 1
            if total_visible == 0 or total_checked == 0:
                self.results_table.header().set_check_state(Qt.CheckState.Unchecked)
            elif total_checked == total_visible:
                self.results_table.header().set_check_state(Qt.CheckState.Checked)
            else:
                self.results_table.header().set_check_state(Qt.CheckState.PartiallyChecked)

        def _update_summary(self):
            total_vms = 0
            visible_vms = 0
            root_idx = self._tree_model.invisibleRootItem().index()
            for group_row in range(self._tree_model.rowCount()):
                group_item = self._tree_model.item(group_row, 0)
                if group_item is None:
                    continue
                count = group_item.rowCount()
                total_vms += count
                if not self.results_table.isRowHidden(group_row, root_idx):
                    visible_vms += count
            if total_vms == visible_vms:
                self.summary_label.setText(f"Found {total_vms} Shadow VMs")
            else:
                self.summary_label.setText(f"Showing {visible_vms} of {total_vms} Shadow VMs (filtered)")

        # ---- VCD sessions ----

        def _add_vcd_instance(self):
            dlg = VCDInstanceDialog(self)
            if dlg.exec() == QDialog.DialogCode.Accepted:
                session = dlg.get_session()
                if session:
                    self.vcd_sessions.append(session)
                    self._refresh_sessions_ui()
                    self.scan_btn.setEnabled(True)
                    self.log(
                        f"Configured: {session['server']} / {session['org']} — "
                        f"{len(session['catalogs'])} catalog(s), "
                        f"{len(session['datastores'])} datastore(s)"
                    )
                    self.statusBar().showMessage("Ready to scan.")

        def _remove_vcd_session(self, idx: int):
            if 0 <= idx < len(self.vcd_sessions):
                server = self.vcd_sessions[idx]["server"]
                try:
                    self.vcd_sessions[idx]["client"].disconnect()
                except Exception:
                    pass
                del self.vcd_sessions[idx]
                self._refresh_sessions_ui()
                self.scan_btn.setEnabled(bool(self.vcd_sessions))

                # Remove this VCD instance's discovered Shadow VMs from the results tree.
                group_rows_to_remove = [
                    group_row
                    for group_row in range(self._tree_model.rowCount())
                    if (vcd_cell := self._tree_model.item(group_row, COL_VCD)) is not None
                    and vcd_cell.text() == server
                ]
                for group_row in reversed(group_rows_to_remove):
                    self._tree_model.removeRow(group_row)

                self.shadow_vms = [s for s in self.shadow_vms if s.vcd_server != server]
                self.cleanup_btn.setEnabled(len(self.shadow_vms) > 0)
                self._update_summary()
                self._update_selected_count()
                self._update_header_check_state()

        def _refresh_sessions_ui(self):
            layout = self._sessions_list_layout
            while layout.count():
                item = layout.takeAt(0)
                w = item.widget()
                if w:
                    w.deleteLater()

            if not self.vcd_sessions:
                self._add_instance_btn.setText("Connect to VCD")
                lbl = QLabel("Not connected to any VCD instance.")
                lbl.setStyleSheet("color: #888; font-style: italic; font-size: 11px;")
                layout.addWidget(lbl)
            else:
                self._add_instance_btn.setText("+ Add VCD Instance")
                for i, session in enumerate(self.vcd_sessions):
                    cats = len(session["catalogs"])
                    dss = len(session["datastores"])
                    row_widget = QWidget()
                    row_layout = QHBoxLayout(row_widget)
                    row_layout.setContentsMargins(0, 0, 0, 0)
                    lbl = QLabel(
                        f"● {session['server']}  /  {session['org']}"
                        f"  —  {cats} catalog(s), {dss} datastore(s)"
                    )
                    lbl.setStyleSheet("color: #90caf9; font-size: 11px;")
                    row_layout.addWidget(lbl, 1)
                    remove_btn = QPushButton("✕")
                    remove_btn.setMaximumWidth(28)
                    remove_btn.setMaximumHeight(22)
                    remove_btn.setStyleSheet(
                        "color: #f44336; font-weight: bold; font-size: 11px;"
                    )
                    remove_btn.clicked.connect(
                        lambda checked=False, ii=i: self._remove_vcd_session(ii)
                    )
                    row_layout.addWidget(remove_btn)
                    layout.addWidget(row_widget)

        # ---- scan ----

        def scan_shadow_vms(self):
            if not self.vcd_sessions:
                QMessageBox.warning(
                    self, "Error",
                    "No VCD instances configured.\nClick '+ Add VCD Instance' to configure one."
                )
                return

            all_sessions = list(self.vcd_sessions)
            total_vcds = len(all_sessions)
            total_cats = sum(len(s["catalogs"]) for s in all_sessions)
            total_ds = sum(len(s["datastores"]) for s in all_sessions)
            self.log(
                f"Scanning {total_vcds} VCD instance(s) in parallel — "
                f"{total_cats} catalog(s), {total_ds} datastore(s)..."
            )
            self.statusBar().showMessage("Scanning...")
            self.scan_btn.setEnabled(False)
            self.cleanup_btn.setEnabled(False)
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 0)

            self.scan_worker = WorkerThread(scan_sessions, all_sessions)
            self.scan_worker.finished.connect(self._on_scan_finished)
            self.scan_worker.error.connect(self._on_scan_error)
            self.scan_worker.start()

        def _on_scan_error(self, error_message: str):
            self.progress_bar.setVisible(False)
            self.scan_btn.setEnabled(True)
            self.cleanup_btn.setEnabled(len(self.shadow_vms) > 0)
            self.log(f"Scan failed: {error_message}")
            self.statusBar().showMessage("Scan failed")
            QMessageBox.critical(
                self, "Scan Error", f"Failed to scan for Shadow VMs:\n{error_message}"
            )

        def _on_scan_finished(self, scan_result):
            if isinstance(scan_result, ScanResult):
                shadow_vms = scan_result.shadows
            else:  # a plain list of ShadowVM
                shadow_vms, scan_result = list(scan_result), ScanResult(shadows=list(scan_result))
            self.shadow_vms = shadow_vms

            # Clear filters, sort state, and rebuild model
            self._active_filters.clear()
            self._sort_col = -1
            self._sort_asc = True
            header = self.results_table.header()
            for c in FILTERABLE_COLUMNS:
                header.set_filtered(c, False)
                self._update_filter_button(c, False)
            header.set_sort_indicator(-1, True)
            self._select_all_state = False

            self._tree_model.blockSignals(True)
            self._tree_model.removeRows(0, self._tree_model.rowCount())

            # Group by (template, catalog, datastore, vcd_server) so the same template on
            # different datastores or VCD instances appears as distinct rows.
            from collections import defaultdict
            groups: dict[tuple, list] = defaultdict(list)
            for shadow in self.shadow_vms:
                key = (
                    shadow.container_name.lower() if shadow.container_name else '',
                    shadow.catalog_name.lower(),
                    shadow.datastore_name.lower(),
                    shadow.vcd_server.lower(),
                )
                groups[key].append(shadow)

            for key in sorted(groups.keys()):
                group_shadows = groups[key]
                first = group_shadows[0]
                template_name = first.container_name or "(unknown)"
                catalog_name = first.catalog_name
                datastore_name = first.datastore_name
                vm_count = len(group_shadows)

                # Group row: template name (bold), catalog, VM count, datastore
                grp_chk = QStandardItem()
                grp_chk.setCheckable(True)
                grp_chk.setCheckState(Qt.CheckState.Unchecked)
                grp_chk.setEditable(False)
                grp_chk.setData(True, IS_GROUP_ROLE)
                grp_chk.setFlags(
                    grp_chk.flags()
                    | Qt.ItemFlag.ItemIsUserTristate
                )

                grp_tpl = QStandardItem(template_name)
                grp_tpl.setEditable(False)
                grp_tpl.setData(True, IS_GROUP_ROLE)
                font = grp_tpl.font()
                font.setBold(True)
                grp_tpl.setFont(font)

                grp_cat = QStandardItem(catalog_name)
                grp_cat.setEditable(False)
                grp_cat.setData(True, IS_GROUP_ROLE)

                grp_vm = QStandardItem(str(vm_count))
                grp_vm.setEditable(False)
                grp_vm.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

                grp_ds = QStandardItem(datastore_name)
                grp_ds.setEditable(False)

                grp_vcd = QStandardItem(first.vcd_server)
                grp_vcd.setEditable(False)
                grp_vcd.setData(True, IS_GROUP_ROLE)

                grp_org = QStandardItem(first.org_name)
                grp_org.setEditable(False)
                grp_org.setData(True, IS_GROUP_ROLE)

                strengths = {s.match_strength == MATCH_EXACT for s in group_shadows}
                grp_match = QStandardItem(
                    "exact" if strengths == {True} else ("weak" if strengths == {False} else "mixed")
                )
                grp_match.setEditable(False)
                grp_match.setData(True, IS_GROUP_ROLE)

                self._tree_model.appendRow(
                    [grp_chk, grp_tpl, grp_cat, grp_vm, grp_ds, grp_vcd, grp_org, grp_match]
                )

                # Child rows: VM name (indented) in COL_TEMPLATE; VCD/Org blank (implied by group)
                for shadow in sorted(group_shadows, key=lambda s: s.name.lower()):
                    chk_item = QStandardItem()
                    chk_item.setCheckable(True)
                    chk_item.setCheckState(Qt.CheckState.Unchecked)
                    chk_item.setEditable(False)
                    chk_item.setData(False, IS_GROUP_ROLE)

                    tpl_item = QStandardItem("  " + shadow.name)
                    tpl_item.setEditable(False)

                    cat_item = QStandardItem("")
                    cat_item.setData(shadow, SHADOW_VM_ROLE)
                    cat_item.setEditable(False)

                    vm_item = QStandardItem("")
                    vm_item.setEditable(False)

                    ds_item = QStandardItem(shadow.datastore_name)
                    ds_item.setEditable(False)

                    vcd_item = QStandardItem("")
                    vcd_item.setEditable(False)

                    org_item = QStandardItem("")
                    org_item.setEditable(False)

                    match_text = shadow.match_strength or "?"
                    if shadow.ambiguous_with:
                        match_text += " (ambiguous)"
                    match_item = QStandardItem(match_text)
                    match_item.setEditable(False)
                    tip = f"Rule: {shadow.match_rule or '?'}"
                    if shadow.parent_ref:
                        tip += f"\nParent reference: {shadow.parent_ref}"
                    if shadow.ambiguous_with:
                        tip += "\nAlso fits: " + ", ".join(
                            f"{a.get('template')} [{a.get('catalog')}]" for a in shadow.ambiguous_with
                        )
                    match_item.setToolTip(tip)
                    if shadow.is_weak:
                        match_item.setForeground(QColor(255, 167, 38))
                        tpl_item.setToolTip("Weak match (name/substring only): not selected by bulk select")

                    grp_chk.appendRow(
                        [chk_item, tpl_item, cat_item, vm_item, ds_item, vcd_item, org_item, match_item]
                    )

            self._tree_model.setHorizontalHeaderLabels(COLUMN_HEADERS)
            self._tree_model.blockSignals(False)

            # Collapse all groups by default
            self.results_table.collapseAll()

            counts = scan_result.counts
            self.summary_label.setText(
                f"Found {len(self.shadow_vms)} Shadow VMs ({counts['exact']} exact, {counts['weak']} weak)"
                + ("" if scan_result.complete else " - INCOMPLETE, see log")
            )
            self.progress_bar.setVisible(False)
            self.scan_btn.setEnabled(True)
            self.cleanup_btn.setEnabled(len(self.shadow_vms) > 0)
            self.results_table.header().set_check_state(Qt.CheckState.Unchecked)
            state = "complete" if scan_result.complete else "INCOMPLETE"
            self.statusBar().showMessage(f"Scan {state}: {len(self.shadow_vms)} Shadow VMs found")
            self.log(
                f"Scan {state}: {len(self.shadow_vms)} Shadow VMs ({counts['exact']} exact, "
                f"{counts['weak']} weak); {counts['other_template']} belong to other templates, "
                f"{counts['unmatched']} unmatched"
            )
            for w in scan_result.warnings:
                self.log(f"Warning: {w}")
            for e in scan_result.errors:
                self.log(f"Error: {format_error(e)}")
            self._update_selected_count()
            if not scan_result.complete:
                QMessageBox.warning(
                    self, "Scan Incomplete",
                    "Some queries failed, so these results are partial:\n\n"
                    + "\n".join(format_error(e) for e in scan_result.errors[:10])
                )

        # ---- cleanup ----

        def _collect_delete_selection(self):
            """Return (checked shadows in visible rows, count of checked rows hidden by filters)."""
            visible = []
            visible_ids = set()
            for chk in self._iter_visible_child_check_items():
                if chk.checkState() == Qt.CheckState.Checked:
                    shadow = self._shadow_for_check_item(chk)
                    if shadow is not None:
                        visible.append(shadow)
                        visible_ids.add(id(shadow))
            hidden = 0
            for group_row in range(self._tree_model.rowCount()):
                group_item = self._tree_model.item(group_row, 0)
                if group_item is None:
                    continue
                for child_row in range(group_item.rowCount()):
                    chk = group_item.child(child_row, COL_CHECK)
                    if chk and chk.checkState() == Qt.CheckState.Checked:
                        shadow = self._shadow_for_check_item(chk)
                        if shadow is not None and id(shadow) not in visible_ids:
                            hidden += 1
            return visible, hidden

        def _delete_confirmation_text(self, selected: list, hidden: int) -> str:
            exact = [s for s in selected if s.match_strength == MATCH_EXACT]
            weak = [s for s in selected if s.match_strength != MATCH_EXACT]
            lines = [
                f"Are you sure you want to delete {len(selected)} selected Shadow VMs?",
                "",
                f"Exact matches (parent template reference): {len(exact)}",
                f"WEAK matches (name/substring only): {len(weak)}",
            ]
            for s in weak[:10]:
                lines.append(f"    - {s.name}  ->  {s.container_name} [{s.match_strength or '?'}]")
            if len(weak) > 10:
                lines.append(f"    ... and {len(weak) - 10} more")
            if hidden:
                lines += ["", f"{hidden} checked row(s) hidden by the current filters will be skipped "
                              f"(not deleted)."]
            lines += ["", "This action cannot be undone!"]
            return "\n".join(lines)

        def cleanup_shadows(self):
            if not self.vcd_sessions:
                return

            # Only rows visible under the current filters are deleted.
            selected_shadow_vms, hidden = self._collect_delete_selection()

            if not selected_shadow_vms:
                msg = "No Shadow VMs selected for deletion."
                if hidden:
                    msg += (f"\n\n{hidden} checked row(s) are hidden by the current filters; hidden rows "
                            f"are never deleted.")
                QMessageBox.information(self, "No Selection", msg)
                return

            reply = QMessageBox.question(
                self, "Confirm Deletion",
                self._delete_confirmation_text(selected_shadow_vms, hidden),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

            self.log("Starting Shadow VM deletion...")
            self.statusBar().showMessage("Deleting Shadow VMs...")
            self.cleanup_btn.setEnabled(False)
            self.scan_btn.setEnabled(False)
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, len(selected_shadow_vms))
            self.progress_bar.setValue(0)

            # Run deletion on a background thread (it sleeps between deletes) so the
            # UI stays responsive instead of showing the macOS spinning beachball.
            self._deleted_shadow_ids = set()
            self.delete_worker = self.DeleteWorker(
                self, list(self.vcd_sessions), selected_shadow_vms
            )
            self.delete_worker.progress.connect(self._on_delete_progress)
            self.delete_worker.item_done.connect(self._on_delete_item_done)
            self.delete_worker.finished.connect(self._on_delete_finished)
            self.delete_worker.start()

        def _on_delete_progress(self, current: int, total: int, name: str):
            self.progress_bar.setValue(current)
            self.statusBar().showMessage(f"Deleting {current}/{total}: {name}")

        def _on_delete_item_done(self, result):
            shadow = result.shadow
            if result.status == "deleted":
                self.log(f"Deleted: {shadow.name}")
                self._deleted_shadow_ids.add(id(shadow))
            elif result.status == "accepted_unverified":
                self.log(f"Accepted, not verified: {shadow.name} - {result.message}")
                self._deleted_shadow_ids.add(id(shadow))
            elif result.status == "skipped":
                self.log(f"Skipped: {shadow.name} - {result.message}")
            else:
                self.log(f"Failed: {shadow.name} - {result.message}")

        def _on_delete_finished(self, summary: dict):
            deleted_shadows = self._deleted_shadow_ids

            # Remove deleted child rows from tree model; remove empty group rows
            self._tree_model.blockSignals(True)
            group_rows_to_remove = []
            for group_row in range(self._tree_model.rowCount()):
                group_item = self._tree_model.item(group_row, 0)
                if group_item is None:
                    continue
                child_rows_to_remove = []
                for child_row in range(group_item.rowCount()):
                    cat_cell = group_item.child(child_row, COL_CATALOG)
                    if cat_cell:
                        s = cat_cell.data(SHADOW_VM_ROLE)
                        if s and id(s) in deleted_shadows:
                            child_rows_to_remove.append(child_row)
                for child_row in reversed(child_rows_to_remove):
                    group_item.removeRow(child_row)
                if group_item.rowCount() == 0:
                    group_rows_to_remove.append(group_row)
            for group_row in reversed(group_rows_to_remove):
                self._tree_model.removeRow(group_row)
            self._tree_model.blockSignals(False)

            self.shadow_vms = [s for s in self.shadow_vms if id(s) not in deleted_shadows]

            self.progress_bar.setVisible(False)
            self.scan_btn.setEnabled(True)
            self.cleanup_btn.setEnabled(len(self.shadow_vms) > 0)
            self._update_summary()
            text = (f"Deleted: {summary['deleted']}, accepted (not verified): {summary['unverified']}, "
                    f"failed: {summary['failed']}, skipped: {summary['skipped']}")
            self.statusBar().showMessage(f"Deletion complete: {text}")
            self.log(f"Deletion complete: {text}")
            for reason in summary.get("stopped", []):
                self.log(f"Stopped: {reason}")
            self._update_selected_count()

            body = (
                f"Deletion complete.\n\nDeleted (confirmed by VCD): {summary['deleted']}\n"
                f"Accepted, not verified: {summary['unverified']}\n"
                f"Failed: {summary['failed']}\nSkipped: {summary['skipped']}"
            )
            if summary.get("stopped"):
                body += "\n\n" + "\n".join(summary["stopped"])
            QMessageBox.information(self, "Deletion Complete", body)

        def closeEvent(self, event):
            # Wait for any running background worker so the app doesn't crash with
            # "QThread: Destroyed while thread is still running".
            for attr in ("scan_worker", "delete_worker"):
                worker = getattr(self, attr, None)
                if worker is not None and worker.isRunning():
                    worker.wait()
            for session in self.vcd_sessions:
                try:
                    session["client"].disconnect()
                except Exception:
                    pass
            event.accept()

    if build_only:
        return {"MainWindow": MainWindow, "VCDInstanceDialog": VCDInstanceDialog,
                "WorkerThread": WorkerThread, "EditSavedServerDialog": EditSavedServerDialog}

    # Run the application
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Base, QColor(35, 35, 35))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(25, 25, 25))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Text, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 0, 0))
    palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(0, 0, 0))
    app.setPalette(palette)

    window = MainWindow()
    window.show()

    return app.exec()


def main():
    # Load .env file if present
    load_env_file()

    parser = argparse.ArgumentParser(
        description="VMware Cloud Director Shadow VM Cleanup Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Run in GUI mode (default)
    python vcd_shadow_cleaner.py

    # Run in CLI mode with API token
    python vcd_shadow_cleaner.py --cli --server vcd.example.com --token YOUR_API_TOKEN \\
        --tenant MyTenant --catalog MyCatalog --datastore MyDatastore

    # Use a connection profile saved from the GUI (credentials come from the
    # system keyring and are only used to authenticate the scan/cleanup)
    python vcd_shadow_cleaner.py --cli --saved-server "Production VCD" \\
        --catalog MyCatalog --datastore MyDatastore --dry-run

    # Move base64-stored credentials into the system keyring (preview first)
    python vcd_shadow_cleaner.py --migrate-credentials --dry-run
    python vcd_shadow_cleaner.py --migrate-credentials

    # List saved connection profiles / discover resource names
    python vcd_shadow_cleaner.py --cli --list-servers
    python vcd_shadow_cleaner.py --cli --saved-server "Production VCD" \\
        --list-tenants --list-catalogs --list-datastores

    # Machine-readable output for scripts and AI agents
    # (JSON on stdout, progress on stderr)
    python vcd_shadow_cleaner.py --cli --saved-server "Production VCD" \\
        --catalog MyCatalog --datastore MyDatastore --dry-run --json

    # Run in CLI mode using environment variables (VCD_SERVER, VCD_TOKEN, etc.)
    # .env file is also supported
    python vcd_shadow_cleaner.py --cli --tenant MyTenant --catalog MyCatalog --datastore MyDatastore

Deletion is permanent. Unless --dry-run is given, the CLI asks "Are you sure?"
on the controlling terminal (/dev/tty, or CONIN$ on Windows) and requires typing
'yes'. The answer is never read from stdin, so piping 'yes' cannot confirm it; with
no terminal the CLI refuses to delete (exit 5). There is no flag to skip it.
By default only exact matches (the shadow VM's parent template reference is a
selected template) are deleted; --include-weak adds name/substring matches.

Exit codes: 0 success; 1 internal/usage error; 2 catalog or datastore not found;
3 authentication failed; 4 VCD or network error (results incomplete, nothing
deleted); 5 delete refused (no terminal); 7 some deletes failed or were skipped.
        """
    )

    parser.add_argument("--cli", action="store_true", help="Run in command-line interface mode (default is GUI)")

    # Connection args (can be loaded from env vars)
    parser.add_argument("--server", "-s", default=os.environ.get("VCD_SERVER"), help="VCD server hostname or IP")
    parser.add_argument("--token", "-t", default=os.environ.get("VCD_TOKEN"), help="VCD API token")
    parser.add_argument("--username", "-u", default=os.environ.get("VCD_USER"), help="VCD username (alternative to token)")
    parser.add_argument("--password", "-p", default=os.environ.get("VCD_PASSWORD"), help="VCD password (alternative to token)")
    parser.add_argument("--saved-server", "-S", metavar="NAME",
                        help="Use a connection profile saved from the GUI, matched by display name, hostname, or id. "
                             "Supplies the server, stored credential (from the system keyring), default org, and SSL "
                             "setting. Stored credentials are only used to authenticate this shadow-VM scan/cleanup. "
                             "Implies --cli.")
    parser.add_argument("--list-servers", action="store_true",
                        help="List saved server profiles (credentials are never shown) and exit. Implies --cli.")
    parser.add_argument("--migrate-credentials", action="store_true",
                        help="Move saved-server credentials stored base64-encoded in servers.json into the "
                             "system keyring, then exit. Backs up servers.json first; with --dry-run only "
                             "reports what would happen. Credential values are never shown. Implies --cli.")

    parser.add_argument("--tenant", default=os.environ.get("VCD_TENANT"), help="Target tenant/organization name")
    parser.add_argument("--catalog", "-c", default=os.environ.get("VCD_CATALOG"), help="Catalog name(s) to scan, comma-separated")
    parser.add_argument("--datastore", "-d", default=os.environ.get("VCD_DATASTORE"), help="Datastore name(s) to scan, comma-separated")

    parser.add_argument("--list-tenants", action="store_true",
                        help="Connect, list tenants/organizations, and exit. Implies --cli.")
    parser.add_argument("--list-catalogs", action="store_true",
                        help="Connect, list catalogs (filtered by --tenant if given), and exit. Implies --cli.")
    parser.add_argument("--list-datastores", action="store_true",
                        help="Connect, list datastores, and exit. Implies --cli.")

    parser.add_argument("--dry-run", action="store_true", help="Show what would be deleted without making changes")
    parser.add_argument("--include-weak", action="store_true",
                        help="Also delete weak matches (found only by name or substring). By default only "
                             "exact matches (parent template reference) are deleted.")
    parser.add_argument("--json", action="store_true",
                        help="Print results as JSON on stdout (progress goes to stderr); for scripts and AI agents")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug output during the scan")
    parser.add_argument("--skip-ssl-verify", action="store_true", default=os.environ.get("VCD_SKIP_SSL", "false").lower() == "true", help="Skip SSL certificate verification")

    args = parser.parse_args()

    # CLI-only actions imply --cli; otherwise default to GUI
    cli_mode = (args.cli or args.saved_server or args.list_servers or args.migrate_credentials
                or args.list_tenants or args.list_catalogs or args.list_datastores)
    if not cli_mode:
        return run_gui()

    # --list-servers / --migrate-credentials only touch the local profile store
    # (and the keyring); no connection args needed
    if args.list_servers or args.migrate_credentials:
        return run_cli(args)

    if not args.server and not args.saved_server:
        print("ERROR: --server is required in CLI mode (or set VCD_SERVER env var, or use --saved-server).")
        return 1

    # Catalog/datastore are only required for an actual scan, not for discovery
    if not (args.list_tenants or args.list_catalogs or args.list_datastores):
        if not args.catalog:
            print("ERROR: --catalog is required in CLI mode (or set VCD_CATALOG env var). "
                  "Use --list-catalogs to discover catalog names.")
            return 1
        if not args.datastore:
            print("ERROR: --datastore is required in CLI mode (or set VCD_DATASTORE env var). "
                  "Use --list-datastores to discover datastore names.")
            return 1

    return run_cli(args)


if __name__ == "__main__":
    sys.exit(main())
