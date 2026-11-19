# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the application

```bash
# Activate the virtual environment first
source venv/bin/activate

# GUI mode (default)
python vcd_shadow_cleaner.py

# CLI mode
python vcd_shadow_cleaner.py --cli --server <vcd_host> --token <api_token> \
    --tenant <tenant_name> --catalog <catalog_name> --datastore <datastore_name> \
    [--dry-run] [--include-weak] [--json] [--skip-ssl-verify]

# CLI mode with a saved server profile (created in the GUI; credential from OS keyring)
python vcd_shadow_cleaner.py --cli --saved-server "<profile_name>" \
    --catalog <catalog_name> --datastore <datastore_name> [--dry-run] [--json]

# Discovery (each implies --cli): --list-servers, --list-tenants, --list-catalogs, --list-datastores

# Tests (offline, fake VCD session; the GUI test runs offscreen)
venv/bin/python -m pytest -q tests
```

CLI safety: unless `--dry-run` is given, the CLI prompts "Are you sure?" on the controlling terminal (`_open_tty()`: `/dev/tty`, `CONIN$` on Windows) and requires typing `yes`; stdin is never read for it, and with no terminal it refuses (exit 5). There is deliberately no `--yes`/`--force` bypass flag. It deletes exact matches only unless `--include-weak`. Exit codes: 0 ok, 1 internal/usage, 2 catalog/datastore name not found, 3 auth failed, 4 VCD/network error (incomplete; JSON `complete: false` + `errors`), 5 no terminal to confirm, 7 deletes failed or skipped. `--json` prints machine-readable results on stdout and moves all progress output to stderr. Saved-server credentials are used only to authenticate the shadow-VM scan/cleanup session.

## Building standalone executables

```bash
# macOS
pyinstaller vcd_shadow_cleaner.py --noconsole --onefile --add-data "vcd_shadow_cleaner.svg:." --icon "vcd_shadow_cleaner.icns"

# Windows (must be run on Windows)
pyinstaller vcd_shadow_cleaner.py --noconsole --onefile --add-data "vcd_shadow_cleaner.svg:." --icon "vcd_shadow_cleaner.ico"

# Output is placed in dist/
```

## Architecture

The entire application lives in a single file: `vcd_shadow_cleaner.py`. Tests live in `tests/` (pytest; `tests/helpers.py` holds the fake HTTP session). Set `VSC_MODULE_PATH` to run them against another copy of the file.

### Key classes and data flow

**`VCDClient`** — all VCD API calls. Handles authentication (API token via OAuth refresh, or username/password via CloudAPI/legacy sessions), pagination, and deletion. Uses VCD API version `38.0`. Every request goes through `_request()` (timeout `HTTP_TIMEOUT`, GET-only retry on 429/502/503/504, query values encoded via `params=`). Failures raise `VCDAuthError` / `VCDQueryError` (stage, target, HTTP status); no query returns an empty list on error.

**`scan_shadow_vms()`** (module-level) takes catalog/datastore names or the identity dicts from discovery, filters template and shadow records client-side by catalog org / datastore / vCenter where the record carries the field (warning otherwise), and returns a `ScanResult` (`shadows`, `counts`, `errors`, `warnings`, `complete`). Each matched `ShadowVM` gets `match_strength`: **exact** (parent reference is a selected template) → **name** (container name, or name prefix) → **substring** (token boundaries `- _ space . ( )` only); longest template name first, other fits in `ambiguous_with`. A shadow whose parent reference points at an unselected template counts as `other_template` and is never name-matched. `scan_sessions()` scans several GUI sessions and keeps partial results when one fails.

**`delete_shadow_vms()`** — the one delete loop for CLI and GUI: 3 s pause, stop after 3 consecutive failures or any 401/403. `VCDClient.delete_shadow_vm()` polls a returned task and reports deleted / accepted_unverified / failed / timeout.

**`ShadowVM` / `VAppTemplate`** — plain dataclasses representing API resources.

**`run_gui()`** — PySide6 GUI, defined entirely inside this function. Contains nested class definitions for all Qt widgets, workers, and models. Key nested classes:
- `ColumnFilterProxyModel` — Excel-style per-column filter proxy
- `FilterPopupDialog` — multi-select filter popup
- `WorkerThread(QThread)` — background thread for connect/discovery/scan; emits `finished(object)` and `error(str)`
- `DeleteWorker(QThread)` — runs `delete_shadow_vms()` per VCD instance in parallel
- `MainWindow(QMainWindow)` — the main GUI window; cascading dropdowns load tenants → catalogs (multi-select) → datastores; results shown as a tree view grouped by parent template, with a Match column. Header/group checkboxes select exact matches only unless "Include weak matches in bulk select" is on; deletion takes only checked rows visible under the filters.

`run_gui(build_only=True)` returns the GUI classes without starting the app (used by the offscreen test).

**`run_cli(args)`** — CLI wrapper around `VCDClient` + `scan_shadow_vms`; resolves catalog/datastore names via discovery (in `--tenant`'s org) before scanning.

### VCD API endpoints used

| Resource | Endpoint |
|---|---|
| Token auth | `/oauth/provider/token` or `/oauth/tenant/{org}/token` |
| CloudAPI session | `/cloudapi/1.0.0/sessions[/provider]` |
| Legacy session | `/api/sessions` |
| Organizations | `/api/org` |
| Catalogs / templates | `/api/query?type=adminCatalog\|catalog\|adminVAppTemplate` |
| Datastores | `/api/query?type=datastore` |
| Shadow VMs | `/api/query?type=adminShadowVM&filter=datastoreName==<name>` |
| Delete shadow VM | `DELETE <shadow_vm.href>`, then `GET` the task (Location header or task href) until it finishes |

All paginated endpoints use `page` / `pageSize=100` / `sortAsc=name` and page until `total` is reached. Filter values containing filter-syntax characters (`; , ( ) = ! < > ~ *` and quotes) are not sent server-side; those records are filtered client-side.

### Environment variables / `.env` file

The app loads a `.env` file from the working directory on startup. Supported variables: `VCD_SERVER`, `VCD_TOKEN`, `VCD_USER`, `VCD_PASSWORD`, `VCD_TENANT`, `VCD_CATALOG`, `VCD_DATASTORE`.

## Important constraints

- **Destructive tool** — deletions are permanent and cannot be undone. The GUI requires explicit confirmation before any delete; the CLI requires `yes` typed on the controlling terminal.
- SSL verification is disabled by default (`verify_ssl=False`) via `urllib3.disable_warnings`. The UI exposes a toggle for this.
- The shared delete loop applies a 3-second sleep between each VM deletion to avoid hitting VCD rate limits.
- `servers.json` is written atomically with mode 0600; a credential falls back to its base64 copy there when the keyring has none.
- Multi-catalog selection is supported in the GUI (checkboxes in a list); CLI accepts comma-separated catalog names.
