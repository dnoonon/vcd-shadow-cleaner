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
    [--dry-run] [--json] [--skip-ssl-verify]

# CLI mode with a saved server profile (created in the GUI; credential from OS keyring)
python vcd_shadow_cleaner.py --cli --saved-server "<profile_name>" \
    --catalog <catalog_name> --datastore <datastore_name> [--dry-run] [--json]

# Discovery (each implies --cli): --list-servers, --list-tenants, --list-catalogs, --list-datastores
```

CLI safety: unless `--dry-run` is given, the CLI always prompts "Are you sure?" and requires typing `yes` before deleting; there is deliberately no `--yes`/`--force` bypass flag. `--json` prints machine-readable results on stdout and moves all progress output to stderr. Saved-server credentials are used only to authenticate the shadow-VM scan/cleanup session.

## Building standalone executables

```bash
# macOS
pyinstaller vcd_shadow_cleaner.py --noconsole --onefile --add-data "vcd_shadow_cleaner.svg:." --icon "vcd_shadow_cleaner.icns"

# Windows (must be run on Windows)
pyinstaller vcd_shadow_cleaner.py --noconsole --onefile --add-data "vcd_shadow_cleaner.svg:." --icon "vcd_shadow_cleaner.ico"

# Output is placed in dist/
```

## Architecture

The entire application lives in a single file: `vcd_shadow_cleaner.py`. There are no tests.

### Key classes and data flow

**`VCDClient`** — all VCD API calls. Handles authentication (API token via OAuth refresh, or username/password via CloudAPI/legacy sessions), pagination, and deletion. Uses VCD API version `38.0`. The `scan_shadow_vms()` function (module-level) orchestrates the scan by fetching templates from one or more catalogs and matching them against shadow VMs on a datastore using three strategies in priority order: HREF/ID match → container name match → VM name prefix/substring match.

**`ShadowVM` / `VAppTemplate`** — plain dataclasses representing API resources.

**`run_gui()`** — PySide6 GUI, defined entirely inside this function. Contains nested class definitions for all Qt widgets, workers, and models. Key nested classes:
- `ColumnFilterProxyModel` — Excel-style per-column filter proxy
- `FilterPopupDialog` — multi-select filter popup
- `ShadowVMWorker(QThread)` — background thread for scanning; emits `finished(list)` and `error(str)` signals
- `DeleteWorker(QThread)` — background thread for deletion with a 3-second delay between deletes (rate limit)
- `MainWindow(QMainWindow)` — the main GUI window; cascading dropdowns load tenants → catalogs (multi-select) → datastores; results shown as a tree view grouped by parent template

**`run_cli(args)`** — thin CLI wrapper around `VCDClient` + `scan_shadow_vms`.

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
| Delete shadow VM | `DELETE <shadow_vm.href>` |

All paginated endpoints use `page` / `pageSize=100` query parameters and check `total` in the response.

### Environment variables / `.env` file

The app loads a `.env` file from the working directory on startup. Supported variables: `VCD_SERVER`, `VCD_TOKEN`, `VCD_USER`, `VCD_PASSWORD`, `VCD_TENANT`, `VCD_CATALOG`, `VCD_DATASTORE`.

## Important constraints

- **Destructive tool** — deletions are permanent and cannot be undone. The GUI requires explicit confirmation before any delete.
- SSL verification is disabled by default (`verify_ssl=False`) via `urllib3.disable_warnings`. The UI exposes a toggle for this.
- The delete loop applies a 3-second sleep between each VM deletion to avoid hitting VCD rate limits.
- Multi-catalog selection is supported in the GUI (checkboxes in a list); CLI accepts comma-separated catalog names.
