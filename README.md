# VMware Cloud Director Shadow VM Cleaner

![Application Icon](images/vcd_shadow_cleaner_thumb.png)

A Python application for managing Shadow VMs in VMware Cloud Director. This tool helps identify and clean up Shadow VMs that may accumulate over time, particularly after datastore re-allocations. It allows you to remove all or select Shadow VMs from a specified datastore.

## WARNING - USE WITH CAUTION

> [!CAUTION]
> This script is designed to DELETE content from VMware Cloud Director. Deletion will not occur until you click the "Yes" button on the confirmation popup that appears when you click the Cleanup Shadows button. Verify and re-verify before proceeding since the delete will be a permanent action that cannot be undone.

![Delete Confirmation](images/image-3.png)

## Features

* **GUI:** User-friendly graphical interface for easy interaction.
* **Authentication:** Supports API token and username/password authentication to VCD.
* **Tenant Support:** Ability to specify a tenant or use the system tenant (provider).
* **Catalog and Datastore Filtering:** Scan for Shadow VMs within a specific catalog and on a particular datastore.
* **Dry Run:** Preview deletion operations without making actual changes.
* **SSL Verification Control:** Option to skip SSL verification for lab or development environments.
* **Application Icon:** A custom SVG icon for better visual identification.
* **Graceful Disconnection:** Automatically disconnects from VCD when the application closes.

## Requirements

* Python 3.8+
* PySide6 (for GUI mode)
* requests

## Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/burkeazbill/vcd-shadow-cleaner.git
    cd vcd-shadow-cleaner
    ```

2. **Create a virtual environment (recommended):**

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3. **Install dependencies:**

    ```bash
    pip3 install -r requirements.txt
    ```

## Usage

### GUI Mode (Default)

Simply run the script without any arguments:

```bash
python vcd_shadow_cleaner.py
```

The GUI will launch, allowing you to enter your VCD server details, authenticate, and then scan and clean up Shadow VMs.

### CLI Mode

Use the `--cli` flag along with the required arguments. Connection details can come from three places (in order of precedence): command-line arguments, environment variables (`VCD_SERVER`, `VCD_TOKEN`, `VCD_USER`, `VCD_PASSWORD`, `VCD_TENANT`, `VCD_CATALOG`, `VCD_DATASTORE`; a `.env` file is also supported), or a **saved server profile** created in the GUI (`--saved-server`).

```bash
python vcd_shadow_cleaner.py --cli --server <vcd_host> --token <api_token> \
    --tenant <tenant_name> --catalog <catalog_name> --datastore <datastore_name> \
    [--dry-run] [--json] [--skip-ssl-verify]
```

> [!IMPORTANT]
> Deletion is permanent. Unless `--dry-run` is given, the CLI always asks **"Are you sure?"** and requires typing `yes` before any Shadow VM is deleted. There is deliberately no flag to skip that confirmation — use `--dry-run` for unattended analysis.

**Using stored credentials:** server profiles saved in the GUI (Manage Saved Servers) can be reused from the CLI with `--saved-server <name>`. The profile supplies the server hostname, the stored credential (retrieved from the OS keyring), the default org, and the SSL setting. Stored credentials are only ever used to authenticate the shadow-VM scan/cleanup session — they are never printed or used for anything else.

**Examples:**

* **List saved server profiles (credentials are never shown):**

    ```bash
    python vcd_shadow_cleaner.py --list-servers
    ```

* **Dry run using a saved server profile:**

    ```bash
    python vcd_shadow_cleaner.py --cli --saved-server "Production VCD" \
        --catalog MyCatalog --datastore MyDatastore --dry-run
    ```

* **Discover tenant, catalog, and datastore names before scanning:**

    ```bash
    python vcd_shadow_cleaner.py --cli --saved-server "Production VCD" \
        --list-tenants --list-catalogs --list-datastores
    ```

* **Dry Run with API Token:**

    ```bash
    python vcd_shadow_cleaner.py --cli --server vcd.example.com --token YOUR_API_TOKEN \
        --tenant MyTenant --catalog MyCatalog --datastore MyDatastore --dry-run
    ```

* **Using Username/Password:**

    ```bash
    python vcd_shadow_cleaner.py --cli --server vcd.example.com --username admin@system --password password \
        --tenant MyTenant --catalog MyCatalog --datastore MyDatastore
    ```

* **Machine-readable output for scripts and AI agents** (JSON on stdout, progress on stderr):

    ```bash
    python vcd_shadow_cleaner.py --cli --saved-server "Production VCD" \
        --catalog MyCatalog --datastore MyDatastore --dry-run --json
    ```

* **Display Help Information:**

    ```bash
    python vcd_shadow_cleaner.py --help
    ```

Multiple catalogs or datastores can be scanned in one run by passing comma-separated names to `--catalog` / `--datastore`. During deletion the CLI pauses 3 seconds between VMs (same rate limiting as the GUI).

## Workflow

```mermaid
graph TD
    A[Start Application] --> B{GUI or CLI?};
    B -- GUI (Default) --> C[Initialize GUI];
    B -- CLI --> D[Parse CLI Arguments];
    C --> E{Connect to VCD};
    D --> E;
    E -- Connection Successful --> F[Load Tenants, Catalogs, Datastores];
    E -- Connection Failed --> G[Display Error & Exit];
    F --> H[User Selects Filters: Tenant -> Catalog -> Datastore];
    H --> I[Scan for Shadow VMs];
    I --> J{Shadow VMs Found?};
    J -- Yes --> K[Display/Print Shadow VMs on the specified Datastore for vAppTemplates found in the selected Catalog];
    J -- No --> L[Display 'No VMs Found' & Exit];
    K -- GUI: User Selects VMs --> M["Confirm Deletion (GUI/CLI)"];
    K -- CLI: User Confirms --> M;
    M -- Confirmed --> N[Start Deletion Loop];
    N --> O{Delete VM & Apply 3s delay for Rate Limit};
    O -- VM Deleted --> N;
    N -- All VMs Processed --> P[Display Deletion Summary & Exit];
    M -- Cancelled --> P;
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Building Executables (Optional)

The application can be compiled into a standalone executable for macOS, Linux, and Windows using `PyInstaller`. This process typically needs to be done on the target operating system (e.g., build a Windows executable on Windows).

### Prerequisites

1. **Install PyInstaller:** Ensure PyInstaller is installed in your virtual environment:

    ```bash
    pip install PyInstaller
    ```

### Compilation Commands

Navigate to the project's root directory in your terminal and activate your virtual environment before running these commands.

* **For Windows (from a Windows machine):**

    ```bash
    pyinstaller vcd_shadow_cleaner.py --noconsole --onefile --add-data "vcd_shadow_cleaner.svg:." --icon "vcd_shadow_cleaner.ico"
    ```

* **For macOS (from a macOS machine):**

    ```bash
    pyinstaller vcd_shadow_cleaner.py --noconsole --onefile --add-data "vcd_shadow_cleaner.svg:." --icon "vcd_shadow_cleaner.icns"
    ```

* **For Linux (from a Linux machine):**

    ```bash
    pyinstaller vcd_shadow_cleaner.py --noconsole --onefile --add-data "vcd_shadow_cleaner.svg:." --icon "vcd_shadow_cleaner.icns"
    ```

    **Note:** *For Linux, the `--icon` option primarily affects the executable's appearance in file managers. The `--add-data` ensures the SVG icon is available for the PySide6 application itself to load internally.*

After compilation, the executables will be found in the `dist/` directory.
