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
                    [--dry-run]
"""

import argparse
import sys
import json
import urllib3
import os
import time
import uuid
import base64

try:
    import keyring
    _KEYRING_AVAILABLE = True
except ImportError:
    _KEYRING_AVAILABLE = False

_CONFIG_DIR = os.path.expanduser("~/.vcd-shadow-cleaner")
_SERVERS_FILE = os.path.join(_CONFIG_DIR, "servers.json")
_KEYRING_SERVICE = "vcd-shadow-cleaner"

from dataclasses import dataclass
from typing import Optional, List, Set, Tuple
from datetime import datetime

import requests

# Suppress SSL warnings for development (should be removed in production)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
        print(f"Warning: Failed to load .env file: {e}")


def _load_saved_servers() -> list:
    if not os.path.exists(_SERVERS_FILE):
        return []
    try:
        with open(_SERVERS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


def _persist_saved_servers(servers: list) -> None:
    os.makedirs(_CONFIG_DIR, exist_ok=True)
    with open(_SERVERS_FILE, "w") as f:
        json.dump(servers, f, indent=2)


def _get_credential(server_id: str) -> str:
    """Return stored password/token for a saved server, or empty string."""
    if _KEYRING_AVAILABLE:
        try:
            result = keyring.get_password(_KEYRING_SERVICE, server_id)
            return result or ""
        except Exception:
            return ""
    # fallback: base64 in JSON
    for s in _load_saved_servers():
        if s.get("id") == server_id:
            raw = s.get("_credential_b64", "")
            if raw:
                try:
                    return base64.b64decode(raw.encode()).decode()
                except Exception:
                    return ""
    return ""


def _set_credential(server_id: str, credential: str) -> None:
    """Store password/token for a saved server."""
    if _KEYRING_AVAILABLE:
        try:
            keyring.set_password(_KEYRING_SERVICE, server_id, credential)
            return
        except Exception:
            pass
    # fallback: base64 in JSON
    servers = _load_saved_servers()
    for s in servers:
        if s.get("id") == server_id:
            s["_credential_b64"] = base64.b64encode(credential.encode()).decode()
            break
    _persist_saved_servers(servers)


def _delete_credential(server_id: str) -> None:
    """Remove stored credential for a saved server."""
    if _KEYRING_AVAILABLE:
        try:
            keyring.delete_password(_KEYRING_SERVICE, server_id)
        except Exception:
            pass
    else:
        servers = _load_saved_servers()
        for s in servers:
            if s.get("id") == server_id:
                s.pop("_credential_b64", None)
                break
        _persist_saved_servers(servers)


@dataclass
class ShadowVM:
    """Represents a Shadow VM in VCD."""
    name: str
    href: str
    container_name: str  # Parent vApp Template name (if resolved)
    container_id: str    # Parent vApp Template ID/HREF
    datastore_name: str
    vm_id: str
    primary_vm_href: str # Link to the primary VM
    catalog_name: str = ""
    vcd_server: str = ""
    org_name: str = ""


@dataclass
class VAppTemplate:
    """Represents a vApp Template in VCD."""
    name: str
    href: str
    id: str
    catalog_name: str


class VCDClient:
    """VMware Cloud Director API Client."""

    def __init__(self, host: str, verify_ssl: bool = False):
        self.host = host.rstrip('/')
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.access_token: Optional[str] = None
        self.api_version = "38.0"  # VCD API version
        self.current_org: Optional[str] = None

    def _get_headers(self) -> dict:
        """Get common API headers."""
        headers = {
            "Accept": f"application/*+json;version={self.api_version}",
            "Content-Type": "application/json"
        }
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        return headers

    def authenticate_with_token(self, api_token: str, org: str = "system") -> bool:
        """
        Authenticate to VCD using an API token.
        
        Args:
            api_token: The VCD API refresh token
            org: The organization ('system' for provider login)
            
        Returns:
            True if authentication successful, False otherwise
        """
        try:
            if org.lower() == "system":
                uri = f"https://{self.host}/oauth/provider/token"
            else:
                uri = f"https://{self.host}/oauth/tenant/{org}/token"

            body = f"grant_type=refresh_token&refresh_token={api_token}"
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded"
            }

            response = self.session.post(uri, headers=headers, data=body)
            response.raise_for_status()

            data = response.json()
            self.access_token = data.get("access_token")
            self.current_org = org
            return True
        except Exception as e:
            print(f"Authentication failed: {e}")
            return False

    def authenticate_with_credentials(self, username: str, password: str, org: str = "system") -> bool:
        """
        Authenticate to VCD using username and password.
        
        Tries multiple authentication methods in order:
        1. CloudAPI sessions (modern VCD 10.x+)
        2. Legacy /api/sessions
        
        Args:
            username: VCD username
            password: VCD password
            org: The organization ('system' for provider login)
            
        Returns:
            True if authentication successful, False otherwise
        """
        # Try CloudAPI sessions first (VCD 10.x+)
        if self._authenticate_cloudapi(username, password, org):
            return True
        
        # Try legacy /api/sessions
        if self._authenticate_legacy(username, password, org):
            return True
        
        print("All authentication methods failed.")
        return False

    def _authenticate_cloudapi(self, username: str, password: str, org: str = "system") -> bool:
        """
        Modern CloudAPI authentication using /cloudapi/1.0.0/sessions.
        Works with VCD 10.x and later.
        """
        try:
            # For provider (system) login, use /cloudapi/1.0.0/sessions/provider
            if org.lower() == "system":
                uri = f"https://{self.host}/cloudapi/1.0.0/sessions/provider"
            else:
                uri = f"https://{self.host}/cloudapi/1.0.0/sessions"

            headers = {
                "Accept": f"application/json;version={self.api_version}",
                "Content-Type": "application/json"
            }

            # Use Basic Auth
            import base64
            if org.lower() == "system":
                auth_string = f"{username}@system"
            else:
                auth_string = f"{username}@{org}"
            
            credentials = base64.b64encode(f"{auth_string}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {credentials}"

            response = self.session.post(uri, headers=headers)
            response.raise_for_status()

            # Get the access token from response header
            self.access_token = response.headers.get("X-VMWARE-VCLOUD-ACCESS-TOKEN")
            if not self.access_token:
                # Try getting from response body
                try:
                    data = response.json()
                    self.access_token = data.get("accessToken") or data.get("token")
                except:
                    pass
            
            if self.access_token:
                self.current_org = org
                print(f"CloudAPI authentication successful")
                return True
            else:
                print("CloudAPI auth: No access token in response")
                return False
                
        except requests.exceptions.HTTPError as e:
            print(f"CloudAPI authentication failed: {e}")
            return False
        except Exception as e:
            print(f"CloudAPI authentication error: {e}")
            return False

    def _authenticate_legacy(self, username: str, password: str, org: str = "system") -> bool:
        """
        Legacy authentication using /api/sessions (for older VCD versions).
        """
        try:
            uri = f"https://{self.host}/api/sessions"
            
            # For system org, use username@system format
            if org.lower() == "system":
                auth_user = f"{username}@system"
            else:
                auth_user = f"{username}@{org}"

            headers = {
                "Accept": f"application/*+json;version={self.api_version}",
            }

            response = self.session.post(
                uri, 
                headers=headers, 
                auth=(auth_user, password)
            )
            response.raise_for_status()

            # Get the auth token from header
            self.access_token = response.headers.get("X-VMWARE-VCLOUD-ACCESS-TOKEN")
            self.current_org = org
            print("Legacy authentication successful")
            return True
        except Exception as e:
            print(f"Legacy authentication failed: {e}")
            return False

    def get_organizations(self) -> List[dict]:
        """Get list of organizations (tenants) visible to the authenticated user."""
        try:
            uri = f"https://{self.host}/api/org"
            response = self.session.get(uri, headers=self._get_headers())
            response.raise_for_status()
            
            data = response.json()
            orgs = []
            for org in data.get("org", []):
                orgs.append({
                    "name": org.get("name"),
                    "href": org.get("href")
                })
            return sorted(orgs, key=lambda x: x.get("name", ""))
        except Exception as e:
            print(f"Failed to get organizations: {e}")
            return []

    def switch_to_org(self, org_name: str) -> bool:
        """Switch context to a specific organization."""
        self.current_org = org_name
        return True

    def get_catalogs(self, org_name: Optional[str] = None) -> List[dict]:
        """
        Get list of catalogs visible to the authenticated user.
        
        Args:
            org_name: Optional organization name to filter catalogs by.
                      If provided, only returns catalogs belonging to or shared with that org.
        """
        catalogs = []
        
        # Build filter based on org if provided
        org_filter = ""
        if org_name and org_name.lower() != "system":
            # Filter by org name - this will get catalogs owned by this org
            org_filter = f"&filter=orgName=={org_name}"
        
        # Try adminCatalog first (for provider/system admin access)
        query_types = ["adminCatalog", "catalog"]
        
        for query_type in query_types:
            try:
                page = 1
                page_size = 100
                total_fetched = 0
                
                while True:
                    uri = f"https://{self.host}/api/query?type={query_type}&format=records&page={page}&pageSize={page_size}{org_filter}"
                    response = self.session.get(uri, headers=self._get_headers())
                    
                    if response.status_code == 403:
                        # Not authorized for this query type, try next
                        break
                    
                    response.raise_for_status()
                    data = response.json()
                    
                    records = data.get("record", [])
                    if not records:
                        break
                    
                    for record in records:
                        catalog_entry = {
                            "name": record.get("name"),
                            "href": record.get("href"),
                            "orgName": record.get("orgName", record.get("org", "N/A")),
                            "isShared": record.get("isShared", False),
                            "isPublished": record.get("isPublished", False),
                        }
                        # Avoid duplicates
                        if not any(c["name"] == catalog_entry["name"] and c["orgName"] == catalog_entry["orgName"] for c in catalogs):
                            catalogs.append(catalog_entry)
                    
                    total_fetched += len(records)
                    
                    # Check if there are more pages
                    total_records = int(data.get("total", 0))
                    if total_fetched >= total_records or len(records) < page_size:
                        break
                    
                    page += 1
                
                # If we got catalogs with adminCatalog, no need to try catalog
                if catalogs:
                    break
                    
            except requests.exceptions.HTTPError as e:
                print(f"Query type {query_type} failed: {e}")
                continue
            except Exception as e:
                print(f"Error fetching catalogs with {query_type}: {e}")
                continue
        
        # If org filter was applied but we also need shared catalogs, fetch those too
        if org_name and org_name.lower() != "system":
            shared_catalogs = self._get_shared_catalogs_for_org(org_name)
            for cat in shared_catalogs:
                if not any(c["name"] == cat["name"] for c in catalogs):
                    catalogs.append(cat)
        
        print(f"Found {len(catalogs)} catalogs for org '{org_name or 'all'}'")
        return sorted(catalogs, key=lambda x: (x.get("orgName", ""), x.get("name", "")))

    def _get_shared_catalogs_for_org(self, org_name: str) -> List[dict]:
        """Get catalogs that are shared/published and accessible to the specified org."""
        catalogs = []
        page = 1
        page_size = 100

        try:
            while True:
                uri = f"https://{self.host}/api/query?type=adminCatalog&format=records&filter=isPublished==true&page={page}&pageSize={page_size}"
                response = self.session.get(uri, headers=self._get_headers())
                if response.status_code != 200:
                    break

                data = response.json()
                records = data.get("record", [])

                if not records:
                    break

                for record in records:
                    catalogs.append({
                        "name": record.get("name"),
                        "href": record.get("href"),
                        "orgName": record.get("orgName", "N/A"),
                        "isShared": True,
                        "isPublished": True,
                    })

                total_records = int(data.get("total", 0))
                if len(catalogs) >= total_records or len(records) < page_size:
                    break

                page += 1

        except Exception as e:
            print(f"Error fetching shared catalogs: {e}")
        return catalogs

    def get_datastores(self) -> List[dict]:
        """Get list of datastores (requires provider-level access)."""
        datastores = []
        page = 1
        page_size = 100

        try:
            while True:
                uri = f"https://{self.host}/api/query?type=datastore&format=records&page={page}&pageSize={page_size}"
                response = self.session.get(uri, headers=self._get_headers())
                response.raise_for_status()

                data = response.json()
                records = data.get("record", [])

                if not records:
                    break

                for record in records:
                    datastores.append({
                        "name": record.get("name"),
                        "href": record.get("href"),
                        "vcName": record.get("vcName", ""),
                        "datastoreType": record.get("datastoreType", "")
                    })

                total_records = int(data.get("total", 0))
                if len(datastores) >= total_records or len(records) < page_size:
                    break

                page += 1

            return sorted(datastores, key=lambda x: x.get("name", ""))
        except Exception as e:
            print(f"Failed to get datastores: {e}")
            return []

    def get_vapp_templates_in_catalog(self, catalog_name: str) -> List[VAppTemplate]:
        """Get all vApp templates in a specific catalog."""
        templates = []
        page = 1
        page_size = 100

        try:
            while True:
                uri = f"https://{self.host}/api/query?type=adminVAppTemplate&format=records&filter=catalogName=={catalog_name}&page={page}&pageSize={page_size}"
                response = self.session.get(uri, headers=self._get_headers())
                response.raise_for_status()

                data = response.json()
                records = data.get("record", [])

                if not records:
                    break

                for record in records:
                    templates.append(VAppTemplate(
                        name=record.get("name", ""),
                        href=record.get("href", ""),
                        id=record.get("id", "") or record.get("href", ""),
                        catalog_name=record.get("catalogName", "")
                    ))

                total_records = int(data.get("total", 0))
                if len(templates) >= total_records or len(records) < page_size:
                    break

                page += 1

            return templates
        except Exception as e:
            print(f"Failed to get vApp templates: {e}")
            return []

    def get_shadow_vms_on_datastore(self, datastore_name: str, debug: bool = False) -> List[ShadowVM]:
        """Get all Shadow VMs on a specific datastore."""
        shadows = []
        page = 1
        page_size = 100
        
        try:
            while True:
                uri = f"https://{self.host}/api/query?type=adminShadowVM&format=records&filter=datastoreName=={datastore_name}&page={page}&pageSize={page_size}"
                response = self.session.get(uri, headers=self._get_headers())
                response.raise_for_status()
                
                data = response.json()
                records = data.get("record", [])
                
                if not records:
                    break
                
                # Debug: print first record to see available fields
                if debug and page == 1 and records:
                    print(f"DEBUG: Sample Shadow VM record fields: {list(records[0].keys())}")
                    print(f"DEBUG: Sample Shadow VM record: {records[0]}")
                
                for record in records:
                    # The container/parent template reference might be in different fields
                    # Check multiple possible field names for NAME
                    container_name = (
                        record.get("containerName") or 
                        record.get("container") or 
                        record.get("vappTemplate") or
                        record.get("catalogItem") or
                        record.get("name", "").split(" ")[0] if " " in record.get("name", "") else ""
                    )
                    
                    # Capture the container/parent reference ID/HREF
                    # Based on debug output, primaryVAppTemplate is the key field
                    container_id = (
                        record.get("primaryVAppTemplate") or 
                        record.get("container") or 
                        record.get("vAppTemplate") or 
                        record.get("entity") or
                        ""
                    )
                    
                    # Also capture the primary template reference if available
                    primary_vm_name = record.get("primaryVmName", "")
                    primary_vm_href = record.get("primaryVM", "")
                    
                    shadows.append(ShadowVM(
                        name=record.get("name", ""),
                        href=record.get("href", ""),
                        container_name=container_name,
                        container_id=container_id,
                        datastore_name=record.get("datastoreName", ""),
                        vm_id=record.get("href", "").split("/")[-1] if record.get("href") else "",
                        primary_vm_href=primary_vm_href
                    ))
                
                # Check pagination
                total_records = int(data.get("total", 0))
                if len(shadows) >= total_records or len(records) < page_size:
                    break
                page += 1
                
            return shadows
        except Exception as e:
            print(f"Failed to get Shadow VMs: {e}")
            return []

    def delete_shadow_vm(self, shadow_vm: ShadowVM) -> Tuple[bool, str]:
        """
        Delete a Shadow VM.
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            response = self.session.delete(shadow_vm.href, headers=self._get_headers())
            
            if response.status_code in [200, 202, 204]:
                return True, f"Successfully deleted {shadow_vm.name}"
            else:
                return False, f"Failed to delete {shadow_vm.name}: {response.status_code}"
        except Exception as e:
            return False, f"Error deleting {shadow_vm.name}: {e}"

    def disconnect(self):
        """Disconnect from VCD."""
        try:
            if self.access_token:
                uri = f"https://{self.host}/api/session"
                self.session.delete(uri, headers=self._get_headers())
        except:
            pass
        finally:
            self.access_token = None
            self.current_org = None


def scan_shadow_vms(client: VCDClient, catalog_names: List[str], datastore_names,
                    vcd_server: str = "", org_name: str = "", debug: bool = True) -> List[ShadowVM]:
    """
    Scan for Shadow VMs on one or more datastores that belong to templates in one or more catalogs.

    Args:
        client: Authenticated VCDClient
        catalog_names: List of catalog names (or a single name) to scan
        datastore_names: List of datastore names (or a single name) to scan for shadow VMs
        vcd_server: VCD server hostname to stamp on results (for multi-VCD consolidation)
        org_name: Org/tenant name to stamp on results
        debug: Enable debug output

    Returns:
        List of matching shadow VMs with catalog_name, vcd_server, org_name populated
    """
    if isinstance(catalog_names, str):
        catalog_names = [catalog_names]
    if isinstance(datastore_names, str):
        datastore_names = [datastore_names]

    print(f"\nScanning for Shadow VMs...")
    print(f"  Catalogs: {', '.join(catalog_names)}")
    print(f"  Datastores: {', '.join(datastore_names)}")

    # Build combined lookup structures across all catalogs
    # Maps template HREF/ID -> (template_name, catalog_name)
    template_ids: dict[str, tuple[str, str]] = {}
    # Maps template name -> catalog_name (first catalog wins for name-based matching)
    template_name_to_catalog: dict[str, str] = {}

    for cat_name in catalog_names:
        templates = client.get_vapp_templates_in_catalog(cat_name)
        print(f"  Found {len(templates)} templates in catalog '{cat_name}'")
        if debug and templates:
            print(f"  DEBUG: Sample template names ({cat_name}): {[t.name for t in templates[:5]]}")

        for t in templates:
            if t.href:
                template_ids[t.href] = (t.name, cat_name)
            if t.id:
                template_ids[t.id] = (t.name, cat_name)
            if t.name not in template_name_to_catalog:
                template_name_to_catalog[t.name] = cat_name

    template_names = set(template_name_to_catalog.keys())

    all_shadows = []
    for ds_name in datastore_names:
        ds_shadows = client.get_shadow_vms_on_datastore(ds_name, debug=debug)
        print(f"  Found {len(ds_shadows)} Shadow VMs on datastore '{ds_name}'")
        all_shadows.extend(ds_shadows)
    print(f"  Found {len(all_shadows)} Shadow VMs across {len(datastore_names)} datastore(s)")

    if debug and all_shadows:
        print(f"  DEBUG: Sample Shadow VM container_names: {[s.container_name for s in all_shadows[:5]]}")
        print(f"  DEBUG: Sample Shadow VM container_ids: {[s.container_id for s in all_shadows[:5]]}")
        print(f"  DEBUG: Sample Shadow VM names: {[s.name for s in all_shadows[:5]]}")

    matching_shadows = []

    for shadow in all_shadows:
        # Strategy 1: Direct container_id match (HREF/ID)
        if shadow.container_id and shadow.container_id in template_ids:
            tpl_name, cat_name = template_ids[shadow.container_id]
            shadow.container_name = tpl_name
            shadow.catalog_name = cat_name
            matching_shadows.append(shadow)
            continue

        # Strategy 2: Direct container_name match
        if shadow.container_name in template_names:
            shadow.catalog_name = template_name_to_catalog[shadow.container_name]
            matching_shadows.append(shadow)
            continue

        # Strategy 3: Check if shadow VM name contains any template name
        for tpl_name in template_names:
            if shadow.name.startswith(tpl_name) or tpl_name in shadow.name:
                shadow.container_name = tpl_name
                shadow.catalog_name = template_name_to_catalog[tpl_name]
                matching_shadows.append(shadow)
                break

    # Stamp server/org on every matched shadow
    for s in matching_shadows:
        s.vcd_server = vcd_server
        s.org_name = org_name

    # Deduplicate by href
    seen_hrefs = set()
    unique_shadows = []
    for s in matching_shadows:
        if s.href not in seen_hrefs:
            seen_hrefs.add(s.href)
            unique_shadows.append(s)

    print(f"  Matched {len(unique_shadows)} Shadow VMs to catalog templates")

    return unique_shadows


def print_shadow_vm_table(shadows: List[ShadowVM]):
    """Print Shadow VMs in ASCII table format."""
    if not shadows:
        print("\nNo Shadow VMs found matching the criteria.")
        return

    # Calculate column widths
    name_width = max(len(s.name) for s in shadows)
    name_width = max(name_width, len("Shadow VM Name"))

    template_width = max(len(s.container_name) for s in shadows)
    template_width = max(template_width, len("Parent Template"))

    cat_width = max(len(s.catalog_name) for s in shadows)
    cat_width = max(cat_width, len("Catalog"))

    ds_width = max(len(s.datastore_name) for s in shadows)
    ds_width = max(ds_width, len("Datastore"))

    total_width = name_width + template_width + cat_width + ds_width + 13

    # Print header
    print("\n" + "=" * total_width)
    print(f"| {'Shadow VM Name':<{name_width}} | {'Parent Template':<{template_width}} | {'Catalog':<{cat_width}} | {'Datastore':<{ds_width}} |")
    print("|" + "-" * (name_width + 2) + "|" + "-" * (template_width + 2) + "|" + "-" * (cat_width + 2) + "|" + "-" * (ds_width + 2) + "|")

    # Print rows
    for shadow in shadows:
        print(f"| {shadow.name:<{name_width}} | {shadow.container_name:<{template_width}} | {shadow.catalog_name:<{cat_width}} | {shadow.datastore_name:<{ds_width}} |")

    # Print footer
    print("=" * total_width)
    print(f"\nTotal Shadow VMs: {len(shadows)}")


def run_cli(args):
    """Run in CLI mode."""
    print("=" * 60)
    print("VMware Cloud Director Shadow VM Cleanup Tool")
    print("=" * 60)
    
    if args.dry_run:
        print("\n*** DRY RUN MODE - No changes will be made ***\n")
    
    # Initialize client
    client = VCDClient(args.server, verify_ssl=not args.skip_ssl_verify)
    
    # Authenticate
    print(f"\nConnecting to {args.server}...")
    if args.token:
        if not client.authenticate_with_token(args.token, "system"):
            print("ERROR: Authentication failed")
            return 1
    elif args.username and args.password:
        if not client.authenticate_with_credentials(args.username, args.password, "system"):
            print("ERROR: Authentication failed")
            return 1
    else:
        print("ERROR: Either --token or --username/--password must be provided")
        return 1
    
    print("Connected successfully!")
    
    # Switch to tenant if specified
    if args.tenant and args.tenant.lower() != "system":
        print(f"Switching to tenant: {args.tenant}")
        client.switch_to_org(args.tenant)
    
    # Scan for Shadow VMs (support comma-separated catalog and datastore names from CLI)
    catalog_names = [c.strip() for c in args.catalog.split(",")]
    datastore_names = [d.strip() for d in args.datastore.split(",")]
    shadows = scan_shadow_vms(client, catalog_names, datastore_names)
    
    # Print results
    print_shadow_vm_table(shadows)
    
    if not shadows:
        client.disconnect()
        return 0
    
    if args.dry_run:
        print("\n*** DRY RUN COMPLETE - No Shadow VMs were deleted ***")
        client.disconnect()
        return 0
    
    # Prompt for confirmation
    print(f"\nAre you sure you want to delete {len(shadows)} Shadow VMs?")
    response = input("Type 'yes' to confirm: ").strip().lower()
    
    if response != 'yes':
        print("Operation cancelled.")
        client.disconnect()
        return 0
    
    # Delete Shadow VMs
    print("\nDeleting Shadow VMs...")
    success_count = 0
    fail_count = 0
    
    for i, shadow in enumerate(shadows, 1):
        print(f"  [{i}/{len(shadows)}] Deleting {shadow.name}...", end=" ")
        success, message = client.delete_shadow_vm(shadow)
        if success:
            print("OK")
            success_count += 1
        else:
            print(f"FAILED - {message}")
            fail_count += 1
    
    print(f"\nDeletion complete: {success_count} succeeded, {fail_count} failed")
    
    client.disconnect()
    return 0 if fail_count == 0 else 1


def run_gui():
    """Run in GUI mode with PySide6."""
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
    COLUMN_HEADERS = ["", "Parent Template", "Catalog", "Shadow VMs", "Datastore", "VCD Instance", "Org"]
    FILTERABLE_COLUMNS = {COL_CATALOG, COL_TEMPLATE, COL_DATASTORE, COL_VCD, COL_ORG}

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

    SORTABLE_COLUMNS = {COL_TEMPLATE, COL_CATALOG, COL_VMNAME, COL_DATASTORE, COL_VCD, COL_ORG}
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
                warn = QLabel("Warning: keyring not installed — credentials stored as base64 in config file (not encrypted).")
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
            server = self._server_input.text().strip()
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
                _set_credential(server_id, new_credential)
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
            server = self._server_input.text().strip()
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
                 if s.get("server") == server
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
            cred = _get_credential(server_id)
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
                item.setData(Qt.ItemDataRole.UserRole, catalog["name"])
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
                item.setData(Qt.ItemDataRole.UserRole, ds["name"])
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
                "server": self._server_input.text().strip(),
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
            """Deletes shadow VMs, running each VCD instance's sequential loop in parallel."""
            progress = Signal(int, int, str)        # current, total, name
            item_done = Signal(object, bool, str)   # shadow, success, message
            finished = Signal(int, int)             # success_count, fail_count

            def __init__(self, parent, sessions, shadows, delay_seconds=3):
                super().__init__(parent)
                self.sessions = sessions    # list of session dicts with 'client'/'server'
                self.shadows = shadows
                self.delay_seconds = delay_seconds

            def run(self):
                import time as _time
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
                    local_success = 0
                    local_fail = 0
                    for i, shadow in enumerate(group_shadows):
                        with progress_lock:
                            completed_count += 1
                            current = completed_count
                        self.progress.emit(
                            current, total_items, f"[{server}] {shadow.name}"
                        )
                        if client is None:
                            self.item_done.emit(
                                shadow, False, f"No client for server '{server}'"
                            )
                            local_fail += 1
                        else:
                            ok, msg = client.delete_shadow_vm(shadow)
                            self.item_done.emit(shadow, ok, msg)
                            if ok:
                                local_success += 1
                            else:
                                local_fail += 1
                        if i < len(group_shadows) - 1:
                            _time.sleep(self.delay_seconds)
                    return local_success, local_fail

                total_success = 0
                total_fail = 0
                with ThreadPoolExecutor(max_workers=max(1, len(groups))) as executor:
                    futs = [
                        executor.submit(delete_group, srv, shds)
                        for srv, shds in groups.items()
                    ]
                    for fut in as_completed(futs):
                        s, f = fut.result()
                        total_success += s
                        total_fail += f

                self.finished.emit(total_success, total_fail)

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

        def _on_header_select_all_clicked(self):
            """Toggle all visible child rows when the header checkbox is clicked."""
            # Determine next state: if anything is unchecked, check all; otherwise uncheck all
            header = self.results_table.header()
            current = header._check_state
            if current == Qt.CheckState.Checked:
                new_check = Qt.CheckState.Unchecked
            else:
                new_check = Qt.CheckState.Checked
            self._select_all_state = (new_check == Qt.CheckState.Checked)
            root_idx = self._tree_model.invisibleRootItem().index()
            self._tree_model.blockSignals(True)
            for group_row in range(self._tree_model.rowCount()):
                group_item = self._tree_model.item(group_row, 0)
                if group_item is None:
                    continue
                if self.results_table.isRowHidden(group_row, root_idx):
                    continue
                for child_row in range(group_item.rowCount()):
                    child_chk = group_item.child(child_row, COL_CHECK)
                    if child_chk:
                        child_chk.setCheckState(new_check)
                self._update_group_checkbox(group_item)
            self._tree_model.blockSignals(False)
            self._update_selected_count()
            self._update_header_check_state()
            # blockSignals suppressed dataChanged, so force the view to repaint
            # the checkboxes it just silently updated.
            self.results_table.viewport().update()

        def _on_group_checkbox_clicked(self, group_item: QStandardItem):
            """When a group-row checkbox is toggled, apply state to all children."""
            new_check = group_item.checkState()
            # If the new state is PartiallyChecked (from a user click cycling tri-state),
            # treat it as Checked so clicking always goes to a definite state.
            if new_check == Qt.CheckState.PartiallyChecked:
                new_check = Qt.CheckState.Checked
                self._tree_model.blockSignals(True)
                group_item.setCheckState(new_check)
                self._tree_model.blockSignals(False)
            self._tree_model.blockSignals(True)
            for child_row in range(group_item.rowCount()):
                child_chk = group_item.child(child_row, COL_CHECK)
                if child_chk:
                    child_chk.setCheckState(new_check)
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
            selected = 0
            for group_row in range(self._tree_model.rowCount()):
                group_item = self._tree_model.item(group_row, 0)
                if group_item is None:
                    continue
                for child_row in range(group_item.rowCount()):
                    child_chk = group_item.child(child_row, COL_CHECK)
                    if child_chk and child_chk.checkState() == Qt.CheckState.Checked:
                        selected += 1
            self.statusBar().showMessage(f"Selected Shadow VMs: {selected}")

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

            def run_parallel_scan():
                from concurrent.futures import ThreadPoolExecutor, as_completed

                def scan_one(session):
                    return scan_shadow_vms(
                        session["client"],
                        session["catalogs"],
                        session["datastores"],
                        vcd_server=session["server"],
                        org_name=session["org"],
                        debug=False,
                    )

                all_shadows = []
                with ThreadPoolExecutor(max_workers=max(1, len(all_sessions))) as executor:
                    futures = [executor.submit(scan_one, s) for s in all_sessions]
                    for future in as_completed(futures):
                        all_shadows.extend(future.result())
                return all_shadows

            self.scan_worker = WorkerThread(run_parallel_scan)
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

        def _on_scan_finished(self, shadow_vms):
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

                self._tree_model.appendRow(
                    [grp_chk, grp_tpl, grp_cat, grp_vm, grp_ds, grp_vcd, grp_org]
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

                    grp_chk.appendRow(
                        [chk_item, tpl_item, cat_item, vm_item, ds_item, vcd_item, org_item]
                    )

            self._tree_model.setHorizontalHeaderLabels(COLUMN_HEADERS)
            self._tree_model.blockSignals(False)

            # Collapse all groups by default
            self.results_table.collapseAll()

            self.summary_label.setText(f"Found {len(self.shadow_vms)} Shadow VMs")
            self.progress_bar.setVisible(False)
            self.scan_btn.setEnabled(True)
            self.cleanup_btn.setEnabled(len(self.shadow_vms) > 0)
            self.results_table.header().set_check_state(Qt.CheckState.Unchecked)
            self.statusBar().showMessage(f"Scan complete: {len(self.shadow_vms)} Shadow VMs found")
            self.log(f"Scan complete: {len(self.shadow_vms)} Shadow VMs")
            self._update_selected_count()

        # ---- cleanup ----

        def cleanup_shadows(self):
            if not self.vcd_sessions:
                return

            selected_shadow_vms = []
            for group_row in range(self._tree_model.rowCount()):
                group_item = self._tree_model.item(group_row, 0)
                if group_item is None:
                    continue
                for child_row in range(group_item.rowCount()):
                    child_chk = group_item.child(child_row, COL_CHECK)
                    if child_chk and child_chk.checkState() == Qt.CheckState.Checked:
                        cat_cell = group_item.child(child_row, COL_CATALOG)
                        if cat_cell:
                            shadow = cat_cell.data(SHADOW_VM_ROLE)
                            if shadow:
                                selected_shadow_vms.append(shadow)

            if not selected_shadow_vms:
                QMessageBox.information(self, "No Selection", "No Shadow VMs selected for deletion.")
                return

            reply = QMessageBox.question(
                self, "Confirm Deletion",
                f"Are you sure you want to delete {len(selected_shadow_vms)} selected Shadow VMs?\n\n"
                "This action cannot be undone!",
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

        def _on_delete_item_done(self, shadow, success: bool, message: str):
            if success:
                self.log(f"Deleted: {shadow.name}")
                self._deleted_shadow_ids.add(id(shadow))
            else:
                self.log(f"Failed: {shadow.name} - {message}")

        def _on_delete_finished(self, success_count: int, fail_count: int):
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
            self.statusBar().showMessage(f"Deletion complete: {success_count} succeeded, {fail_count} failed")
            self.log(f"Deletion complete: {success_count} succeeded, {fail_count} failed")
            self._update_selected_count()

            QMessageBox.information(
                self, "Deletion Complete",
                f"Deletion complete!\n\nSuccessful: {success_count}\nFailed: {fail_count}"
            )

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
    
    # Run in CLI mode using environment variables (VCD_SERVER, VCD_TOKEN, etc.)
    # .env file is also supported
    python vcd_shadow_cleaner.py --cli --tenant MyTenant --catalog MyCatalog --datastore MyDatastore
        """
    )

    parser.add_argument("--cli", action="store_true", help="Run in command-line interface mode (default is GUI)")
    
    # Connection args (can be loaded from env vars)
    parser.add_argument("--server", "-s", default=os.environ.get("VCD_SERVER"), help="VCD server hostname or IP")
    parser.add_argument("--token", "-t", default=os.environ.get("VCD_TOKEN"), help="VCD API token")
    parser.add_argument("--username", "-u", default=os.environ.get("VCD_USER"), help="VCD username (alternative to token)")
    parser.add_argument("--password", "-p", default=os.environ.get("VCD_PASSWORD"), help="VCD password (alternative to token)")
    
    parser.add_argument("--tenant", default=os.environ.get("VCD_TENANT"), help="Target tenant/organization name")
    parser.add_argument("--catalog", "-c", default=os.environ.get("VCD_CATALOG"), help="Catalog name to scan")
    parser.add_argument("--datastore", "-d", default=os.environ.get("VCD_DATASTORE"), help="Datastore name to scan")
    
    parser.add_argument("--dry-run", action="store_true", help="Show what would be deleted without making changes")
    parser.add_argument("--skip-ssl-verify", action="store_true", default=os.environ.get("VCD_SKIP_SSL", "false").lower() == "true", help="Skip SSL certificate verification")
    
    args = parser.parse_args()
    
    # Default to GUI if --cli is not specified
    if not args.cli:
        return run_gui()
    else:
        # CLI mode requires certain arguments
        if not args.server:
            print("ERROR: --server is required in CLI mode (or set VCD_SERVER env var).")
            return 1
        if not args.catalog:
            print("ERROR: --catalog is required in CLI mode (or set VCD_CATALOG env var).")
            return 1
        if not args.datastore:
            print("ERROR: --datastore is required in CLI mode (or set VCD_DATASTORE env var).")
            return 1
        
        return run_cli(args)


if __name__ == "__main__":
    sys.exit(main())
