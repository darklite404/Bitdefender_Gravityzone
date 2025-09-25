#!/usr/bin/env python3
r"""
Version: 1.3.0 (2024-06-19)
Editor: Pichet Jarunithi
Fetch Bitdefender GravityZone endpoints, find duplicate endpoint names, and export duplicates to CSV.

What this script does
- Calls GravityZone JSON-RPC API (network) and fetches:
  - getEndpointsList: main list of endpoints.
  - getNetworkInventoryItems: inventory items (may contain nested details).
- Finds endpoints that share the same name (case-insensitive) from getEndpointsList only.
- Exports duplicates to a timestamped CSV.
- Optionally prints all endpoints/inventory to console and/or exports all to CSV(s).
- Auto-updates prerequisites (requests, certifi, packaging) and restarts if updates were applied.
- Supports EU (cloud), US (cloudgz) and AP (cloudap) API endpoints.
- Detailed logging with --debug.

CSV columns (duplicates and "export all")
- name,fqdn,machineType,operatingSystemVersion,ip,macs,ssid,managedWithBest,lastSeen,loggedInUser

Requirements
- Python 3.8+ recommended.
- Outbound HTTPS to GravityZone endpoints.
- Bitdefender GravityZone API key with permissions to query endpoints.
- The script can auto-update required packages (requests, certifi, packaging) and will restart itself when it does.

API key
- Pass with --api-key "YOUR_KEY"
- Or set environment variable BITDEFENDER_API_KEY
  - Windows (PowerShell):  setx BITDEFENDER_API_KEY "YOUR_KEY"
  - Windows (CMD):         setx BITDEFENDER_API_KEY "YOUR_KEY"
  - Linux/macOS (bash):    export BITDEFENDER_API_KEY="YOUR_KEY"
- If neither is provided, the script exits with code 2.

Regions and endpoints
- --region ap:               https://cloudap.gravityzone.bitdefender.com/api/v1.0/jsonrpc/network
- --region eu:               https://cloud.gravityzone.bitdefender.com/api/v1.0/jsonrpc/network
- --region us:               https://cloudgz.gravityzone.bitdefender.com/api/v1.0/jsonrpc/network
- Pick the region that matches your GravityZone console. If unsure, try the default first.

Security note
- Use --insecure only as a last resort when corporate MITM/proxies break TLS validation. It disables certificate verification.

Output files and naming
- Duplicates CSV:
  - Controlled by --output. The script always names files with a timestamp prefix: YYYYMMDD_HHMM.csv.
  - If --output is a directory or ends with a path separator, the file is written inside that directory.
  - If --output is a file path, the parent directory is used; the filename is still timestamped (the literal name is not used).
- Export all CSVs (when --export-all is provided):
  - Writes two files with timestamp in the selected directory:
    - <timestamp>_endpoints.csv
    - <timestamp>_inventory.csv

Logging
- Default: INFO to stdout.
- --debug: verbose diagnostics, including sample payload structures and derived fields.
- --log-file <path>: also writes detailed logs to the specified file.

Exit codes
- 0: success
- 1: runtime error (network/API/other)
- 2: missing API key
- On first run it may auto-update packages and restart.

Command-line options (quick)
- --api-key: API key (or use BITDEFENDER_API_KEY).
- --region: "ap" (alias: "non-eu"), "eu", or "us". Default: "non-eu".
- --output: target directory or path to influence where the timestamped duplicates CSV is written.
- --list-all: print all endpoints and inventory to console.
- --export-all: directory or path (parent directory is used) for writing all endpoints/inventory CSVs.
- --debug: verbose logs.
- --insecure: disable TLS certificate verification (not recommended).
- --log-file: optional log file path.

Examples

Windows (PowerShell)
1) Using environment variable and defaults (non-EU region):
   setx BITDEFENDER_API_KEY "PASTE_YOUR_KEY_HERE"
   python getComputerlist.r3.py

2) Specify region and write outputs to a folder:
   python getComputerlist.r3.py `
     --region eu `
     --output "C:\Exports\" `
     --export-all "C:\Exports\" `
     --log-file "C:\Exports\gz_run.log" `
     --debug

3) Provide API key on the command line:
   python getComputerlist.r3.py --api-key "PASTE_YOUR_KEY" --output "./exports/" --debug
   python getComputerlist.r3.py --api-key "PASTE_YOUR_KEY" --region ap --output "./exports/" --debug

Operational notes
- Duplicate detection is based on name (case-insensitive) from getEndpointsList results only.
- The inventory call is mostly for additional visibility and optional export; it is not used for de-duplication.
- For proxies: requests uses HTTPS_PROXY/HTTP_PROXY environment variables if set.
- If you receive 401/403 errors, verify your API key and GravityZone permissions.
- If you see SSL errors, leave --insecure off unless you fully understand the risk; instead, fix trust store (certifi) or configure your proxy.

Troubleshooting
- "No API key provided": set BITDEFENDER_API_KEY or pass --api-key.
- "API error: ...": re-check region and permissions; confirm endpoint is reachable.
- SSL/TLS validation failure: corporate proxy inspection could be at fault; try updating certifi, adding your proxy’s CA to the system store, or use --insecure as a last resort.
- Timeouts: check network egress, firewall, or corporate proxy rules.

Fields exported (best-effort)
- name, fqdn, machineType, operatingSystemVersion, ip, macs, ssid, managedWithBest, lastSeen, loggedInUser
- Some fields may be empty or derived from nested structures (best effort).

"""
import os
import sys
import csv
import json
import base64
import argparse
import logging
from uuid import uuid4
from typing import List, Dict, Any, Optional
from datetime import datetime

# --- Bootstrap: ensure latest packages and restart if updated ---
def ensure_latest_packages(packages: List[str], logger: logging.Logger) -> None:
    import subprocess
    import importlib
    from importlib import metadata
    from urllib.request import urlopen
    from urllib.error import URLError, HTTPError

    # Ensure 'packaging' exists first (needed for proper version comparison)
    try:
        from packaging.version import parse as vparse  # noqa: F401
    except Exception:
        logger.info("Installing/Updating prerequisite: packaging")
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "packaging"], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Try importing again in the same process
        try:
            from packaging.version import parse as vparse  # noqa: F401
        except Exception:
            logger.error("Failed to import 'packaging'. Please install it manually.")
            sys.exit(1)

    from packaging.version import parse as vparse

    updated_any = False
    for pkg in packages:
        try:
            installed_ver = metadata.version(pkg)
        except metadata.PackageNotFoundError:
            installed_ver = None

        latest_ver = None
        try:
            with urlopen(f"https://pypi.org/pypi/{pkg}/json", timeout=15) as resp:
                data = json.load(resp)
                latest_ver = data.get("info", {}).get("version")
        except (URLError, HTTPError, json.JSONDecodeError) as e:
            logger.warning(f"Could not check latest version for {pkg}: {e}")
            continue

        if latest_ver is None:
            continue

        needs_update = installed_ver is None or vparse(installed_ver) < vparse(latest_ver)
        if needs_update:
            logger.info(f"Updating {pkg} from {installed_ver or 'not installed'} to {latest_ver}")
            result = subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", pkg], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode != 0:
                logger.error(f"Failed to update {pkg}: {result.stderr.strip()}")
                continue
            updated_any = True

    if updated_any:
        # Restart the script with same args
        logger.info("Updates applied. Restarting script...")
        os.execv(sys.executable, [sys.executable] + sys.argv)

# --- Argument parsing and logging setup ---
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Find duplicate endpoint names via Bitdefender GravityZone API and export details to CSV.")
    parser.add_argument("--api-key", help="Bitdefender API key. If omitted, reads from BITDEFENDER_API_KEY env var.", default=os.getenv("BITDEFENDER_API_KEY"))
    parser.add_argument(
        "--region",
        choices=["ap", "eu", "us", "non-eu"],
        default="non-eu",
        help="API region: ap (alias: non-eu), eu, or us. Default: non-eu (maps to ap)."
    )
    parser.add_argument("--output", default="duplicates_endpoints.csv", help="CSV output filepath")
    parser.add_argument("--debug", action="store_true", help="Enable detailed debug logs")
    parser.add_argument("--insecure", action="store_true", help="Allow insecure HTTPS (disable certificate verification). Not recommended.")
    parser.add_argument("--log-file", default=None, help="Optional path to write detailed logs.")
    parser.add_argument("--list-all", action="store_true", help="Print all endpoints to console.")
    parser.add_argument("--export-all", default=None, help="Optional CSV path to export all endpoints.")
    return parser.parse_args()

def setup_logger(debug: bool, log_file: Optional[str] = None) -> logging.Logger:
    logger = logging.getLogger("gzdup")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    if logger.handlers:
        logger.handlers.clear()

    formatter = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s")

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if debug else logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        logger.info(f"Logging to file: {log_file}")

    return logger

# --- API helpers ---
def get_endpoint_url(region: str) -> str:
    if region == "eu":
        return "https://cloud.gravityzone.bitdefender.com/api/v1.0/jsonrpc/network"
    if region == "us":
        return "https://cloudgz.gravityzone.bitdefender.com/api/v1.0/jsonrpc/network"
    # treat both "ap" and legacy "non-eu" as AP
    return "https://cloudap.gravityzone.bitdefender.com/api/v1.0/jsonrpc/network"

def make_auth_header(api_key: str) -> str:
    token = base64.b64encode(f"{api_key}:".encode("utf-8")).decode("utf-8")
    return f"Basic {token}"

def fetch_all_endpoints(api_url: str, auth_header: str, insecure: bool, logger: logging.Logger, method: str = "getEndpointsList") -> List[Dict[str, Any]]:
    import requests

    headers = {
        "Content-Type": "application/json",
        "Authorization": auth_header,
    }

    items: List[Dict[str, Any]] = []
    page = 1
    per_page = 100

    verify = not insecure
    if not verify:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

    while True:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": {
                "filters": {
                    "depth": {"allItemsRecursively": True}
                },
                "page": page,
                "perPage": per_page,
            },
            "id": str(uuid4()),
        }

        logger.debug(f"Requesting page {page} with perPage {per_page}")
        resp = requests.post(api_url, json=payload, headers=headers, timeout=60, verify=verify)
        resp.raise_for_status()
        data = resp.json()

        if "error" in data:
            raise RuntimeError(f"API error: {data['error']}")

        result = data.get("result", {})
        page_items = result.get("items", [])
        # Extra DEBUG for first page to see structure differences
        if page == 1 and logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"[{method}] result keys: {list(result.keys())}")
            if page_items:
                try:
                    logger.debug(f"[{method}] first item sample: {json.dumps(page_items[0], ensure_ascii=False)[:4000]}")
                except Exception:
                    logger.debug(f"[{method}] first item (repr): {repr(page_items[0])[:4000]}")

        items.extend(page_items)

        total = result.get("total", 0)
        pages_count = result.get("pagesCount", 1)
        logger.debug(f"Fetched {len(page_items)} items (total so far: {len(items)} of {total}); pagesCount={pages_count}")

        if page >= pages_count:
            break
        page += 1

    logger.info(f"Fetched total items with method {method}: {len(items)}")
    return items

# --- Duplicate detection and CSV export ---
def group_duplicates_by_name(items: List[Dict[str, Any]], logger: logging.Logger) -> Dict[str, List[Dict[str, Any]]]:
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for it in items:
        name = (it.get("name") or "").strip()
        if not name:
            continue
        key = name.casefold()
        groups.setdefault(key, []).append(it)
    dupes = {k: v for k, v in groups.items() if len(v) > 1}
    logger.info(f"Duplicate groups found: {len(dupes)}")
    return dupes

def pick_logged_in_user(item: Dict[str, Any]) -> Any:
    for k in ["loggedInUser", "lastLoggedInUser", "loggedUser", "user", "loginUser"]:
        if k in item:
            return item.get(k)
    return ""

def export_duplicates_to_csv(dupes: Dict[str, List[Dict[str, Any]]], output_path: str, logger: logging.Logger) -> None:
    fieldnames = [
        "name",
        "fqdn",
        "machineType",
        "operatingSystemVersion",
        "ip",
        "macs",
        "ssid",
        "managedWithBest",
        "lastSeen",
        "loggedInUser",
    ]
    rows = []
    for key, items in dupes.items():
        for it in items:
            rows.append({
                "name": it.get("name", ""),
                "fqdn": it.get("fqdn", ""),
                "machineType": it.get("machineType", ""),
                "operatingSystemVersion": it.get("operatingSystemVersion", ""),
                "ip": it.get("ip", ""),
                "macs": "|".join(it.get("macs", []) or []),
                "ssid": it.get("ssid", ""),
                "managedWithBest": it.get("managedWithBest", ""),
                "lastSeen": it.get("lastSeen", ""),
                "loggedInUser": pick_logged_in_user(it),
            })

    if not rows:
        logger.info("No duplicates found. CSV will not be created.")
        return

    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    logger.info(f"Wrote {len(rows)} duplicate endpoint rows to {output_path}")

# Helpers to diagnose and extract fields from nested inventory structures
def _find_first_key_recursive(obj: Any, candidate_keys: List[str], max_depth: int = 4) -> Optional[Any]:
    """Depth-limited recursive search for first existing key in candidate_keys."""
    from collections import deque
    if obj is None:
        return None
    seen = set()
    dq = deque([(obj, 0)])
    cand_set = set(k.casefold() for k in candidate_keys)
    while dq:
        cur, depth = dq.popleft()
        if id(cur) in seen:
            continue
        seen.add(id(cur))
        if isinstance(cur, dict):
            # Direct hit
            for k, v in cur.items():
                if k.casefold() in cand_set and v not in (None, "", []):
                    return v
            # Traverse deeper if allowed
            if depth < max_depth:
                for v in cur.values():
                    dq.append((v, depth + 1))
        elif isinstance(cur, list):
            if depth < max_depth:
                for v in cur:
                    dq.append((v, depth + 1))
    return None

def _normalize_list_or_scalar(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        # flatten one level of dicts/values
        flat: List[str] = []
        for x in value:
            if isinstance(x, dict):
                # try common id-like or address-like keys
                flat.append(str(
                    _find_first_key_recursive(x, ["value", "address", "ip", "mac", "id", "name"], max_depth=1) or x
                ))
            else:
                flat.append(str(x))
        return "|".join(map(str, flat))
    if isinstance(value, dict):
        # try some common fields if dict
        return str(_find_first_key_recursive(value, ["value", "address", "ip", "mac", "id", "name"], max_depth=1) or "")
    return str(value)

def extract_common_fields(item: Dict[str, Any]) -> Dict[str, str]:
    """
    Try to extract common fields from either endpoint list or network inventory items.
    Falls back to recursive search for inventory responses where fields are nested.
    """
    # Candidate key lists
    name_keys = ["name", "hostname", "displayName", "computerName", "vmName", "title", "label"]
    fqdn_keys = ["fqdn", "dnsName", "hostFqdn", "fullyQualifiedName", "domainName", "dns", "hostName"]
    os_keys = ["operatingSystemVersion", "osName", "os", "operatingSystem", "platform"]
    ip_keys = ["ip", "ipAddress", "primaryIpAddress", "ipv4", "ipv4Address", "address"]
    mac_keys = ["macs", "mac", "macAddress", "macAddresses"]
    machine_type_keys = ["machineType", "type", "deviceType", "endpointType"]

    # Direct values
    name = item.get("name") or _find_first_key_recursive(item, name_keys)
    fqdn = item.get("fqdn") or _find_first_key_recursive(item, fqdn_keys)
    osv = item.get("operatingSystemVersion") or _find_first_key_recursive(item, os_keys)
    ip = item.get("ip") or _find_first_key_recursive(item, ip_keys)
    macs = item.get("macs") or _find_first_key_recursive(item, mac_keys)
    machine_type = item.get("machineType") or _find_first_key_recursive(item, machine_type_keys)

    return {
        "name": _normalize_list_or_scalar(name),
        "fqdn": _normalize_list_or_scalar(fqdn),
        "machineType": _normalize_list_or_scalar(machine_type),
        "operatingSystemVersion": _normalize_list_or_scalar(osv),
        "ip": _normalize_list_or_scalar(ip),
        "macs": _normalize_list_or_scalar(macs),
    }

def debug_dump_item_structure(method: str, items: List[Dict[str, Any]], logger: logging.Logger, sample: int = 5) -> None:
    """
    Extra diagnostics: show keys, sample JSON, and what we can extract for name/fqdn/ip from nested structures.
    """
    if not logger.isEnabledFor(logging.DEBUG) or not items:
        return
    logger.debug(f"[{method}] diagnostic dump of first {min(sample, len(items))} items")
    for idx, it in enumerate(items[:sample], start=1):
        try:
            logger.debug(f"[{method}] item #{idx} top-level keys: {sorted(list(it.keys()))}")
        except Exception:
            pass
        try:
            logger.debug(f"[{method}] item #{idx} raw (truncated): {json.dumps(it, ensure_ascii=False)[:4000]}")
        except Exception:
            logger.debug(f"[{method}] item #{idx} raw (repr truncated): {repr(it)[:4000]}")
        # Derived fields via recursive extraction
        derived = extract_common_fields(it)
        logger.debug(f"[{method}] item #{idx} derived fields -> name={derived.get('name')!r}, fqdn={derived.get('fqdn')!r}, ip={derived.get('ip')!r}, os={derived.get('operatingSystemVersion')!r}")

def log_all_endpoints(items: List[Dict[str, Any]], logger: logging.Logger, level: int = logging.INFO) -> None:
    for it in items:
        # Use recursive extraction to surface fields even for inventory items
        fields = extract_common_fields(it)
        logger.log(
            level,
            "Endpoint: name=%s, fqdn=%s, machineType=%s, os=%s, ip=%s, macs=%s, ssid=%s, managedWithBest=%s, lastSeen=%s, loggedInUser=%s",
            fields.get("name", "") or it.get("name", ""),
            fields.get("fqdn", "") or it.get("fqdn", ""),
            fields.get("machineType", "") or it.get("machineType", ""),
            fields.get("operatingSystemVersion", "") or it.get("operatingSystemVersion", ""),
            fields.get("ip", "") or it.get("ip", ""),
            fields.get("macs", "") or "|".join(it.get("macs", []) or []),
            it.get("ssid", ""),
            it.get("managedWithBest", ""),
            it.get("lastSeen", ""),
            pick_logged_in_user(it),
        )

def export_all_to_csv(items: List[Dict[str, Any]], output_path: str, logger: logging.Logger) -> None:
    fieldnames = [
        "name",
        "fqdn",
        "machineType",
        "operatingSystemVersion",
        "ip",
        "macs",
        "ssid",
        "managedWithBest",
        "lastSeen",
        "loggedInUser",
    ]
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for it in items:
            writer.writerow({
                "name": it.get("name", ""),
                "fqdn": it.get("fqdn", ""),
                "machineType": it.get("machineType", ""),
                "operatingSystemVersion": it.get("operatingSystemVersion", ""),
                "ip": it.get("ip", ""),
                "macs": "|".join(it.get("macs", []) or []),
                "ssid": it.get("ssid", ""),
                "managedWithBest": it.get("managedWithBest", ""),
                "lastSeen": it.get("lastSeen", ""),
                "loggedInUser": pick_logged_in_user(it),
            })
    logger.info(f"Wrote all {len(items)} endpoints to {output_path}")

def resolve_timestamped_csv_path(preferred: Optional[str], suffix: Optional[str], logger: logging.Logger) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"{ts}{suffix or ''}.csv"
    dirpath: Optional[str] = None

    if preferred:
        if preferred.endswith(os.sep) or os.path.isdir(preferred):
            dirpath = preferred
        else:
            parent = os.path.dirname(preferred)
            if parent:
                dirpath = parent

    if not dirpath:
        dirpath = os.getcwd()

    path = os.path.join(dirpath, filename)
    logger.debug(f"Resolved CSV path: {path}")
    return path

# --- Main ---
def main() -> None:
    args = parse_args()
    logger = setup_logger(args.debug, args.log_file)

    if not args.api_key:
        logger.error("No API key provided. Use --api-key or set BITDEFENDER_API_KEY environment variable.")
        sys.exit(2)

    ensure_latest_packages(["requests", "certifi", "packaging"], logger)

    api_url = get_endpoint_url(args.region)
    logger.debug(f"Using API endpoint: {api_url} (region: {args.region})")

    auth_header = make_auth_header(args.api_key)
    logger.debug("Authorization header prepared.")

    try:
        logger.info("Scanning with method: getEndpointsList")
        items_endpoints = fetch_all_endpoints(api_url, auth_header, args.insecure, logger, method="getEndpointsList")

        logger.info("Scanning with method: getNetworkInventoryItems")
        items_inventory = fetch_all_endpoints(api_url, auth_header, args.insecure, logger, method="getNetworkInventoryItems")

        # Extra diagnostics: dump item structure when --debug
        if args.debug:
            debug_dump_item_structure("getEndpointsList", items_endpoints, logger, sample=3)
            debug_dump_item_structure("getNetworkInventoryItems", items_inventory, logger, sample=5)

        if args.list_all:
            logger.info("Endpoints (getEndpointsList):")
            log_all_endpoints(items_endpoints, logger, level=logging.INFO)
            logger.info("Inventory (getNetworkInventoryItems):")
            log_all_endpoints(items_inventory, logger, level=logging.INFO)
        elif args.debug:
            logger.debug("Endpoints (getEndpointsList):")
            log_all_endpoints(items_endpoints, logger, level=logging.DEBUG)
            logger.debug("Inventory (getNetworkInventoryItems):")
            log_all_endpoints(items_inventory, logger, level=logging.DEBUG)

        duplicates_out = resolve_timestamped_csv_path(args.output, None, logger)

        if args.export_all is not None:
            all_out_endpoints = resolve_timestamped_csv_path(args.export_all, "_endpoints", logger)
            all_out_inventory = resolve_timestamped_csv_path(args.export_all, "_inventory", logger)
            export_all_to_csv(items_endpoints, all_out_endpoints, logger)
            export_all_to_csv(items_inventory, all_out_inventory, logger)

        dupes = group_duplicates_by_name(items_endpoints, logger)
        export_duplicates_to_csv(dupes, duplicates_out, logger)

    except Exception as e:
        logger.error(f"Failure: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
