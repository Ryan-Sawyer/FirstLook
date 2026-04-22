import ipaddress
from typing import Any

import nmap


# =============================================================
# Nmap Scanner
# =============================================================
# Wraps python-nmap to perform host discovery and port scanning.
#
# Basic scan:  ping sweep + top 1000 ports + OS detection
# Deep scan:   full port range + aggressive service/version + OS
#
# Results are normalised into the AssetCreate schema format
# that the push client will POST to the control server.
# =============================================================


def _parse_host(host: str, host_data: dict[str, Any], scan_type: str) -> dict | None:
    """
    Parse a single nmap host entry into an AssetCreate-compatible dict.

    Args:
        host:       IP address string.
        host_data:  nmap host data dict.
        scan_type:  'basic' or 'deep'.

    Returns:
        Asset dict or None if the host is down.
    """
    # Skip hosts that didn't respond
    if host_data.get("status", {}).get("state") != "up":
        return None

    # Hostname
    hostnames = host_data.get("hostnames", [])
    hostname = hostnames[0].get("name") if hostnames else None
    if hostname == host:
        hostname = None  # Don't store the IP as a hostname

    # OS fingerprint
    os_fingerprint = None
    osmatch = host_data.get("osmatch", [])
    if osmatch:
        best = osmatch[0]
        os_fingerprint = f"{best.get('name', '')} ({best.get('accuracy', '')}%)"

    # Infer asset type from OS string and open ports
    asset_type = _infer_asset_type(os_fingerprint, host_data)

    # SNMP description — not available from nmap, will be enriched separately
    snmp_description = None

    # Build interface
    interface = {
        "mac_address":    _get_mac(host_data),
        "ipv4_address":   host,
        "discovered_via": "nmap",
    }

    # Filter out entries with no usable MAC
    if not interface["mac_address"]:
        return None

    return {
        "hostname":         hostname,
        "asset_type":       asset_type,
        "os_fingerprint":   os_fingerprint,
        "snmp_description": snmp_description,
        "interfaces": [interface],
    }


def _get_mac(host_data: dict) -> str | None:
    """
    Extract MAC address from nmap host data.
    nmap only reports MACs for hosts on the same Layer 2 segment.

    Returns:
        MAC address string or None.
    """
    addresses = host_data.get("addresses", {})
    return addresses.get("mac")


def _infer_asset_type(os_fingerprint: str | None, host_data: dict) -> str:
    """
    Make a best-guess at asset type from OS string and open ports.

    Args:
        os_fingerprint: OS string from nmap, or None.
        host_data:      Full nmap host data dict.

    Returns:
        Asset type string matching the AssetType enum.
    """
    os = (os_fingerprint or "").lower()
    tcp = host_data.get("tcp", {})
    open_ports = set(tcp.keys())

    # Network device detection by OS string
    for keyword in ["cisco", "juniper", "aruba", "ubiquiti", "mikrotik", "fortinet"]:
        if keyword in os:
            return "switch"

    # Printer detection
    for port in [9100, 515, 631]:
        if port in open_ports:
            return "printer"

    # Server vs workstation by OS string
    if any(kw in os for kw in ["server", "ubuntu", "debian", "centos", "rhel", "linux"]):
        return "server"

    if any(kw in os for kw in ["windows 10", "windows 11", "macos", "mac os x"]):
        return "workstation"

    if "windows server" in os:
        return "server"

    return "unknown"


def run_basic_scan(subnets: list[str], throttle: float = 0.5) -> list[dict]:
    """
    Run a basic discovery scan across the given subnets.

    Nmap flags:
        -sS     SYN scan (requires root)
        -O      OS detection
        -T3     Normal timing template
        --top-ports 1000    Scan top 1000 most common ports
        --scan-delay        Throttle between probes

    Args:
        subnets:    List of CIDR ranges to scan.
        throttle:   Seconds between host probes.

    Returns:
        List of asset dicts ready for submission.
    """
    nm = nmap.PortScanner()
    assets = []

    for subnet in subnets:
        # Validate subnet before passing to nmap
        try:
            ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            print(f"[NMAP] Invalid subnet: {subnet} — skipping")
            continue

        print(f"[NMAP] Basic scan: {subnet}")

        try:
            nm.scan(
                hosts=subnet,
                arguments=f"-sS -O -T4 --top-ports 1000 --scan-delay {throttle}s",
            )
        except Exception as e:
            print(f"[NMAP] Scan failed for {subnet}: {e}")
            continue

        for host in nm.all_hosts():
            asset = _parse_host(host, nm[host], "basic")
            if asset:
                assets.append(asset)
                print(f"[NMAP] Found: {host} ({asset.get('hostname') or 'no hostname'}) — {asset['asset_type']}")

    print(f"[NMAP] Basic scan complete. {len(assets)} hosts found.")
    return assets


def run_deep_scan(subnets: list[str], throttle: float = 0.5) -> list[dict]:
    """
    Run a deep scan — full port range, aggressive service/version detection.

    Nmap flags:
        -sS     SYN scan
        -sV     Service/version detection
        -O      OS detection
        -A      Aggressive mode (includes script scanning)
        -p-     All 65535 ports
        -T3     Normal timing
        --scan-delay    Throttle

    Args:
        subnets:    List of CIDR ranges to scan.
        throttle:   Seconds between host probes.

    Returns:
        List of asset dicts ready for submission.
    """
    nm = nmap.PortScanner()
    assets = []

    is_root = os.geteuid() == 0
    scan_args = (
        f"-sS -sV -O -T4 --top-ports 1000 "
        f"--host-timeout 120s --scan-delay {throttle}s"
    ) if is_root else (
        f"-sT -sV -T4 --top-ports 1000 "
        f"--host-timeout 120s --scan-delay {throttle}s"
    )

    for subnet in subnets:
        try:
            ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            print(f"[NMAP] Invalid subnet: {subnet} — skipping")
            continue

        print(f"[NMAP] Deep scan: {subnet} (this may take a while)")

        try:
            nm.scan(
                hosts=subnet,
                arguments=scan_args,
            )
        except Exception as e:
            print(f"[NMAP] Deep scan failed for {subnet}: {e}")
            continue

        for host in nm.all_hosts():
            asset = _parse_host(host, nm[host], "deep")
            if asset:
                assets.append(asset)
                print(f"[NMAP] Found: {host} ({asset.get('hostname') or 'no hostname'}) — {asset['asset_type']}")

    print(f"[NMAP] Deep scan complete. {len(assets)} hosts found.")
    return assets
