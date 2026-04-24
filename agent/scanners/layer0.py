import ipaddress
import socket
import subprocess
from typing import Optional

import nmap
from mac_vendor_lookup import MacLookup, VendorNotFoundError


# =============================================================
# Layer 0 Scanner
# =============================================================
# Fast, passive, credential-free discovery.
#
# Step 1 — Ping sweep to find live hosts on the subnet
# Step 2 — Reverse DNS lookup against local/specified DNS server
# Step 3 — MAC OUI lookup to infer vendor and device type
#
# Output is a list of lightweight asset dicts ready to push
# to the control server. No port scanning, no credentials.
# Completes in seconds on a /24.
# =============================================================


# =============================================================
# Vendor → ITflow asset type map
# =============================================================
# Keep this minimal — Layer 2 will refine types using SNMP
# and vendor APIs. If we're not confident, we say "Other".
# =============================================================

VENDOR_TYPE_MAP = {
    # Firewall/Router
    "fortinet":         "Firewall/Router",
    "palo alto":        "Firewall/Router",
    "sonicwall":        "Firewall/Router",
    "sonic wall":       "Firewall/Router",
    "mikrotik":         "Firewall/Router",
    "cisco":            "Firewall/Router",
    "juniper":          "Firewall/Router",
    "watchguard":       "Firewall/Router",
    "meraki":           "Firewall/Router",
    "peplink":          "Firewall/Router",

    # Switch (APs included — refined in Layer 2)
    "ubiquiti":         "Switch",
    "netgear":          "Switch",
    "aruba":            "Switch",
    "ruckus":           "Switch",
    "extreme":          "Switch",
    "aerohive":         "Switch",
    "cambium":          "Switch",

    # Desktop/Workstation
    "apple":            "Desktop",
    "lenovo":           "Desktop",
    "dell":             "Desktop",
    "intel":            "Desktop",
    "microsoft":        "Desktop",
    "acer":             "Desktop",
    "asus":             "Desktop",
    "toshiba":          "Desktop",
    "samsung":          "Desktop",
    "lg":               "Desktop",
    "gigabyte":         "Desktop",
    "asustek":          "Desktop",

    # Everything else → Other at runtime
}


# =============================================================
# MAC OUI Lookup
# =============================================================

# Initialise the MAC lookup table once at module load
_mac_lookup = MacLookup()

try:
    _mac_lookup.update_vendors()
except Exception:
    # If update fails (no internet) use the bundled offline database
    pass


def get_vendor(mac: str) -> Optional[str]:
    """
    Look up the vendor name for a MAC address using the OUI database.

    Args:
        mac: MAC address string in any common format.

    Returns:
        Vendor name string, or None if not found.
    """
    try:
        return _mac_lookup.lookup(mac)
    except (VendorNotFoundError, Exception):
        return None


def infer_device_type(vendor: Optional[str]) -> str:
    """
    Infer ITflow asset type from vendor string.
    Matches against known vendor keywords — defaults to 'Other'.

    Args:
        vendor: Vendor name from OUI lookup, or None.

    Returns:
        ITflow asset type string.
    """
    if not vendor:
        return "Other"

    vendor_lower = vendor.lower()

    for keyword, device_type in VENDOR_TYPE_MAP.items():
        if keyword in vendor_lower:
            return device_type

    return "Other"


# =============================================================
# DNS Resolution
# =============================================================

def get_local_dns_server() -> Optional[str]:
    """
    Read the first nameserver from /etc/resolv.conf.
    This is the DNS server the agent's host is configured to use —
    on a client network this is typically their internal DNS server.

    Returns:
        DNS server IP string, or None if not determinable.
    """
    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
    except Exception:
        pass
    return None


def reverse_dns(ip: str, dns_server: Optional[str] = None) -> Optional[str]:
    """
    Perform a reverse DNS lookup for an IP address.
    Uses the specified DNS server if provided, otherwise falls
    back to the system resolver.

    Args:
        ip:         IPv4 address to resolve.
        dns_server: DNS server IP to query, or None for system default.

    Returns:
        Hostname string, or None if not resolvable.
    """
    if dns_server:
        # Use dig to query a specific DNS server
        try:
            result = subprocess.run(
                ["dig", "+short", "+time=2", "+tries=1",
                 f"@{dns_server}", "-x", ip],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout.strip()
            if output and not output.startswith(";"):
                # dig returns hostname with trailing dot — strip it
                hostname = output.rstrip(".")
                if hostname and hostname != ip:
                    return hostname
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass
        return None
    else:
        # Fall back to system resolver
        try:
            socket.setdefaulttimeout(2.0)
            hostname, _, _ = socket.gethostbyaddr(ip)
            if hostname and hostname != ip:
                return hostname
        except (socket.herror, socket.gaierror, socket.timeout, Exception):
            pass
        finally:
            socket.setdefaulttimeout(None)
        return None


# =============================================================
# Ping Sweep
# =============================================================

def ping_sweep(subnet: str) -> list[dict]:
    """
    Run a fast ping sweep to find live hosts on the subnet.
    Uses nmap -sn (no port scan) which is fast and requires
    no special privileges for ICMP on most systems.

    Also captures MAC addresses for hosts on the same L2 segment.

    Args:
        subnet: CIDR range to sweep e.g. '192.168.1.0/24'

    Returns:
        List of dicts with keys: ip, mac (or None)
    """
    nm = nmap.PortScanner()
    hosts = []

    try:
        print(f"[L0] Ping sweep: {subnet}")
        nm.scan(hosts=subnet, arguments="-sn -T4 --host-timeout 10s")
    except Exception as e:
        print(f"[L0] Ping sweep failed for {subnet}: {e}")
        return []

    for host in nm.all_hosts():
        if nm[host].get("status", {}).get("state") != "up":
            continue

        mac = nm[host].get("addresses", {}).get("mac")
        hosts.append({
            "ip":  host,
            "mac": mac,
        })

    print(f"[L0] Ping sweep complete — {len(hosts)} live hosts found")
    return hosts


# =============================================================
# Layer 0 Main
# =============================================================

def run_layer0(subnets: list[str], dns_server: Optional[str] = None) -> list[dict]:
    """
    Run a full Layer 0 discovery scan across the given subnets.

    Steps:
        1. Ping sweep each subnet to find live hosts
        2. Reverse DNS lookup for each live host
        3. MAC OUI lookup to infer vendor and device type

    Args:
        subnets:    List of CIDR ranges to scan.
        dns_server: DNS server IP to use for PTR lookups.
                    If None, auto-detects from /etc/resolv.conf.

    Returns:
        List of asset dicts compatible with the ScanResultsSubmit schema.
    """
    # Auto-detect DNS server if not specified
    if not dns_server:
        dns_server = get_local_dns_server()
        if dns_server:
            print(f"[L0] Using DNS server: {dns_server}")
        else:
            print("[L0] No DNS server detected — hostname resolution may be limited")

    all_assets = []

    for subnet in subnets:
        # Validate subnet
        try:
            ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            print(f"[L0] Invalid subnet: {subnet} — skipping")
            continue

        # Step 1 — Ping sweep
        live_hosts = ping_sweep(subnet)

        if not live_hosts:
            print(f"[L0] No live hosts found on {subnet}")
            continue

        # Steps 2 & 3 — DNS + OUI per host
        for host in live_hosts:
            ip  = host["ip"]
            mac = host["mac"]

            # Step 2 — Reverse DNS
            hostname = reverse_dns(ip, dns_server)
            if hostname:
                print(f"[L0] {ip} → {hostname}")
            else:
                print(f"[L0] {ip} → no PTR record")

            # Step 3 — OUI lookup
            vendor      = get_vendor(mac) if mac else None
            device_type = infer_device_type(vendor)

            if vendor:
                print(f"[L0] {ip} MAC {mac} → {vendor} ({device_type})")
            else:
                print(f"[L0] {ip} MAC {mac or 'unknown'} → vendor unknown (Other)")

            # Build asset dict
            asset = {
                "hostname":         hostname,
                "asset_type":       device_type,
                "os_fingerprint":   None,
                "snmp_description": vendor,   # Store vendor in snmp_description for now
                "interfaces": [],
            }

            # Only add interface if we have a MAC
            if mac:
                asset["interfaces"].append({
                    "mac_address":    mac.lower(),
                    "ipv4_address":   ip,
                    "interface_name": None,
                    "discovered_via": "nmap",
                })
            else:
                # No MAC — still record the host but without interface
                # Deduplication will use IP fallback
                asset["interfaces"].append({
                    "mac_address":    _generate_placeholder_mac(ip),
                    "ipv4_address":   ip,
                    "interface_name": None,
                    "discovered_via": "nmap",
                })

            all_assets.append(asset)

    print(f"\n[L0] Layer 0 complete — {len(all_assets)} assets discovered")
    return all_assets


def _generate_placeholder_mac(ip: str) -> str:
    """
    Generate a deterministic placeholder MAC for hosts where nmap
    couldn't capture the MAC (typically hosts on a different L2 segment
    reached via a router). Uses the IP octets to ensure uniqueness.

    Format: 02:00:xx:xx:xx:xx (02 prefix = locally administered)

    Args:
        ip: IPv4 address string.

    Returns:
        Placeholder MAC string.
    """
    octets = ip.split(".")
    return f"02:00:{int(octets[0]):02x}:{int(octets[1]):02x}:{int(octets[2]):02x}:{int(octets[3]):02x}"
