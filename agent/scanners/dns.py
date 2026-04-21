import socket
from typing import Optional


# =============================================================
# Reverse DNS Scanner
# =============================================================
# Attempts to resolve hostnames for discovered IP addresses
# using the local DNS infrastructure.
#
# This is intentionally simple — a single PTR lookup per IP.
# No external DNS is queried; this uses whatever resolver
# the Linux box is configured with (typically the client's
# internal DNS server, which is exactly what we want).
# =============================================================


def resolve_hostname(ip: str) -> Optional[str]:
    """
    Attempt a reverse DNS lookup for the given IP address.

    Args:
        ip: IPv4 address string.

    Returns:
        Resolved hostname string, or None if lookup fails.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        # Don't return the IP itself as a hostname
        if hostname == ip:
            return None
        return hostname
    except (socket.herror, socket.gaierror):
        # No PTR record or DNS unavailable — expected for many hosts
        return None
    except Exception:
        return None


def enrich_assets_dns(assets: list[dict]) -> list[dict]:
    """
    Run reverse DNS lookups across a list of assets in place.
    Only fills in hostname if one hasn't already been found.

    Args:
        assets: List of asset dicts.

    Returns:
        The same list with hostnames filled in where resolvable.
    """
    for asset in assets:
        # Skip if we already have a hostname from nmap or SNMP
        if asset.get("hostname"):
            continue

        ifaces = asset.get("interfaces", [])
        if not ifaces:
            continue

        ip = ifaces[0].get("ipv4_address")
        if not ip:
            continue

        hostname = resolve_hostname(ip)
        if hostname:
            asset["hostname"] = hostname
            print(f"[DNS] {ip} → {hostname}")

    return assets
