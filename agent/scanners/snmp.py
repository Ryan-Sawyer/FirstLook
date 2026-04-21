from typing import Any

from easysnmp import Session, EasySNMPTimeoutError, EasySNMPConnectionError


# =============================================================
# SNMP Scanner
# =============================================================
# Walks public OIDs on discovered hosts to enrich asset data.
# Uses community string 'public' — no credentials required.
#
# OIDs we care about for basic discovery:
#   sysDescr    .1.3.6.1.2.1.1.1.0   System description
#   sysName     .1.3.6.1.2.1.1.5.0   Configured hostname
#   sysContact  .1.3.6.1.2.1.1.4.0   Contact info
#   sysLocation .1.3.6.1.2.1.1.6.0   Physical location
#
# Interface table (ifTable):
#   ifDescr     .1.3.6.1.2.1.2.2.1.2    Interface name
#   ifPhysAddr  .1.3.6.1.2.1.2.2.1.6    MAC address
#   ifOperStatus .1.3.6.1.2.1.2.2.1.8   Operational status
#
# IP address table:
#   ipAdEntAddr     .1.3.6.1.2.1.4.20.1.1   IP address
#   ipAdEntIfIndex  .1.3.6.1.2.1.4.20.1.2   Interface index
# =============================================================

COMMUNITY = "public"
SNMP_VERSION = 2
TIMEOUT = 2      # seconds per OID request
RETRIES = 1


# System OIDs
OID_SYS_DESCR    = ".1.3.6.1.2.1.1.1.0"
OID_SYS_NAME     = ".1.3.6.1.2.1.1.5.0"
OID_SYS_CONTACT  = ".1.3.6.1.2.1.1.4.0"
OID_SYS_LOCATION = ".1.3.6.1.2.1.1.6.0"

# Interface table OIDs
OID_IF_DESCR    = ".1.3.6.1.2.1.2.2.1.2"
OID_IF_PHYS_ADDR = ".1.3.6.1.2.1.2.2.1.6"
OID_IF_OPER_STATUS = ".1.3.6.1.2.1.2.2.1.8"

# IP address table OIDs
OID_IP_ADDR     = ".1.3.6.1.2.1.4.20.1.1"
OID_IP_IF_INDEX = ".1.3.6.1.2.1.4.20.1.2"


def _format_mac(raw: str) -> str | None:
    """
    Format a raw SNMP MAC address (hex bytes) into aa:bb:cc:dd:ee:ff.

    Args:
        raw: Raw SNMP octet string.

    Returns:
        Formatted MAC string or None if invalid.
    """
    if not raw or raw == "0x":
        return None
    try:
        # Strip '0x' prefix and split into bytes
        clean = raw.replace("0x", "").replace(" ", "")
        if len(clean) != 12:
            return None
        return ":".join(clean[i:i+2] for i in range(0, 12, 2)).lower()
    except Exception:
        return None


def enrich_asset(ip: str) -> dict[str, Any] | None:
    """
    Attempt an SNMP walk on a host to gather system and interface data.

    Args:
        ip: IP address to query.

    Returns:
        Dict with 'snmp_description', 'hostname', and 'interfaces',
        or None if SNMP is not available on the host.
    """
    try:
        session = Session(
            hostname=ip,
            community=COMMUNITY,
            version=SNMP_VERSION,
            timeout=TIMEOUT,
            retries=RETRIES,
        )

        # Fetch system OIDs
        sys_descr    = _get_oid(session, OID_SYS_DESCR)
        sys_name     = _get_oid(session, OID_SYS_NAME)

        if not sys_descr and not sys_name:
            # Nothing useful from SNMP
            return None

        print(f"[SNMP] {ip} responded — {sys_name or 'no sysName'}")

        # Fetch interface table
        interfaces = _get_interfaces(session, ip)

        return {
            "snmp_description": sys_descr,
            "hostname":         sys_name or None,
            "interfaces":       interfaces,
        }

    except (EasySNMPTimeoutError, EasySNMPConnectionError):
        # Host not running SNMP or unreachable — expected for most hosts
        return None
    except Exception as e:
        print(f"[SNMP] Unexpected error on {ip}: {e}")
        return None


def _get_oid(session: Session, oid: str) -> str | None:
    """
    Fetch a single OID value from an SNMP session.

    Returns:
        String value or None if unavailable.
    """
    try:
        result = session.get(oid)
        value = result.value
        if value and value not in ("NOSUCHOBJECT", "NOSUCHINSTANCE", ""):
            return value.strip()
        return None
    except Exception:
        return None


def _get_interfaces(session: Session, ip: str) -> list[dict]:
    """
    Walk the SNMP interface table to collect MAC addresses
    and interface names for a host.

    Args:
        session:    Active SNMP session.
        ip:         Host IP address (used to build interface record).

    Returns:
        List of interface dicts compatible with InterfaceCreate schema.
    """
    interfaces = []

    try:
        # Walk interface physical addresses
        mac_results = session.walk(OID_IF_PHYS_ADDR)
        name_results = session.walk(OID_IF_DESCR)
        status_results = session.walk(OID_IF_OPER_STATUS)

        # Build index → name and index → status maps
        name_map = {r.oid_index: r.value for r in name_results}
        status_map = {r.oid_index: r.value for r in status_results}

        for item in mac_results:
            mac = _format_mac(item.value)
            if not mac:
                continue

            idx = item.oid_index
            status = status_map.get(idx, "")

            # Only include operationally up interfaces (status == "1")
            if status and status != "1":
                continue

            interface = {
                "mac_address":    mac,
                "ipv4_address":   ip,
                "interface_name": name_map.get(idx),
                "discovered_via": "snmp",
            }
            interfaces.append(interface)

    except Exception as e:
        print(f"[SNMP] Interface walk failed for {ip}: {e}")

    return interfaces


def enrich_assets(assets: list[dict]) -> list[dict]:
    """
    Run SNMP enrichment across a list of assets in place.
    Updates hostname, snmp_description, and interfaces where available.

    Args:
        assets: List of asset dicts from nmap scan.

    Returns:
        The same list with SNMP data merged in where available.
    """
    for asset in assets:
        # Get the primary IP from the first interface
        ifaces = asset.get("interfaces", [])
        if not ifaces:
            continue

        ip = ifaces[0].get("ipv4_address")
        if not ip:
            continue

        snmp_data = enrich_asset(ip)
        if not snmp_data:
            continue

        # Merge SNMP data — don't overwrite existing nmap hostname
        if snmp_data.get("snmp_description"):
            asset["snmp_description"] = snmp_data["snmp_description"]

        if not asset.get("hostname") and snmp_data.get("hostname"):
            asset["hostname"] = snmp_data["hostname"]

        # Merge SNMP interfaces — add any MACs not already found by nmap
        existing_macs = {i["mac_address"] for i in asset["interfaces"] if i.get("mac_address")}
        for iface in snmp_data.get("interfaces", []):
            if iface.get("mac_address") not in existing_macs:
                asset["interfaces"].append(iface)
                existing_macs.add(iface["mac_address"])

    return assets
