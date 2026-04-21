import subprocess
from typing import Optional


# =============================================================
# LLDP Scanner
# =============================================================
# Uses lldpctl (from the lldpd package) to discover directly
# connected network devices — switches, routers, and APs that
# advertise themselves via the Link Layer Discovery Protocol.
#
# LLDP is passive — it only reports what the device on the
# other end of a cable has broadcast. It is extremely useful
# for mapping the network topology without any active probing.
#
# Requirements:
#   - lldpd must be installed and running on the agent host:
#     apt install lldpd && systemctl enable --now lldpd
#   - The agent must be directly connected (Layer 2) to the
#     devices it wants to discover via LLDP.
#
# lldpctl output format used: -f keyvalue
# =============================================================


def _parse_lldpctl_output(raw: str) -> list[dict]:
    """
    Parse lldpctl -f keyvalue output into a list of neighbour dicts.

    lldpctl keyvalue format example:
        lldp.eth0.via=LLDP
        lldp.eth0.age=0 day, 00:02:13
        lldp.eth0.chassis.name=switch-core-01
        lldp.eth0.chassis.mac=aa:bb:cc:dd:ee:ff
        lldp.eth0.chassis.mgmt-ip=192.168.1.1
        lldp.eth0.chassis.descr=Cisco IOS Software...
        lldp.eth0.port.descr=GigabitEthernet0/1
        lldp.eth0.port.ifname=Gi0/1

    Args:
        raw: Raw lldpctl keyvalue output string.

    Returns:
        List of neighbour dicts.
    """
    neighbours: dict[str, dict] = {}

    for line in raw.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue

        key, _, value = line.partition("=")
        parts = key.split(".")

        # Expect format: lldp.<interface>.<section>.<field>
        if len(parts) < 4 or parts[0] != "lldp":
            continue

        interface = parts[1]
        section   = parts[2]
        field     = ".".join(parts[3:])

        if interface not in neighbours:
            neighbours[interface] = {"local_interface": interface}

        if section == "chassis":
            neighbours[interface][f"chassis_{field.replace('.', '_')}"] = value
        elif section == "port":
            neighbours[interface][f"port_{field.replace('.', '_')}"] = value

    return list(neighbours.values())


def _neighbour_to_asset(neighbour: dict) -> Optional[dict]:
    """
    Convert an LLDP neighbour entry into an AssetCreate-compatible dict.

    Args:
        neighbour: Parsed LLDP neighbour dict.

    Returns:
        Asset dict or None if insufficient data.
    """
    mac = neighbour.get("chassis_mac")
    if not mac:
        return None

    hostname    = neighbour.get("chassis_name")
    description = neighbour.get("chassis_descr")
    mgmt_ip     = neighbour.get("chassis_mgmt-ip") or neighbour.get("chassis_mgmt_ip")

    # Infer asset type from LLDP description
    asset_type = _infer_type_from_lldp(description or "", hostname or "")

    interface = {
        "mac_address":    mac.lower(),
        "ipv4_address":   mgmt_ip,
        "interface_name": neighbour.get("port_ifname") or neighbour.get("port_descr"),
        "discovered_via": "lldp",
    }

    return {
        "hostname":         hostname,
        "asset_type":       asset_type,
        "os_fingerprint":   None,
        "snmp_description": description,
        "interfaces":       [interface],
    }


def _infer_type_from_lldp(description: str, name: str) -> str:
    """
    Attempt to classify device type from LLDP description/name strings.
    """
    combined = (description + " " + name).lower()

    for keyword in ["cisco", "juniper", "aruba", "ubiquiti", "mikrotik",
                    "fortinet", "netgear", "switch", "catalyst"]:
        if keyword in combined:
            return "switch"

    if any(kw in combined for kw in ["access point", "wireless", " ap ", "unifi"]):
        return "ap"

    if any(kw in combined for kw in ["router", "gateway", "firewall", "pfsense", "opnsense"]):
        return "router"

    return "switch"  # Most LLDP-speaking devices are network equipment


def run_lldp_discovery() -> list[dict]:
    """
    Run lldpctl to discover LLDP neighbours and return as asset dicts.

    Returns:
        List of asset dicts for each LLDP neighbour found.
        Empty list if lldpd is not running or no neighbours found.
    """
    try:
        result = subprocess.run(
            ["lldpctl", "-f", "keyvalue"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except FileNotFoundError:
        print("[LLDP] lldpctl not found — install lldpd to enable LLDP discovery")
        return []
    except subprocess.TimeoutExpired:
        print("[LLDP] lldpctl timed out")
        return []
    except Exception as e:
        print(f"[LLDP] Unexpected error: {e}")
        return []

    if result.returncode != 0:
        print(f"[LLDP] lldpctl returned non-zero: {result.stderr.strip()}")
        return []

    if not result.stdout.strip():
        print("[LLDP] No LLDP neighbours found")
        return []

    neighbours = _parse_lldpctl_output(result.stdout)
    assets = []

    for neighbour in neighbours:
        asset = _neighbour_to_asset(neighbour)
        if asset:
            assets.append(asset)
            print(f"[LLDP] Neighbour: {asset.get('hostname') or 'unknown'} "
                  f"({asset['asset_type']}) via {neighbour.get('local_interface')}")

    print(f"[LLDP] Discovery complete. {len(assets)} neighbours found.")
    return assets
