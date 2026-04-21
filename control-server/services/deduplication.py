import uuid
from typing import List

from sqlalchemy.orm import Session

from db.models import Interface
from db.schemas import InterfaceCreate


# =============================================================
# Deduplication Service
# =============================================================
#
# Strategy: MAC address as the primary deduplication anchor.
#
# When an agent submits scan results, each incoming asset carries
# one or more interfaces with MAC addresses. Before creating a new
# asset record we check whether any of those MACs already exist
# in the interfaces table for this client.
#
# If a match is found the asset is considered a duplicate — it was
# already discovered in a previous scan run. We skip creating it
# again rather than building up duplicate records over time.
#
# This means rescanning a client's environment is safe and
# idempotent — you get updated results without polluting the
# asset table with duplicates.
#
# Edge cases handled:
#   - Broadcast/multicast MACs are ignored as dedup anchors
#   - All-zero MACs (00:00:00:00:00:00) are ignored
#   - Virtual/private MACs commonly assigned by hypervisors
#     are flagged but still used if no other MAC is available
# =============================================================


# MACs that should never be used as deduplication anchors
_IGNORED_MACS = {
    "00:00:00:00:00:00",
    "ff:ff:ff:ff:ff:ff",
}

# OUI prefixes commonly assigned by hypervisors to virtual interfaces.
# These are valid MACs but less reliable as unique device identifiers.
_VIRTUAL_OUI_PREFIXES = {
    "00:0c:29",  # VMware
    "00:50:56",  # VMware
    "00:15:5d",  # Hyper-V
    "52:54:00",  # QEMU/KVM
    "08:00:27",  # VirtualBox
}


def normalise_mac(mac: str) -> str:
    """
    Normalise a MAC address to lowercase colon-separated format.
    Handles input formats: aa:bb:cc:dd:ee:ff, AA-BB-CC-DD-EE-FF,
    aabbccddeeff, AA:BB:CC:DD:EE:FF.

    Args:
        mac: Raw MAC address string.

    Returns:
        Normalised MAC in aa:bb:cc:dd:ee:ff format.
    """
    # Strip separators and lowercase
    clean = mac.replace(":", "").replace("-", "").replace(".", "").lower()

    if len(clean) != 12:
        raise ValueError(f"Invalid MAC address: {mac!r}")

    return ":".join(clean[i:i+2] for i in range(0, 12, 2))


def is_ignored_mac(mac: str) -> bool:
    """
    Returns True if the MAC should be skipped as a dedup anchor.

    Args:
        mac: Normalised MAC address string.

    Returns:
        True if the MAC is broadcast, multicast, or all-zero.
    """
    if mac in _IGNORED_MACS:
        return True

    # Multicast bit — least significant bit of first octet is 1
    first_octet = int(mac.split(":")[0], 16)
    if first_octet & 0x01:
        return True

    return False


def is_virtual_mac(mac: str) -> bool:
    """
    Returns True if the MAC belongs to a known hypervisor OUI.
    Virtual MACs are still used for dedup but flagged as less reliable.

    Args:
        mac: Normalised MAC address string.

    Returns:
        True if the MAC matches a known virtual OUI prefix.
    """
    oui = mac[:8]  # First three octets e.g. "00:0c:29"
    return oui in _VIRTUAL_OUI_PREFIXES


def get_dedup_macs(interfaces: List[InterfaceCreate]) -> List[str]:
    """
    Extract the usable deduplication MACs from a list of interfaces.
    Ignores broadcast, multicast, and all-zero MACs.
    Prefers physical MACs over virtual ones where both are present.

    Args:
        interfaces: List of InterfaceCreate objects from the scan payload.

    Returns:
        List of normalised MAC strings suitable for dedup lookup.
        Empty list if no usable MACs are found.
    """
    physical_macs = []
    virtual_macs = []

    for iface in interfaces:
        try:
            mac = normalise_mac(iface.mac_address)
        except ValueError:
            continue

        if is_ignored_mac(mac):
            continue

        if is_virtual_mac(mac):
            virtual_macs.append(mac)
        else:
            physical_macs.append(mac)

    # Prefer physical MACs — fall back to virtual if that's all we have
    return physical_macs if physical_macs else virtual_macs


def deduplicate_assets(
    db: Session,
    client_uuid: uuid.UUID,
    interfaces: List[InterfaceCreate],
) -> bool:
    """
    Check whether an incoming asset is a duplicate of one already
    recorded for this client, based on MAC address matching.

    Args:
        db:             Active database session.
        client_uuid:    The client this asset belongs to.
        interfaces:     The interfaces discovered on the asset.

    Returns:
        True if the asset is a duplicate and should be skipped.
        False if the asset is new and should be created.
    """
    dedup_macs = get_dedup_macs(interfaces)

    if not dedup_macs:
        # No usable MACs — cannot deduplicate. Treat as new asset.
        # This avoids silently dropping assets from devices that
        # don't expose a MAC (rare but possible with some SNMP responses).
        return False

    existing = db.query(Interface).filter(
        Interface.client_uuid == client_uuid,
        Interface.mac_address.in_(dedup_macs),
    ).first()

    return existing is not None


def find_existing_asset_uuid(
    db: Session,
    client_uuid: uuid.UUID,
    interfaces: List[InterfaceCreate],
) -> uuid.UUID | None:
    """
    Returns the asset_uuid of an existing asset that matches one of
    the incoming MACs, or None if no match is found.

    Useful when you want to update an existing asset rather than
    skip it entirely — for example, refreshing a hostname or
    OS fingerprint discovered in a deeper scan.

    Args:
        db:             Active database session.
        client_uuid:    The client this asset belongs to.
        interfaces:     The interfaces discovered on the asset.

    Returns:
        asset_uuid if a matching asset exists, None otherwise.
    """
    dedup_macs = get_dedup_macs(interfaces)

    if not dedup_macs:
        return None

    existing = db.query(Interface).filter(
        Interface.client_uuid == client_uuid,
        Interface.mac_address.in_(dedup_macs),
    ).first()

    return existing.asset_uuid if existing else None
