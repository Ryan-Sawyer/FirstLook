from typing import Optional

import httpx

from core.config import get_settings
from db.models import Asset, AssetType, Client


# =============================================================
# Exceptions
# =============================================================

class ITflowNotConfiguredError(Exception):
    """Raised when ITflow credentials are missing from settings."""
    pass


class ITflowAPIError(Exception):
    """Raised when the ITflow API returns an unexpected response."""
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


# =============================================================
# Asset Type Mapping
# =============================================================
#
# Maps FirstLook's internal asset types to ITflow's asset type
# identifiers. Update these values if your ITflow instance uses
# custom asset type IDs.
#
# ITflow default asset type IDs (verify against your instance):
#   1  = Desktop/Workstation
#   2  = Laptop
#   3  = Server
#   4  = Network Device (switch, router, AP)
#   5  = Printer
#   6  = Other
#
_ASSET_TYPE_MAP: dict[AssetType, str] = {
    AssetType.server:       "Server",
    AssetType.workstation:  "Workstation",
    AssetType.switch:       "Switch",
    AssetType.router:       "Firewall/Router",
    AssetType.ap:           "Access Point",
    AssetType.printer:      "Printer",
    AssetType.unknown:      "Other",
}

# =============================================================
# ITflow Client
# =============================================================

class ITflowClient:
    """
    Thin HTTP client for the ITflow REST API.

    Handles client and asset creation. Initialised from settings —
    raises ITflowNotConfiguredError if credentials are missing.

    Uses httpx for synchronous HTTP requests. Timeouts are set
    conservatively to avoid hanging the scan results submission
    if ITflow is slow or unreachable.
    """

    _TIMEOUT = 10.0  # seconds

    def __init__(self):
        settings = get_settings()

        if not settings.itflow_url or not settings.itflow_api_key:
            raise ITflowNotConfiguredError(
                "ITFLOW_URL and ITFLOW_API_KEY must be set to use ITflow sync."
            )

        self.base_url = settings.itflow_url.rstrip("/")
        self.api_key  = settings.itflow_api_key
        self.headers  = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        }

    # ─────────────────────────────────────────
    # Client Methods
    # ─────────────────────────────────────────

    def get_or_create_client(self, client: Client) -> str:
        """
        Looks up a client in ITflow by name. Creates it if not found.
        Returns the ITflow client ID as a string.

        Args:
            client: The FirstLook Client model instance.

        Returns:
            ITflow client ID string.

        Raises:
            ITflowAPIError: If the API call fails.
        """
        existing_id = self._find_client_by_name(client.name)
        if existing_id:
            return existing_id

        return self._create_client(client)

    def _find_client_by_name(self, name: str) -> Optional[str]:
        """
        Search ITflow for a client matching the given name.
        Returns the ITflow client ID if found, None otherwise.
        """
        try:
            response = httpx.get(
                f"{self.base_url}/api/v1/clients",
                headers=self.headers,
                params={"name": name},
                timeout=self._TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()

            clients = data.get("data", [])
            for c in clients:
                if c.get("client_name", "").lower() == name.lower():
                    return str(c["client_id"])

            return None

        except httpx.HTTPStatusError as e:
            raise ITflowAPIError(
                f"ITflow client search failed: {e.response.text}",
                status_code=e.response.status_code,
            )
        except httpx.RequestError as e:
            raise ITflowAPIError(f"ITflow connection error: {e}")

    def _create_client(self, client: Client) -> str:
        """
        Create a new client record in ITflow.
        Returns the new ITflow client ID.
        """
        payload = {
            "client_name":  client.name,
            "client_status": "Active",
        }

        if client.contact_name:
            payload["client_main_contact"] = client.contact_name
        if client.contact_email:
            payload["client_main_email"] = client.contact_email
        if client.contact_phone:
            payload["client_main_phone"] = client.contact_phone

        try:
            response = httpx.post(
                f"{self.base_url}/api/v1/clients",
                headers=self.headers,
                json=payload,
                timeout=self._TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()
            return str(data["data"]["client_id"])

        except httpx.HTTPStatusError as e:
            raise ITflowAPIError(
                f"ITflow client creation failed: {e.response.text}",
                status_code=e.response.status_code,
            )
        except httpx.RequestError as e:
            raise ITflowAPIError(f"ITflow connection error: {e}")

    # ─────────────────────────────────────────
    # Asset Methods
    # ─────────────────────────────────────────

    def push_asset(self, itflow_client_id: str, asset: Asset) -> str:
        """
        Push a single asset to ITflow. Creates a new asset record.
        Returns the ITflow asset ID as a string.

        Args:
            itflow_client_id:   The ITflow client ID to associate the asset with.
            asset:              The FirstLook Asset model instance.

        Returns:
            ITflow asset ID string.

        Raises:
            ITflowAPIError: If the API call fails.
        """
        # Resolve primary IP from first interface if available
        primary_ip = None
        if asset.interfaces:
            primary_ip = next(
                (str(i.ipv4_address) for i in asset.interfaces if i.ipv4_address),
                None,
            )

        payload = {
            "asset_clientid":   itflow_client_id,
            "asset_type":       _ASSET_TYPE_MAP.get(asset.asset_type, 6),
            "asset_name":       asset.hostname or f"Unknown-{str(asset.asset_uuid)[:8]}",
            "asset_status":     "Active",
        }

        if primary_ip:
            payload["asset_ip"] = primary_ip

        if asset.os_fingerprint:
            payload["asset_os"] = asset.os_fingerprint

        if asset.snmp_description:
            payload["asset_notes"] = f"SNMP: {asset.snmp_description}"

        try:
            response = httpx.post(
                f"{self.base_url}/api/v1/assets",
                headers=self.headers,
                json=payload,
                timeout=self._TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()
            return str(data["data"]["asset_id"])

        except httpx.HTTPStatusError as e:
            raise ITflowAPIError(
                f"ITflow asset push failed for {asset.asset_uuid}: {e.response.text}",
                status_code=e.response.status_code,
            )
        except httpx.RequestError as e:
            raise ITflowAPIError(f"ITflow connection error: {e}")
