import httpx
from typing import Optional
from core.config import get_settings
from db.models import Asset, AssetType, Client


class ITflowNotConfiguredError(Exception):
    pass


class ITflowAPIError(Exception):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


_ASSET_TYPE_MAP: dict[AssetType, str] = {
    AssetType.server:       "Server",
    AssetType.workstation:  "Desktop",
    AssetType.switch:       "Network Device",
    AssetType.router:       "Network Device",
    AssetType.ap:           "Network Device",
    AssetType.printer:      "Printer",
    AssetType.unknown:      "Other",
}


class ITflowClient:

    _TIMEOUT = 10.0

    def __init__(self):
        settings = get_settings()

        if not settings.itflow_url or not settings.itflow_api_key:
            raise ITflowNotConfiguredError(
                "ITFLOW_URL and ITFLOW_API_KEY must be set to use ITflow sync."
            )

        self.base_url = settings.itflow_url.rstrip("/")
        self.api_key  = settings.itflow_api_key

    def _get(self, endpoint: str, params: dict) -> dict:
        """Make a GET request to ITflow API."""
        params["api_key"] = self.api_key
        try:
            response = httpx.get(
                f"{self.base_url}/api/v1/{endpoint}",
                params=params,
                timeout=self._TIMEOUT,
                follow_redirects=True,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise ITflowAPIError(
                f"ITflow GET {endpoint} failed: {e.response.text}",
                status_code=e.response.status_code,
            )
        except httpx.RequestError as e:
            raise ITflowAPIError(f"ITflow connection error: {e}")

    def _post(self, endpoint: str, payload: dict) -> dict:
        """Make a POST request to ITflow API."""
        payload["api_key"] = self.api_key
        try:
            response = httpx.post(
                f"{self.base_url}/api/v1/{endpoint}",
                json=payload,
                timeout=self._TIMEOUT,
                follow_redirects=True,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise ITflowAPIError(
                f"ITflow POST {endpoint} failed: {e.response.text}",
                status_code=e.response.status_code,
            )
        except httpx.RequestError as e:
            raise ITflowAPIError(f"ITflow connection error: {e}")

    # ─────────────────────────────────────────
    # Client Methods
    # ─────────────────────────────────────────

    def get_or_create_client(self, client: Client) -> str:
        existing_id = self._find_client_by_name(client.name)
        if existing_id:
            return existing_id
        return self._create_client(client)

    def _find_client_by_name(self, name: str) -> Optional[str]:
        try:
            data = self._get("clients/read.php", {"client_name": name})
            clients = data.get("data", [])
            if clients:
                return str(clients[0]["client_id"])
            return None
        except ITflowAPIError:
            return None

    def _create_client(self, client: Client) -> str:
        payload = {
            "client_name": client.name,
        }
        if client.contact_name:
            payload["client_main_contact"] = client.contact_name
        if client.contact_email:
            payload["client_main_email"] = client.contact_email
        if client.contact_phone:
            payload["client_main_phone"] = client.contact_phone

        data = self._post("clients/create.php", payload)
        return str(data["data"][0]["insert_id"])

    # ─────────────────────────────────────────
    # Asset Methods
    # ─────────────────────────────────────────

    def push_asset(self, itflow_client_id: str, asset: Asset) -> str:
        primary_ip = None
        primary_mac = None

        if asset.interfaces:
            primary_ip = next(
                (str(i.ipv4_address) for i in asset.interfaces if i.ipv4_address),
                None,
            )
            primary_mac = next(
                (str(i.mac_address) for i in asset.interfaces if i.mac_address),
                None,
            )

        payload = {
            "client_id":    itflow_client_id,
            "asset_name":   asset.hostname or f"Unknown-{str(asset.asset_uuid)[:8]}",
            "asset_type":   _ASSET_TYPE_MAP.get(asset.asset_type, "Other"),
            "asset_status": "Deployed",
        }

        if primary_ip:
            payload["asset_ip"] = primary_ip
        if primary_mac:
            payload["asset_mac"] = primary_mac
        if asset.os_fingerprint:
            payload["asset_os"] = asset.os_fingerprint
        if asset.snmp_description:
            payload["asset_notes"] = f"SNMP: {asset.snmp_description}"

        data = self._post("assets/create.php", payload)
        return str(data["data"][0]["insert_id"])
