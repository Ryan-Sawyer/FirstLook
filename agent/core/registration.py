import socket

import httpx

from .config import AgentConfig


# =============================================================
# Agent Registration
# =============================================================
# Called once on first boot after the install command runs.
# Sends the agent UUID and plain-text token to the control
# server to activate the agent and record its IP address.
# =============================================================


def get_local_ip() -> str | None:
    """
    Attempt to determine the agent's local IP address by
    opening a UDP socket toward the control server.
    No data is actually sent — this just reveals which
    interface the OS would route through.

    Returns:
        Local IP address string, or None if undetermined.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return None


def register(config: AgentConfig) -> bool:
    """
    Register the agent with the control server.
    Sets agent status from 'pending' to 'active' server-side.

    Args:
        config: Loaded AgentConfig instance.

    Returns:
        True if registration succeeded, False otherwise.
    """
    ip = get_local_ip()

    payload = {
        "agent_uuid":   config.agent_uuid,
        "api_token":    config.api_token,
        "ip_address":   ip,
    }

    try:
        response = httpx.post(
            f"{config.server_url}/api/agents/register",
            json=payload,
            timeout=15.0,
        )
        response.raise_for_status()
        print(f"[REGISTER] Agent registered successfully. IP: {ip}")
        return True

    except httpx.HTTPStatusError as e:
        print(f"[REGISTER] Registration failed: {e.response.status_code} {e.response.text}")
        return False

    except httpx.RequestError as e:
        print(f"[REGISTER] Could not reach control server: {e}")
        return False


def send_heartbeat(config: AgentConfig) -> bool:
    """
    Send a heartbeat to the control server to update last_seen_at.

    Args:
        config: Loaded AgentConfig instance.

    Returns:
        True if heartbeat was accepted, False otherwise.
    """
    ip = get_local_ip()

    try:
        response = httpx.post(
            f"{config.server_url}/api/agents/{config.agent_uuid}/heartbeat",
            json={"ip_address": ip},
            headers={"Authorization": f"Bearer {config.api_token}"},
            timeout=10.0,
        )
        response.raise_for_status()
        return True

    except Exception:
        # Heartbeat failure is non-fatal — log and continue
        return False
