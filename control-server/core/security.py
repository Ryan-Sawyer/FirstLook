import hashlib
import secrets


# =============================================================
# Agent Token Helpers
# =============================================================

TOKEN_BYTES = 32  # 32 bytes = 256-bit token


def generate_agent_token() -> str:
    """
    Generate a cryptographically secure plain-text token.
    Returned once at agent prep time and never stored plain.

    Returns:
        A URL-safe base64 token string.
    """
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(plain_token: str) -> str:
    """
    Hash a plain-text token for safe storage.
    Uses SHA-256 — fast enough for single-use token verification
    and sufficient for non-password secret material.

    Args:
        plain_token: The plain-text token to hash.

    Returns:
        A hex-encoded SHA-256 digest.
    """
    return hashlib.sha256(plain_token.encode()).hexdigest()


def verify_token(plain_token: str, hashed_token: str) -> bool:
    """
    Compare a plain-text token against a stored hash.
    Uses hmac.compare_digest via secrets.compare_digest to
    prevent timing attacks.

    Args:
        plain_token:    The plain-text token from the agent request.
        hashed_token:   The stored hash from the database.

    Returns:
        True if the token matches, False otherwise.
    """
    candidate_hash = hash_token(plain_token)
    return secrets.compare_digest(candidate_hash, hashed_token)


def generate_install_command(base_url: str, agent_uuid: str, plain_token: str) -> str:
    """
    Build the one-liner install command shown on the agent prep page.
    The agent uses this to register itself with the control server.

    Args:
        base_url:       The control server's public base URL.
        agent_uuid:     The UUID assigned to the new agent.
        plain_token:    The plain-text token issued at prep time.

    Returns:
        A curl one-liner the MSP tech can paste into the target Linux box.
    """
    return (
        f"curl -sSL {base_url}/agent/install.sh | "
        f"sudo bash -s -- --server {base_url} --agent-id {agent_uuid} --token {plain_token}"
    )
