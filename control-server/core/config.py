from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    All values can be overridden via the .env file.
    """

    # ─────────────────────────────────────────
    # Database
    # ─────────────────────────────────────────
    database_url: str

    # ─────────────────────────────────────────
    # Security
    # ─────────────────────────────────────────
    # Generate with: python -c "import secrets; print(secrets.token_hex(32))"
    secret_key: str

    # ─────────────────────────────────────────
    # Control Server
    # ─────────────────────────────────────────
    # Publicly accessible base URL — used to generate agent install commands
    firstlook_base_url: str = "http://localhost:8000"

    # ─────────────────────────────────────────
    # ITflow Integration (optional)
    # ─────────────────────────────────────────
    itflow_url:     Optional[str] = None
    itflow_api_key: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )


@lru_cache
def get_settings() -> Settings:
    """
    Returns a cached Settings instance.
    Using lru_cache means the .env file is only read once
    at startup rather than on every request.
    """
    return Settings()
