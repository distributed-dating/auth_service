"""Application settings (infrastructure layer)."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class PyJwtSettings(BaseSettings):
    """Service settings loaded from environment."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    secret_key: str
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 7
    algorithm: str = "HS256"
