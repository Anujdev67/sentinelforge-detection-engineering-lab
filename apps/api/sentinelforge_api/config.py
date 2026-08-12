"""Environment-backed API settings with safe local defaults."""

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="SENTINELFORGE_",
        extra="ignore",
        case_sensitive=False,
    )

    env: str = "development"
    demo_mode: bool = False
    database_url: str = "sqlite:///./sentinelforge.db"
    cors_origins: str = "http://localhost:5173"
    api_url: str = "http://localhost:8000"
    log_level: str = Field(default="INFO", pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    live_reputation_enabled: bool = False
    reputation_cache_ttl_minutes: int = Field(default=60, ge=5, le=1440)
    reputation_timeout_seconds: float = Field(default=8.0, ge=1.0, le=20.0)
    virustotal_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None
    greynoise_api_key: SecretStr | None = None

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
