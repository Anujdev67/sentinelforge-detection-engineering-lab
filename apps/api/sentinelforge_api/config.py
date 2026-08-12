"""Environment-backed API settings with safe local defaults."""

import re
from functools import lru_cache
from urllib.parse import urlsplit

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

_HOST_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?|[a-zA-Z0-9])$"
)
_LOCAL_HTTP_HOSTS = {"localhost", "127.0.0.1", "::1"}


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
    allowed_hosts: str = "localhost,127.0.0.1,api,testserver"
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
        origins = [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]
        if not origins:
            raise ValueError("At least one explicit CORS origin is required.")
        for origin in origins:
            parsed = urlsplit(origin)
            if (
                origin == "*"
                or parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(f"Unsafe CORS origin: {origin!r}")
            if parsed.scheme == "http" and parsed.hostname not in _LOCAL_HTTP_HOSTS:
                raise ValueError("Non-loopback CORS origins must use HTTPS.")
        return origins

    @property
    def allowed_host_list(self) -> list[str]:
        hosts = [host.strip() for host in self.allowed_hosts.split(",") if host.strip()]
        if not hosts or any(host == "*" or not _HOST_PATTERN.fullmatch(host) for host in hosts):
            raise ValueError("Allowed hosts must be explicit hostnames or IP addresses.")
        return hosts


@lru_cache
def get_settings() -> Settings:
    return Settings()
