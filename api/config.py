from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    sandbox_api_key: str = Field(..., alias="SANDBOX_API_KEY")
    sandbox_webhook_secret: str = Field(..., alias="SANDBOX_WEBHOOK_SECRET")

    sandbox_cf_access_aud: str | None = Field(default=None, alias="SANDBOX_CF_ACCESS_AUD")
    sandbox_cf_access_certs_url: str | None = Field(
        default=None, alias="SANDBOX_CF_ACCESS_CERTS_URL"
    )

    sandbox_fernet_key: str = Field(..., alias="SANDBOX_FERNET_KEY")

    sandbox_state_db: Path = Field(
        Path("/var/lib/sandboxes/state.db"), alias="SANDBOX_STATE_DB"
    )
    sandbox_compose_dir: Path = Field(
        Path("/var/lib/sandboxes/composes"), alias="SANDBOX_COMPOSE_DIR"
    )
    sandbox_tls_dir: Path = Field(
        Path("/var/lib/sandboxes/tls"), alias="SANDBOX_TLS_DIR"
    )
    sandbox_log_dir: Path = Field(
        Path("/var/log/sandboxes"), alias="SANDBOX_LOG_DIR"
    )

    sandbox_public_host: str = Field(..., alias="SANDBOX_PUBLIC_HOST")
    sandbox_mysql_host: str = Field(..., alias="SANDBOX_MYSQL_HOST")
    sandbox_port_range_start: int = Field(33060, alias="SANDBOX_PORT_RANGE_START")
    sandbox_port_range_end: int = Field(33999, alias="SANDBOX_PORT_RANGE_END")
    sandbox_tunnel_bind_host: str = Field("127.0.0.1", alias="SANDBOX_TUNNEL_BIND_HOST")
    sandbox_working_dir: Path = Field(
        Path("/opt/sqldb-sandbox-setup"), alias="SANDBOX_WORKING_DIR"
    )

    prod_ssh_host: str = Field(..., alias="PROD_SSH_HOST")
    prod_ssh_user: str = Field("sandbox", alias="PROD_SSH_USER")
    prod_ssh_key: Path = Field(
        Path("/home/sandbox/.ssh/sandbox_prod_ed25519"), alias="PROD_SSH_KEY"
    )
    prod_ssh_port: int = Field(22, alias="PROD_SSH_PORT")
    prod_mysql_host: str = Field(..., alias="PROD_MYSQL_HOST")
    prod_mysql_port: int = Field(3306, alias="PROD_MYSQL_PORT")
    prod_mysql_user: str = Field(..., alias="PROD_MYSQL_USER")
    prod_mysql_password: str = Field(..., alias="PROD_MYSQL_PASSWORD")

    sandbox_mysql_image: str = Field("mysql:8.4", alias="SANDBOX_MYSQL_IMAGE")
    sandbox_ttl_min_seconds: int = Field(14400, alias="SANDBOX_TTL_MIN_SECONDS")
    sandbox_ttl_default_seconds: int = Field(21600, alias="SANDBOX_TTL_DEFAULT_SECONDS")
    sandbox_ttl_max_seconds: int = Field(28800, alias="SANDBOX_TTL_MAX_SECONDS")
    sandbox_ttl_reset_add_seconds: int = Field(7200, alias="SANDBOX_TTL_RESET_ADD_SECONDS")
    sandbox_reaper_interval_seconds: int = Field(30, alias="SANDBOX_REAPER_INTERVAL_SECONDS")

    sandbox_test_mode: bool = Field(False, alias="SANDBOX_TEST_MODE")

    @field_validator(
        "sandbox_state_db",
        "sandbox_compose_dir",
        "sandbox_tls_dir",
        "sandbox_log_dir",
        "prod_ssh_key",
    )
    @classmethod
    def _expand_path(cls, v: Path) -> Path:
        return Path(v).expanduser()

    @field_validator("sandbox_port_range_end")
    @classmethod
    def _port_range_order(cls, v: int, info) -> int:
        start = info.data.get("sandbox_port_range_start", 33060)
        if v < start:
            raise ValueError("SANDBOX_PORT_RANGE_END must be >= SANDBOX_PORT_RANGE_START")
        return v

    @field_validator("sandbox_ttl_max_seconds")
    @classmethod
    def _ttl_max_above_default(cls, v: int, info) -> int:
        default = info.data.get("sandbox_ttl_default_seconds", 21600)
        minimum = info.data.get("sandbox_ttl_min_seconds", 14400)
        if v < default:
            raise ValueError("SANDBOX_TTL_MAX_SECONDS must be >= SANDBOX_TTL_DEFAULT_SECONDS")
        if default < minimum:
            raise ValueError("SANDBOX_TTL_DEFAULT_SECONDS must be >= SANDBOX_TTL_MIN_SECONDS")
        return v

    @property
    def port_range(self) -> range:
        return range(self.sandbox_port_range_start, self.sandbox_port_range_end + 1)

    @property
    def cf_access_enabled(self) -> bool:
        return bool(
            self.sandbox_cf_access_aud and self.sandbox_cf_access_certs_url
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


def reset_settings_cache() -> None:
    get_settings.cache_clear()