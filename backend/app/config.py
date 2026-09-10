from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Local overrides are read from backend/.env; secrets must remain in the
    # process environment or dedicated secret files.
    app_name: str = "Aegis"
    database_url: str = "sqlite:///./monitoring.db"
    ping_timeout_seconds: float = Field(default=1.0, ge=0.1, le=10.0)
    monitor_check_workers: int = Field(
        default=32,
        ge=1,
        le=128,
        validation_alias="AEGIS_MONITOR_CHECK_WORKERS",
    )
    monitor_interval_seconds: float = 60.0
    scheduler_enabled: bool = True
    backup_enabled: bool = Field(default=True, validation_alias="AEGIS_BACKUP_ENABLED")
    backup_interval_hours: int = Field(default=24, ge=1, le=720, validation_alias="AEGIS_BACKUP_INTERVAL_HOURS")
    backup_keep_count: int = Field(default=14, ge=1, le=365, validation_alias="AEGIS_BACKUP_KEEP_COUNT")
    backup_directory: str = Field(default="./backups", validation_alias="AEGIS_BACKUP_DIRECTORY")
    report_directory: str = Field(default="./reports", validation_alias="AEGIS_REPORT_DIRECTORY")
    attachment_directory: str = Field(default="./attachments", validation_alias="AEGIS_ATTACHMENT_DIRECTORY")
    foundry_local_url: str | None = Field(default=None, validation_alias="AEGIS_FOUNDRY_LOCAL_URL")
    foundry_local_model: str | None = Field(default=None, validation_alias="AEGIS_FOUNDRY_LOCAL_MODEL")
    history_retention_days: int = Field(default=90, ge=7, le=3650, validation_alias="AEGIS_HISTORY_RETENTION_DAYS")
    allow_public_lan_discovery: bool = Field(
        default=False,
        validation_alias="AEGIS_ALLOW_PUBLIC_LAN_DISCOVERY",
    )
    discovery_ping_workers: int = Field(
        default=64,
        ge=1,
        le=256,
        validation_alias="AEGIS_DISCOVERY_PING_WORKERS",
    )
    discovery_ping_timeout_seconds: float = Field(
        default=0.4,
        ge=0.1,
        le=5.0,
        validation_alias="AEGIS_DISCOVERY_PING_TIMEOUT_SECONDS",
    )
    discovery_mdns_timeout_seconds: float = Field(
        default=2.0,
        ge=0.5,
        le=10.0,
        validation_alias="AEGIS_DISCOVERY_MDNS_TIMEOUT_SECONDS",
    )
    nvd_api_key: SecretStr | None = Field(default=None, validation_alias="NVD_API_KEY")

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
