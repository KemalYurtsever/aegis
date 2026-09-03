from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Local overrides are read from backend/.env; secrets must remain in the
    # process environment or dedicated secret files.
    app_name: str = "LIIMS"
    database_url: str = "sqlite:///./monitoring.db"
    ping_timeout_seconds: float = 2.0
    monitor_interval_seconds: float = 60.0
    scheduler_enabled: bool = True
    backup_enabled: bool = Field(default=True, validation_alias="LIIMS_BACKUP_ENABLED")
    backup_interval_hours: int = Field(default=24, ge=1, le=720, validation_alias="LIIMS_BACKUP_INTERVAL_HOURS")
    backup_keep_count: int = Field(default=14, ge=1, le=365, validation_alias="LIIMS_BACKUP_KEEP_COUNT")
    backup_directory: str = Field(default="./backups", validation_alias="LIIMS_BACKUP_DIRECTORY")
    report_directory: str = Field(default="./reports", validation_alias="LIIMS_REPORT_DIRECTORY")
    attachment_directory: str = Field(default="./attachments", validation_alias="LIIMS_ATTACHMENT_DIRECTORY")
    foundry_local_url: str | None = Field(default=None, validation_alias="LIIMS_FOUNDRY_LOCAL_URL")
    foundry_local_model: str | None = Field(default=None, validation_alias="LIIMS_FOUNDRY_LOCAL_MODEL")
    history_retention_days: int = Field(default=90, ge=7, le=3650, validation_alias="LIIMS_HISTORY_RETENTION_DAYS")
    allow_public_lan_discovery: bool = Field(
        default=False,
        validation_alias="LIIMS_ALLOW_PUBLIC_LAN_DISCOVERY",
    )
    authorized_lab_mode: bool = Field(
        default=False,
        validation_alias="LIIMS_AUTHORIZED_LAB_MODE",
    )
    discovery_arp_packets_per_second: int = Field(
        default=20,
        ge=1,
        le=100,
        validation_alias="LIIMS_DISCOVERY_ARP_PACKETS_PER_SECOND",
    )

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
