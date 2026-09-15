from __future__ import annotations

from functools import lru_cache
from ipaddress import IPv4Network
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="HNM_", extra="ignore", case_sensitive=False
    )

    app_name: str = "Home Network Monitor"
    environment: Literal["development", "test", "production"] = "development"
    secret_key: str = Field(default="development-only-change-me", min_length=16)
    admin_username: str = "admin"
    admin_password: str | None = None
    database_url: str = "sqlite:///./home_net_monitor.db"
    session_cookie_name: str = "hnm_session"
    session_lifetime_seconds: int = 43_200
    session_https_only: bool = False

    network_interface: str | None = None
    subnet: str | None = None
    discovery_interval_seconds: int = Field(default=300, ge=30)
    device_offline_after_seconds: int = Field(default=600, ge=60)
    discovery_enabled: bool = True
    traffic_capture_enabled: bool = False
    capture_bpf_filter: str = "ip or ip6"
    traffic_retention_days: int = Field(default=30, ge=1, le=3650)
    dns_retention_days: int = Field(default=7, ge=1, le=365)
    diagnostics_enabled: bool = True
    diagnostics_interval_seconds: int = Field(default=300, ge=60)
    diagnostic_hostname: str = "example.com"
    visibility_mode: Literal["auto", "computer", "gateway", "mirror"] = "auto"
    speedtest_enabled: bool = True
    speedtest_scheduled: bool = False
    speedtest_interval_seconds: int = Field(default=21_600, ge=900)
    speedtest_download_url: str = "https://speed.cloudflare.com/__down"
    speedtest_upload_url: str = "https://speed.cloudflare.com/__up"
    speedtest_download_bytes: int = Field(default=10_000_000, ge=100_000, le=100_000_000)
    speedtest_upload_bytes: int = Field(default=2_000_000, ge=100_000, le=25_000_000)

    router_adapter: Literal["disabled", "ssh", "http"] = "disabled"
    router_host: str = "192.168.1.1"
    router_port: int = Field(default=22, ge=1, le=65535)
    router_username: str | None = None
    router_password: str | None = None
    router_ssh_key_path: Path | None = None
    router_status_command: str = "uptime"
    router_reboot_command: str = "sudo /sbin/reboot"
    router_http_status_url: str | None = None
    router_http_reboot_url: str | None = None
    router_http_bearer_token: str | None = None
    router_verify_tls: bool = True

    login_rate_limit: int = Field(default=5, ge=1)
    login_rate_window_seconds: int = Field(default=300, ge=30)
    reboot_rate_limit: int = Field(default=1, ge=1)
    reboot_rate_window_seconds: int = Field(default=300, ge=30)
    speedtest_rate_limit: int = Field(default=2, ge=1)
    speedtest_rate_window_seconds: int = Field(default=300, ge=30)

    @field_validator("subnet")
    @classmethod
    def validate_subnet(cls, value: str | None) -> str | None:
        if value:
            IPv4Network(value, strict=False)
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
