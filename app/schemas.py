from __future__ import annotations

from datetime import datetime, timezone

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip_address: str
    mac_address: str
    hostname: str | None
    vendor: str | None
    first_seen: datetime
    last_seen: datetime
    is_online: bool
    notes: str | None
    category: str
    trust_status: str

    @field_serializer("first_seen", "last_seen")
    def serialize_utc(self, value: datetime) -> datetime:
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


class DeviceUpdate(BaseModel):
    hostname: str | None = Field(default=None, max_length=255)
    notes: str | None = Field(default=None, max_length=2000)
    category: Literal["unknown", "computer", "phone", "tablet", "iot", "media", "network", "server"] | None = None
    trust_status: Literal["unknown", "trusted", "guest", "review", "blocked"] | None = None


class TrafficFlowOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    bucket_start: datetime
    source_ip: str
    destination_ip: str
    destination_domain: str | None
    direction: str
    protocol: str
    destination_port: int | None
    packet_count: int
    byte_count: int

    @field_serializer("bucket_start")
    def serialize_utc(self, value: datetime) -> datetime:
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)


class SetupRequest(BaseModel):
    username: str = Field(default="admin", min_length=1, max_length=80)
    password: str = Field(min_length=12, max_length=256)


class RebootRequest(BaseModel):
    confirmation: str
