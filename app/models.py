from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(45), index=True)
    mac_address: Mapped[str] = mapped_column(String(17), unique=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255))
    vendor: Mapped[str | None] = mapped_column(String(255))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    is_online: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    notes: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(32), default="unknown", server_default="unknown")
    trust_status: Mapped[str] = mapped_column(String(32), default="unknown", server_default="unknown", index=True)

    traffic_flows: Mapped[list[TrafficFlow]] = relationship(back_populates="device")


class DiscoveryRun(Base):
    __tablename__ = "discovery_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    subnet: Mapped[str] = mapped_column(String(64))
    interface: Mapped[str | None] = mapped_column(String(64))
    devices_found: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="running")
    error: Mapped[str | None] = mapped_column(Text)


class DnsObservation(Base):
    __tablename__ = "dns_observations"
    __table_args__ = (Index("ix_dns_ip_last_seen", "resolved_ip", "last_seen"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    domain: Mapped[str] = mapped_column(String(253), index=True)
    resolved_ip: Mapped[str] = mapped_column(String(45), index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TrafficFlow(Base):
    __tablename__ = "traffic_flows"
    __table_args__ = (
        UniqueConstraint(
            "bucket_start", "source_ip", "destination_ip", "protocol", "destination_port",
            name="uq_traffic_bucket_flow",
        ),
        Index("ix_traffic_device_bucket", "device_id", "bucket_start"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), index=True)
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    destination_ip: Mapped[str] = mapped_column(String(45), index=True)
    destination_domain: Mapped[str | None] = mapped_column(String(253), index=True)
    direction: Mapped[str] = mapped_column(String(16), default="outbound", server_default="outbound", index=True)
    protocol: Mapped[str] = mapped_column(String(16))
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    packet_count: Mapped[int] = mapped_column(Integer, default=1)
    byte_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    device: Mapped[Device | None] = relationship(back_populates="traffic_flows")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(80))
    action: Mapped[str] = mapped_column(String(80), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45))
    success: Mapped[bool] = mapped_column(Boolean)
    detail: Mapped[str | None] = mapped_column(Text)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    alert_type: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(160))
    message: Mapped[str] = mapped_column(Text)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), index=True)
    dedupe_key: Mapped[str] = mapped_column(String(255), unique=True)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, index=True)


class DiagnosticRun(Base):
    __tablename__ = "diagnostic_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(24), default="checking", index=True)
    summary: Mapped[str] = mapped_column(String(255), default="Checking your connection")
    interface: Mapped[str | None] = mapped_column(String(64))
    local_ip: Mapped[str | None] = mapped_column(String(45))
    gateway_ip: Mapped[str | None] = mapped_column(String(45))
    subnet: Mapped[str | None] = mapped_column(String(64))
    gateway_status: Mapped[str] = mapped_column(String(24), default="unknown")
    gateway_latency_ms: Mapped[int | None] = mapped_column(Integer)
    internet_status: Mapped[str] = mapped_column(String(24), default="unknown")
    internet_latency_ms: Mapped[int | None] = mapped_column(Integer)
    dns_status: Mapped[str] = mapped_column(String(24), default="unknown")
    dns_latency_ms: Mapped[int | None] = mapped_column(Integer)
    packet_loss_percent: Mapped[int | None] = mapped_column(Integer)
    recommendations_json: Mapped[str] = mapped_column(Text, default="[]")
    error: Mapped[str | None] = mapped_column(Text)


class SpeedTestRun(Base):
    __tablename__ = "speed_test_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(24), default="running", index=True)
    provider: Mapped[str] = mapped_column(String(80), default="Cloudflare")
    download_mbps: Mapped[float | None] = mapped_column(Float)
    upload_mbps: Mapped[float | None] = mapped_column(Float)
    latency_ms: Mapped[float | None] = mapped_column(Float)
    jitter_ms: Mapped[float | None] = mapped_column(Float)
    bytes_transferred: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)


class RouterHealthSample(Base):
    __tablename__ = "router_health_samples"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    status: Mapped[str] = mapped_column(String(24), default="ok", index=True)
    model: Mapped[str | None] = mapped_column(String(80))
    rx_power_dbm: Mapped[float | None] = mapped_column(Float)
    tx_power_dbm: Mapped[float | None] = mapped_column(Float)
    temperature_c: Mapped[int | None] = mapped_column(Integer)
    cpu_percent: Mapped[int | None] = mapped_column(Integer)
    uptime_seconds: Mapped[int | None] = mapped_column(Integer)
    wan_status: Mapped[str | None] = mapped_column(String(32))
    snapshot_json: Mapped[str] = mapped_column(Text, default="{}")
    findings_json: Mapped[str] = mapped_column(Text, default="[]")
    error: Mapped[str | None] = mapped_column(Text)
