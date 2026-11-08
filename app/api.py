from __future__ import annotations

import json
import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import case, desc, func, select, update
from sqlalchemy.orm import Session

from app.audit import record_audit
from app.config import Settings, get_settings
from app.database import get_db
from app.models import (
    Alert,
    AuditEvent,
    Device,
    DiagnosticRun,
    DiscoveryRun,
    RouterHealthSample,
    SpeedTestRun,
    TrafficFlow,
    User,
)
from app.schemas import DeviceOut, DeviceUpdate, LoginRequest, RebootRequest, SetupRequest, TrafficFlowOut
from app.security import (
    RateLimitRule,
    create_session_token,
    get_current_user,
    rate_limiter,
    require_csrf,
    hash_password,
    verify_password,
)
from app.services.discovery import DiscoveryService
from app.services.diagnostics import NetworkDiagnosticsService
from app.services.enrichment import classify_destination
from app.services.network import detect_network
from app.services.router_health import RouterHealthService
from app.services.speedtest import SpeedTestService

router = APIRouter(prefix="/api")


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def as_utc(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def diagnostic_dict(run: DiagnosticRun) -> dict:
    try:
        recommendations = json.loads(run.recommendations_json)
    except (TypeError, json.JSONDecodeError):
        recommendations = []
    return {
        "id": run.id,
        "created_at": as_utc(run.created_at),
        "completed_at": as_utc(run.completed_at),
        "status": run.status,
        "summary": run.summary,
        "network": {
            "interface": run.interface,
            "local_ip": run.local_ip,
            "gateway_ip": run.gateway_ip,
            "subnet": run.subnet,
        },
        "checks": {
            "router": {"status": run.gateway_status, "latency_ms": run.gateway_latency_ms, "packet_loss_percent": run.packet_loss_percent},
            "internet": {"status": run.internet_status, "latency_ms": run.internet_latency_ms},
            "dns": {"status": run.dns_status, "latency_ms": run.dns_latency_ms},
        },
        "recommendations": recommendations,
        "error": run.error,
    }


def speedtest_dict(run: SpeedTestRun) -> dict:
    return {
        "id": run.id,
        "created_at": as_utc(run.created_at),
        "completed_at": as_utc(run.completed_at),
        "status": run.status,
        "provider": run.provider,
        "download_mbps": run.download_mbps,
        "upload_mbps": run.upload_mbps,
        "latency_ms": run.latency_ms,
        "jitter_ms": run.jitter_ms,
        "bytes_transferred": run.bytes_transferred,
        "error": run.error,
    }


@router.get("/auth/setup-status")
def setup_status(db: Session = Depends(get_db)):
    return {"required": (db.scalar(select(func.count(User.id))) or 0) == 0}


@router.post("/auth/setup")
def first_run_setup(
    payload: SetupRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    source = client_ip(request)
    try:
        is_loopback = ipaddress.ip_address(source).is_loopback
    except ValueError:
        is_loopback = False
    if not is_loopback:
        raise HTTPException(status_code=403, detail="First-time setup must be completed on this computer")
    rate_limiter.check(f"setup:{source}", RateLimitRule(5, 300))
    if (db.scalar(select(func.count(User.id))) or 0) != 0:
        raise HTTPException(status_code=409, detail="NetScope is already configured")
    user = User(username=payload.username, password_hash=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    token, csrf = create_session_token(user, settings)
    response.set_cookie(
        settings.session_cookie_name,
        token,
        httponly=True,
        secure=settings.session_https_only,
        samesite="strict",
        max_age=settings.session_lifetime_seconds,
        path="/",
    )
    record_audit(db, actor=user.username, action="first_run.setup", source_ip=source, success=True)
    return {"username": user.username, "csrf_token": csrf}


@router.post("/auth/login")
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    source = client_ip(request)
    rate_limiter.check(
        f"login:{source}", RateLimitRule(settings.login_rate_limit, settings.login_rate_window_seconds)
    )
    user = db.scalar(select(User).where(User.username == payload.username))
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        record_audit(db, actor=payload.username, action="login", source_ip=source, success=False)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token, csrf = create_session_token(user, settings)
    response.set_cookie(
        settings.session_cookie_name,
        token,
        httponly=True,
        secure=settings.session_https_only,
        samesite="strict",
        max_age=settings.session_lifetime_seconds,
        path="/",
    )
    record_audit(db, actor=user.username, action="login", source_ip=source, success=True)
    return {"username": user.username, "csrf_token": csrf}


@router.post("/auth/logout", dependencies=[Depends(require_csrf)])
def logout(
    request: Request,
    response: Response,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    response.delete_cookie(settings.session_cookie_name, path="/")
    record_audit(db, actor=user.username, action="logout", source_ip=client_ip(request), success=True)
    return {"ok": True}


@router.get("/auth/me")
def me(request: Request, user: User = Depends(get_current_user), settings: Settings = Depends(get_settings)):
    from app.security import _decode

    payload = _decode(request.cookies[settings.session_cookie_name], settings.secret_key)
    return {"username": user.username, "csrf_token": payload["csrf"]}


@router.get("/overview")
def overview(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    total = db.scalar(select(func.count(Device.id))) or 0
    online = db.scalar(select(func.count(Device.id)).where(Device.is_online.is_(True))) or 0
    packets, byte_count, upload_bytes, download_bytes = db.execute(
        select(
            func.coalesce(func.sum(TrafficFlow.packet_count), 0),
            func.coalesce(func.sum(TrafficFlow.byte_count), 0),
            func.coalesce(func.sum(case((TrafficFlow.direction == "outbound", TrafficFlow.byte_count), else_=0)), 0),
            func.coalesce(func.sum(case((TrafficFlow.direction == "inbound", TrafficFlow.byte_count), else_=0)), 0),
        ).where(TrafficFlow.bucket_start >= since)
    ).one()
    new_devices = db.scalar(select(func.count(Device.id)).where(Device.first_seen >= since)) or 0
    unread_alerts = db.scalar(select(func.count(Alert.id)).where(Alert.is_read.is_(False))) or 0
    last_run = db.scalar(select(DiscoveryRun).order_by(DiscoveryRun.started_at.desc()).limit(1))
    return {
        "devices_total": total,
        "devices_online": online,
        "packets_24h": packets,
        "bytes_24h": byte_count,
        "upload_bytes_24h": upload_bytes,
        "download_bytes_24h": download_bytes,
        "new_devices_24h": new_devices,
        "unread_alerts": unread_alerts,
        "last_discovery": as_utc(last_run.started_at) if last_run else None,
        "last_discovery_status": last_run.status if last_run else "never",
    }


@router.get("/system/status")
def system_status(
    request: Request,
    settings: Settings = Depends(get_settings),
    _: User = Depends(get_current_user),
):
    collector = request.app.state.traffic_collector
    context = detect_network(settings.subnet, settings.network_interface)
    configured_mode = settings.visibility_mode
    if collector.state != "running":
        visibility = "discovery_only"
        visibility_label = "Devices only"
        visibility_detail = "NetScope can find nearby devices, but traffic capture is unavailable."
    elif configured_mode in {"gateway", "mirror"}:
        visibility = "whole_network"
        visibility_label = "Whole network"
        visibility_detail = "Capture is configured at a gateway or mirrored network point."
    else:
        visibility = "this_device"
        visibility_label = "This computer"
        visibility_detail = "Traffic totals mostly describe this computer; device discovery still covers the local network."
    return {
        "traffic_capture": collector.state,
        "traffic_capture_error": collector.error,
        "discovery_scheduler": "running" if request.app.state.scheduler.running else "stopped",
        "visibility": visibility,
        "visibility_label": visibility_label,
        "visibility_detail": visibility_detail,
        "network": {
            "interface": context.interface,
            "local_ip": context.local_ip,
            "gateway_ip": context.gateway_ip,
            "subnet": context.subnet,
        },
        "speedtest": "available" if settings.speedtest_enabled else "disabled",
    }


@router.get("/diagnostics/latest")
def latest_diagnostic(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    run = db.scalar(select(DiagnosticRun).order_by(DiagnosticRun.created_at.desc()).limit(1))
    return diagnostic_dict(run) if run else None


@router.get("/diagnostics/history")
def diagnostic_history(
    limit: int = Query(default=24, ge=1, le=200),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    runs = db.scalars(select(DiagnosticRun).order_by(DiagnosticRun.created_at.desc()).limit(limit))
    return [diagnostic_dict(run) for run in runs]


@router.get("/diagnostics/uptime")
def diagnostic_uptime(
    hours: int = Query(default=168, ge=1, le=720),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    runs = list(
        db.scalars(
            select(DiagnosticRun)
            .where(DiagnosticRun.created_at >= since, DiagnosticRun.completed_at.is_not(None))
            .order_by(DiagnosticRun.created_at)
        )
    )
    successful = [run for run in runs if run.internet_status == "ok"]
    outages = 0
    in_outage = False
    for run in runs:
        failed = run.internet_status == "failed"
        if failed and not in_outage:
            outages += 1
        in_outage = failed
    latencies = [run.internet_latency_ms for run in successful if run.internet_latency_ms is not None]
    losses = [run.packet_loss_percent for run in runs if run.packet_loss_percent is not None]
    return {
        "hours": hours,
        "sample_count": len(runs),
        "availability_percent": round(len(successful) / len(runs) * 100, 2) if runs else None,
        "outage_count": outages,
        "average_latency_ms": round(sum(latencies) / len(latencies)) if latencies else None,
        "maximum_packet_loss_percent": max(losses) if losses else None,
        "current_status": runs[-1].internet_status if runs else "unknown",
    }


@router.post("/diagnostics/run", dependencies=[Depends(require_csrf)])
def run_diagnostic(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
):
    rate_limiter.check("diagnostics:global", RateLimitRule(2, 30))
    try:
        run_id = NetworkDiagnosticsService(settings).run()
    except Exception as exc:
        record_audit(db, actor=user.username, action="diagnostics.run", source_ip=client_ip(request), success=False, detail=str(exc)[:500])
        raise HTTPException(status_code=502, detail="The connection check could not finish") from exc
    run = db.get(DiagnosticRun, run_id)
    record_audit(db, actor=user.username, action="diagnostics.run", source_ip=client_ip(request), success=True)
    return diagnostic_dict(run)


@router.get("/speedtest/latest")
def latest_speedtest(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    run = db.scalar(
        select(SpeedTestRun)
        .where(SpeedTestRun.status == "completed")
        .order_by(SpeedTestRun.created_at.desc())
        .limit(1)
    )
    return speedtest_dict(run) if run else None


@router.get("/speedtest/history")
def speedtest_history(
    limit: int = Query(default=48, ge=1, le=500),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    runs = db.scalars(
        select(SpeedTestRun)
        .where(SpeedTestRun.status == "completed")
        .order_by(SpeedTestRun.created_at.desc())
        .limit(limit)
    )
    return [speedtest_dict(run) for run in runs]


@router.post("/speedtest/run", dependencies=[Depends(require_csrf)])
def run_speedtest(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
):
    if not settings.speedtest_enabled:
        raise HTTPException(status_code=409, detail="Speed testing is disabled")
    rate_limiter.check(
        f"speedtest:{user.id}",
        RateLimitRule(settings.speedtest_rate_limit, settings.speedtest_rate_window_seconds),
    )
    try:
        run_id = SpeedTestService(settings).run()
    except Exception as exc:
        record_audit(db, actor=user.username, action="speedtest.run", source_ip=client_ip(request), success=False, detail=str(exc)[:500])
        raise HTTPException(status_code=502, detail="Internet speed test failed") from exc
    run = db.get(SpeedTestRun, run_id)
    record_audit(
        db,
        actor=user.username,
        action="speedtest.run",
        source_ip=client_ip(request),
        success=True,
        detail=f"download={run.download_mbps}; upload={run.upload_mbps}; latency={run.latency_ms}",
    )
    return speedtest_dict(run)


@router.get("/analytics/household")
def household_analytics(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    now = datetime.now(timezone.utc)
    current_start = now - timedelta(hours=24)
    previous_start = current_start - timedelta(hours=24)
    current_bytes = db.scalar(select(func.coalesce(func.sum(TrafficFlow.byte_count), 0)).where(TrafficFlow.bucket_start >= current_start)) or 0
    previous_bytes = db.scalar(
        select(func.coalesce(func.sum(TrafficFlow.byte_count), 0)).where(
            TrafficFlow.bucket_start >= previous_start, TrafficFlow.bucket_start < current_start
        )
    ) or 0
    change_percent = None if not previous_bytes else round((current_bytes - previous_bytes) / previous_bytes * 100)
    category_rows = db.execute(select(Device.category, func.count(Device.id)).group_by(Device.category))
    trust_rows = db.execute(select(Device.trust_status, func.count(Device.id)).group_by(Device.trust_status))
    flows = db.execute(
        select(TrafficFlow.bucket_start, TrafficFlow.byte_count).where(TrafficFlow.bucket_start >= now - timedelta(days=7))
    )
    hourly: dict[int, int] = defaultdict(int)
    for bucket, byte_count in flows:
        hourly[as_utc(bucket).hour] += byte_count
    peak_hour = max(hourly, key=hourly.get) if hourly else None
    trusted = db.scalar(select(func.count(Device.id)).where(Device.trust_status.in_(["trusted", "guest"]))) or 0
    total = db.scalar(select(func.count(Device.id))) or 0
    return {
        "category_breakdown": {category or "unknown": count for category, count in category_rows},
        "trust_breakdown": {trust or "unknown": count for trust, count in trust_rows},
        "recognized_devices": trusted,
        "total_devices": total,
        "recognized_percent": round(trusted / total * 100) if total else 100,
        "traffic_bytes_24h": current_bytes,
        "traffic_change_percent": change_percent,
        "peak_hour": peak_hour,
        "new_devices_7d": db.scalar(select(func.count(Device.id)).where(Device.first_seen >= now - timedelta(days=7))) or 0,
    }


@router.get("/activity")
def activity_feed(
    limit: int = Query(default=30, ge=1, le=100),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    items: list[dict] = []
    alerts = db.execute(
        select(Alert, Device.hostname, Device.ip_address)
        .outerjoin(Device, Alert.device_id == Device.id)
        .order_by(Alert.last_seen.desc())
        .limit(limit)
    )
    for alert, hostname, ip_address in alerts:
        items.append({
            "type": alert.alert_type,
            "severity": alert.severity,
            "title": alert.title,
            "detail": alert.message,
            "device_name": hostname or ip_address,
            "created_at": as_utc(alert.last_seen),
        })
    discoveries = db.scalars(select(DiscoveryRun).order_by(DiscoveryRun.started_at.desc()).limit(10))
    for run in discoveries:
        items.append({
            "type": "scan",
            "severity": "info" if run.status == "completed" else "warning",
            "title": "Network scan completed" if run.status == "completed" else "Network scan failed",
            "detail": f"Found {run.devices_found} devices on {run.subnet}." if run.status == "completed" else "The device scan did not finish.",
            "device_name": None,
            "created_at": as_utc(run.completed_at or run.started_at),
        })
    return sorted(items, key=lambda item: item["created_at"], reverse=True)[:limit]


@router.post("/discovery/scan", dependencies=[Depends(require_csrf)])
def run_discovery(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
):
    source = client_ip(request)
    rate_limiter.check("discovery:global", RateLimitRule(1, 15))
    try:
        count = DiscoveryService(settings).run()
    except Exception as exc:
        record_audit(
            db, actor=user.username, action="discovery.scan", source_ip=source, success=False,
            detail=str(exc)[:500],
        )
        raise HTTPException(status_code=502, detail="Network discovery failed; see audit log") from exc
    record_audit(
        db, actor=user.username, action="discovery.scan", source_ip=source, success=True,
        detail=f"devices_found={count}",
    )
    return {"devices_found": count}


@router.get("/devices", response_model=list[DeviceOut])
def devices(
    online: bool | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    query = select(Device).order_by(desc(Device.is_online), Device.hostname, Device.ip_address)
    if online is not None:
        query = query.where(Device.is_online == online)
    return list(db.scalars(query))


@router.patch("/devices/{device_id}", response_model=DeviceOut, dependencies=[Depends(require_csrf)])
def update_device(
    device_id: int,
    payload: DeviceUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    changes = payload.model_dump(exclude_unset=True)
    for field in ("category", "trust_status"):
        if changes.get(field) is None:
            changes.pop(field, None)
    for key, value in changes.items():
        setattr(device, key, value)
    db.commit()
    db.refresh(device)
    record_audit(
        db, actor=user.username, action="device.update", source_ip=client_ip(request), success=True,
        detail=f"device_id={device_id}; fields={','.join(changes)}",
    )
    return device


@router.get("/devices/{device_id}/detail")
def device_detail(
    device_id: int,
    hours: int = Query(default=24, ge=1, le=720),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    totals = db.execute(
        select(
            func.coalesce(func.sum(TrafficFlow.byte_count), 0).label("bytes"),
            func.coalesce(func.sum(TrafficFlow.packet_count), 0).label("packets"),
            func.count(func.distinct(TrafficFlow.destination_ip)).label("destinations"),
            func.coalesce(func.sum(case((TrafficFlow.direction == "outbound", TrafficFlow.byte_count), else_=0)), 0).label("upload_bytes"),
            func.coalesce(func.sum(case((TrafficFlow.direction == "inbound", TrafficFlow.byte_count), else_=0)), 0).label("download_bytes"),
        ).where(TrafficFlow.device_id == device_id, TrafficFlow.bucket_start >= since)
    ).one()
    return {
        "device": DeviceOut.model_validate(device),
        "traffic": dict(totals._mapping),
    }


@router.get("/devices/{device_id}/traffic", response_model=list[TrafficFlowOut])
def device_traffic(
    device_id: int,
    hours: int = Query(default=24, ge=1, le=720),
    limit: int = Query(default=200, ge=1, le=1000),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    if db.get(Device, device_id) is None:
        raise HTTPException(status_code=404, detail="Device not found")
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    return list(
        db.scalars(
            select(TrafficFlow)
            .where(TrafficFlow.device_id == device_id, TrafficFlow.bucket_start >= since)
            .order_by(TrafficFlow.bucket_start.desc())
            .limit(limit)
        )
    )


@router.get("/traffic/top-destinations")
def top_destinations(
    hours: int = Query(default=24, ge=1, le=720),
    limit: int = Query(default=10, ge=1, le=100),
    device_id: int | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    destination = func.coalesce(TrafficFlow.destination_domain, TrafficFlow.destination_ip).label("destination")
    query = (
        select(
            destination,
            func.sum(TrafficFlow.packet_count).label("packets"),
            func.sum(TrafficFlow.byte_count).label("bytes"),
        )
        .where(TrafficFlow.bucket_start >= since)
        .where(TrafficFlow.direction == "outbound")
        .group_by(destination)
        .order_by(func.sum(TrafficFlow.byte_count).desc())
        .limit(limit)
    )
    if device_id is not None:
        query = query.where(TrafficFlow.device_id == device_id)
    results = []
    for row in db.execute(query):
        item = dict(row._mapping)
        organization, category = classify_destination(item["destination"])
        item.update({"organization": organization, "category": category})
        results.append(item)
    return results


@router.get("/traffic/timeline")
def traffic_timeline(
    hours: int = Query(default=24, ge=1, le=168),
    device_id: int | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    query = (
        select(
            TrafficFlow.bucket_start,
            func.sum(TrafficFlow.packet_count).label("packets"),
            func.sum(TrafficFlow.byte_count).label("bytes"),
            func.sum(case((TrafficFlow.direction == "outbound", TrafficFlow.byte_count), else_=0)).label("upload_bytes"),
            func.sum(case((TrafficFlow.direction == "inbound", TrafficFlow.byte_count), else_=0)).label("download_bytes"),
        )
        .where(TrafficFlow.bucket_start >= since)
        .group_by(TrafficFlow.bucket_start)
        .order_by(TrafficFlow.bucket_start)
    )
    if device_id is not None:
        query = query.where(TrafficFlow.device_id == device_id)
    return [
        {**dict(row._mapping), "bucket_start": as_utc(row.bucket_start)}
        for row in db.execute(query)
    ]


@router.get("/traffic/top-devices")
def top_devices(
    hours: int = Query(default=24, ge=1, le=720),
    limit: int = Query(default=8, ge=1, le=50),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = db.execute(
        select(
            Device.id,
            Device.hostname,
            Device.ip_address,
            Device.category,
            func.sum(TrafficFlow.byte_count).label("bytes"),
            func.sum(case((TrafficFlow.direction == "outbound", TrafficFlow.byte_count), else_=0)).label("upload_bytes"),
            func.sum(case((TrafficFlow.direction == "inbound", TrafficFlow.byte_count), else_=0)).label("download_bytes"),
        )
        .join(TrafficFlow, TrafficFlow.device_id == Device.id)
        .where(TrafficFlow.bucket_start >= since)
        .group_by(Device.id)
        .order_by(func.sum(TrafficFlow.byte_count).desc())
        .limit(limit)
    )
    return [dict(row._mapping) for row in rows]


@router.get("/traffic/protocols")
def protocol_breakdown(
    hours: int = Query(default=24, ge=1, le=720),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = db.execute(
        select(
            TrafficFlow.protocol,
            func.sum(TrafficFlow.byte_count).label("bytes"),
            func.sum(TrafficFlow.packet_count).label("packets"),
        )
        .where(TrafficFlow.bucket_start >= since)
        .group_by(TrafficFlow.protocol)
        .order_by(func.sum(TrafficFlow.byte_count).desc())
    )
    return [dict(row._mapping) for row in rows]


@router.get("/topology")
def topology(
    settings: Settings = Depends(get_settings),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    devices = list(db.scalars(select(Device).order_by(desc(Device.is_online), Device.hostname)))
    nodes = [
        {
            "id": "router",
            "label": "Home gateway",
            "subtitle": settings.router_host,
            "kind": "router",
            "online": True,
            "trust_status": "trusted",
        }
    ]
    links = []
    for device in devices:
        nodes.append(
            {
                "id": f"device-{device.id}",
                "device_id": device.id,
                "label": device.hostname or device.ip_address,
                "subtitle": device.ip_address,
                "kind": device.category,
                "online": device.is_online,
                "trust_status": device.trust_status,
            }
        )
        links.append({"source": "router", "target": f"device-{device.id}"})
    return {"nodes": nodes, "links": links}


@router.get("/security/summary")
def security_summary(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    unread = list(db.scalars(select(Alert).where(Alert.is_read.is_(False))))
    warning_count = sum(alert.severity == "warning" for alert in unread)
    critical_count = sum(alert.severity == "critical" for alert in unread)
    review_devices = db.scalar(
        select(func.count(Device.id)).where(Device.trust_status.in_(["unknown", "review"]))
    ) or 0
    score = max(0, 100 - critical_count * 20 - warning_count * 7 - min(review_devices, 5) * 2)
    return {
        "score": score,
        "status": "good" if score >= 85 else "attention" if score >= 60 else "risk",
        "unread_alerts": len(unread),
        "warning_alerts": warning_count,
        "critical_alerts": critical_count,
        "devices_to_review": review_devices,
    }


@router.get("/alerts")
def alerts(
    unread_only: bool = False,
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    query = select(Alert, Device.hostname, Device.ip_address).outerjoin(Device, Alert.device_id == Device.id)
    if unread_only:
        query = query.where(Alert.is_read.is_(False))
    rows = db.execute(query.order_by(Alert.last_seen.desc()).limit(limit))
    return [
        {
            "id": alert.id,
            "created_at": as_utc(alert.created_at),
            "last_seen": as_utc(alert.last_seen),
            "severity": alert.severity,
            "alert_type": alert.alert_type,
            "title": alert.title,
            "message": alert.message,
            "device_id": alert.device_id,
            "device_name": hostname or ip_address,
            "is_read": alert.is_read,
        }
        for alert, hostname, ip_address in rows
    ]


@router.post("/alerts/{alert_id}/read", dependencies=[Depends(require_csrf)])
def mark_alert_read(
    alert_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_read = True
    db.commit()
    record_audit(
        db,
        actor=user.username,
        action="alert.read",
        source_ip=client_ip(request),
        success=True,
        detail=f"alert_id={alert_id}",
    )
    return {"ok": True}


@router.post("/alerts/actions/read-all", dependencies=[Depends(require_csrf)])
def mark_all_alerts_read(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    db.execute(update(Alert).where(Alert.is_read.is_(False)).values(is_read=True))
    db.commit()
    record_audit(
        db, actor=user.username, action="alerts.read_all", source_ip=client_ip(request), success=True
    )
    return {"ok": True}


@router.get("/router/status")
def router_status(request: Request, _: User = Depends(get_current_user)):
    return request.app.state.router_controller.status().as_dict()


@router.post("/router/reboot", dependencies=[Depends(require_csrf)])
def reboot_router(
    payload: RebootRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
):
    if payload.confirmation != "REBOOT":
        raise HTTPException(status_code=400, detail="Type REBOOT to confirm")
    source = client_ip(request)
    rate_limiter.check(
        f"reboot:{user.id}", RateLimitRule(settings.reboot_rate_limit, settings.reboot_rate_window_seconds)
    )
    try:
        request.app.state.router_controller.reboot()
    except Exception as exc:
        record_audit(db, actor=user.username, action="router.reboot", source_ip=source, success=False, detail=str(exc)[:500])
        raise HTTPException(status_code=502, detail="Router reboot failed; see audit log") from exc
    record_audit(db, actor=user.username, action="router.reboot", source_ip=source, success=True)
    return {"accepted": True}


def router_health_dict(sample: RouterHealthSample, include_snapshot: bool = True) -> dict:
    data = {
        "id": sample.id,
        "created_at": as_utc(sample.created_at),
        "status": sample.status,
        "model": sample.model,
        "rx_power_dbm": sample.rx_power_dbm,
        "tx_power_dbm": sample.tx_power_dbm,
        "temperature_c": sample.temperature_c,
        "cpu_percent": sample.cpu_percent,
        "uptime_seconds": sample.uptime_seconds,
        "wan_status": sample.wan_status,
        "findings": json.loads(sample.findings_json or "[]"),
        "error": sample.error,
    }
    if include_snapshot:
        data["snapshot"] = json.loads(sample.snapshot_json or "{}")
    return data


@router.get("/router/health/latest")
def latest_router_health(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    sample = db.scalar(select(RouterHealthSample).order_by(RouterHealthSample.created_at.desc()).limit(1))
    return router_health_dict(sample) if sample else None


@router.get("/router/health/history")
def router_health_history(
    hours: int = Query(default=168, ge=1, le=24 * 90),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    samples = db.scalars(
        select(RouterHealthSample)
        .where(RouterHealthSample.created_at >= since)
        .order_by(RouterHealthSample.created_at.asc())
    )
    return [router_health_dict(sample, include_snapshot=False) for sample in samples]


@router.post("/router/health/run", dependencies=[Depends(require_csrf)])
def run_router_health(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
):
    if settings.router_adapter != "huawei_ont":
        raise HTTPException(status_code=409, detail="Router health requires a health-capable router adapter")
    rate_limiter.check(f"router-health:{user.id}", RateLimitRule(3, 300))
    sample_id = RouterHealthService(settings, request.app.state.router_controller).run()
    sample = db.get(RouterHealthSample, sample_id)
    record_audit(
        db,
        actor=user.username,
        action="router.health",
        source_ip=client_ip(request),
        success=sample.status != "failed",
        detail=f"status={sample.status}",
    )
    return router_health_dict(sample)


@router.get("/audit")
def audit_events(
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    events = db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit))
    return [
        {
            "created_at": as_utc(event.created_at),
            "actor": event.actor,
            "action": event.action,
            "source_ip": event.source_ip,
            "success": event.success,
            "detail": event.detail,
        }
        for event in events
    ]
