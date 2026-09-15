from datetime import datetime, timezone

from app.database import SessionLocal
from app.models import DiagnosticRun
from app.services.diagnostics import ProbeResult, recommendations_for


def test_healthy_diagnostic_recommendation():
    recommendations = recommendations_for(
        ProbeResult("ok", 3, 0), ProbeResult("ok", 40), ProbeResult("ok", 8)
    )
    assert "healthy" in recommendations[0]


def test_diagnostic_distinguishes_isp_from_wifi_problem():
    recommendations = recommendations_for(
        ProbeResult("ok", 4, 0), ProbeResult("failed"), ProbeResult("failed")
    )
    assert "router" in recommendations[0]
    assert "ISP" in recommendations[0]


def test_latest_diagnostic_api(authenticated_client):
    with SessionLocal() as db:
        db.add(
            DiagnosticRun(
                created_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
                status="healthy",
                summary="Your connection looks healthy",
                interface="en0",
                local_ip="192.168.1.20",
                gateway_ip="192.168.1.1",
                subnet="192.168.1.0/24",
                gateway_status="ok",
                gateway_latency_ms=3,
                internet_status="ok",
                internet_latency_ms=32,
                dns_status="ok",
                dns_latency_ms=9,
                packet_loss_percent=0,
                recommendations_json='["Everything looks good."]',
            )
        )
        db.commit()
    response = authenticated_client.get("/api/diagnostics/latest")
    assert response.status_code == 200
    assert response.json()["checks"]["internet"]["latency_ms"] == 32
    assert response.json()["recommendations"] == ["Everything looks good."]


def test_household_analytics_is_friendly_when_empty(authenticated_client):
    response = authenticated_client.get("/api/analytics/household")
    assert response.status_code == 200
    assert response.json()["recognized_percent"] == 100


def test_uptime_summary_counts_outage_sequences(authenticated_client):
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        for minute, status in enumerate(("ok", "failed", "failed", "ok")):
            db.add(
                DiagnosticRun(
                    created_at=now,
                    completed_at=now,
                    status="healthy" if status == "ok" else "offline",
                    internet_status=status,
                    internet_latency_ms=20 if status == "ok" else None,
                    gateway_status="ok",
                    dns_status="ok",
                    packet_loss_percent=minute,
                )
            )
        db.commit()
    response = authenticated_client.get("/api/diagnostics/uptime")
    assert response.status_code == 200
    assert response.json()["availability_percent"] == 50.0
    assert response.json()["outage_count"] == 1
    assert response.json()["average_latency_ms"] == 20
