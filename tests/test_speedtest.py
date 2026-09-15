from datetime import datetime, timezone

from app.database import SessionLocal
from app.models import SpeedTestRun
from app.services.speedtest import megabits_per_second


def test_megabits_per_second_uses_decimal_units():
    assert megabits_per_second(10_000_000, 1) == 80.0
    assert megabits_per_second(0, 1) == 0.0


def test_speedtest_latest_and_history(authenticated_client):
    with SessionLocal() as db:
        db.add(
            SpeedTestRun(
                created_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
                status="completed",
                download_mbps=184.2,
                upload_mbps=47.8,
                latency_ms=22.4,
                jitter_ms=3.1,
                bytes_transferred=12_000_000,
            )
        )
        db.commit()
    latest = authenticated_client.get("/api/speedtest/latest")
    assert latest.status_code == 200
    assert latest.json()["download_mbps"] == 184.2
    assert latest.json()["bytes_transferred"] == 12_000_000
    history = authenticated_client.get("/api/speedtest/history")
    assert len(history.json()) == 1
