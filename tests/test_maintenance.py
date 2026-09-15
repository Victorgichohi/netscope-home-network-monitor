from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.config import get_settings
from app.database import SessionLocal
from app.models import DnsObservation, TrafficFlow
from app.services.maintenance import purge_expired_metadata


def test_retention_removes_expired_metadata():
    old = datetime.now(timezone.utc) - timedelta(days=60)
    with SessionLocal() as db:
        db.add(
            TrafficFlow(
                bucket_start=old,
                source_ip="192.168.1.2",
                destination_ip="203.0.113.2",
                protocol="TCP",
                destination_port=443,
                last_seen=old,
            )
        )
        db.add(DnsObservation(domain="old.example", resolved_ip="203.0.113.2", last_seen=old))
        db.commit()
    purge_expired_metadata(get_settings())
    with SessionLocal() as db:
        assert db.scalar(select(TrafficFlow)) is None
        assert db.scalar(select(DnsObservation)) is None
