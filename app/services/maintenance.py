from datetime import datetime, timedelta, timezone

from sqlalchemy import delete

from app.config import Settings
from app.database import SessionLocal
from app.models import DnsObservation, TrafficFlow


def purge_expired_metadata(settings: Settings) -> None:
    now = datetime.now(timezone.utc)
    with SessionLocal() as db:
        db.execute(
            delete(TrafficFlow).where(
                TrafficFlow.last_seen < now - timedelta(days=settings.traffic_retention_days)
            )
        )
        db.execute(
            delete(DnsObservation).where(
                DnsObservation.last_seen < now - timedelta(days=settings.dns_retention_days)
            )
        )
        db.commit()
