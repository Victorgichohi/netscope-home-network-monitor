from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Alert


def raise_alert(
    db: Session,
    *,
    severity: str,
    alert_type: str,
    title: str,
    message: str,
    dedupe_key: str,
    device_id: int | None = None,
) -> Alert:
    now = datetime.now(timezone.utc)
    alert = db.scalar(select(Alert).where(Alert.dedupe_key == dedupe_key))
    if alert is None:
        alert = Alert(
            severity=severity,
            alert_type=alert_type,
            title=title,
            message=message,
            device_id=device_id,
            dedupe_key=dedupe_key,
            created_at=now,
            last_seen=now,
        )
        db.add(alert)
    else:
        alert.last_seen = now
        alert.message = message
        alert.is_read = False
    return alert
