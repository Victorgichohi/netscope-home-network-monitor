from sqlalchemy.orm import Session

from app.models import AuditEvent


def record_audit(
    db: Session,
    *,
    actor: str,
    action: str,
    source_ip: str | None,
    success: bool,
    detail: str | None = None,
) -> None:
    db.add(
        AuditEvent(
            actor=actor,
            action=action,
            source_ip=source_ip,
            success=success,
            detail=detail,
        )
    )
    db.commit()
