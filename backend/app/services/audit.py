import json
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from app.models.entities import AuditLog, User


def client_ip(request: Request | None) -> str:
    if request is None:
        return ""
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.split(",", 1)[0].strip() or (request.client.host if request.client else "unknown")


def audit_log(
    db: Session,
    *,
    action: str,
    actor: User | None = None,
    request: Request | None = None,
    target_type: str = "",
    target_id: str = "",
    status: str = "success",
    details: dict[str, Any] | None = None,
    commit: bool = False,
) -> None:
    redacted = details or {}
    db.add(
        AuditLog(
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else "",
            action=action,
            target_type=target_type,
            target_id=str(target_id)[:120],
            status=status,
            ip_address=client_ip(request),
            details=json.dumps(redacted, default=str),
        )
    )
    if commit:
        db.commit()
