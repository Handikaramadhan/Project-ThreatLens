from redis import Redis
from sqlalchemy import desc, func, select, text
from sqlalchemy.orm import Session

from fastapi import APIRouter, Depends

from app.core.config import settings
from app.core.database import get_db
from app.models.entities import AlertDelivery, AuditLog, CollectionRun
from app.schemas.admin import AuditLogOut, SystemHealthOut
from app.services.auth import AuthContext, require_admin


router = APIRouter()


def _alembic_revision(db: Session) -> str:
    try:
        return str(db.scalar(text("select version_num from alembic_version")) or "")
    except Exception:
        db.rollback()
        return "unknown"


@router.get("/admin/audit-logs", response_model=list[AuditLogOut])
def audit_logs(
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_admin),
) -> list[AuditLog]:
    return list(
        db.scalars(
            select(AuditLog).order_by(desc(AuditLog.created_at)).limit(200)
        ).all()
    )


@router.get("/admin/system-health", response_model=SystemHealthOut)
def system_health(
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_admin),
) -> SystemHealthOut:
    database_status = "down"
    redis_status = "down"
    try:
        db.execute(text("select 1"))
        database_status = "ok"
    except Exception:
        db.rollback()

    redis = Redis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
    try:
        if redis.ping():
            redis_status = "ok"
    except Exception:
        pass
    finally:
        redis.close()

    latest = db.scalar(select(CollectionRun).order_by(desc(CollectionRun.started_at)).limit(1))
    audit_count = db.scalar(select(func.count()).select_from(AuditLog)) or 0
    failed_alerts = db.scalar(
        select(func.count()).select_from(AlertDelivery).where(AlertDelivery.status == "failed")
    ) or 0
    return SystemHealthOut(
        service="threatlens-api",
        database=database_status,
        redis=redis_status,
        alembic_revision=_alembic_revision(db),
        latest_collection_status=latest.status if latest else "never_run",
        latest_collection_started_at=latest.started_at if latest else None,
        latest_collection_finished_at=latest.finished_at if latest else None,
        audit_events=audit_count,
        failed_alert_deliveries=failed_alerts,
    )
