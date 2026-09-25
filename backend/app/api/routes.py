import json

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from redis import Redis
from sqlalchemy import desc, select, text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.models.entities import CollectionRun
from app.schemas.dashboard import DashboardPayload
from app.services.audit import audit_log
from app.services.auth import AuthContext, get_auth_context, require_admin_csrf
from app.services.dashboard import get_dashboard
from worker.tasks import collect_threat_intel

router = APIRouter()


@router.get("/health")
def health(db: Session = Depends(get_db)) -> dict[str, object]:
    checks = {"database": "down", "redis": "down"}
    try:
        db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        db.rollback()

    redis = Redis.from_url(
        settings.redis_url,
        socket_connect_timeout=2,
        socket_timeout=2,
    )
    try:
        if redis.ping():
            checks["redis"] = "ok"
    except Exception:
        pass
    finally:
        redis.close()

    if "down" in checks.values():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"status": "degraded", "checks": checks},
        )
    return {"status": "ok", "service": "threatlens-api", "checks": checks}


@router.get("/dashboard", response_model=DashboardPayload)
def dashboard(
    response: Response,
    db: Session = Depends(get_db),
    _: AuthContext = Depends(get_auth_context),
) -> DashboardPayload:
    response.headers["Cache-Control"] = "no-store"
    return get_dashboard(db)


@router.get("/collection/status")
def collection_status(
    db: Session = Depends(get_db),
    _: AuthContext = Depends(get_auth_context),
) -> dict:
    run = db.scalar(select(CollectionRun).order_by(desc(CollectionRun.started_at)).limit(1))
    if run is None:
        return {"status": "never_run"}
    return {
        "status": run.status,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "details": json.loads(run.details),
    }


@router.post("/collection/run", status_code=202)
def start_collection(
    request: Request,
    db: Session = Depends(get_db),
    context: AuthContext = Depends(require_admin_csrf),
) -> dict[str, str]:
    task = collect_threat_intel.delay()
    audit_log(
        db,
        action="collection.run",
        actor=context.user,
        request=request,
        target_type="collection_task",
        target_id=task.id,
        status="queued",
        commit=True,
    )
    return {"status": "queued", "task_id": task.id}
