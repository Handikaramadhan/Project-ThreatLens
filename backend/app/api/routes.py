import json

from fastapi import APIRouter, Depends, Response
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.entities import CollectionRun
from app.schemas.dashboard import DashboardPayload
from app.services.auth import AuthContext, get_auth_context, require_admin_csrf
from app.services.dashboard import get_dashboard
from worker.tasks import collect_threat_intel

router = APIRouter()


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "threatlens-api"}


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
def start_collection(_: AuthContext = Depends(require_admin_csrf)) -> dict[str, str]:
    task = collect_threat_intel.delay()
    return {"status": "queued", "task_id": task.id}
