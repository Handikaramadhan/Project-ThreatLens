from datetime import datetime
from io import BytesIO
from typing import Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.entities import IOC
from app.services.auth import AuthContext, get_auth_context
from app.services.ioc_excel import build_ioc_workbook

router = APIRouter()


@router.get("/iocs/export.xlsx")
def export_iocs(
    indicator_type: Literal["all", "ip", "domain", "url", "hash"] = Query(
        default="all",
        alias="type",
    ),
    db: Session = Depends(get_db),
    _: AuthContext = Depends(get_auth_context),
) -> StreamingResponse:
    statement = select(IOC).order_by(IOC.last_seen.desc(), IOC.indicator)
    if indicator_type != "all":
        statement = statement.where(func.lower(IOC.type) == indicator_type)
    items = list(db.scalars(statement).all())
    workbook = build_ioc_workbook(items, indicator_type)
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M")
    filename = f"ThreatLens-IOC-{indicator_type}-{timestamp}.xlsx"
    return StreamingResponse(
        BytesIO(workbook),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )
