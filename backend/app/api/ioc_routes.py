from datetime import datetime
from io import BytesIO
from typing import Literal

from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.time import utc_now
from app.models.entities import IOC
from app.schemas.iocs import IOCOut
from app.services.auth import AuthContext, get_auth_context
from app.services.ioc_excel import build_ioc_workbook
from app.services.ioc_relevance import related_assets_for_ioc

router = APIRouter()


@router.get("/iocs", response_model=list[IOCOut])
def list_iocs(
    response: Response,
    indicator_type: Literal["all", "ip", "domain", "url", "hash"] = Query(default="all", alias="type"),
    db: Session = Depends(get_db),
    _: AuthContext = Depends(get_auth_context),
) -> list[IOCOut]:
    statement = select(IOC).order_by(IOC.last_seen.desc(), IOC.indicator).limit(500)
    if indicator_type != "all":
        statement = statement.where(func.lower(IOC.type) == indicator_type)
    items = list(db.scalars(statement).all())
    response.headers["Cache-Control"] = "no-store"
    return [
        IOCOut(
            indicator=item.indicator,
            type=item.type,
            threat=item.threat,
            severity=item.severity,
            source=item.source,
            first_seen=item.first_seen,
            last_seen=item.last_seen,
            related_assets=related_assets_for_ioc(db, item),
        )
        for item in items
    ]


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
    timestamp = utc_now().strftime("%Y%m%d-%H%M")
    filename = f"ThreatLens-IOC-{indicator_type}-{timestamp}.xlsx"
    return StreamingResponse(
        BytesIO(workbook),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )
