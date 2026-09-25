from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.time import utc_now
from app.models.entities import Asset, AssetExposure, CVE, CVEDetail
from app.schemas.assets import AssetExposureOut, AssetExposureUpdate, AssetOut, AssetWrite
from app.services.audit import audit_log
from app.services.auth import AuthContext, get_auth_context, require_csrf
from app.services.alerts import flush_alert_events
from app.services.asset_matching import explain_exposure, refresh_asset_exposures

router = APIRouter()


def _asset_out(asset: Asset, matching_cve: int = 0) -> AssetOut:
    return AssetOut(
        id=asset.id,
        name=asset.name,
        asset_type=asset.asset_type,
        os_version=asset.os_version,
        vendor=asset.vendor,
        product=asset.product,
        version=asset.version,
        environment=asset.environment,
        criticality=asset.criticality,
        internet_exposed=asset.internet_exposed,
        owner=asset.owner,
        risk=asset.risk,
        matching_cve=matching_cve,
    )


def _ensure_unique_name(db: Session, name: str, asset_id: int | None = None) -> None:
    query = select(Asset.id).where(func.lower(Asset.name) == name.lower())
    if asset_id is not None:
        query = query.where(Asset.id != asset_id)
    if db.scalar(query) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Asset name already exists")


@router.get("/assets", response_model=list[AssetOut])
def list_assets(
    db: Session = Depends(get_db),
    _: AuthContext = Depends(get_auth_context),
) -> list[AssetOut]:
    rows = db.execute(
        select(Asset, func.count(AssetExposure.id))
        .outerjoin(AssetExposure, AssetExposure.asset_id == Asset.id)
        .group_by(Asset.id)
        .order_by(Asset.name)
    ).all()
    return [_asset_out(asset, count) for asset, count in rows]


@router.post("/assets", response_model=AssetOut, status_code=201)
def create_asset(
    payload: AssetWrite,
    request: Request,
    db: Session = Depends(get_db),
    context: AuthContext = Depends(require_csrf),
) -> AssetOut:
    _ensure_unique_name(db, payload.name)
    asset = Asset(**payload.model_dump())
    db.add(asset)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Asset name already exists") from None
    db.refresh(asset)
    matching_cve = refresh_asset_exposures(db, asset.id)
    audit_log(
        db,
        action="asset.create",
        actor=context.user,
        request=request,
        target_type="asset",
        target_id=str(asset.id),
        details={"name": asset.name, "matching_cve": matching_cve},
    )
    db.commit()
    flush_alert_events(db)
    return _asset_out(asset, matching_cve)


@router.put("/assets/{asset_id}", response_model=AssetOut)
def update_asset(
    asset_id: int,
    payload: AssetWrite,
    request: Request,
    db: Session = Depends(get_db),
    context: AuthContext = Depends(require_csrf),
) -> AssetOut:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    _ensure_unique_name(db, payload.name, asset_id)
    for field, value in payload.model_dump().items():
        setattr(asset, field, value)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Asset name already exists") from None
    db.refresh(asset)
    matching_cve = refresh_asset_exposures(db, asset.id)
    audit_log(
        db,
        action="asset.update",
        actor=context.user,
        request=request,
        target_type="asset",
        target_id=str(asset.id),
        details={"name": asset.name, "matching_cve": matching_cve},
    )
    db.commit()
    flush_alert_events(db)
    return _asset_out(asset, matching_cve)


@router.post("/assets/recalculate", response_model=dict[str, int])
def recalculate_asset_exposures(
    request: Request,
    db: Session = Depends(get_db),
    context: AuthContext = Depends(require_csrf),
) -> dict[str, int]:
    count = refresh_asset_exposures(db)
    audit_log(
        db,
        action="asset.exposures.recalculate",
        actor=context.user,
        request=request,
        target_type="asset_exposure",
        details={"matching_cve": count},
    )
    db.commit()
    flush_alert_events(db)
    return {"matching_cve": count}


def _asset_exposure_out(asset: Asset, exposure: AssetExposure, cve: CVE, detail: CVEDetail | None) -> AssetExposureOut:
    explanation = explain_exposure(asset, cve, detail, exposure.matching_score)
    return AssetExposureOut(
        cve_id=cve.cve_id,
        title=cve.title,
        severity=cve.severity,
        risk=exposure.risk,
        matching_score=exposure.matching_score,
        confidence=explanation.confidence,
        match_type=explanation.match_type,
        affected_vendor=explanation.affected_vendor,
        affected_product=explanation.affected_product,
        affected_version=explanation.affected_version,
        affected_version_range=explanation.affected_version_range,
        status=exposure.status,
        review_note=exposure.review_note,
        reviewed_at=exposure.reviewed_at,
        reviewed_by=exposure.reviewed_by,
        reason=explanation.reason,
        evidence=explanation.evidence,
        limitations=explanation.limitations,
        published_at=cve.published_at,
        kev=cve.kev,
    )


@router.get("/assets/{asset_id}/exposures", response_model=list[AssetExposureOut])
def asset_exposures(
    asset_id: int,
    db: Session = Depends(get_db),
    _: AuthContext = Depends(get_auth_context),
) -> list[AssetExposureOut]:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    rows = db.execute(
        select(AssetExposure, CVE, CVEDetail)
        .join(CVE, CVE.cve_id == AssetExposure.cve_id)
        .outerjoin(CVEDetail, CVEDetail.cve_id == CVE.cve_id)
        .where(AssetExposure.asset_id == asset.id)
        .order_by(AssetExposure.matching_score.desc(), CVE.published_at.desc())
    ).all()
    return [
        _asset_exposure_out(asset, exposure, cve, detail)
        for exposure, cve, detail in rows
    ]


@router.patch("/assets/{asset_id}/exposures/{cve_id}", response_model=AssetExposureOut)
def update_asset_exposure(
    asset_id: int,
    cve_id: str,
    payload: AssetExposureUpdate,
    request: Request,
    db: Session = Depends(get_db),
    context: AuthContext = Depends(require_csrf),
) -> AssetExposureOut:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    row = db.execute(
        select(AssetExposure, CVE, CVEDetail)
        .join(CVE, CVE.cve_id == AssetExposure.cve_id)
        .outerjoin(CVEDetail, CVEDetail.cve_id == CVE.cve_id)
        .where(AssetExposure.asset_id == asset.id, AssetExposure.cve_id == cve_id)
    ).first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset exposure not found")

    exposure, cve, detail = row
    exposure.status = payload.status
    exposure.review_note = payload.review_note
    exposure.reviewed_at = utc_now()
    exposure.reviewed_by = context.user.username
    audit_log(
        db,
        action="asset.exposure.review",
        actor=context.user,
        request=request,
        target_type="asset_exposure",
        target_id=f"{asset.id}:{cve_id}",
        details={"asset": asset.name, "cve_id": cve_id, "status": payload.status},
    )
    db.commit()
    db.refresh(exposure)
    return _asset_exposure_out(asset, exposure, cve, detail)


@router.delete("/assets/{asset_id}", status_code=204)
def delete_asset(
    asset_id: int,
    request: Request,
    db: Session = Depends(get_db),
    context: AuthContext = Depends(require_csrf),
) -> None:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    db.execute(delete(AssetExposure).where(AssetExposure.asset_id == asset.id))
    audit_log(
        db,
        action="asset.delete",
        actor=context.user,
        request=request,
        target_type="asset",
        target_id=str(asset.id),
        details={"name": asset.name},
    )
    db.delete(asset)
    db.commit()
