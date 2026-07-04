from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.entities import Asset, AssetExposure
from app.schemas.assets import AssetOut, AssetWrite
from app.services.auth import AuthContext, get_auth_context, require_csrf

router = APIRouter()


def _asset_out(asset: Asset, matching_cve: int = 0) -> AssetOut:
    return AssetOut(
        id=asset.id,
        name=asset.name,
        asset_type=asset.asset_type,
        os_version=asset.os_version,
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
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_csrf),
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
    return _asset_out(asset)


@router.put("/assets/{asset_id}", response_model=AssetOut)
def update_asset(
    asset_id: int,
    payload: AssetWrite,
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_csrf),
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
    matching_cve = db.scalar(
        select(func.count()).select_from(AssetExposure).where(AssetExposure.asset_id == asset.id)
    ) or 0
    return _asset_out(asset, matching_cve)


@router.delete("/assets/{asset_id}", status_code=204)
def delete_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_csrf),
) -> None:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    db.execute(delete(AssetExposure).where(AssetExposure.asset_id == asset.id))
    db.delete(asset)
    db.commit()
