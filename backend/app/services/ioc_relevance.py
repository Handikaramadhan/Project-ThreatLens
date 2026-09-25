import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import Asset, AssetExposure, IOC
from app.schemas.iocs import RelatedAssetRef


CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def related_assets_for_ioc(db: Session, ioc: IOC) -> list[RelatedAssetRef]:
    text = " ".join([ioc.indicator, ioc.threat, ioc.source]).lower()
    related: dict[int, RelatedAssetRef] = {}

    cve_ids = {match.group(0).upper() for match in CVE_PATTERN.finditer(text)}
    if cve_ids:
        rows = db.execute(
            select(Asset, AssetExposure.cve_id)
            .join(AssetExposure, AssetExposure.asset_id == Asset.id)
            .where(AssetExposure.cve_id.in_(cve_ids))
        ).all()
        for asset, cve_id in rows:
            related[asset.id] = RelatedAssetRef(
                id=asset.id,
                name=asset.name,
                risk=asset.risk,
                reason=f"IOC references {cve_id} affecting this asset",
            )

    assets = db.scalars(select(Asset).order_by(Asset.name)).all()
    for asset in assets:
        candidates = [
            asset.name,
            asset.vendor,
            asset.product,
            asset.os_version,
        ]
        match = next((item for item in candidates if item and len(item) >= 3 and item.lower() in text), "")
        if match and asset.id not in related:
            related[asset.id] = RelatedAssetRef(
                id=asset.id,
                name=asset.name,
                risk=asset.risk,
                reason=f"IOC text mentions asset attribute: {match}",
            )

    return sorted(related.values(), key=lambda item: item.name)[:10]
