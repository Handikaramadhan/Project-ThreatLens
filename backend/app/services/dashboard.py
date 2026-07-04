from datetime import datetime, timedelta

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.models.entities import Asset, AssetExposure, CVE, IOC, MitreTechnique, ThreatNews
from app.schemas.dashboard import (
    AssetExposureItem,
    CVEItem,
    CVETrendPoint,
    DashboardPayload,
    DistributionPoint,
    IOCItem,
    Metric,
    NewsItem,
    TechniqueItem,
)


def get_dashboard(db: Session) -> DashboardPayload:
    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)
    trend_start = (now - timedelta(days=13)).replace(hour=0, minute=0, second=0, microsecond=0)
    critical_cves = db.scalar(select(func.count()).select_from(CVE).where(CVE.severity == "Critical", CVE.published_at >= week_ago)) or 0
    kev_count = db.scalar(select(func.count()).select_from(CVE).where(CVE.kev.is_(True))) or 0
    new_iocs = db.scalar(select(func.count()).select_from(IOC).where(IOC.first_seen >= week_ago)) or 0
    high_assets = db.scalar(select(func.count()).select_from(Asset).where(Asset.risk == "High")) or 0

    cves = db.scalars(select(CVE).order_by(desc(CVE.published_at)).limit(100)).all()
    iocs = []
    for indicator_type in ("ip", "domain", "url", "hash"):
        iocs.extend(
            db.scalars(
                select(IOC)
                .where(IOC.type == indicator_type)
                .order_by(desc(IOC.last_seen))
                .limit(100)
            ).all()
        )
    news = db.scalars(select(ThreatNews).order_by(desc(ThreatNews.published_at)).limit(100)).all()
    techniques = db.scalars(select(MitreTechnique).order_by(desc(MitreTechnique.count)).limit(8)).all()
    exposure_rows = db.execute(
        select(Asset, func.count(AssetExposure.id))
        .outerjoin(AssetExposure, AssetExposure.asset_id == Asset.id)
        .group_by(Asset.id)
        .order_by(desc(Asset.risk))
        .limit(100)
    ).all()
    trend_rows = db.execute(
        select(func.date(CVE.published_at), CVE.severity, func.count(CVE.id))
        .where(CVE.published_at >= trend_start)
        .group_by(func.date(CVE.published_at), CVE.severity)
    ).all()
    trend_counts: dict[str, dict[str, int]] = {}
    for day, severity, count in trend_rows:
        day_key = day.isoformat() if hasattr(day, "isoformat") else str(day)
        trend_counts.setdefault(day_key, {})[str(severity).lower()] = int(count)

    severity_rows = db.execute(
        select(CVE.severity, func.count(CVE.id)).group_by(CVE.severity)
    ).all()
    ioc_type_rows = db.execute(
        select(IOC.type, func.count(IOC.id)).group_by(IOC.type)
    ).all()
    asset_risk_rows = db.execute(
        select(Asset.risk, func.count(Asset.id)).group_by(Asset.risk)
    ).all()

    cve_trend = []
    for offset in range(14):
        day = (trend_start + timedelta(days=offset)).date().isoformat()
        values = trend_counts.get(day, {})
        cve_trend.append(
            CVETrendPoint(
                date=day,
                critical=values.get("critical", 0),
                high=values.get("high", 0),
                medium=values.get("medium", 0),
                low=values.get("low", 0),
                unknown=values.get("unknown", 0),
            )
        )

    return DashboardPayload(
        metrics=[
            Metric(label="Critical CVE (7 hari)", value=critical_cves, delta="published in the last 7 days", tone="danger"),
            Metric(label="Known exploited", value=kev_count, delta="tracked in the CISA KEV catalog", tone="warning"),
            Metric(label="New indicators", value=new_iocs, delta="observed in the last 7 days", tone="success"),
            Metric(label="High-risk assets", value=high_assets, delta="requires exposure review", tone="info"),
        ],
        cves=[
            CVEItem(
                cve_id=item.cve_id,
                severity=item.severity,
                vendor=item.vendor,
                product=item.product,
                published_at=item.published_at,
                kev=item.kev,
            )
            for item in cves
        ],
        iocs=[IOCItem(indicator=item.indicator, type=item.type, severity=item.severity, source=item.source) for item in iocs],
        news=[
            NewsItem(
                title=item.title,
                source=item.source,
                published_at=item.published_at,
                url=item.url,
                summary=item.summary,
            )
            for item in news
        ],
        techniques=[TechniqueItem(technique_id=item.technique_id, name=item.name, tactic=item.tactic, count=item.count) for item in techniques],
        exposures=[
            AssetExposureItem(
                asset=asset.name,
                asset_type=asset.asset_type,
                os_version=asset.os_version,
                matching_cve=count,
                risk=asset.risk,
            )
            for asset, count in exposure_rows
        ],
        cve_trend=cve_trend,
        severity_distribution=[
            DistributionPoint(label=str(label or "Unknown").title(), value=int(count))
            for label, count in severity_rows
        ],
        ioc_distribution=[
            DistributionPoint(label=str(label or "unknown").upper(), value=int(count))
            for label, count in ioc_type_rows
        ],
        asset_risk_distribution=[
            DistributionPoint(label=str(label or "Unknown").title(), value=int(count))
            for label, count in asset_risk_rows
        ],
    )
