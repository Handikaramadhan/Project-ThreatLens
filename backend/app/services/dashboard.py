import json
from datetime import datetime, timedelta

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.core.time import utc_now
from app.models.entities import Asset, AssetExposure, CollectionRun, CVE, CVEDetail, IOC, MitreTechnique, ThreatNews
from app.schemas.cves import CVSSMetrics
from app.schemas.dashboard import (
    AssetExposureItem,
    CollectionSummary,
    CVEItem,
    CVETrendPoint,
    DashboardPayload,
    DistributionPoint,
    IOCItem,
    Metric,
    NewsItem,
    SourceStatusItem,
    TechniqueItem,
)
from app.services.cve_analysis import build_mitre_mapping


SUCCESS_SOURCE_STATUSES = {"ok", "fallback"}
NON_FAILURE_SOURCE_STATUSES = {"ok", "fallback", "skipped"}
DEGRADED_SOURCE_STATUSES = {"error", "stale"}


def _run_sources(run: CollectionRun) -> list[dict]:
    try:
        details = json.loads(run.details or "{}")
    except json.JSONDecodeError:
        details = {}

    raw_sources = details.get("sources")
    if isinstance(raw_sources, list):
        return [item for item in raw_sources if isinstance(item, dict)]

    sources: list[dict] = []
    results = details.get("results") if isinstance(details.get("results"), dict) else {}
    errors = details.get("errors") if isinstance(details.get("errors"), dict) else {}
    for key, value in results.items():
        sources.append(
            {
                "id": str(key),
                "name": str(key).replace("_", " ").title(),
                "category": "collector",
                "status": "ok",
                "count": value if isinstance(value, int) else None,
                "message": "" if isinstance(value, int) else str(value),
            }
        )
    for key, value in errors.items():
        sources.append(
            {
                "id": str(key),
                "name": str(key).replace("_", " ").title(),
                "category": "collector",
                "status": "error",
                "message": str(value),
            }
        )
    return sources


def _source_history(db: Session, source_ids: set[str]) -> dict[str, dict]:
    if not source_ids:
        return {}

    runs = db.scalars(select(CollectionRun).order_by(desc(CollectionRun.started_at)).limit(50)).all()
    history = {
        source_id: {
            "consecutive_failures": 0,
            "last_success_at": None,
            "last_seen_at": None,
            "failure_streak_open": True,
        }
        for source_id in source_ids
    }

    for run in runs:
        finished_or_started = run.finished_at or run.started_at
        for item in _run_sources(run):
            source_id = str(item.get("id") or item.get("name") or "unknown")
            if source_id not in history:
                continue
            status = str(item.get("status") or "unknown")
            source_history = history[source_id]
            if source_history["last_seen_at"] is None:
                source_history["last_seen_at"] = finished_or_started
            if status in SUCCESS_SOURCE_STATUSES and source_history["last_success_at"] is None:
                source_history["last_success_at"] = finished_or_started
            if source_history["failure_streak_open"]:
                if status in DEGRADED_SOURCE_STATUSES:
                    source_history["consecutive_failures"] += 1
                elif status in NON_FAILURE_SOURCE_STATUSES:
                    source_history["failure_streak_open"] = False

    for item in history.values():
        item.pop("failure_streak_open", None)
    return history


def _collection_summary(db: Session) -> CollectionSummary | None:
    run = db.scalar(select(CollectionRun).order_by(desc(CollectionRun.started_at)).limit(1))
    if run is None:
        return None

    raw_sources = _run_sources(run)
    sources = []
    source_ids = {str(item.get("id") or item.get("name") or "unknown") for item in raw_sources}
    history = _source_history(db, source_ids)
    for item in raw_sources:
        source_id = str(item.get("id") or item.get("name") or "unknown")
        status = str(item.get("status") or "unknown")
        message = str(item.get("message") or "")
        if (
            run.finished_at is not None
            and status in {"ok", "fallback"}
            and utc_now() - run.finished_at > timedelta(hours=2)
        ):
            status = "stale"
            message = message or "last collection finished more than 2 hours ago"
        source_history = history.get(source_id, {})
        sources.append(
            SourceStatusItem(
                id=source_id,
                name=str(item.get("name") or item.get("id") or "Unknown"),
                category=str(item.get("category") or "collector"),
                status=status,
                count=item.get("count") if isinstance(item.get("count"), int) else None,
                message=message,
                consecutive_failures=int(source_history.get("consecutive_failures") or 0),
                last_success_at=source_history.get("last_success_at"),
                last_seen_at=source_history.get("last_seen_at"),
            )
        )

    duration_seconds = None
    if run.started_at and run.finished_at:
        duration_seconds = max(0.0, (run.finished_at - run.started_at).total_seconds())

    return CollectionSummary(
        status=run.status,
        started_at=run.started_at,
        finished_at=run.finished_at,
        duration_seconds=duration_seconds,
        degraded_sources=sum(1 for item in sources if item.status in DEGRADED_SOURCE_STATUSES),
        sources=sources,
    )


def _derived_techniques(cves: list[CVE], details_by_id: dict[str, CVEDetail]) -> list[TechniqueItem]:
    counts: dict[str, dict[str, object]] = {}
    for cve in cves:
        detail = details_by_id.get(cve.cve_id)
        payload = {}
        if detail is not None:
            try:
                raw_payload = json.loads(detail.nvd_payload or "{}")
                payload = raw_payload if isinstance(raw_payload, dict) else {}
            except json.JSONDecodeError:
                payload = {}

        description = str(payload.get("description") or cve.description or cve.title or "")
        raw_weaknesses = payload.get("weaknesses") if isinstance(payload.get("weaknesses"), list) else []
        weaknesses = [str(item) for item in raw_weaknesses]
        cvss_payload = payload.get("cvss") if isinstance(payload.get("cvss"), dict) else None
        cvss = CVSSMetrics.model_validate(cvss_payload) if cvss_payload else None
        for mapping in build_mitre_mapping(description, weaknesses, cvss):
            current = counts.setdefault(
                mapping.technique_id,
                {
                    "name": mapping.name,
                    "tactic": mapping.tactic,
                    "count": 0,
                },
            )
            current["count"] = int(current["count"]) + 1

    return [
        TechniqueItem(
            technique_id=technique_id,
            name=str(item["name"]),
            tactic=str(item["tactic"]),
            count=int(item["count"]),
        )
        for technique_id, item in sorted(
            counts.items(),
            key=lambda pair: (-int(pair[1]["count"]), pair[0]),
        )[:8]
    ]


def get_dashboard(db: Session) -> DashboardPayload:
    now = utc_now()
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
    details_by_id = {
        detail.cve_id: detail
        for detail in db.scalars(select(CVEDetail).where(CVEDetail.cve_id.in_([item.cve_id for item in cves]))).all()
    }
    technique_items = [
        TechniqueItem(technique_id=item.technique_id, name=item.name, tactic=item.tactic, count=item.count)
        for item in techniques
    ] or _derived_techniques(cves, details_by_id)
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
        techniques=technique_items,
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
        collection=_collection_summary(db),
    )
