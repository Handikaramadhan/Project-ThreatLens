import json
import re
from io import BytesIO
from datetime import datetime, timedelta
from math import ceil
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.entities import Asset, AssetExposure, CVE, CVEDetail, CVEWebEnrichment, IOC, ThreatNews
from app.schemas.cves import (
    AffectedProduct,
    CVEListItem,
    CVEPage,
    CVEDetailOut,
    CVEReference,
    CVSSMetrics,
    ExploitStatus,
    RemediationItem,
    RelatedAsset,
    RelatedIOC,
    RelatedNews,
)
from app.services.auth import AuthContext, get_auth_context
from app.services.cve_detail import fetch_and_store_nvd_cve, fetch_and_store_nvd_detail
from app.services.cve_analysis import build_mitre_mapping, build_root_cause
from app.services.cve_pdf import build_cve_pdf
from app.services.web_remediation import fetch_and_store_web_remediation
from app.services.product_resolution import is_unknown_product

router = APIRouter()
CACHE_TTL = timedelta(hours=24)
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _json_payload(value: str) -> dict:
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, json.JSONDecodeError):
        return {}


@router.get("/cves", response_model=CVEPage)
def list_cves(
    response: Response,
    query: str = Query(default="", max_length=120),
    severity: Literal["All", "Critical", "High", "Medium", "Low", "Unknown"] = "All",
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=500, ge=1, le=500),
    db: Session = Depends(get_db),
    _: AuthContext = Depends(get_auth_context),
) -> CVEPage:
    filters = []
    normalized_query = query.strip()
    exact_cve_id = normalized_query.upper() if CVE_ID_PATTERN.fullmatch(normalized_query) else ""
    if exact_cve_id and not db.scalar(select(CVE.id).where(CVE.cve_id == exact_cve_id)):
        try:
            fetch_and_store_nvd_cve(db, exact_cve_id)
            response.headers["X-ThreatLens-NVD-Lookup"] = "fetched"
        except LookupError:
            db.rollback()
            response.headers["X-ThreatLens-NVD-Lookup"] = "not-found"
        except Exception:
            db.rollback()
            response.headers["X-ThreatLens-NVD-Lookup"] = "unavailable"

    if normalized_query:
        pattern = f"%{normalized_query}%"
        filters.append(
            or_(
                CVE.cve_id.ilike(pattern),
                CVE.vendor.ilike(pattern),
                CVE.product.ilike(pattern),
                CVE.title.ilike(pattern),
            )
        )
    if severity != "All":
        filters.append(CVE.severity == severity)

    total = db.scalar(select(func.count()).select_from(CVE).where(*filters)) or 0
    pages = max(1, ceil(total / limit))
    safe_page = min(page, pages)
    rows = db.scalars(
        select(CVE)
        .where(*filters)
        .order_by(CVE.published_at.desc(), CVE.cve_id.desc())
        .offset((safe_page - 1) * limit)
        .limit(limit)
    ).all()
    response.headers["Cache-Control"] = "no-store"
    return CVEPage(
        items=[
            CVEListItem(
                cve_id=item.cve_id,
                severity=item.severity,
                vendor=item.vendor,
                product=item.product,
                published_at=item.published_at,
                kev=item.kev,
            )
            for item in rows
        ],
        total=total,
        page=safe_page,
        limit=limit,
        pages=pages,
    )


@router.get("/cves/{cve_id}", response_model=CVEDetailOut)
def cve_detail(
    cve_id: str,
    response: Response,
    db: Session = Depends(get_db),
    _: AuthContext = Depends(get_auth_context),
) -> CVEDetailOut:
    normalized_id = cve_id.strip().upper()
    cve = db.scalar(select(CVE).where(CVE.cve_id == normalized_id))
    if cve is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CVE not found")

    detail = db.get(CVEDetail, normalized_id)
    cache_fresh = bool(
        detail
        and detail.nvd_fetched_at
        and detail.nvd_fetched_at >= datetime.utcnow() - CACHE_TTL
    )
    if not cache_fresh:
        try:
            detail = fetch_and_store_nvd_detail(db, normalized_id)
        except Exception:
            db.rollback()
            detail = db.get(CVEDetail, normalized_id)

    nvd = _json_payload(detail.nvd_payload) if detail else {}
    kev = _json_payload(detail.kev_payload) if detail else {}
    web_enrichment = db.get(CVEWebEnrichment, normalized_id)
    cached_web = _json_payload(web_enrichment.payload) if web_enrichment else {}
    web_cache_fresh = bool(
        web_enrichment
        and web_enrichment.fetched_at
        and web_enrichment.fetched_at >= datetime.utcnow() - CACHE_TTL
        and (
            "affected_products" in cached_web
            or not is_unknown_product(cve.product)
        )
    )
    if not web_cache_fresh:
        try:
            web_enrichment = fetch_and_store_web_remediation(db, normalized_id)
        except Exception:
            db.rollback()
            web_enrichment = db.get(CVEWebEnrichment, normalized_id)
    web = _json_payload(web_enrichment.payload) if web_enrichment else {}
    web_has_sources = any(web.get(key) for key in ("mitigations", "workarounds", "sources"))
    cvss = nvd.get("cvss")
    affected_products = []
    seen_products: set[tuple[str, str, str, str]] = set()
    for product_item in [
        *(nvd.get("affected_products") or []),
        *(web.get("affected_products") or []),
    ]:
        identity = (
            str(product_item.get("vendor") or "").lower(),
            str(product_item.get("product") or "").lower(),
            str(product_item.get("version") or "").lower(),
            str(product_item.get("version_range") or "").lower(),
        )
        if identity in seen_products:
            continue
        seen_products.add(identity)
        affected_products.append(product_item)
    affected_products = affected_products or [
        {
            "vendor": cve.vendor,
            "product": cve.product or "Unknown",
            "version": "Not available",
            "vulnerable": True,
            "version_range": "",
        },
    ]
    primary_product = next(
        (item for item in affected_products if item.get("vulnerable", True)),
        affected_products[0],
    )
    display_vendor = cve.vendor
    display_product = cve.product
    if is_unknown_product(display_product) and not is_unknown_product(primary_product.get("product")):
        display_product = str(primary_product.get("product"))
    if is_unknown_product(display_vendor) and not is_unknown_product(primary_product.get("vendor")):
        display_vendor = str(primary_product.get("vendor"))
    required_action = kev.get("requiredAction") or nvd.get("cisa_required_action") or ""
    mitigation = list(web.get("mitigations") or [])
    if required_action:
        mitigation.insert(
            0,
            {
                "text": required_action,
                "source": "CISA KEV",
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            },
        )
    remediation_sources = list(web.get("sources") or [])
    relevant_tags = {"Vendor Advisory", "Patch", "Mitigation", "Third Party Advisory"}
    for reference in nvd.get("references", []):
        if relevant_tags.intersection(reference.get("tags", [])):
            remediation_sources.append(reference)

    asset_rows = db.scalars(
        select(Asset)
        .join(AssetExposure, AssetExposure.asset_id == Asset.id)
        .where(AssetExposure.cve_id == normalized_id)
        .order_by(Asset.name)
    ).all()
    pattern = f"%{normalized_id}%"
    iocs = db.scalars(
        select(IOC)
        .where(or_(IOC.threat.ilike(pattern), IOC.source.ilike(pattern)))
        .order_by(IOC.last_seen.desc())
        .limit(50)
    ).all()
    news = db.scalars(
        select(ThreatNews)
        .where(or_(ThreatNews.title.ilike(pattern), ThreatNews.summary.ilike(pattern)))
        .order_by(ThreatNews.published_at.desc())
        .limit(10)
    ).all()
    known_exploited = bool(cve.kev or kev or nvd.get("cisa_exploit_add"))

    cvss_model = CVSSMetrics(**cvss) if cvss else None
    description = nvd.get("description") or cve.description or "Description is not available."
    weaknesses = [str(item) for item in nvd.get("weaknesses", [])]

    response.headers["Cache-Control"] = "no-store"
    return CVEDetailOut(
        cve_id=cve.cve_id,
        title=nvd.get("cisa_vulnerability_name") or cve.title,
        description=description,
        severity=cve.severity,
        vendor=display_vendor,
        product=display_product,
        cvss_score=float(cvss.get("base_score", cve.cvss_score) if cvss else cve.cvss_score),
        cvss=cvss_model,
        kev=cve.kev,
        exploit_status=ExploitStatus(
            known_exploited=known_exploited,
            date_added=kev.get("dateAdded") or nvd.get("cisa_exploit_add") or "",
            action_due=kev.get("dueDate") or nvd.get("cisa_action_due") or "",
            required_action=required_action,
            ransomware_use=kev.get("knownRansomwareCampaignUse") or "Unknown",
            notes=kev.get("notes") or "",
        ),
        weaknesses=weaknesses,
        affected_products=[AffectedProduct(**item) for item in affected_products],
        mitigation=[RemediationItem(**item) for item in mitigation],
        workarounds=[RemediationItem(**item) for item in web.get("workarounds", [])],
        remediation_sources=[CVEReference(**item) for item in remediation_sources[:60]],
        references=[CVEReference(**item) for item in nvd.get("references", [])],
        related_iocs=[
            RelatedIOC(
                indicator=item.indicator,
                type=item.type,
                threat=item.threat,
                severity=item.severity,
                source=item.source,
            )
            for item in iocs
        ],
        related_assets=[
            RelatedAsset(
                id=item.id,
                name=item.name,
                asset_type=item.asset_type,
                os_version=item.os_version,
                owner=item.owner,
                risk=item.risk,
            )
            for item in asset_rows
        ],
        related_news=[
            RelatedNews(
                title=item.title,
                source=item.source,
                url=item.url,
                published_at=item.published_at,
            )
            for item in news
        ],
        published_at=cve.published_at,
        source=cve.source,
        detail_source="NVD + CISA KEV + CVE.org/GitHub" if web_has_sources else "NVD + CISA KEV" if nvd and kev else "NVD" if nvd else "Local cache",
        fetched_at=max(
            [value for value in [
                detail.nvd_fetched_at if detail else None,
                web_enrichment.fetched_at if web_enrichment else None,
            ] if value],
            default=None,
        ),
        root_cause=build_root_cause(description, weaknesses),
        mitre_techniques=build_mitre_mapping(description, weaknesses, cvss_model),
    )


@router.get("/cves/{cve_id}/pdf")
def cve_detail_pdf(
    cve_id: str,
    db: Session = Depends(get_db),
    context: AuthContext = Depends(get_auth_context),
) -> StreamingResponse:
    detail = cve_detail(cve_id, Response(), db, context)
    pdf = build_cve_pdf(detail)
    filename = f"ThreatLens-{detail.cve_id}.pdf"
    return StreamingResponse(
        BytesIO(pdf),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
        },
    )
