import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.entities import CVE, CVEDetail
from app.services.product_resolution import is_unknown_product

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "ThreatLens/1.0 (home-lab threat intelligence dashboard)"


def _nvd_headers() -> dict[str, str]:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
    return headers


def _fetch_nvd_record(cve_id: str) -> dict[str, Any]:
    with httpx.Client(timeout=20, follow_redirects=True, headers=_nvd_headers()) as client:
        response = client.get(NVD_URL, params={"cveId": cve_id})
        response.raise_for_status()
        rows = response.json().get("vulnerabilities", [])
    if not rows:
        raise LookupError(f"{cve_id} not found in NVD")
    cve = rows[0].get("cve", {})
    if str(cve.get("id", "")).upper() != cve_id:
        raise LookupError(f"{cve_id} not found in NVD")
    return cve


def _nvd_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.utcnow()
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo:
        parsed = parsed.astimezone(UTC).replace(tzinfo=None)
    return parsed


def _label(value: str) -> str:
    return unquote(value).replace("\\", "").replace("_", " ").strip().title()


def _cvss_metrics(cve: dict[str, Any]) -> dict[str, Any] | None:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        records = metrics.get(key) or []
        if not records:
            continue
        record = next((item for item in records if item.get("type") == "Primary"), records[0])
        data = record.get("cvssData", {})
        return {
            "version": str(data.get("version") or key.removeprefix("cvssMetricV")),
            "vector": str(data.get("vectorString") or ""),
            "base_score": float(data.get("baseScore") or 0),
            "base_severity": str(data.get("baseSeverity") or record.get("baseSeverity") or "Unknown").title(),
            "exploitability_score": record.get("exploitabilityScore"),
            "impact_score": record.get("impactScore"),
            "attack_vector": str(data.get("attackVector") or data.get("accessVector") or "Unknown").replace("_", " ").title(),
            "attack_complexity": str(data.get("attackComplexity") or data.get("accessComplexity") or "Unknown").replace("_", " ").title(),
            "privileges_required": str(data.get("privilegesRequired") or data.get("authentication") or "Unknown").replace("_", " ").title(),
            "user_interaction": str(data.get("userInteraction") or "Unknown").replace("_", " ").title(),
            "scope": str(data.get("scope") or "Unknown").replace("_", " ").title(),
            "confidentiality_impact": str(data.get("confidentialityImpact") or "Unknown").replace("_", " ").title(),
            "integrity_impact": str(data.get("integrityImpact") or "Unknown").replace("_", " ").title(),
            "availability_impact": str(data.get("availabilityImpact") or "Unknown").replace("_", " ").title(),
        }
    return None


def _affected_products(cve: dict[str, Any]) -> list[dict[str, Any]]:
    products: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            criteria = node.get("criteria")
            if isinstance(criteria, str) and criteria.startswith("cpe:2.3:"):
                parts = criteria.split(":")
                vendor = _label(parts[3]) if len(parts) > 3 else "Unknown"
                product = _label(parts[4]) if len(parts) > 4 else "Unknown"
                raw_version = parts[5] if len(parts) > 5 else "*"
                version = "All / unspecified" if raw_version in {"*", "-"} else _label(raw_version)
                ranges = []
                for key, operator in (
                    ("versionStartIncluding", ">="),
                    ("versionStartExcluding", ">"),
                    ("versionEndIncluding", "<="),
                    ("versionEndExcluding", "<"),
                ):
                    if node.get(key):
                        ranges.append(f"{operator} {node[key]}")
                version_range = ", ".join(ranges)
                identity = (vendor, product, version, version_range)
                if identity not in seen:
                    seen.add(identity)
                    products.append(
                        {
                            "vendor": vendor,
                            "product": product,
                            "version": version,
                            "vulnerable": bool(node.get("vulnerable", True)),
                            "version_range": version_range,
                        }
                    )
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(cve.get("configurations", []))
    return products[:100]


def build_nvd_payload(cve: dict[str, Any]) -> dict[str, Any]:
    descriptions = cve.get("descriptions", [])
    description = next(
        (item.get("value", "") for item in descriptions if item.get("lang") == "en"),
        descriptions[0].get("value", "") if descriptions else "",
    )
    weaknesses = []
    for weakness in cve.get("weaknesses", []):
        for item in weakness.get("description", []):
            value = item.get("value")
            if value and value not in weaknesses and value not in {"NVD-CWE-noinfo", "NVD-CWE-Other"}:
                weaknesses.append(value)
    references = [
        {
            "url": item.get("url", ""),
            "source": item.get("source", ""),
            "tags": item.get("tags", []),
        }
        for item in cve.get("references", [])
        if item.get("url")
    ][:40]
    return {
        "description": description,
        "cvss": _cvss_metrics(cve),
        "weaknesses": weaknesses[:20],
        "affected_products": _affected_products(cve),
        "references": references,
        "cisa_exploit_add": cve.get("cisaExploitAdd", ""),
        "cisa_action_due": cve.get("cisaActionDue", ""),
        "cisa_required_action": cve.get("cisaRequiredAction", ""),
        "cisa_vulnerability_name": cve.get("cisaVulnerabilityName", ""),
    }


def get_or_create_detail(db: Session, cve_id: str) -> CVEDetail:
    detail = db.get(CVEDetail, cve_id)
    if detail is None:
        detail = CVEDetail(cve_id=cve_id)
        db.add(detail)
    return detail


def store_nvd_payload(db: Session, cve_id: str, payload: dict[str, Any]) -> CVEDetail:
    detail = get_or_create_detail(db, cve_id)
    detail.nvd_payload = json.dumps(payload)
    detail.nvd_fetched_at = datetime.utcnow()
    return detail


def store_kev_payload(db: Session, cve_id: str, payload: dict[str, Any]) -> CVEDetail:
    detail = get_or_create_detail(db, cve_id)
    detail.kev_payload = json.dumps(payload)
    detail.kev_fetched_at = datetime.utcnow()
    return detail


def fetch_and_store_nvd_detail(db: Session, cve_id: str) -> CVEDetail:
    cve = _fetch_nvd_record(cve_id)
    detail = store_nvd_payload(db, cve_id, build_nvd_payload(cve))
    db.commit()
    db.refresh(detail)
    return detail


def fetch_and_store_nvd_cve(db: Session, cve_id: str) -> CVE:
    cve = _fetch_nvd_record(cve_id)
    nvd = build_nvd_payload(cve)
    cvss = nvd.get("cvss") or {}
    affected_products = nvd.get("affected_products") or []
    primary_product = next(
        (item for item in affected_products if item.get("vulnerable")),
        affected_products[0] if affected_products else {},
    )
    description = str(nvd.get("description") or "")
    title = str(
        nvd.get("cisa_vulnerability_name")
        or description.split(". ", 1)[0]
        or cve_id
    )

    item = db.scalar(select(CVE).where(CVE.cve_id == cve_id))
    if item is None:
        item = CVE(
            cve_id=cve_id,
            title=title[:255],
            description=description,
            severity=str(cvss.get("base_severity") or "Unknown")[:16],
            vendor=str(primary_product.get("vendor") or "Unknown")[:120],
            product=str(primary_product.get("product") or "")[:120],
            cvss_score=float(cvss.get("base_score") or 0),
            kev=bool(nvd.get("cisa_exploit_add")),
            published_at=_nvd_datetime(cve.get("published")),
            source="NVD",
        )
        db.add(item)
    else:
        item.title = title[:255]
        item.description = description
        item.severity = str(cvss.get("base_severity") or "Unknown")[:16]
        next_vendor = str(primary_product.get("vendor") or "Unknown")[:120]
        next_product = str(primary_product.get("product") or "")[:120]
        if not is_unknown_product(next_vendor) or is_unknown_product(item.vendor):
            item.vendor = next_vendor
        if not is_unknown_product(next_product) or is_unknown_product(item.product):
            item.product = next_product
        item.cvss_score = float(cvss.get("base_score") or 0)
        item.kev = item.kev or bool(nvd.get("cisa_exploit_add"))
        item.published_at = _nvd_datetime(cve.get("published"))
        item.source = "NVD"

    store_nvd_payload(db, cve_id, nvd)
    db.commit()
    db.refresh(item)
    return item
