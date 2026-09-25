import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any

import httpx
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.time import utc_now
from app.models.entities import CVE, CVEWebEnrichment
from app.services.product_resolution import extract_cve_org_products, is_unknown_product

CVE_API_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
GITHUB_ADVISORY_URL = "https://api.github.com/advisories"
USER_AGENT = "ThreatLens/1.0 (home-lab threat intelligence dashboard)"


def _fetch_json(url: str, params: dict[str, str] | None = None) -> Any:
    with httpx.Client(
        timeout=httpx.Timeout(12, connect=5),
        follow_redirects=True,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/vnd.github+json, application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    ) as client:
        response = client.get(url, params=params)
        response.raise_for_status()
        return response.json()


def _english_values(items: Any) -> list[str]:
    if not isinstance(items, list):
        return []
    values = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("lang", "en") != "en":
            continue
        value = str(item.get("value") or "").strip()
        if value:
            values.append(value)
    return values


def _append_unique(items: list[dict[str, Any]], value: dict[str, Any], key: str = "text") -> None:
    identity = str(value.get(key) or "").strip().lower()
    if identity and all(str(item.get(key) or "").strip().lower() != identity for item in items):
        items.append(value)


def build_web_remediation(
    cve_id: str,
    cve_record: dict[str, Any] | None,
    github_advisories: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    mitigations: list[dict[str, Any]] = []
    workarounds: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    record_url = f"https://www.cve.org/CVERecord?id={cve_id}"

    if cve_record:
        containers = cve_record.get("containers", {})
        cna = containers.get("cna") or {}
        all_containers = [cna, *(containers.get("adp") or [])]
        for container in all_containers:
            provider = container.get("providerMetadata", {}).get("shortName") or "CVE.org CNA"
            for text in _english_values(container.get("solutions")):
                _append_unique(
                    mitigations,
                    {"text": text, "source": f"{provider} via CVE.org", "url": record_url},
                )
            for text in _english_values(container.get("workarounds")):
                _append_unique(
                    workarounds,
                    {"text": text, "source": f"{provider} via CVE.org", "url": record_url},
                )
            for reference in container.get("references") or []:
                url = str(reference.get("url") or "")
                if url:
                    _append_unique(
                        sources,
                        {
                            "url": url,
                            "source": provider,
                            "tags": [str(tag) for tag in reference.get("tags") or []],
                        },
                        key="url",
                    )
        _append_unique(
            sources,
            {"url": record_url, "source": "CVE.org", "tags": ["CVE Record"]},
            key="url",
        )

    for advisory in github_advisories or []:
        advisory_url = str(advisory.get("html_url") or "")
        ghsa_id = str(advisory.get("ghsa_id") or "GitHub Advisory")
        for vulnerability in advisory.get("vulnerabilities") or []:
            package = vulnerability.get("package") or {}
            package_name = package.get("name") or "affected package"
            ecosystem = package.get("ecosystem") or "package"
            patched = str(vulnerability.get("patched_versions") or "").strip()
            if patched:
                _append_unique(
                    mitigations,
                    {
                        "text": f"Upgrade {ecosystem} package {package_name} to a patched version: {patched}.",
                        "source": f"GitHub Advisory Database ({ghsa_id})",
                        "url": advisory_url,
                    },
                )
        if advisory_url:
            _append_unique(
                sources,
                {
                    "url": advisory_url,
                    "source": "GitHub Advisory Database",
                    "tags": [ghsa_id],
                },
                key="url",
            )

    return {
        "mitigations": mitigations,
        "workarounds": workarounds,
        "sources": sources[:60],
        "affected_products": extract_cve_org_products(cve_record),
    }


def fetch_and_store_web_remediation(db: Session, cve_id: str) -> CVEWebEnrichment:
    with ThreadPoolExecutor(max_workers=2) as executor:
        cve_future = executor.submit(_fetch_json, CVE_API_URL.format(cve_id=cve_id))
        github_future = executor.submit(_fetch_json, GITHUB_ADVISORY_URL, {"cve_id": cve_id})
        try:
            cve_record = cve_future.result()
        except Exception:
            cve_record = None
        try:
            github_result = github_future.result()
            github_advisories = github_result if isinstance(github_result, list) else []
        except Exception:
            github_advisories = []

    payload = build_web_remediation(cve_id, cve_record, github_advisories)
    enrichment = db.get(CVEWebEnrichment, cve_id)
    if enrichment is None:
        enrichment = CVEWebEnrichment(cve_id=cve_id)
        db.add(enrichment)
    enrichment.payload = json.dumps(payload)
    enrichment.fetched_at = utc_now()
    cve = db.scalar(select(CVE).where(CVE.cve_id == cve_id))
    products = payload.get("affected_products") or []
    if cve is not None and products:
        primary = products[0]
        if is_unknown_product(cve.product):
            cve.product = str(primary.get("product") or "")[:120]
        if is_unknown_product(cve.vendor):
            cve.vendor = str(primary.get("vendor") or "Unknown")[:120]
    db.commit()
    db.refresh(enrichment)
    return enrichment
