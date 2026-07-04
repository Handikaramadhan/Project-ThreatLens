import csv
import ipaddress
import io
import json
import re
import time
from datetime import UTC, datetime, timedelta
from html import unescape
from typing import Any
from urllib.parse import urlparse

import feedparser
import httpx
from dateutil import parser as date_parser
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.entities import CVE, CVEDetail, IOC, CollectionRun, ThreatNews
from app.services.cve_detail import build_nvd_payload
from app.services.product_resolution import infer_product_from_description, is_unknown_product

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
RSS_FEEDS = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
}
PHISHDESTROY_URL = "https://api.destroy.tools/v1/feed/primary_active"
FEODO_RECOMMENDED_IPS_URL = (
    "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
)
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
MALWAREBAZAAR_RECENT_CSV_URL = "https://bazaar.abuse.ch/export/csv/recent/"
ALIENVAULT_REPUTATION_URL = "https://reputation.alienvault.com/reputation.generic"
USER_AGENT = "ThreatLens/1.0 (home-lab threat intelligence collector)"
RETRYABLE_STATUS = {429, 500, 502, 503, 504}


def _get_with_retry(client: httpx.Client, url: str, **kwargs: Any) -> httpx.Response:
    last_error: Exception | None = None
    for attempt in range(4):
        try:
            response = client.get(url, **kwargs)
            if response.status_code not in RETRYABLE_STATUS:
                response.raise_for_status()
                return response
            response.raise_for_status()
        except (httpx.HTTPError, httpx.TimeoutException) as exc:
            last_error = exc
            if attempt == 3:
                raise
            retry_after = response.headers.get("Retry-After") if "response" in locals() else None
            delay = min(float(retry_after), 30) if retry_after and retry_after.isdigit() else 5 * (2**attempt)
            time.sleep(delay)
    raise last_error or RuntimeError(f"Request failed: {url}")


def _utc_naive(value: str | None, fallback: datetime | None = None) -> datetime:
    if not value:
        return fallback or datetime.utcnow()
    parsed = date_parser.parse(value)
    if parsed.tzinfo:
        parsed = parsed.astimezone(UTC).replace(tzinfo=None)
    return parsed


def _plain_text(value: str) -> str:
    return unescape(re.sub(r"<[^>]+>", " ", value)).strip()


def _english_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions", [])
    match = next((item for item in descriptions if item.get("lang") == "en"), None)
    return (match or (descriptions[0] if descriptions else {})).get("value", "")


def _cvss(cve: dict[str, Any]) -> tuple[float, str]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        records = metrics.get(key) or []
        if not records:
            continue
        record = records[0]
        data = record.get("cvssData", {})
        score = float(data.get("baseScore") or 0)
        severity = data.get("baseSeverity") or record.get("baseSeverity") or "Unknown"
        return score, str(severity).title()
    return 0, "Unknown"


def _vendor_product(cve: dict[str, Any]) -> tuple[str, str]:
    def walk(node: Any) -> str | None:
        if isinstance(node, dict):
            criteria = node.get("criteria")
            if isinstance(criteria, str) and criteria.startswith("cpe:2.3:"):
                return criteria
            for value in node.values():
                found = walk(value)
                if found:
                    return found
        elif isinstance(node, list):
            for value in node:
                found = walk(value)
                if found:
                    return found
        return None

    criteria = walk(cve.get("configurations", []))
    if not criteria:
        return "Unknown", ""
    parts = criteria.split(":")
    vendor = parts[3].replace("_", " ").title() if len(parts) > 3 else "Unknown"
    product = parts[4].replace("_", " ").title() if len(parts) > 4 else ""
    return vendor, product


def _apply_cve(db: Session, item: CVE | None, payload: dict[str, Any]) -> CVE:
    if item is None:
        item = CVE(**payload)
        db.add(item)
        return item
    for key, value in payload.items():
        if key == "product" and is_unknown_product(value) and not is_unknown_product(item.product):
            continue
        if key == "vendor" and is_unknown_product(value) and not is_unknown_product(item.vendor):
            continue
        setattr(item, key, value)
    return item


def _upsert_cve(db: Session, payload: dict[str, Any]) -> CVE:
    item = db.scalar(select(CVE).where(CVE.cve_id == payload["cve_id"]))
    return _apply_cve(db, item, payload)


def collect_cisa_kev(db: Session, client: httpx.Client) -> tuple[set[str], int]:
    response = _get_with_retry(client, CISA_KEV_URL)
    vulnerabilities = response.json().get("vulnerabilities", [])
    kev_ids = {item["cveID"] for item in vulnerabilities if item.get("cveID")}
    detail_rows = db.scalars(select(CVEDetail).where(CVEDetail.cve_id.in_(kev_ids))).all() if kev_ids else []
    details_by_id = {item.cve_id: item for item in detail_rows}
    fetched_at = datetime.utcnow()
    for vulnerability in vulnerabilities:
        cve_id = vulnerability.get("cveID")
        if not cve_id:
            continue
        detail = details_by_id.get(cve_id)
        if detail is None:
            detail = CVEDetail(cve_id=cve_id)
            db.add(detail)
            details_by_id[cve_id] = detail
        detail.kev_payload = json.dumps(vulnerability)
        detail.kev_fetched_at = fetched_at

    existing = db.scalars(select(CVE).where(CVE.cve_id.in_(kev_ids))).all() if kev_ids else []
    existing_by_id = {item.cve_id: item for item in existing}
    for item in existing_by_id.values():
        item.kev = True

    # Keep a useful recent KEV window even when the corresponding NVD item is older.
    for item in sorted(vulnerabilities, key=lambda value: value.get("dateAdded", ""), reverse=True)[:100]:
        cve_id = item.get("cveID")
        if not cve_id:
            continue
        current = existing_by_id.get(cve_id)
        if current:
            current.kev = True
            continue
        existing_by_id[cve_id] = _apply_cve(
            db,
            None,
            {
                "cve_id": cve_id,
                "title": item.get("vulnerabilityName", cve_id)[:255],
                "description": item.get("shortDescription", ""),
                "severity": "High",
                "vendor": item.get("vendorProject", "Unknown")[:120],
                "product": item.get("product", "")[:120],
                "cvss_score": 0,
                "kev": True,
                "published_at": _utc_naive(item.get("dateAdded")),
                "source": "CISA KEV",
            },
        )
    db.commit()
    return kev_ids, len(vulnerabilities)


def collect_nvd(db: Session, client: httpx.Client, kev_ids: set[str]) -> int:
    end = datetime.now(UTC)
    start = end - timedelta(days=max(1, min(settings.collector_window_days, 120)))
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    params: dict[str, Any] = {
        "pubStartDate": start.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "pubEndDate": end.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "resultsPerPage": 2000,
        "noRejected": "",
    }
    count = 0
    start_index = 0

    while True:
        params["startIndex"] = start_index
        response = _get_with_retry(client, NVD_URL, params=params, headers=headers)
        body = response.json()
        rows = body.get("vulnerabilities", [])
        cve_rows = [wrapper.get("cve", {}) for wrapper in rows]
        cve_ids = [cve.get("id") for cve in cve_rows if cve.get("id")]
        existing = db.scalars(select(CVE).where(CVE.cve_id.in_(cve_ids))).all() if cve_ids else []
        existing_by_id = {item.cve_id: item for item in existing}
        existing_details = db.scalars(
            select(CVEDetail).where(CVEDetail.cve_id.in_(cve_ids))
        ).all() if cve_ids else []
        details_by_id = {item.cve_id: item for item in existing_details}
        fetched_at = datetime.utcnow()
        for cve in cve_rows:
            cve_id = cve.get("id")
            if not cve_id:
                continue
            description = _english_description(cve)
            score, severity = _cvss(cve)
            vendor, product = _vendor_product(cve)
            if is_unknown_product(product):
                inferred = infer_product_from_description(description)
                if inferred:
                    inferred_vendor, inferred_product = inferred
                    if is_unknown_product(vendor) and not is_unknown_product(inferred_vendor):
                        vendor = inferred_vendor
                    product = inferred_product
            title = cve.get("cisaVulnerabilityName") or description.split(". ", 1)[0] or cve_id
            existing_by_id[cve_id] = _apply_cve(
                db,
                existing_by_id.get(cve_id),
                {
                    "cve_id": cve_id,
                    "title": title[:255],
                    "description": description,
                    "severity": severity,
                    "vendor": vendor[:120],
                    "product": product[:120],
                    "cvss_score": score,
                    "kev": cve_id in kev_ids or bool(cve.get("cisaExploitAdd")),
                    "published_at": _utc_naive(cve.get("published")),
                    "source": "NVD",
                },
            )
            detail = details_by_id.get(cve_id)
            if detail is None:
                detail = CVEDetail(cve_id=cve_id)
                db.add(detail)
                details_by_id[cve_id] = detail
            detail.nvd_payload = json.dumps(build_nvd_payload(cve))
            detail.nvd_fetched_at = fetched_at
            count += 1
        db.commit()
        start_index += len(rows)
        if not rows or start_index >= int(body.get("totalResults", 0)):
            break
        time.sleep(0.7 if settings.nvd_api_key else 6.0)
    db.execute(delete(CVE).where(CVE.source == "seed"))
    db.commit()
    return count


def collect_news(db: Session, client: httpx.Client) -> int:
    count = 0
    for source, url in RSS_FEEDS.items():
        response = _get_with_retry(client, url)
        feed = feedparser.parse(response.content)
        for entry in feed.entries[:30]:
            link = entry.get("link")
            title = _plain_text(entry.get("title", ""))
            if not link or not title:
                continue
            item = db.scalar(select(ThreatNews).where(ThreatNews.url == link))
            payload = {
                "title": title[:255],
                "source": source,
                "published_at": _utc_naive(entry.get("published") or entry.get("updated")),
                "summary": _plain_text(entry.get("summary", "")),
            }
            if item is None:
                db.add(ThreatNews(url=link, **payload))
            else:
                for key, value in payload.items():
                    setattr(item, key, value)
            count += 1
        db.commit()
    db.execute(delete(ThreatNews).where(ThreatNews.url.like("https://example.local/%")))
    db.commit()
    return count


def _parse_feodo_ips(payload: str) -> list[str]:
    indicators: list[str] = []
    for line in payload.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        try:
            indicators.append(str(ipaddress.ip_address(value)))
        except ValueError:
            continue
    return list(dict.fromkeys(indicators))


def _parse_openphish_urls(payload: str) -> list[str]:
    indicators: list[str] = []
    for line in payload.splitlines():
        value = line.strip()
        if not value or len(value) > 255:
            continue
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue
        indicators.append(value)
    return list(dict.fromkeys(indicators))


def _parse_alienvault_ips(payload: str) -> list[str]:
    indicators: list[str] = []
    for line in payload.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        candidate = value.split("#", 1)[0].strip().split()[0]
        try:
            indicators.append(str(ipaddress.ip_address(candidate)))
        except ValueError:
            continue
    return list(dict.fromkeys(indicators))


def _parse_malwarebazaar_hashes(payload: str) -> list[dict[str, Any]]:
    csv_lines: list[str] = []
    for line in payload.splitlines():
        value = line.strip()
        if not value:
            continue
        if value.startswith("#"):
            header = value.lstrip("#").strip()
            if "first_seen_utc" in header and "sha256_hash" in header:
                csv_lines.append(header)
            continue
        csv_lines.append(value)

    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in csv.DictReader(io.StringIO("\n".join(csv_lines)), skipinitialspace=True):
        indicator = (row.get("sha256_hash") or "").strip().lower()
        if not re.fullmatch(r"[a-f0-9]{64}", indicator) or indicator in seen:
            continue
        signature = (row.get("signature") or "").strip()
        threat = signature if signature and signature.lower() != "n/a" else "malware sample"
        records.append(
            {
                "indicator": indicator,
                "threat": threat[:120],
                "first_seen": _utc_naive(row.get("first_seen_utc")),
            }
        )
        seen.add(indicator)
    return records


def _upsert_iocs(
    db: Session,
    indicator_type: str,
    records: list[dict[str, Any]],
    source: str,
    severity: str = "High",
) -> int:
    if not records:
        return 0
    indicators = [str(record["indicator"]) for record in records]
    existing = db.scalars(
        select(IOC).where(IOC.type == indicator_type, IOC.indicator.in_(indicators))
    ).all()
    existing_by_indicator = {item.indicator: item for item in existing}
    now = datetime.utcnow()
    for record in records:
        indicator = str(record["indicator"])
        item = existing_by_indicator.get(indicator)
        if item is None:
            item = IOC(
                indicator=indicator,
                type=indicator_type,
                threat=str(record.get("threat") or ""),
                severity=severity,
                source=source,
                first_seen=record.get("first_seen") or now,
                last_seen=now,
            )
            db.add(item)
            existing_by_indicator[indicator] = item
        else:
            item.threat = str(record.get("threat") or item.threat)
            item.severity = severity
            item.source = source
            item.last_seen = now
    db.commit()
    return len(records)


def collect_feodo_ips(db: Session, client: httpx.Client) -> int:
    response = _get_with_retry(client, FEODO_RECOMMENDED_IPS_URL)
    records = [
        {"indicator": indicator, "threat": "botnet C2"}
        for indicator in _parse_feodo_ips(response.text)
    ]
    return _upsert_iocs(db, "ip", records, "Feodo Tracker")


def collect_openphish_urls(db: Session, client: httpx.Client) -> int:
    response = _get_with_retry(client, OPENPHISH_FEED_URL)
    records = [
        {"indicator": indicator, "threat": "phishing"}
        for indicator in _parse_openphish_urls(response.text)
    ]
    return _upsert_iocs(db, "url", records, "OpenPhish")


def collect_alienvault_ips(db: Session, client: httpx.Client) -> int:
    response = _get_with_retry(client, ALIENVAULT_REPUTATION_URL)
    records = [
        {"indicator": indicator, "threat": "malicious host"}
        for indicator in _parse_alienvault_ips(response.text)
    ]
    return _upsert_iocs(
        db,
        "ip",
        records,
        "AlienVault Reputation",
        severity="Medium",
    )


def collect_malwarebazaar_hashes(db: Session, client: httpx.Client) -> int:
    response = _get_with_retry(client, MALWAREBAZAAR_RECENT_CSV_URL)
    records = _parse_malwarebazaar_hashes(response.text)
    return _upsert_iocs(db, "hash", records, "MalwareBazaar")


def collect_urlhaus(db: Session, client: httpx.Client) -> int:
    if not settings.urlhaus_auth_key:
        return 0
    url = f"https://urlhaus-api.abuse.ch/v2/files/exports/{settings.urlhaus_auth_key}/recent.csv"
    response = _get_with_retry(client, url)
    count = 0
    for row in csv.DictReader(io.StringIO(response.text)):
        indicator = row.get("url") or row.get("URL")
        if not indicator:
            continue
        item = db.scalar(select(IOC).where(IOC.indicator == indicator, IOC.type == "url"))
        now = datetime.utcnow()
        if item is None:
            db.add(
                IOC(
                    indicator=indicator[:255],
                    type="url",
                    threat=(row.get("threat") or row.get("Threat") or "malware")[:120],
                    severity="High",
                    source="URLhaus",
                    first_seen=now,
                    last_seen=now,
                )
            )
        else:
            item.last_seen = now
        count += 1
        if count >= 500:
            break
    db.commit()
    return count


def collect_phishdestroy(db: Session, client: httpx.Client) -> int:
    response = _get_with_retry(client, PHISHDESTROY_URL)
    domains = response.json().get("domains", [])
    if not domains:
        return 0

    sample_size = min(1000, len(domains))
    step = max(1, len(domains) // sample_size)
    sampled = domains[::step][:sample_size]
    existing = db.scalars(
        select(IOC).where(IOC.type == "domain", IOC.indicator.in_(sampled))
    ).all()
    existing_by_indicator = {item.indicator: item for item in existing}
    now = datetime.utcnow()
    for domain in sampled:
        item = existing_by_indicator.get(domain)
        if item is None:
            db.add(
                IOC(
                    indicator=domain[:255],
                    type="domain",
                    threat="phishing",
                    severity="High",
                    source="PhishDestroy",
                    first_seen=now,
                    last_seen=now,
                )
            )
        else:
            item.last_seen = now
            item.severity = "High"
            item.source = "PhishDestroy"
    db.execute(delete(IOC).where(IOC.indicator.contains("xx")))
    db.commit()
    return len(sampled)


def run_collection(db: Session) -> dict[str, Any]:
    now = datetime.utcnow()
    db.execute(
        update(CollectionRun)
        .where(CollectionRun.status == "running")
        .values(status="interrupted", finished_at=now)
    )
    run = CollectionRun(status="running")
    db.add(run)
    db.commit()
    db.refresh(run)

    results: dict[str, Any] = {}
    errors: dict[str, str] = {}
    with httpx.Client(
        timeout=httpx.Timeout(45),
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json, application/xml, text/xml, */*"},
    ) as client:
        try:
            kev_ids, results["cisa_kev_catalog"] = collect_cisa_kev(db, client)
        except Exception as exc:
            db.rollback()
            kev_ids = set()
            errors["cisa_kev"] = str(exc)
        try:
            results["nvd_cves"] = collect_nvd(db, client, kev_ids)
        except Exception as exc:
            db.rollback()
            errors["nvd"] = str(exc)
        try:
            results["news"] = collect_news(db, client)
        except Exception as exc:
            db.rollback()
            errors["news"] = str(exc)
        try:
            results["urlhaus_iocs"] = collect_urlhaus(db, client)
            if not settings.urlhaus_auth_key:
                results["urlhaus"] = "skipped: URLHAUS_AUTH_KEY not configured"
        except Exception as exc:
            db.rollback()
            errors["urlhaus"] = str(exc)
        try:
            results["phishdestroy_iocs"] = collect_phishdestroy(db, client)
        except Exception as exc:
            db.rollback()
            errors["phishdestroy"] = str(exc)
        try:
            results["feodo_ip_iocs"] = collect_feodo_ips(db, client)
        except Exception as exc:
            db.rollback()
            errors["feodo"] = str(exc)
        try:
            results["alienvault_ip_iocs"] = collect_alienvault_ips(db, client)
        except Exception as exc:
            db.rollback()
            errors["alienvault"] = str(exc)
        try:
            results["openphish_url_iocs"] = collect_openphish_urls(db, client)
        except Exception as exc:
            db.rollback()
            errors["openphish"] = str(exc)
        try:
            results["malwarebazaar_hash_iocs"] = collect_malwarebazaar_hashes(db, client)
        except Exception as exc:
            db.rollback()
            errors["malwarebazaar"] = str(exc)

    run = db.get(CollectionRun, run.id)
    run.finished_at = datetime.utcnow()
    run.status = "partial" if errors else "success"
    run.details = json.dumps({"results": results, "errors": errors})
    db.commit()
    return {"status": run.status, "results": results, "errors": errors}
