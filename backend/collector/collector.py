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
from sqlalchemy import delete, select, text, update
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.time import utc_now
from app.models.entities import CVE, CVEDetail, IOC, CollectionRun, ThreatNews
from app.services.alerts import alert_event_key, flush_alert_events, queue_alert_event
from app.services.asset_matching import refresh_asset_exposures
from app.services.cve_detail import build_nvd_payload
from app.services.product_resolution import infer_product_from_description, is_unknown_product

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
RSS_FEEDS = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "SecurityWeek": "https://www.securityweek.com/feed/",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "SANS Internet Storm Center": "https://isc.sans.edu/rssfeed_full.xml",
    "Google Security Blog": "https://feeds.feedburner.com/GoogleOnlineSecurityBlog",
}
PHISHDESTROY_URL = "https://api.destroy.tools/v1/feed/primary_active"
PHISHDESTROY_FALLBACK_URL = (
    "https://raw.githubusercontent.com/phishdestroy/destroylist/"
    "main/rootlist/formats/primary_active/domains.txt"
)
FEODO_RECOMMENDED_IPS_URL = (
    "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
)
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
MALWAREBAZAAR_RECENT_CSV_URL = "https://bazaar.abuse.ch/export/csv/recent/"
ALIENVAULT_REPUTATION_URL = "https://reputation.alienvault.com/reputation.generic"
USER_AGENT = "ThreatLens/1.0 (home-lab threat intelligence collector)"
RETRYABLE_STATUS = {429, 500, 502, 503, 504}
COLLECTION_LOCK_ID = 847_264_193


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
        return fallback or utc_now()
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
    fetched_at = utc_now()
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
        queue_alert_event(
            db,
            event_type="cve",
            event_key=alert_event_key("cve", cve_id),
            title=f"{cve_id} masuk CISA KEV",
            body=f"{item.get('vulnerabilityName', cve_id)}. Vendor: {item.get('vendorProject', 'Unknown')}.",
            severity="High",
            link=f"/#/cve?cve={cve_id}",
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
        fetched_at = utc_now()
        for cve in cve_rows:
            cve_id = cve.get("id")
            if not cve_id:
                continue
            is_new_cve = cve_id not in existing_by_id
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
            if is_new_cve:
                queue_alert_event(
                    db,
                    event_type="cve",
                    event_key=alert_event_key("cve", cve_id),
                    title=f"CVE baru: {cve_id}",
                    body=f"{title[:180]}\nVendor/Product: {vendor} {product}. CVSS: {score}.",
                    severity=severity if severity in {"Low", "Medium", "High", "Critical"} else "Medium",
                    link=f"/#/cve?cve={cve_id}",
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


def collect_news(db: Session, client: httpx.Client) -> tuple[int, dict[str, int], dict[str, str]]:
    count = 0
    source_counts: dict[str, int] = {}
    source_errors: dict[str, str] = {}
    for source, url in RSS_FEEDS.items():
        try:
            response = _get_with_retry(client, url)
            feed = feedparser.parse(response.content)
            source_count = 0
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
                    queue_alert_event(
                        db,
                        event_type="news",
                        event_key=alert_event_key("news", link),
                        title=title,
                        body=f"{source}\n{link}",
                        severity="Medium",
                        link=link,
                    )
                else:
                    for key, value in payload.items():
                        setattr(item, key, value)
                count += 1
                source_count += 1
            source_counts[source] = source_count
            db.commit()
        except Exception as exc:
            db.rollback()
            source_errors[source] = str(exc)
    db.execute(delete(ThreatNews).where(ThreatNews.url.like("https://example.local/%")))
    db.commit()
    return count, source_counts, source_errors


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


def _normalize_domain(value: object) -> str | None:
    candidate = str(value or "").strip().lower().rstrip(".")
    if not candidate or len(candidate) > 253:
        return None
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = candidate.split(".")
    if len(labels) < 2:
        return None
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not re.fullmatch(r"[a-z0-9-]+", label)
        for label in labels
    ):
        return None
    return candidate


def _parse_phishdestroy_json(payload: Any) -> list[str]:
    if not isinstance(payload, dict):
        return []
    values = payload.get("domains")
    if not isinstance(values, list):
        return []
    domains = [_normalize_domain(value) for value in values]
    return list(dict.fromkeys(domain for domain in domains if domain))


def _parse_phishdestroy_text(payload: str) -> list[str]:
    domains = []
    for line in payload.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        domain = _normalize_domain(value)
        if domain:
            domains.append(domain)
    return list(dict.fromkeys(domains))


def _fetch_phishdestroy_domains(
    client: httpx.Client,
) -> tuple[list[str], str]:
    try:
        response = client.get(PHISHDESTROY_URL)
        response.raise_for_status()
        domains = _parse_phishdestroy_json(response.json())
        if domains:
            return domains, "api"
    except (httpx.HTTPError, ValueError):
        pass

    response = _get_with_retry(client, PHISHDESTROY_FALLBACK_URL)
    domains = _parse_phishdestroy_text(response.text)
    if not domains:
        raise ValueError("PhishDestroy API and fallback feed returned no valid domains")
    return domains, "github_fallback"


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
    now = utc_now()
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
            if severity in {"High", "Critical"}:
                queue_alert_event(
                    db,
                    event_type="ioc",
                    event_key=alert_event_key("ioc", f"{indicator_type}:{indicator}"),
                    title=f"IOC baru: {indicator_type.upper()}",
                    body=f"{indicator}\nThreat: {item.threat or 'unknown'}\nSource: {source}",
                    severity=severity,
                    link="/#/ioc",
                )
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
        now = utc_now()
        if item is None:
            indicator = indicator[:255]
            db.add(
                IOC(
                    indicator=indicator,
                    type="url",
                    threat=(row.get("threat") or row.get("Threat") or "malware")[:120],
                    severity="High",
                    source="URLhaus",
                    first_seen=now,
                    last_seen=now,
                )
            )
            queue_alert_event(
                db,
                event_type="ioc",
                event_key=alert_event_key("ioc", f"url:{indicator}"),
                title="IOC baru: URL",
                body=f"{indicator}\nThreat: {row.get('threat') or row.get('Threat') or 'malware'}\nSource: URLhaus",
                severity="High",
                link="/#/ioc",
            )
        else:
            item.last_seen = now
        count += 1
        if count >= 500:
            break
    db.commit()
    return count


def collect_phishdestroy(
    db: Session,
    client: httpx.Client,
) -> tuple[int, str]:
    domains, source = _fetch_phishdestroy_domains(client)

    sample_size = min(1000, len(domains))
    step = max(1, len(domains) // sample_size)
    sampled = domains[::step][:sample_size]
    existing = db.scalars(
        select(IOC).where(IOC.type == "domain", IOC.indicator.in_(sampled))
    ).all()
    existing_by_indicator = {item.indicator: item for item in existing}
    now = utc_now()
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
            queue_alert_event(
                db,
                event_type="ioc",
                event_key=alert_event_key("ioc", f"domain:{domain}"),
                title="IOC baru: DOMAIN",
                body=f"{domain}\nThreat: phishing\nSource: PhishDestroy",
                severity="High",
                link="/#/ioc",
            )
        else:
            item.last_seen = now
            item.severity = "High"
            item.source = "PhishDestroy"
    db.commit()
    return len(sampled), source


def _acquire_collection_lock(db: Session) -> bool:
    if db.get_bind().dialect.name != "postgresql":
        return True
    return bool(
        db.scalar(
            text("SELECT pg_try_advisory_lock(:lock_id)"),
            {"lock_id": COLLECTION_LOCK_ID},
        )
    )


def _release_collection_lock(db: Session) -> None:
    if db.get_bind().dialect.name != "postgresql":
        return
    db.rollback()
    db.execute(
        text("SELECT pg_advisory_unlock(:lock_id)"),
        {"lock_id": COLLECTION_LOCK_ID},
    )
    db.commit()


def _source_status(
    source_id: str,
    name: str,
    category: str,
    status: str,
    *,
    count: int | None = None,
    message: str = "",
) -> dict[str, Any]:
    return {
        "id": source_id,
        "name": name,
        "category": category,
        "status": status,
        "count": count,
        "message": message,
    }


def _retention_cutoff(days: int) -> datetime | None:
    if days <= 0:
        return None
    return utc_now() - timedelta(days=days)


def _delete_result_count(result: Any) -> int:
    return int(getattr(result, "rowcount", 0) or 0)


def _prune_old_data(db: Session, current_run_id: int | None = None) -> dict[str, int]:
    pruned = {
        "pruned_news": 0,
        "pruned_iocs": 0,
        "pruned_collection_runs": 0,
    }

    news_cutoff = _retention_cutoff(settings.news_retention_days)
    if news_cutoff is not None:
        pruned["pruned_news"] = _delete_result_count(
            db.execute(delete(ThreatNews).where(ThreatNews.published_at < news_cutoff))
        )

    ioc_cutoff = _retention_cutoff(settings.ioc_retention_days)
    if ioc_cutoff is not None:
        pruned["pruned_iocs"] = _delete_result_count(
            db.execute(delete(IOC).where(IOC.last_seen < ioc_cutoff))
        )

    run_cutoff = _retention_cutoff(settings.collection_run_retention_days)
    min_keep = max(1, settings.collection_run_min_keep)
    if run_cutoff is not None:
        keep_ids = [
            int(run_id)
            for run_id in db.scalars(
                select(CollectionRun.id).order_by(CollectionRun.started_at.desc()).limit(min_keep)
            ).all()
        ]
        if current_run_id is not None:
            keep_ids.append(current_run_id)
        delete_query = delete(CollectionRun).where(CollectionRun.started_at < run_cutoff)
        if keep_ids:
            delete_query = delete_query.where(CollectionRun.id.not_in(set(keep_ids)))
        pruned["pruned_collection_runs"] = _delete_result_count(db.execute(delete_query))

    db.commit()
    return pruned


def _previous_source_statuses(db: Session, current_run_id: int) -> dict[str, str]:
    previous = db.scalar(
        select(CollectionRun)
        .where(CollectionRun.id < current_run_id)
        .order_by(CollectionRun.started_at.desc())
        .limit(1)
    )
    if previous is None or not previous.details:
        return {}
    try:
        payload = json.loads(previous.details)
    except (TypeError, ValueError):
        return {}
    statuses: dict[str, str] = {}
    for source in payload.get("sources", []):
        source_id = source.get("id")
        status = source.get("status")
        if source_id and status:
            statuses[str(source_id)] = str(status)
    return statuses


def _run_collection_locked(db: Session) -> dict[str, Any]:
    now = utc_now()
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
    sources: list[dict[str, Any]] = []
    with httpx.Client(
        timeout=httpx.Timeout(45),
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json, application/xml, text/xml, */*"},
    ) as client:
        try:
            kev_ids, results["cisa_kev_catalog"] = collect_cisa_kev(db, client)
            sources.append(
                _source_status(
                    "cisa_kev",
                    "CISA KEV",
                    "vulnerability",
                    "ok",
                    count=results["cisa_kev_catalog"],
                )
            )
        except Exception as exc:
            db.rollback()
            kev_ids = set()
            errors["cisa_kev"] = str(exc)
            sources.append(_source_status("cisa_kev", "CISA KEV", "vulnerability", "error", message=str(exc)))
        try:
            results["nvd_cves"] = collect_nvd(db, client, kev_ids)
            sources.append(
                _source_status("nvd", "NVD", "vulnerability", "ok", count=results["nvd_cves"])
            )
        except Exception as exc:
            db.rollback()
            errors["nvd"] = str(exc)
            sources.append(_source_status("nvd", "NVD", "vulnerability", "error", message=str(exc)))
        try:
            news_count, news_source_counts, news_source_errors = collect_news(db, client)
            results["news"] = news_count
            results["news_sources"] = news_source_counts
            for name, count in news_source_counts.items():
                sources.append(
                    _source_status(
                        name.lower().replace(" ", "_"),
                        name,
                        "news",
                        "ok",
                        count=count,
                    )
                )
            for name, error in news_source_errors.items():
                errors[f"news:{name}"] = error
                sources.append(
                    _source_status(
                        name.lower().replace(" ", "_"),
                        name,
                        "news",
                        "error",
                        message=error,
                    )
                )
        except Exception as exc:
            db.rollback()
            errors["news"] = str(exc)
            for name in RSS_FEEDS:
                sources.append(
                    _source_status(
                        name.lower().replace(" ", "_"),
                        name,
                        "news",
                        "error",
                        message=str(exc),
                    )
                )
        try:
            results["urlhaus_iocs"] = collect_urlhaus(db, client)
            if not settings.urlhaus_auth_key:
                results["urlhaus"] = "skipped: URLHAUS_AUTH_KEY not configured"
                sources.append(
                    _source_status(
                        "urlhaus",
                        "URLhaus",
                        "ioc",
                        "skipped",
                        count=0,
                        message="URLHAUS_AUTH_KEY not configured",
                    )
                )
            else:
                sources.append(
                    _source_status(
                        "urlhaus",
                        "URLhaus",
                        "ioc",
                        "ok",
                        count=results["urlhaus_iocs"],
                    )
                )
        except Exception as exc:
            db.rollback()
            errors["urlhaus"] = str(exc)
            sources.append(_source_status("urlhaus", "URLhaus", "ioc", "error", message=str(exc)))
        try:
            phishdestroy_count, phishdestroy_source = collect_phishdestroy(db, client)
            results["phishdestroy_iocs"] = phishdestroy_count
            results["phishdestroy_source"] = phishdestroy_source
            sources.append(
                _source_status(
                    "phishdestroy",
                    "PhishDestroy",
                    "ioc",
                    "fallback" if phishdestroy_source != "api" else "ok",
                    count=phishdestroy_count,
                    message=f"using {phishdestroy_source}",
                )
            )
        except Exception as exc:
            db.rollback()
            errors["phishdestroy"] = str(exc)
            sources.append(_source_status("phishdestroy", "PhishDestroy", "ioc", "error", message=str(exc)))
        try:
            results["feodo_ip_iocs"] = collect_feodo_ips(db, client)
            sources.append(
                _source_status("feodo", "Feodo Tracker", "ioc", "ok", count=results["feodo_ip_iocs"])
            )
        except Exception as exc:
            db.rollback()
            errors["feodo"] = str(exc)
            sources.append(_source_status("feodo", "Feodo Tracker", "ioc", "error", message=str(exc)))
        try:
            results["alienvault_ip_iocs"] = collect_alienvault_ips(db, client)
            sources.append(
                _source_status(
                    "alienvault",
                    "AlienVault Reputation",
                    "ioc",
                    "ok",
                    count=results["alienvault_ip_iocs"],
                )
            )
        except Exception as exc:
            db.rollback()
            errors["alienvault"] = str(exc)
            sources.append(_source_status("alienvault", "AlienVault Reputation", "ioc", "error", message=str(exc)))
        try:
            results["openphish_url_iocs"] = collect_openphish_urls(db, client)
            sources.append(
                _source_status("openphish", "OpenPhish", "ioc", "ok", count=results["openphish_url_iocs"])
            )
        except Exception as exc:
            db.rollback()
            errors["openphish"] = str(exc)
            sources.append(_source_status("openphish", "OpenPhish", "ioc", "error", message=str(exc)))
        try:
            results["malwarebazaar_hash_iocs"] = collect_malwarebazaar_hashes(db, client)
            sources.append(
                _source_status(
                    "malwarebazaar",
                    "MalwareBazaar",
                    "ioc",
                    "ok",
                    count=results["malwarebazaar_hash_iocs"],
                )
            )
        except Exception as exc:
            db.rollback()
            errors["malwarebazaar"] = str(exc)
            sources.append(_source_status("malwarebazaar", "MalwareBazaar", "ioc", "error", message=str(exc)))

    run = db.get(CollectionRun, run.id)
    run.finished_at = utc_now()
    try:
        results.update(_prune_old_data(db, run.id))
    except Exception as exc:
        db.rollback()
        errors["retention"] = str(exc)
        sources.append(_source_status("retention", "Retention pruning", "maintenance", "error", message=str(exc)))
    try:
        results["asset_exposures"] = refresh_asset_exposures(db)
    except Exception as exc:
        db.rollback()
        errors["asset_exposures"] = str(exc)
        sources.append(_source_status("asset_exposures", "Asset exposure matching", "maintenance", "error", message=str(exc)))
    run.status = "partial" if errors else "success"
    run.details = json.dumps({"results": results, "errors": errors, "sources": sources})
    db.commit()
    previous_statuses = _previous_source_statuses(db, run.id)
    for source in sources:
        if source.get("status") != "error":
            continue
        source_id = str(source.get("id", "unknown"))
        source_state = "persistent_error" if previous_statuses.get(source_id) == "error" else "new_error"
        queue_alert_event(
            db,
            event_type="source_health",
            event_key=f"source_health:{run.id}:{source_id}",
            title=f"Source bermasalah: {source.get('name', 'Unknown')}",
            body=str(source.get("message") or "Source collection failed")[:1000],
            severity="High",
            link="/#/sources",
            state=source_state,
        )
    alert_deliveries = flush_alert_events(db)
    if alert_deliveries:
        results["alert_deliveries"] = alert_deliveries
    return {"status": run.status, "results": results, "errors": errors, "sources": sources}


def run_collection(db: Session) -> dict[str, Any]:
    if not _acquire_collection_lock(db):
        return {
            "status": "already_running",
            "results": {},
            "errors": {},
            "sources": [],
        }
    try:
        return _run_collection_locked(db)
    finally:
        _release_collection_lock(db)
