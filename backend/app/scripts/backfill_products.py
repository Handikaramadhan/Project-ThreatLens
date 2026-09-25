import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

import httpx
from sqlalchemy import or_, select

from app.core.database import SessionLocal
from app.core.time import utc_now
from app.models.entities import CVE
from app.services.product_resolution import (
    extract_cve_org_products,
    infer_product_from_description,
    is_unknown_product,
)

CVE_API_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
WORKERS = max(1, min(int(os.getenv("PRODUCT_BACKFILL_WORKERS", "6")), 12))
LIMIT = max(0, int(os.getenv("PRODUCT_BACKFILL_LIMIT", "0")))


def fetch_record(client: httpx.Client, cve_id: str) -> tuple[str, dict[str, Any] | None]:
    for attempt in range(3):
        try:
            response = client.get(CVE_API_URL.format(cve_id=cve_id))
            if response.status_code == 404:
                return cve_id, None
            if response.status_code == 429:
                time.sleep(2 ** (attempt + 1))
                continue
            response.raise_for_status()
            payload = response.json()
            return cve_id, payload if isinstance(payload, dict) else None
        except (httpx.HTTPError, ValueError):
            if attempt == 2:
                return cve_id, None
            time.sleep(1 + attempt)
    return cve_id, None


def main() -> None:
    with SessionLocal() as db:
        statement = (
            select(CVE)
            .where(
                or_(
                    CVE.product.is_(None),
                    CVE.product == "",
                    CVE.product.ilike("unknown"),
                )
            )
            .order_by(CVE.published_at.desc())
        )
        if LIMIT:
            statement = statement.limit(LIMIT)
        rows = list(db.scalars(statement).all())
        descriptions = {item.cve_id: item.description for item in rows}
        print(f"product-backfill start total={len(rows)} workers={WORKERS}", flush=True)
        updated = 0
        inferred = 0
        failed = 0
        started = utc_now()

        with httpx.Client(
            timeout=httpx.Timeout(15, connect=5),
            follow_redirects=True,
            headers={"User-Agent": "ThreatLens/1.0 product backfill", "Accept": "application/json"},
        ) as client:
            with ThreadPoolExecutor(max_workers=WORKERS) as executor:
                futures = {
                    executor.submit(fetch_record, client, item.cve_id): item.cve_id
                    for item in rows
                }
                for index, future in enumerate(as_completed(futures), start=1):
                    cve_id, record = future.result()
                    item = db.scalar(select(CVE).where(CVE.cve_id == cve_id))
                    if item is None or not is_unknown_product(item.product):
                        continue
                    products = extract_cve_org_products(record)
                    if products:
                        primary = products[0]
                        item.product = str(primary["product"])[:120]
                        if is_unknown_product(item.vendor):
                            item.vendor = str(primary["vendor"])[:120]
                        updated += 1
                    else:
                        fallback = infer_product_from_description(descriptions.get(cve_id, ""))
                        if fallback:
                            vendor, product = fallback
                            item.product = product[:120]
                            if is_unknown_product(item.vendor):
                                item.vendor = vendor[:120]
                            inferred += 1
                        else:
                            failed += 1
                    if index % 100 == 0:
                        db.commit()
                        print(
                            f"product-backfill progress={index}/{len(rows)} "
                            f"cna={updated} inferred={inferred} unresolved={failed}",
                            flush=True,
                        )
        db.commit()
        elapsed = (utc_now() - started).total_seconds()
        print(
            f"product-backfill done cna={updated} inferred={inferred} "
            f"unresolved={failed} elapsed={elapsed:.1f}s",
            flush=True,
        )


if __name__ == "__main__":
    main()
