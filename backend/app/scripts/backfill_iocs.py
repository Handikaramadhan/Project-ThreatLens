import json
from typing import Callable

import httpx
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from collector.collector import (
    USER_AGENT,
    collect_alienvault_ips,
    collect_feodo_ips,
    collect_malwarebazaar_hashes,
    collect_openphish_urls,
)

Collector = Callable[[Session, httpx.Client], int]


def main() -> None:
    collectors: dict[str, Collector] = {
        "feodo_ip_iocs": collect_feodo_ips,
        "alienvault_ip_iocs": collect_alienvault_ips,
        "openphish_url_iocs": collect_openphish_urls,
        "malwarebazaar_hash_iocs": collect_malwarebazaar_hashes,
    }
    results: dict[str, int] = {}
    errors: dict[str, str] = {}
    with SessionLocal() as db:
        with httpx.Client(
            timeout=httpx.Timeout(45),
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT, "Accept": "text/plain, text/csv, */*"},
        ) as client:
            for name, collector in collectors.items():
                try:
                    results[name] = collector(db, client)
                except Exception as exc:
                    db.rollback()
                    errors[name] = str(exc)
    print(json.dumps({"results": results, "errors": errors}, indent=2))


if __name__ == "__main__":
    main()
