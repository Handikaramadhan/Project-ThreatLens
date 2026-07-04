import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from fastapi import Response
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.cve_routes import list_cves
from app.core.database import Base
from app.models.entities import CVE


class CVEListTests(unittest.TestCase):
    def test_paginates_searches_and_filters_up_to_500_items(self) -> None:
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine, tables=[CVE.__table__])
        now = datetime.utcnow()
        with Session(engine) as db:
            db.add_all(
                [
                    CVE(
                        cve_id=f"CVE-2099-{index:04}",
                        title=f"Example vulnerability {index}",
                        description="",
                        severity="Critical" if index % 2 == 0 else "High",
                        vendor="Acme" if index == 619 else "Example",
                        product="Gateway",
                        cvss_score=9.8,
                        kev=False,
                        published_at=now - timedelta(minutes=index),
                        source="test",
                    )
                    for index in range(620)
                ]
            )
            db.commit()

            first = list_cves(Response(), "", "All", 1, 500, db, object())
            second = list_cves(Response(), "", "All", 2, 500, db, object())
            filtered = list_cves(Response(), "Acme", "High", 1, 500, db, object())

            self.assertEqual(first.total, 620)
            self.assertEqual(first.pages, 2)
            self.assertEqual(len(first.items), 500)
            self.assertEqual(len(second.items), 120)
            self.assertEqual(filtered.total, 1)
            self.assertEqual(filtered.items[0].vendor, "Acme")

    def test_fetches_exact_cve_from_nvd_when_missing_locally(self) -> None:
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine, tables=[CVE.__table__])

        def cache_cve(db: Session, cve_id: str) -> CVE:
            item = CVE(
                cve_id=cve_id,
                title="Oracle Payments vulnerability",
                description="",
                severity="Critical",
                vendor="Oracle",
                product="Payments",
                cvss_score=9.8,
                kev=False,
                published_at=datetime(2026, 5, 28),
                source="NVD",
            )
            db.add(item)
            db.commit()
            return item

        with Session(engine) as db:
            response = Response()
            with patch(
                "app.api.cve_routes.fetch_and_store_nvd_cve",
                side_effect=cache_cve,
            ) as fetch:
                result = list_cves(
                    response,
                    "CVE-2026-46817",
                    "All",
                    1,
                    500,
                    db,
                    object(),
                )
                cached = list_cves(
                    Response(),
                    "CVE-2026-46817",
                    "All",
                    1,
                    500,
                    db,
                    object(),
                )

            self.assertEqual(result.total, 1)
            self.assertEqual(result.items[0].cve_id, "CVE-2026-46817")
            self.assertEqual(cached.total, 1)
            fetch.assert_called_once_with(db, "CVE-2026-46817")
            self.assertEqual(response.headers["X-ThreatLens-NVD-Lookup"], "fetched")


if __name__ == "__main__":
    unittest.main()
