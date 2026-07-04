import json
import unittest
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.models.entities import CVE, CVEDetail
from app.services.cve_detail import fetch_and_store_nvd_cve


class NVDLookupTests(unittest.TestCase):
    def test_fetches_and_caches_exact_nvd_cve(self) -> None:
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine, tables=[CVE.__table__, CVEDetail.__table__])
        nvd_record = {
            "id": "CVE-2026-46817",
            "published": "2026-05-28T18:15:00.000",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Vulnerability in the Oracle Payments product.",
                }
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                        },
                    }
                ]
            },
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:oracle:payments:*:*:*:*:*:*:*:*",
                                }
                            ]
                        }
                    ]
                }
            ],
        }

        with Session(engine) as db:
            with patch(
                "app.services.cve_detail._fetch_nvd_record",
                return_value=nvd_record,
            ):
                item = fetch_and_store_nvd_cve(db, "CVE-2026-46817")

            detail = db.get(CVEDetail, "CVE-2026-46817")
            self.assertEqual(item.vendor, "Oracle")
            self.assertEqual(item.product, "Payments")
            self.assertEqual(item.severity, "Critical")
            self.assertEqual(item.cvss_score, 9.8)
            self.assertEqual(item.source, "NVD")
            self.assertIsNotNone(detail)
            self.assertEqual(
                json.loads(detail.nvd_payload)["description"],
                "Vulnerability in the Oracle Payments product.",
            )


if __name__ == "__main__":
    unittest.main()
