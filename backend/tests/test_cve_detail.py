import json
import unittest
from datetime import datetime

from fastapi import Response
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.cve_routes import cve_detail
from app.core.database import Base
from app.core.time import utc_now
from app.models.entities import Asset, AssetExposure, CVE, CVEDetail, CVEWebEnrichment, IOC, ThreatNews
from app.services.cve_pdf import build_cve_pdf


class CVEDetailTests(unittest.TestCase):
    def test_cached_detail_includes_cvss_relations_and_remediation(self) -> None:
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(
            engine,
            tables=[
                CVE.__table__,
                CVEDetail.__table__,
                CVEWebEnrichment.__table__,
                Asset.__table__,
                AssetExposure.__table__,
                IOC.__table__,
                ThreatNews.__table__,
            ],
        )
        now = utc_now()
        with Session(engine) as db:
            db.add(
                CVE(
                    cve_id="CVE-2099-0001",
                    title="Example vulnerability",
                    description="Local description",
                    severity="Critical",
                    vendor="Example",
                    product="Secure App",
                    cvss_score=9.8,
                    kev=True,
                    published_at=now,
                    source="NVD",
                )
            )
            db.add(
                CVEDetail(
                    cve_id="CVE-2099-0001",
                    nvd_payload=json.dumps(
                        {
                            "description": "Cached NVD description",
                            "cvss": {
                                "version": "3.1",
                                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "base_score": 9.8,
                                "base_severity": "Critical",
                                "attack_vector": "Network",
                                "attack_complexity": "Low",
                                "privileges_required": "None",
                                "user_interaction": "None",
                                "scope": "Unchanged",
                                "confidentiality_impact": "High",
                                "integrity_impact": "High",
                                "availability_impact": "High",
                            },
                            "weaknesses": ["CWE-78"],
                            "affected_products": [
                                {
                                    "vendor": "Example",
                                    "product": "Secure App",
                                    "version": "1.0",
                                    "vulnerable": True,
                                    "version_range": "< 2.0",
                                }
                            ],
                            "references": [],
                        }
                    ),
                    kev_payload=json.dumps(
                        {
                            "dateAdded": "2099-01-02",
                            "dueDate": "2099-01-20",
                            "requiredAction": "Apply updates per vendor instructions.",
                            "knownRansomwareCampaignUse": "Known",
                        }
                    ),
                    nvd_fetched_at=now,
                    kev_fetched_at=now,
                )
            )
            db.add(
                CVEWebEnrichment(
                    cve_id="CVE-2099-0001",
                    payload=json.dumps(
                        {
                            "mitigations": [
                                {
                                    "text": "Upgrade Secure App to 2.0.",
                                    "source": "Example CNA via CVE.org",
                                    "url": "https://example.test/cve",
                                }
                            ],
                            "workarounds": [
                                {
                                    "text": "Disable the vulnerable endpoint.",
                                    "source": "Example CNA via CVE.org",
                                    "url": "https://example.test/cve",
                                }
                            ],
                            "sources": [
                                {
                                    "url": "https://example.test/advisory",
                                    "source": "Example CNA",
                                    "tags": ["Vendor Advisory"],
                                }
                            ],
                        }
                    ),
                    fetched_at=now,
                )
            )
            asset = Asset(
                name="app-prod-01",
                asset_type="Application",
                os_version="1.0",
                owner="Platform",
                risk="Critical",
            )
            db.add(asset)
            db.flush()
            db.add(
                AssetExposure(
                    asset_id=asset.id,
                    cve_id="CVE-2099-0001",
                    matching_score=5,
                    risk="Critical",
                )
            )
            db.add(
                IOC(
                    indicator="203.0.113.10",
                    type="ip",
                    threat="CVE-2099-0001 exploitation",
                    severity="High",
                    source="Test feed",
                )
            )
            db.add(
                ThreatNews(
                    title="CVE-2099-0001 exploited",
                    url="https://example.test/advisory",
                    source="Test",
                    published_at=now,
                    summary="Observed exploitation.",
                )
            )
            db.commit()

            result = cve_detail("cve-2099-0001", Response(), db, object())

            self.assertEqual(result.cvss.base_score, 9.8)
            self.assertTrue(result.exploit_status.known_exploited)
            self.assertEqual(result.mitigation[0].text, "Apply updates per vendor instructions.")
            self.assertEqual(result.mitigation[1].source, "Example CNA via CVE.org")
            self.assertEqual(result.workarounds[0].text, "Disable the vulnerable endpoint.")
            self.assertEqual(result.remediation_sources[0].tags, ["Vendor Advisory"])
            self.assertEqual(result.related_assets[0].name, "app-prod-01")
            self.assertEqual(result.related_iocs[0].indicator, "203.0.113.10")
            self.assertEqual(result.related_news[0].source, "Test")
            self.assertEqual(result.root_cause.category, "Command injection")
            self.assertEqual(result.mitre_techniques[0].technique_id, "T1190")
            self.assertTrue(
                any(item.technique_id == "T1059" for item in result.mitre_techniques)
            )

            pdf = build_cve_pdf(result)
            self.assertTrue(pdf.startswith(b"%PDF-"))
            self.assertGreater(len(pdf), 5000)


if __name__ == "__main__":
    unittest.main()
