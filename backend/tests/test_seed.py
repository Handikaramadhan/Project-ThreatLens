import unittest
from datetime import datetime

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.core.time import utc_now
from app.models.entities import Asset, AssetExposure, CVE, IOC, MitreTechnique, ThreatNews
from app.services.seed import cleanup_demo_records


class DemoDataCleanupTests(unittest.TestCase):
    def test_removes_only_bundled_demo_records(self) -> None:
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(
            engine,
            tables=[
                CVE.__table__,
                IOC.__table__,
                ThreatNews.__table__,
                MitreTechnique.__table__,
                Asset.__table__,
                AssetExposure.__table__,
            ],
        )
        now = utc_now()
        with Session(engine) as db:
            demo_cve = CVE(
                cve_id="CVE-2026-5281",
                title="Chrome zero-day remote code execution",
                description="",
                severity="Critical",
                vendor="Google",
                product="Chrome",
                published_at=now,
                source="NVD/KEV",
            )
            real_cve = CVE(
                cve_id="CVE-2099-0001",
                title="Verified record",
                description="Verified source data",
                severity="High",
                vendor="Example",
                product="Gateway",
                published_at=now,
                source="NVD",
            )
            asset = Asset(name="production", asset_type="Server")
            demo_asset = Asset(
                name="FortiGate-01",
                asset_type="Firewall",
                os_version="7.2.5",
                owner="Network",
                risk="High",
            )
            db.add_all(
                [
                    demo_cve,
                    real_cve,
                    asset,
                    demo_asset,
                    MitreTechnique(
                        technique_id="T1059",
                        name="Command and Scripting Interpreter",
                        tactic="Execution",
                        count=45,
                    ),
                    IOC(
                        indicator="185.197.xx.23",
                        type="ip",
                        threat="demo",
                        severity="High",
                        source="AbuseIPDB",
                    ),
                    IOC(
                        indicator="xxl-security.example",
                        type="domain",
                        threat="verified",
                        severity="Medium",
                        source="Verified Feed",
                    ),
                    ThreatNews(
                        title="Demo",
                        url="https://example.local/news/demo",
                        source="The Hacker News",
                        published_at=now,
                    ),
                    ThreatNews(
                        title="Verified",
                        url="https://news.example.test/verified",
                        source="Verified Feed",
                        published_at=now,
                    ),
                ]
            )
            db.flush()
            db.add(
                AssetExposure(
                    asset_id=asset.id,
                    cve_id=demo_cve.cve_id,
                    matching_score=5,
                    risk="High",
                )
            )
            db.commit()

            cleanup_demo_records(db)

            self.assertIsNone(db.scalar(select(CVE).where(CVE.cve_id == demo_cve.cve_id)))
            self.assertIsNotNone(db.scalar(select(CVE).where(CVE.cve_id == real_cve.cve_id)))
            self.assertIsNone(
                db.scalar(select(IOC).where(IOC.indicator == "185.197.xx.23"))
            )
            self.assertIsNotNone(
                db.scalar(select(IOC).where(IOC.indicator == "xxl-security.example"))
            )
            self.assertEqual(
                db.scalar(select(func.count()).select_from(AssetExposure)),
                0,
            )
            self.assertIsNone(
                db.scalar(select(Asset).where(Asset.name == demo_asset.name))
            )
            self.assertIsNotNone(
                db.scalar(select(Asset).where(Asset.name == asset.name))
            )
            self.assertEqual(
                db.scalar(select(func.count()).select_from(MitreTechnique)),
                0,
            )
            self.assertEqual(
                db.scalar(select(func.count()).select_from(ThreatNews)),
                1,
            )
        engine.dispose()


if __name__ == "__main__":
    unittest.main()
