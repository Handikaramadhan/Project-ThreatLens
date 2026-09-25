import json
import unittest
from datetime import datetime

from fastapi import Request
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from pydantic import ValidationError

from app.api.asset_routes import create_asset, delete_asset, list_assets, update_asset
from app.core.database import Base
from app.core.time import utc_now
from app.models.entities import Asset, AssetExposure, AuditLog, CVE, CVEDetail, User
from app.schemas.assets import AssetWrite
from app.services.asset_matching import explain_exposure, refresh_asset_exposures
from app.services.auth import AuthContext


class AssetSchemaTests(unittest.TestCase):
    def test_asset_fields_are_normalized(self) -> None:
        payload = AssetWrite(
            name="  web-prod-01  ",
            asset_type="  Server  ",
            os_version="  Rocky Linux 9  ",
            owner="  Platform  ",
            risk="High",
        )

        self.assertEqual(payload.name, "web-prod-01")
        self.assertEqual(payload.asset_type, "Server")
        self.assertEqual(payload.owner, "Platform")

    def test_asset_risk_is_restricted(self) -> None:
        with self.assertRaises(ValidationError):
            AssetWrite(name="web-prod-01", asset_type="Server", risk="Urgent")

    def test_asset_requires_name_and_type(self) -> None:
        with self.assertRaises(ValidationError):
            AssetWrite(name="", asset_type="")

    def test_asset_crud_and_exposure_count(self) -> None:
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(
            engine,
            tables=[Asset.__table__, AssetExposure.__table__, AuditLog.__table__, CVE.__table__, CVEDetail.__table__, User.__table__],
        )

        with Session(engine) as db:
            user = User(username="tester", password_hash="not-used", role="admin")
            db.add(user)
            db.commit()
            request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 12345)})
            context = AuthContext(user=user, session=object())
            created = create_asset(
                AssetWrite(name="app-prod-01", asset_type="Application", owner="Platform"),
                request,
                db,
                context,
            )
            self.assertEqual(len(list_assets(db, object())), 1)

            updated = update_asset(
                created.id,
                AssetWrite(
                    name="app-prod-01",
                    asset_type="Application",
                    os_version="2.1",
                    owner="SOC",
                    risk="High",
                ),
                request,
                db,
                context,
            )
            self.assertEqual(updated.owner, "SOC")
            self.assertEqual(updated.risk, "High")

            db.add(
                AssetExposure(
                    asset_id=created.id,
                    cve_id="CVE-2099-0001",
                    matching_score=1,
                    risk="High",
                )
            )
            db.commit()
            self.assertEqual(list_assets(db, object())[0].matching_cve, 1)

            delete_asset(created.id, request, db, context)
            self.assertEqual(list_assets(db, object()), [])

    def test_refresh_asset_exposures_matches_product_and_version_range(self) -> None:
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(
            engine,
            tables=[Asset.__table__, AssetExposure.__table__, CVE.__table__, CVEDetail.__table__],
        )

        with Session(engine) as db:
            asset = Asset(
                name="edge-nginx-01",
                asset_type="Server",
                os_version="nginx 1.24.0 on Ubuntu 22.04",
                owner="Platform",
                risk="High",
            )
            db.add(asset)
            db.add_all(
                [
                    CVE(
                        cve_id="CVE-2099-0001",
                        title="nginx issue",
                        description="",
                        severity="High",
                        vendor="F5",
                        product="nginx",
                        cvss_score=8.1,
                        kev=False,
                        published_at=utc_now(),
                        source="test",
                    ),
                    CVEDetail(
                        cve_id="CVE-2099-0001",
                        nvd_payload=json.dumps(
                            {
                                "affected_products": [
                                    {
                                        "vendor": "F5",
                                        "product": "nginx",
                                        "version": "All / unspecified",
                                        "vulnerable": True,
                                        "version_range": "< 1.25.0",
                                    }
                                ]
                            }
                        ),
                    ),
                    CVE(
                        cve_id="CVE-2099-0002",
                        title="apache issue",
                        description="",
                        severity="Critical",
                        vendor="Apache",
                        product="httpd",
                        cvss_score=9.1,
                        kev=False,
                        published_at=utc_now(),
                        source="test",
                    ),
                ]
            )
            db.commit()

            count = refresh_asset_exposures(db)
            db.commit()

            exposures = db.scalars(select(AssetExposure)).all()
            self.assertEqual(count, 1)
            self.assertEqual(len(exposures), 1)
            self.assertEqual(exposures[0].cve_id, "CVE-2099-0001")
            self.assertGreaterEqual(exposures[0].matching_score, 80)

    def test_refresh_asset_exposures_matches_rocky_linux_to_rhel_major_version(self) -> None:
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(
            engine,
            tables=[Asset.__table__, AssetExposure.__table__, CVE.__table__, CVEDetail.__table__],
        )

        with Session(engine) as db:
            db.add(
                Asset(
                    name="Rocky Linux",
                    asset_type="Server",
                    os_version="9.8",
                    owner="Platform",
                    risk="Medium",
                )
            )
            db.add(
                CVE(
                    cve_id="CVE-2099-0003",
                    title="RHEL issue",
                    description="",
                    severity="High",
                    vendor="Red Hat",
                    product="Enterprise Linux",
                    cvss_score=8.1,
                    kev=False,
                    published_at=utc_now(),
                    source="test",
                )
            )
            db.add(
                CVEDetail(
                    cve_id="CVE-2099-0003",
                    nvd_payload=json.dumps(
                        {
                            "affected_products": [
                                {
                                    "vendor": "Red Hat",
                                    "product": "Enterprise Linux",
                                    "version": "9",
                                    "vulnerable": True,
                                    "version_range": "",
                                }
                            ]
                        }
                    ),
                )
            )
            db.add(
                CVE(
                    cve_id="CVE-2099-0004",
                    title="RHEL 10 issue",
                    description="",
                    severity="Critical",
                    vendor="Red Hat",
                    product="Red Hat Enterprise Linux 10",
                    cvss_score=9.1,
                    kev=False,
                    published_at=utc_now(),
                    source="test",
                )
            )
            db.commit()

            count = refresh_asset_exposures(db)
            db.commit()

            exposure = db.scalar(select(AssetExposure))
            self.assertEqual(count, 1)
            self.assertIsNotNone(exposure)
            self.assertEqual(exposure.cve_id, "CVE-2099-0003")

            cve = db.scalar(select(CVE).where(CVE.cve_id == "CVE-2099-0003"))
            detail = db.get(CVEDetail, "CVE-2099-0003")
            explanation = explain_exposure(db.scalar(select(Asset)), cve, detail, exposure.matching_score)
            self.assertEqual(explanation.confidence, "Medium")
            self.assertEqual(explanation.match_type, "OS family alias")
            self.assertIn("Enterprise Linux", explanation.affected_product)
            self.assertTrue(explanation.evidence)
            self.assertTrue(explanation.limitations)


if __name__ == "__main__":
    unittest.main()
