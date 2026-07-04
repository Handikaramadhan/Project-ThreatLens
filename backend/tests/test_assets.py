import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from pydantic import ValidationError

from app.api.asset_routes import create_asset, delete_asset, list_assets, update_asset
from app.core.database import Base
from app.models.entities import Asset, AssetExposure
from app.schemas.assets import AssetWrite


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
        Base.metadata.create_all(engine, tables=[Asset.__table__, AssetExposure.__table__])

        with Session(engine) as db:
            created = create_asset(
                AssetWrite(name="app-prod-01", asset_type="Application", owner="Platform"),
                db,
                object(),
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
                db,
                object(),
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

            delete_asset(created.id, db, object())
            self.assertEqual(list_assets(db, object()), [])


if __name__ == "__main__":
    unittest.main()
