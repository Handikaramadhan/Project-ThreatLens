"""Add granular alert preference controls.

Revision ID: 20260712_0006
Revises: 20260710_0005
Create Date: 2026-07-12
"""

from alembic import op
import sqlalchemy as sa


revision = "20260712_0006"
down_revision = "20260710_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "alert_preferences",
        sa.Column("cve_minimum_severity", sa.String(length=16), nullable=False, server_default="High"),
    )
    op.add_column(
        "alert_preferences",
        sa.Column("asset_exposure_minimum_severity", sa.String(length=16), nullable=False, server_default="High"),
    )
    op.add_column(
        "alert_preferences",
        sa.Column("ioc_minimum_severity", sa.String(length=16), nullable=False, server_default="High"),
    )
    op.add_column(
        "alert_preferences",
        sa.Column("source_health_alert_mode", sa.String(length=24), nullable=False, server_default="new_error"),
    )
    op.execute(
        """
        update alert_preferences
        set cve_minimum_severity = minimum_severity,
            asset_exposure_minimum_severity = minimum_severity,
            ioc_minimum_severity = minimum_severity
        """
    )


def downgrade() -> None:
    op.drop_column("alert_preferences", "source_health_alert_mode")
    op.drop_column("alert_preferences", "ioc_minimum_severity")
    op.drop_column("alert_preferences", "asset_exposure_minimum_severity")
    op.drop_column("alert_preferences", "cve_minimum_severity")
