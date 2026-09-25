"""Add asset exposure workflow review fields.

Revision ID: 20260707_0003
Revises: 20260707_0002
Create Date: 2026-07-07
"""

from alembic import op
import sqlalchemy as sa


revision = "20260707_0003"
down_revision = "20260707_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("asset_exposures", sa.Column("status", sa.String(length=32), nullable=False, server_default="open"))
    op.add_column("asset_exposures", sa.Column("review_note", sa.Text(), nullable=False, server_default=""))
    op.add_column("asset_exposures", sa.Column("reviewed_at", sa.DateTime(), nullable=True))
    op.add_column("asset_exposures", sa.Column("reviewed_by", sa.String(length=64), nullable=False, server_default=""))
    op.create_index(op.f("ix_asset_exposures_status"), "asset_exposures", ["status"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_asset_exposures_status"), table_name="asset_exposures")
    op.drop_column("asset_exposures", "reviewed_by")
    op.drop_column("asset_exposures", "reviewed_at")
    op.drop_column("asset_exposures", "review_note")
    op.drop_column("asset_exposures", "status")
