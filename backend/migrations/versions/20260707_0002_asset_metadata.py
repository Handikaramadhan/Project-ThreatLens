"""Add richer asset metadata fields.

Revision ID: 20260707_0002
Revises: 20260707_0001
Create Date: 2026-07-07
"""

from alembic import op
import sqlalchemy as sa


revision = "20260707_0002"
down_revision = "20260707_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("vendor", sa.String(length=120), nullable=False, server_default=""))
    op.add_column("assets", sa.Column("product", sa.String(length=120), nullable=False, server_default=""))
    op.add_column("assets", sa.Column("version", sa.String(length=80), nullable=False, server_default=""))
    op.add_column("assets", sa.Column("environment", sa.String(length=40), nullable=False, server_default=""))
    op.add_column("assets", sa.Column("criticality", sa.String(length=16), nullable=False, server_default="Medium"))
    op.add_column("assets", sa.Column("internet_exposed", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    op.drop_column("assets", "internet_exposed")
    op.drop_column("assets", "criticality")
    op.drop_column("assets", "environment")
    op.drop_column("assets", "version")
    op.drop_column("assets", "product")
    op.drop_column("assets", "vendor")
