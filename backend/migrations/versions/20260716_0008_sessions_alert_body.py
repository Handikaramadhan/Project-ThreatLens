"""session metadata and async alert payload

Revision ID: 20260716_0008
Revises: 20260714_0007
Create Date: 2026-07-16
"""

from alembic import op
import sqlalchemy as sa


revision = "20260716_0008"
down_revision = "20260714_0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("auth_sessions", sa.Column("last_seen_at", sa.DateTime(), nullable=True))
    op.add_column("auth_sessions", sa.Column("ip_address", sa.String(length=64), nullable=False, server_default=""))
    op.add_column("auth_sessions", sa.Column("user_agent", sa.String(length=255), nullable=False, server_default=""))
    op.execute("update auth_sessions set last_seen_at = created_at where last_seen_at is null")
    op.alter_column("auth_sessions", "last_seen_at", nullable=False)
    op.create_index(op.f("ix_auth_sessions_last_seen_at"), "auth_sessions", ["last_seen_at"], unique=False)

    op.add_column("alert_deliveries", sa.Column("body", sa.Text(), nullable=False, server_default=""))
    op.add_column("alert_deliveries", sa.Column("link", sa.String(length=500), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("alert_deliveries", "link")
    op.drop_column("alert_deliveries", "body")
    op.drop_index(op.f("ix_auth_sessions_last_seen_at"), table_name="auth_sessions")
    op.drop_column("auth_sessions", "user_agent")
    op.drop_column("auth_sessions", "ip_address")
    op.drop_column("auth_sessions", "last_seen_at")
