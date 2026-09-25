"""Add per-user alert preferences and delivery history.

Revision ID: 20260710_0004
Revises: 20260707_0003
Create Date: 2026-07-10
"""

from alembic import op
import sqlalchemy as sa


revision = "20260710_0004"
down_revision = "20260707_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alert_preferences",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("telegram_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("telegram_chat_id", sa.String(length=80), nullable=False, server_default=""),
        sa.Column("discord_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("discord_webhook_secret", sa.Text(), nullable=False, server_default=""),
        sa.Column("notify_news", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("notify_cve", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("notify_asset_exposure", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("notify_ioc", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("notify_source_health", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("minimum_severity", sa.String(length=16), nullable=False, server_default="High"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("user_id"),
    )
    op.create_index(op.f("ix_alert_preferences_user_id"), "alert_preferences", ["user_id"], unique=True)
    op.create_table(
        "alert_deliveries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("event_key", sa.String(length=255), nullable=False),
        sa.Column("channel", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False, server_default="Medium"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("error", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("sent_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint("user_id", "channel", "event_key", name="uq_alert_delivery_user_channel_event"),
    )
    op.create_index(op.f("ix_alert_deliveries_user_id"), "alert_deliveries", ["user_id"])
    op.create_index(op.f("ix_alert_deliveries_event_type"), "alert_deliveries", ["event_type"])
    op.create_index(op.f("ix_alert_deliveries_channel"), "alert_deliveries", ["channel"])
    op.create_index(op.f("ix_alert_deliveries_status"), "alert_deliveries", ["status"])
    op.create_index(op.f("ix_alert_deliveries_created_at"), "alert_deliveries", ["created_at"])


def downgrade() -> None:
    op.drop_table("alert_deliveries")
    op.drop_table("alert_preferences")
