"""Add audit logs and alert retry count.

Revision ID: 20260714_0007
Revises: 20260712_0006
Create Date: 2026-07-14
"""

from alembic import op
import sqlalchemy as sa


revision = "20260714_0007"
down_revision = "20260712_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "alert_deliveries",
        sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("actor_username", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("action", sa.String(length=80), nullable=False),
        sa.Column("target_type", sa.String(length=80), nullable=False, server_default=""),
        sa.Column("target_id", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="success"),
        sa.Column("ip_address", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("details", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index(op.f("ix_audit_logs_actor_id"), "audit_logs", ["actor_id"])
    op.create_index(op.f("ix_audit_logs_actor_username"), "audit_logs", ["actor_username"])
    op.create_index(op.f("ix_audit_logs_action"), "audit_logs", ["action"])
    op.create_index(op.f("ix_audit_logs_target_type"), "audit_logs", ["target_type"])
    op.create_index(op.f("ix_audit_logs_status"), "audit_logs", ["status"])
    op.create_index(op.f("ix_audit_logs_created_at"), "audit_logs", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_column("alert_deliveries", "retry_count")
