"""Initial ThreatLens schema.

Revision ID: 20260707_0001
Revises:
Create Date: 2026-07-07
"""

from alembic import op
import sqlalchemy as sa


revision = "20260707_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cve",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("vendor", sa.String(length=120), nullable=False),
        sa.Column("product", sa.String(length=120), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=False),
        sa.Column("kev", sa.Boolean(), nullable=False),
        sa.Column("published_at", sa.DateTime(), nullable=False),
        sa.Column("source", sa.String(length=120), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_cve_cve_id"), "cve", ["cve_id"], unique=True)
    op.create_index(op.f("ix_cve_published_at"), "cve", ["published_at"], unique=False)
    op.create_index(op.f("ix_cve_severity"), "cve", ["severity"], unique=False)
    op.create_index(op.f("ix_cve_vendor"), "cve", ["vendor"], unique=False)

    op.create_table(
        "cve_details",
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("nvd_payload", sa.Text(), nullable=False),
        sa.Column("kev_payload", sa.Text(), nullable=False),
        sa.Column("nvd_fetched_at", sa.DateTime(), nullable=True),
        sa.Column("kev_fetched_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("cve_id"),
    )

    op.create_table(
        "cve_web_enrichment",
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("cve_id"),
    )

    op.create_table(
        "ioc",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("indicator", sa.String(length=255), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("threat", sa.String(length=120), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("source", sa.String(length=120), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("indicator", "type", name="uq_ioc_indicator_type"),
    )
    op.create_index(op.f("ix_ioc_indicator"), "ioc", ["indicator"], unique=False)
    op.create_index(op.f("ix_ioc_severity"), "ioc", ["severity"], unique=False)
    op.create_index(op.f("ix_ioc_type"), "ioc", ["type"], unique=False)

    op.create_table(
        "threat_news",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("url", sa.String(length=500), nullable=False),
        sa.Column("source", sa.String(length=120), nullable=False),
        sa.Column("published_at", sa.DateTime(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("url"),
    )
    op.create_index(op.f("ix_threat_news_published_at"), "threat_news", ["published_at"], unique=False)

    op.create_table(
        "mitre_attack",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("technique_id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("tactic", sa.String(length=80), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("technique_id"),
    )
    op.create_index(op.f("ix_mitre_attack_tactic"), "mitre_attack", ["tactic"], unique=False)

    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("asset_type", sa.String(length=80), nullable=False),
        sa.Column("os_version", sa.String(length=120), nullable=False),
        sa.Column("owner", sa.String(length=120), nullable=False),
        sa.Column("risk", sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("channel", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "collection_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("details", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_collection_runs_started_at"), "collection_runs", ["started_at"], unique=False)
    op.create_index(op.f("ix_collection_runs_status"), "collection_runs", ["status"], unique=False)

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_users_active"), "users", ["active"], unique=False)
    op.create_index(op.f("ix_users_role"), "users", ["role"], unique=False)
    op.create_index(op.f("ix_users_username"), "users", ["username"], unique=True)

    op.create_table(
        "asset_exposures",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("matching_score", sa.Integer(), nullable=False),
        sa.Column("risk", sa.String(length=16), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_asset_exposures_cve_id"), "asset_exposures", ["cve_id"], unique=False)

    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("csrf_token", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("csrf_token"),
    )
    op.create_index(op.f("ix_auth_sessions_expires_at"), "auth_sessions", ["expires_at"], unique=False)
    op.create_index(op.f("ix_auth_sessions_token_hash"), "auth_sessions", ["token_hash"], unique=True)
    op.create_index(op.f("ix_auth_sessions_user_id"), "auth_sessions", ["user_id"], unique=False)

    op.create_table(
        "ai_conversations",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=160), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_ai_conversations_updated_at"), "ai_conversations", ["updated_at"], unique=False)
    op.create_index(op.f("ix_ai_conversations_user_id"), "ai_conversations", ["user_id"], unique=False)

    op.create_table(
        "cve_ai_enrichment",
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("provider", sa.String(length=80), nullable=False),
        sa.Column("model", sa.String(length=120), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("generated_by", sa.Integer(), nullable=True),
        sa.Column("generated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["generated_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("cve_id"),
    )

    op.create_table(
        "ai_messages",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("conversation_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("citations", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["conversation_id"], ["ai_conversations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_ai_messages_conversation_id"), "ai_messages", ["conversation_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_ai_messages_conversation_id"), table_name="ai_messages")
    op.drop_table("ai_messages")
    op.drop_table("cve_ai_enrichment")
    op.drop_index(op.f("ix_ai_conversations_user_id"), table_name="ai_conversations")
    op.drop_index(op.f("ix_ai_conversations_updated_at"), table_name="ai_conversations")
    op.drop_table("ai_conversations")
    op.drop_index(op.f("ix_auth_sessions_user_id"), table_name="auth_sessions")
    op.drop_index(op.f("ix_auth_sessions_token_hash"), table_name="auth_sessions")
    op.drop_index(op.f("ix_auth_sessions_expires_at"), table_name="auth_sessions")
    op.drop_table("auth_sessions")
    op.drop_index(op.f("ix_asset_exposures_cve_id"), table_name="asset_exposures")
    op.drop_table("asset_exposures")
    op.drop_index(op.f("ix_users_username"), table_name="users")
    op.drop_index(op.f("ix_users_role"), table_name="users")
    op.drop_index(op.f("ix_users_active"), table_name="users")
    op.drop_table("users")
    op.drop_index(op.f("ix_collection_runs_status"), table_name="collection_runs")
    op.drop_index(op.f("ix_collection_runs_started_at"), table_name="collection_runs")
    op.drop_table("collection_runs")
    op.drop_table("alerts")
    op.drop_table("assets")
    op.drop_index(op.f("ix_mitre_attack_tactic"), table_name="mitre_attack")
    op.drop_table("mitre_attack")
    op.drop_index(op.f("ix_threat_news_published_at"), table_name="threat_news")
    op.drop_table("threat_news")
    op.drop_index(op.f("ix_ioc_type"), table_name="ioc")
    op.drop_index(op.f("ix_ioc_severity"), table_name="ioc")
    op.drop_index(op.f("ix_ioc_indicator"), table_name="ioc")
    op.drop_table("ioc")
    op.drop_table("cve_web_enrichment")
    op.drop_table("cve_details")
    op.drop_index(op.f("ix_cve_vendor"), table_name="cve")
    op.drop_index(op.f("ix_cve_severity"), table_name="cve")
    op.drop_index(op.f("ix_cve_published_at"), table_name="cve")
    op.drop_index(op.f("ix_cve_cve_id"), table_name="cve")
    op.drop_table("cve")
