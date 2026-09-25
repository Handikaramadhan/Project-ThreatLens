"""Store Telegram bot token per alert preference.

Revision ID: 20260710_0005
Revises: 20260710_0004
Create Date: 2026-07-10
"""

from alembic import op
import sqlalchemy as sa


revision = "20260710_0005"
down_revision = "20260710_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "alert_preferences",
        sa.Column("telegram_bot_token_secret", sa.Text(), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("alert_preferences", "telegram_bot_token_secret")
