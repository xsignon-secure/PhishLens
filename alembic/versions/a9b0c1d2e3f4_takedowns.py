"""Takedown tracking and AI triage of reported phishing.

Revision ID: a9b0c1d2e3f4
Revises: e8f9a0b1c2d3
"""
import sqlalchemy as sa

from alembic import op

revision = "a9b0c1d2e3f4"
down_revision = "e8f9a0b1c2d3"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("phish_reports") as batch:
        batch.add_column(sa.Column("ai", sa.JSON(), nullable=True))
    op.create_table(
        "takedowns",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("tenant_id", sa.String(32), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("report_id", sa.String(32), sa.ForeignKey("phish_reports.id"), nullable=True),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("url", sa.String(2000), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("auto", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("draft", sa.JSON(), nullable=False),
        sa.Column("submissions", sa.JSON(), nullable=True),
        sa.Column("live", sa.Boolean(), nullable=True),
        sa.Column("last_check", sa.JSON(), nullable=True),
        sa.Column("sent_at", sa.DateTime(), nullable=True),
        sa.Column("down_at", sa.DateTime(), nullable=True),
        sa.Column("followed_up_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.String(320), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_takedowns_tenant_id", "takedowns", ["tenant_id"])
    op.create_index("ix_takedowns_created_at", "takedowns", ["created_at"])


def downgrade():
    op.drop_index("ix_takedowns_created_at", "takedowns")
    op.drop_index("ix_takedowns_tenant_id", "takedowns")
    op.drop_table("takedowns")
    with op.batch_alter_table("phish_reports") as batch:
        batch.drop_column("ai")
