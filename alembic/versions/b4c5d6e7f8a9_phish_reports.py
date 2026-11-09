"""Phishing report inbox.

Revision ID: b4c5d6e7f8a9
Revises: a3b4c5d6e7f8
"""
import sqlalchemy as sa

from alembic import op

revision = "b4c5d6e7f8a9"
down_revision = "a3b4c5d6e7f8"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "phish_reports",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("tenant_id", sa.String(32), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("reported_by", sa.String(320), nullable=True),
        sa.Column("subject", sa.String(300), nullable=True),
        sa.Column("sender", sa.String(300), nullable=True),
        sa.Column("verdict", sa.String(20), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("header", sa.JSON(), nullable=True),
        sa.Column("links", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_phish_reports_tenant_id", "phish_reports", ["tenant_id"])
    op.create_index("ix_phish_reports_created_at", "phish_reports", ["created_at"])


def downgrade():
    op.drop_index("ix_phish_reports_created_at", "phish_reports")
    op.drop_index("ix_phish_reports_tenant_id", "phish_reports")
    op.drop_table("phish_reports")
