"""DMARC enforcement autopilot.

Revision ID: e1f2a3b4c5d6
Revises: d0e1f2a3b4c5
"""
import sqlalchemy as sa

from alembic import op

revision = "e1f2a3b4c5d6"
down_revision = "d0e1f2a3b4c5"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "dmarc_autopilot",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("tenant_id", sa.String(32), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("target", sa.String(10), nullable=False),
        sa.Column("status", sa.String(10), nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("last_step_at", sa.DateTime(), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(), nullable=True),
        sa.Column("history", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("tenant_id", "domain", name="uq_autopilot_tenant_domain"),
    )
    op.create_index("ix_dmarc_autopilot_tenant_id", "dmarc_autopilot", ["tenant_id"])


def downgrade():
    op.drop_index("ix_dmarc_autopilot_tenant_id", "dmarc_autopilot")
    op.drop_table("dmarc_autopilot")
