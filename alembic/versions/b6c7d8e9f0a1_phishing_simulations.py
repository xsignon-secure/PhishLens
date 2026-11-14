"""Phishing simulations.

Revision ID: b6c7d8e9f0a1
Revises: a5b6c7d8e9f0
"""
import sqlalchemy as sa

from alembic import op

revision = "b6c7d8e9f0a1"
down_revision = "a5b6c7d8e9f0"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("tenants") as batch:
        batch.add_column(sa.Column("sim_domains", sa.JSON(), nullable=True))
    op.create_table(
        "sim_campaigns",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("tenant_id", sa.String(32), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("template", sa.String(40), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("authorized_by", sa.String(320), nullable=False),
        sa.Column("authorized_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_sim_campaigns_tenant_id", "sim_campaigns", ["tenant_id"])
    op.create_index("ix_sim_campaigns_created_at", "sim_campaigns", ["created_at"])
    op.create_table(
        "sim_recipients",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("tenant_id", sa.String(32), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("campaign_id", sa.String(32), sa.ForeignKey("sim_campaigns.id"), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("token", sa.String(64), nullable=False),
        sa.Column("sent_at", sa.DateTime(), nullable=True),
        sa.Column("error", sa.String(300), nullable=True),
        sa.Column("clicked_at", sa.DateTime(), nullable=True),
        sa.Column("reported_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_sim_recipients_tenant_id", "sim_recipients", ["tenant_id"])
    op.create_index("ix_sim_recipients_campaign_id", "sim_recipients", ["campaign_id"])
    op.create_index("ix_sim_recipients_token", "sim_recipients", ["token"], unique=True)


def downgrade():
    op.drop_table("sim_recipients")
    op.drop_table("sim_campaigns")
    with op.batch_alter_table("tenants") as batch:
        batch.drop_column("sim_domains")
