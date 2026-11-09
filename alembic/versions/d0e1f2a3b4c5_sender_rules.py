"""DMARC sender classification: approved/blocked senders, auto-approve.

Revision ID: d0e1f2a3b4c5
Revises: c9d0e1f2a3b4
"""
import sqlalchemy as sa

from alembic import op

revision = "d0e1f2a3b4c5"
down_revision = "c9d0e1f2a3b4"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "sender_rules",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("tenant_id", sa.String(32), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("sender", sa.String(300), nullable=False),
        sa.Column("verdict", sa.String(10), nullable=False),
        sa.Column("source", sa.String(10), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("tenant_id", "domain", "sender", name="uq_sender_rule"),
    )
    op.create_index("ix_sender_rules_tenant_id", "sender_rules", ["tenant_id"])
    with op.batch_alter_table("tenants") as b:
        b.add_column(sa.Column("auto_approve_senders", sa.Boolean(), nullable=False, server_default="0"))


def downgrade():
    with op.batch_alter_table("tenants") as b:
        b.drop_column("auto_approve_senders")
    op.drop_index("ix_sender_rules_tenant_id", "sender_rules")
    op.drop_table("sender_rules")
