"""Threat feed indicators (STIX 2.1 / TAXII 2.1).

Revision ID: a5b6c7d8e9f0
Revises: f4a5b6c7d8e9
"""
import sqlalchemy as sa

from alembic import op

revision = "a5b6c7d8e9f0"
down_revision = "f4a5b6c7d8e9"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "threat_indicators",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("tenant_id", sa.String(32), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("stix_id", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("value", sa.String(2000), nullable=False),
        sa.Column("sources", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("malicious", sa.Boolean(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("modified", sa.DateTime(), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.UniqueConstraint("tenant_id", "stix_id", name="uq_indicator_tenant_stix"),
    )
    op.create_index("ix_threat_indicators_tenant_id", "threat_indicators", ["tenant_id"])
    op.create_index("ix_threat_indicators_modified", "threat_indicators", ["modified"])


def downgrade():
    op.drop_index("ix_threat_indicators_modified", "threat_indicators")
    op.drop_index("ix_threat_indicators_tenant_id", "threat_indicators")
    op.drop_table("threat_indicators")
