"""Report-phish button token per company.

Revision ID: d2e3f4a5b6c7
Revises: c1d2e3f4a5b6
"""
import sqlalchemy as sa

from alembic import op

revision = "d2e3f4a5b6c7"
down_revision = "c1d2e3f4a5b6"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("tenants") as batch:
        batch.add_column(sa.Column("report_token_hash", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("report_token_created_at", sa.DateTime(), nullable=True))
        batch.create_unique_constraint("uq_tenants_report_token_hash", ["report_token_hash"])


def downgrade():
    with op.batch_alter_table("tenants") as batch:
        batch.drop_constraint("uq_tenants_report_token_hash", type_="unique")
        batch.drop_column("report_token_created_at")
        batch.drop_column("report_token_hash")
