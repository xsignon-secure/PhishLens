"""Sender reputation: Google Postmaster and Microsoft SNDS per company.

Revision ID: e3f4a5b6c7d8
Revises: d2e3f4a5b6c7
"""
import sqlalchemy as sa

from alembic import op

revision = "e3f4a5b6c7d8"
down_revision = "d2e3f4a5b6c7"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("tenants") as batch:
        batch.add_column(sa.Column("postmaster_token", sa.Text(), nullable=True))
        batch.add_column(sa.Column("postmaster_email", sa.String(length=254), nullable=True))
        batch.add_column(sa.Column("snds_key", sa.Text(), nullable=True))
        batch.add_column(sa.Column("sender_rep", sa.JSON(), nullable=True))


def downgrade():
    with op.batch_alter_table("tenants") as batch:
        batch.drop_column("sender_rep")
        batch.drop_column("snds_key")
        batch.drop_column("postmaster_email")
        batch.drop_column("postmaster_token")
