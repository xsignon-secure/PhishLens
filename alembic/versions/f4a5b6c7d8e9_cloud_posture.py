"""Microsoft 365 / Google Workspace security check results.

Revision ID: f4a5b6c7d8e9
Revises: e3f4a5b6c7d8
"""
import sqlalchemy as sa

from alembic import op

revision = "f4a5b6c7d8e9"
down_revision = "e3f4a5b6c7d8"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("tenants") as batch:
        batch.add_column(sa.Column("posture", sa.JSON(), nullable=True))


def downgrade():
    with op.batch_alter_table("tenants") as batch:
        batch.drop_column("posture")
