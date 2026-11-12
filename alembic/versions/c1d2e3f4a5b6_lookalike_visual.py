"""Visual lookalike check results per monitor.

Revision ID: c1d2e3f4a5b6
Revises: b0c1d2e3f4a5
"""
import sqlalchemy as sa

from alembic import op

revision = "c1d2e3f4a5b6"
down_revision = "b0c1d2e3f4a5"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("monitors") as batch:
        batch.add_column(sa.Column("lookalike_visual", sa.JSON(), nullable=True))


def downgrade():
    with op.batch_alter_table("monitors") as batch:
        batch.drop_column("lookalike_visual")
