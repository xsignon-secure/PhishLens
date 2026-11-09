"""Certificate Transparency baseline per monitor.

Revision ID: a3b4c5d6e7f8
Revises: f2a3b4c5d6e7
"""
import sqlalchemy as sa

from alembic import op

revision = "a3b4c5d6e7f8"
down_revision = "f2a3b4c5d6e7"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("monitors") as b:
        b.add_column(sa.Column("ct_state", sa.JSON(), nullable=True))


def downgrade():
    with op.batch_alter_table("monitors") as b:
        b.drop_column("ct_state")
