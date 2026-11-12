"""Client portal logins: a user tied to one client label.

Revision ID: b0c1d2e3f4a5
Revises: a9b0c1d2e3f4
"""
import sqlalchemy as sa

from alembic import op

revision = "b0c1d2e3f4a5"
down_revision = "a9b0c1d2e3f4"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("client_scope", sa.String(length=100), nullable=True))


def downgrade():
    with op.batch_alter_table("users") as batch:
        batch.drop_column("client_scope")
