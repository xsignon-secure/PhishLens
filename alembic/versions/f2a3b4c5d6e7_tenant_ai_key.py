"""AI assistant: a company's own Anthropic API key.

Revision ID: f2a3b4c5d6e7
Revises: e1f2a3b4c5d6
"""
import sqlalchemy as sa

from alembic import op

revision = "f2a3b4c5d6e7"
down_revision = "e1f2a3b4c5d6"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("tenants") as b:
        b.add_column(sa.Column("ai_key", sa.Text(), nullable=True))


def downgrade():
    with op.batch_alter_table("tenants") as b:
        b.drop_column("ai_key")
