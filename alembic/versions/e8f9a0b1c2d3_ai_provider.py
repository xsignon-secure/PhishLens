"""Assistant: any AI provider (provider, model, endpoint per company).

Revision ID: e8f9a0b1c2d3
Revises: c5d6e7f8a9b0
"""
import sqlalchemy as sa

from alembic import op

revision = "e8f9a0b1c2d3"
down_revision = "c5d6e7f8a9b0"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("tenants") as batch:
        batch.add_column(sa.Column("ai_provider", sa.String(30), nullable=True))
        batch.add_column(sa.Column("ai_model", sa.String(200), nullable=True))
        batch.add_column(sa.Column("ai_base_url", sa.String(500), nullable=True))
    # Keys saved before this change were all Anthropic keys.
    op.execute("UPDATE tenants SET ai_provider = 'anthropic' WHERE ai_key IS NOT NULL")


def downgrade():
    with op.batch_alter_table("tenants") as batch:
        batch.drop_column("ai_base_url")
        batch.drop_column("ai_model")
        batch.drop_column("ai_provider")
