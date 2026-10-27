"""SAML SSO settings on tenants

Revision ID: f7a8b9c0d1e2
Revises: e6f7a8b9c0d1
Create Date: 2026-10-27
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'f7a8b9c0d1e2'
down_revision: Union[str, Sequence[str], None] = 'e6f7a8b9c0d1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants') as batch:
        batch.add_column(sa.Column('sso_protocol', sa.String(length=10), nullable=True))
        batch.add_column(sa.Column('saml_entity_id', sa.String(length=500), nullable=True))
        batch.add_column(sa.Column('saml_sso_url', sa.String(length=1000), nullable=True))
        batch.add_column(sa.Column('saml_idp_cert', sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('tenants') as batch:
        batch.drop_column('saml_idp_cert')
        batch.drop_column('saml_sso_url')
        batch.drop_column('saml_entity_id')
        batch.drop_column('sso_protocol')
