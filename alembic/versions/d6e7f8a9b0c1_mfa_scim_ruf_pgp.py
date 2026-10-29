"""Enforced 2FA, SCIM provisioning, PGP-encrypted failure reports

Revision ID: d6e7f8a9b0c1
Revises: c3d4e5f6a7b8
Create Date: 2026-10-28
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'd6e7f8a9b0c1'
down_revision: Union[str, Sequence[str], None] = 'c3d4e5f6a7b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants') as batch:
        batch.add_column(sa.Column('mfa_required', sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column('scim_token_hash', sa.String(length=64), nullable=True))
        batch.add_column(sa.Column('ruf_pgp_key', sa.Text(), nullable=True))
        batch.add_column(sa.Column('ruf_pgp_fingerprint', sa.String(length=64), nullable=True))
        batch.create_unique_constraint('uq_tenants_scim_token_hash', ['scim_token_hash'])
    with op.batch_alter_table('forensic_reports') as batch:
        batch.add_column(sa.Column('encrypted', sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('forensic_reports') as batch:
        batch.drop_column('encrypted')
    with op.batch_alter_table('tenants') as batch:
        batch.drop_constraint('uq_tenants_scim_token_hash', type_='unique')
        batch.drop_column('ruf_pgp_fingerprint')
        batch.drop_column('ruf_pgp_key')
        batch.drop_column('scim_token_hash')
        batch.drop_column('mfa_required')
