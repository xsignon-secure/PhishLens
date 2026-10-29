"""Test-email analyzer and SIEM/PSA alert exports

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-10-28
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, Sequence[str], None] = 'b2c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants') as batch:
        batch.add_column(sa.Column('siem', sa.JSON(), nullable=True))
        batch.add_column(sa.Column('psa', sa.JSON(), nullable=True))
    op.create_table(
        'mail_tests',
        sa.Column('id', sa.String(length=32), nullable=False),
        sa.Column('tenant_id', sa.String(length=32), nullable=False),
        sa.Column('user_id', sa.String(length=32), nullable=False),
        sa.Column('token', sa.String(length=32), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('received_at', sa.DateTime(), nullable=True),
        sa.Column('result', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token'),
    )
    op.create_index(op.f('ix_mail_tests_tenant_id'), 'mail_tests', ['tenant_id'], unique=False)
    op.create_index(op.f('ix_mail_tests_created_at'), 'mail_tests', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_mail_tests_created_at'), table_name='mail_tests')
    op.drop_index(op.f('ix_mail_tests_tenant_id'), table_name='mail_tests')
    op.drop_table('mail_tests')
    with op.batch_alter_table('tenants') as batch:
        batch.drop_column('psa')
        batch.drop_column('siem')
