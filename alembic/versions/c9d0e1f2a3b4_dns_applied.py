"""One-click DNS changes, with what they replaced (for undo)

Revision ID: c9d0e1f2a3b4
Revises: b8c9d0e1f2a3
Create Date: 2026-11-09
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'c9d0e1f2a3b4'
down_revision: Union[str, Sequence[str], None] = 'b8c9d0e1f2a3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'dns_applied',
        sa.Column('id', sa.String(length=32), nullable=False),
        sa.Column('tenant_id', sa.String(length=32), nullable=False),
        sa.Column('user_id', sa.String(length=32), nullable=True),
        sa.Column('provider', sa.String(length=20), nullable=False),
        sa.Column('name', sa.String(length=253), nullable=False),
        sa.Column('rtype', sa.String(length=10), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('previous', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('rolled_back_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_dns_applied_tenant_id', 'dns_applied', ['tenant_id'])
    op.create_index('ix_dns_applied_created_at', 'dns_applied', ['created_at'])


def downgrade() -> None:
    op.drop_index('ix_dns_applied_created_at', table_name='dns_applied')
    op.drop_index('ix_dns_applied_tenant_id', table_name='dns_applied')
    op.drop_table('dns_applied')
