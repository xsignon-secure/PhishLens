"""Monitor alert levels and the DNS change timeline

Revision ID: a1b2c3d4e5f6
Revises: f7a8b9c0d1e2
Create Date: 2026-10-28
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = 'f7a8b9c0d1e2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('monitors') as batch:
        batch.add_column(sa.Column('alert_level', sa.String(length=20), nullable=False,
                                   server_default='balanced'))
    op.create_table(
        'dns_changes',
        sa.Column('id', sa.String(length=32), primary_key=True),
        sa.Column('tenant_id', sa.String(length=32), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('monitor_id', sa.String(length=32), sa.ForeignKey('monitors.id'), nullable=False),
        sa.Column('domain', sa.String(length=253), nullable=False),
        sa.Column('record', sa.String(length=20), nullable=False),
        sa.Column('old', sa.JSON(), nullable=False),
        sa.Column('new', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_dns_changes_tenant_id', 'dns_changes', ['tenant_id'])
    op.create_index('ix_dns_changes_monitor_id', 'dns_changes', ['monitor_id'])
    op.create_index('ix_dns_changes_created_at', 'dns_changes', ['created_at'])


def downgrade() -> None:
    op.drop_index('ix_dns_changes_created_at', table_name='dns_changes')
    op.drop_index('ix_dns_changes_monitor_id', table_name='dns_changes')
    op.drop_index('ix_dns_changes_tenant_id', table_name='dns_changes')
    op.drop_table('dns_changes')
    with op.batch_alter_table('monitors') as batch:
        batch.drop_column('alert_level')
