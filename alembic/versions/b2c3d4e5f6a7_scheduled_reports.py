"""Scheduled PDF reports by email

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-10-28
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants') as batch:
        batch.add_column(sa.Column('report_schedule', sa.String(length=10), nullable=False,
                                   server_default='off'))
        batch.add_column(sa.Column('report_sent_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('tenants') as batch:
        batch.drop_column('report_sent_at')
        batch.drop_column('report_schedule')
