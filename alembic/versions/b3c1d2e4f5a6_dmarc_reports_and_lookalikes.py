"""dmarc reports and lookalike tracking

Revision ID: b3c1d2e4f5a6
Revises: 7af353fb1c9a
Create Date: 2026-10-21 23:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b3c1d2e4f5a6'
down_revision: Union[str, Sequence[str], None] = '7af353fb1c9a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('dmarc_reports',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('tenant_id', sa.String(length=32), nullable=False),
    sa.Column('domain', sa.String(length=253), nullable=False),
    sa.Column('org_name', sa.String(length=200), nullable=False),
    sa.Column('report_id', sa.String(length=200), nullable=False),
    sa.Column('date_begin', sa.DateTime(), nullable=True),
    sa.Column('date_end', sa.DateTime(), nullable=True),
    sa.Column('policy', sa.JSON(), nullable=True),
    sa.Column('records', sa.JSON(), nullable=False),
    sa.Column('message_count', sa.Integer(), nullable=False),
    sa.Column('pass_count', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'org_name', 'report_id', name='uq_dmarc_report_tenant_org_id')
    )
    op.create_index(op.f('ix_dmarc_reports_tenant_id'), 'dmarc_reports', ['tenant_id'], unique=False)
    op.create_index(op.f('ix_dmarc_reports_domain'), 'dmarc_reports', ['domain'], unique=False)
    op.create_index(op.f('ix_dmarc_reports_date_begin'), 'dmarc_reports', ['date_begin'], unique=False)
    with op.batch_alter_table('monitors') as batch:
        batch.add_column(sa.Column('lookalikes', sa.JSON(), nullable=True))
        batch.add_column(sa.Column('lookalikes_checked_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('monitors') as batch:
        batch.drop_column('lookalikes_checked_at')
        batch.drop_column('lookalikes')
    op.drop_index(op.f('ix_dmarc_reports_date_begin'), table_name='dmarc_reports')
    op.drop_index(op.f('ix_dmarc_reports_domain'), table_name='dmarc_reports')
    op.drop_index(op.f('ix_dmarc_reports_tenant_id'), table_name='dmarc_reports')
    op.drop_table('dmarc_reports')
