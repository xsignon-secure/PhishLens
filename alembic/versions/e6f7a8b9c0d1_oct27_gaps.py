"""session revocation, TOTP replay guard, TLS-RPT reports, DNS providers,
job leases, shared rate limits

Revision ID: e6f7a8b9c0d1
Revises: d5e6f7a8b9c0
Create Date: 2026-10-27 15:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e6f7a8b9c0d1'
down_revision: Union[str, Sequence[str], None] = 'd5e6f7a8b9c0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('users') as batch:
        batch.add_column(sa.Column('token_version', sa.Integer(), nullable=False, server_default='0'))
        batch.add_column(sa.Column('totp_last_step', sa.Integer(), nullable=True))
        batch.alter_column('totp_secret', existing_type=sa.String(length=64), type_=sa.String(length=200))
    with op.batch_alter_table('tenants') as batch:
        batch.add_column(sa.Column('dns_provider', sa.String(length=20), nullable=True))
        batch.add_column(sa.Column('dns_token', sa.Text(), nullable=True))
    op.execute("UPDATE tenants SET dns_provider = 'cloudflare', dns_token = cloudflare_token "
               "WHERE cloudflare_token IS NOT NULL")
    with op.batch_alter_table('tenants') as batch:
        batch.drop_column('cloudflare_token')

    op.create_table(
        'tls_reports',
        sa.Column('id', sa.String(length=32), nullable=False),
        sa.Column('tenant_id', sa.String(length=32), nullable=False),
        sa.Column('domain', sa.String(length=253), nullable=False),
        sa.Column('org_name', sa.String(length=200), nullable=False),
        sa.Column('report_id', sa.String(length=200), nullable=False),
        sa.Column('date_begin', sa.DateTime(), nullable=True),
        sa.Column('date_end', sa.DateTime(), nullable=True),
        sa.Column('policies', sa.JSON(), nullable=False),
        sa.Column('success_count', sa.Integer(), nullable=False),
        sa.Column('failure_count', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', 'org_name', 'report_id', name='uq_tls_report_tenant_org_id'),
    )
    op.create_index(op.f('ix_tls_reports_tenant_id'), 'tls_reports', ['tenant_id'], unique=False)
    op.create_index(op.f('ix_tls_reports_domain'), 'tls_reports', ['domain'], unique=False)
    op.create_index(op.f('ix_tls_reports_date_begin'), 'tls_reports', ['date_begin'], unique=False)
    op.create_table(
        'job_leases',
        sa.Column('name', sa.String(length=50), nullable=False),
        sa.Column('holder', sa.String(length=64), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('name'),
    )
    op.create_table(
        'rate_counters',
        sa.Column('key', sa.String(length=200), nullable=False),
        sa.Column('window_start', sa.DateTime(), nullable=False),
        sa.Column('count', sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint('key'),
    )


def downgrade() -> None:
    op.drop_table('rate_counters')
    op.drop_table('job_leases')
    op.drop_index(op.f('ix_tls_reports_date_begin'), table_name='tls_reports')
    op.drop_index(op.f('ix_tls_reports_domain'), table_name='tls_reports')
    op.drop_index(op.f('ix_tls_reports_tenant_id'), table_name='tls_reports')
    op.drop_table('tls_reports')
    with op.batch_alter_table('tenants') as batch:
        batch.add_column(sa.Column('cloudflare_token', sa.Text(), nullable=True))
    op.execute("UPDATE tenants SET cloudflare_token = dns_token WHERE dns_provider = 'cloudflare'")
    with op.batch_alter_table('tenants') as batch:
        batch.drop_column('dns_token')
        batch.drop_column('dns_provider')
    with op.batch_alter_table('users') as batch:
        batch.alter_column('totp_secret', existing_type=sa.String(length=200), type_=sa.String(length=64))
        batch.drop_column('totp_last_step')
        batch.drop_column('token_version')
