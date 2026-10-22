"""billing, sso, hosted records, forensic reports, branding

Revision ID: c4d5e6f7a8b9
Revises: b3c1d2e4f5a6
Create Date: 2026-10-22 00:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c4d5e6f7a8b9'
down_revision: Union[str, Sequence[str], None] = 'b3c1d2e4f5a6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TENANT_COLS = [
    sa.Column('stripe_subscription_id', sa.String(length=100), nullable=True),
    sa.Column('subscription_status', sa.String(length=30), nullable=True),
    sa.Column('brand_name', sa.String(length=100), nullable=True),
    sa.Column('brand_color', sa.String(length=7), nullable=True),
    sa.Column('brand_logo', sa.Text(), nullable=True),
    sa.Column('report_footer', sa.String(length=300), nullable=True),
    sa.Column('alert_emails', sa.JSON(), nullable=True),
    sa.Column('sso_issuer', sa.String(length=300), nullable=True),
    sa.Column('sso_client_id', sa.String(length=300), nullable=True),
    sa.Column('sso_client_secret', sa.Text(), nullable=True),
    sa.Column('sso_email_domain', sa.String(length=253), nullable=True),
    sa.Column('sso_enforced', sa.Boolean(), nullable=False, server_default=sa.false()),
    sa.Column('cloudflare_token', sa.Text(), nullable=True),
]


def upgrade() -> None:
    with op.batch_alter_table('tenants') as batch:
        for col in _TENANT_COLS:
            batch.add_column(col)
        batch.create_unique_constraint('uq_tenants_sso_email_domain', ['sso_email_domain'])
    with op.batch_alter_table('monitors') as batch:
        batch.add_column(sa.Column('client', sa.String(length=100), nullable=True))
    op.create_table('forensic_reports',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('tenant_id', sa.String(length=32), nullable=False),
    sa.Column('domain', sa.String(length=253), nullable=False),
    sa.Column('reporter', sa.String(length=200), nullable=True),
    sa.Column('source_ip', sa.String(length=64), nullable=True),
    sa.Column('arrival_date', sa.DateTime(), nullable=True),
    sa.Column('auth_failure', sa.String(length=100), nullable=True),
    sa.Column('delivery_result', sa.String(length=50), nullable=True),
    sa.Column('original_mail_from', sa.String(length=320), nullable=True),
    sa.Column('header_from', sa.String(length=320), nullable=True),
    sa.Column('subject', sa.String(length=300), nullable=True),
    sa.Column('auth_results', sa.Text(), nullable=True),
    sa.Column('fingerprint', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'fingerprint', name='uq_forensic_tenant_fp')
    )
    op.create_index(op.f('ix_forensic_reports_tenant_id'), 'forensic_reports', ['tenant_id'], unique=False)
    op.create_index(op.f('ix_forensic_reports_domain'), 'forensic_reports', ['domain'], unique=False)
    op.create_index(op.f('ix_forensic_reports_created_at'), 'forensic_reports', ['created_at'], unique=False)
    op.create_table('hosted_records',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('tenant_id', sa.String(length=32), nullable=False),
    sa.Column('domain', sa.String(length=253), nullable=False),
    sa.Column('kind', sa.String(length=20), nullable=False),
    sa.Column('config', sa.JSON(), nullable=False),
    sa.Column('published', sa.JSON(), nullable=True),
    sa.Column('policy_id', sa.String(length=32), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'domain', 'kind', name='uq_hosted_tenant_domain_kind')
    )
    op.create_index(op.f('ix_hosted_records_tenant_id'), 'hosted_records', ['tenant_id'], unique=False)
    op.create_index(op.f('ix_hosted_records_domain'), 'hosted_records', ['domain'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_hosted_records_domain'), table_name='hosted_records')
    op.drop_index(op.f('ix_hosted_records_tenant_id'), table_name='hosted_records')
    op.drop_table('hosted_records')
    op.drop_index(op.f('ix_forensic_reports_created_at'), table_name='forensic_reports')
    op.drop_index(op.f('ix_forensic_reports_domain'), table_name='forensic_reports')
    op.drop_index(op.f('ix_forensic_reports_tenant_id'), table_name='forensic_reports')
    op.drop_table('forensic_reports')
    with op.batch_alter_table('monitors') as batch:
        batch.drop_column('client')
    with op.batch_alter_table('tenants') as batch:
        batch.drop_constraint('uq_tenants_sso_email_domain', type_='unique')
        for col in reversed(_TENANT_COLS):
            batch.drop_column(col.name)
