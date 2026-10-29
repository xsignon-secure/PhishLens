"""Admin-created accounts: user status, temporary passwords, lockout,
recovery codes, sessions, per-company SMTP

Revision ID: a7b8c9d0e1f2
Revises: d6e7f8a9b0c1
Create Date: 2026-10-29
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'a7b8c9d0e1f2'
down_revision: Union[str, Sequence[str], None] = 'd6e7f8a9b0c1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('tenants') as batch:
        batch.add_column(sa.Column('status', sa.String(length=20), nullable=False, server_default='active'))
        batch.add_column(sa.Column('smtp', sa.JSON(), nullable=True))
        batch.add_column(sa.Column('welcome_subject', sa.String(length=200), nullable=True))
        batch.add_column(sa.Column('welcome_message', sa.Text(), nullable=True))
    with op.batch_alter_table('users') as batch:
        batch.add_column(sa.Column('full_name', sa.String(length=200), nullable=True))
        batch.add_column(sa.Column('status', sa.String(length=20), nullable=False, server_default='active'))
        batch.add_column(sa.Column('must_change_password', sa.Boolean(), nullable=False, server_default=sa.false()))
        batch.add_column(sa.Column('temp_password_expires_at', sa.DateTime(), nullable=True))
        batch.add_column(sa.Column('failed_logins', sa.Integer(), nullable=False, server_default='0'))
        batch.add_column(sa.Column('locked_until', sa.DateTime(), nullable=True))
        batch.add_column(sa.Column('last_login_at', sa.DateTime(), nullable=True))
        batch.add_column(sa.Column('recovery_codes', sa.JSON(), nullable=True))
        batch.add_column(sa.Column('credentials_status', sa.String(length=20), nullable=True))
        batch.add_column(sa.Column('credentials_error', sa.String(length=300), nullable=True))
        batch.add_column(sa.Column('credentials_sent_at', sa.DateTime(), nullable=True))
    op.create_table(
        'user_sessions',
        sa.Column('id', sa.String(length=32), primary_key=True),
        sa.Column('user_id', sa.String(length=32), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('tenant_id', sa.String(length=32), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('refresh_hash', sa.String(length=64), nullable=False),
        sa.Column('prev_refresh_hash', sa.String(length=64), nullable=True),
        sa.Column('rotated_at', sa.DateTime(), nullable=True),
        sa.Column('device', sa.String(length=200), nullable=True),
        sa.Column('ip', sa.String(length=64), nullable=True),
        sa.Column('mfa_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_used_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_reason', sa.String(length=40), nullable=True),
    )
    op.create_index('ix_user_sessions_user_id', 'user_sessions', ['user_id'])
    op.create_index('ix_user_sessions_tenant_id', 'user_sessions', ['tenant_id'])
    op.create_index('ix_user_sessions_refresh_hash', 'user_sessions', ['refresh_hash'], unique=True)
    op.create_index('ix_user_sessions_prev_refresh_hash', 'user_sessions', ['prev_refresh_hash'])


def downgrade() -> None:
    op.drop_table('user_sessions')
    with op.batch_alter_table('users') as batch:
        for col in ('credentials_sent_at', 'credentials_error', 'credentials_status', 'recovery_codes',
                    'last_login_at', 'locked_until', 'failed_logins', 'temp_password_expires_at',
                    'must_change_password', 'status', 'full_name'):
            batch.drop_column(col)
    with op.batch_alter_table('tenants') as batch:
        for col in ('welcome_message', 'welcome_subject', 'smtp', 'status'):
            batch.drop_column(col)
