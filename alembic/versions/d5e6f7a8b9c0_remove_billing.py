"""remove billing: PhishLens is free and open source

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a8b9
Create Date: 2026-10-22 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd5e6f7a8b9c0'
down_revision: Union[str, Sequence[str], None] = 'c4d5e6f7a8b9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COLS = ('plan', 'stripe_customer_id', 'stripe_subscription_id', 'subscription_status')


def upgrade() -> None:
    with op.batch_alter_table('tenants') as batch:
        for name in _COLS:
            batch.drop_column(name)


def downgrade() -> None:
    with op.batch_alter_table('tenants') as batch:
        batch.add_column(sa.Column('plan', sa.String(length=20), nullable=False, server_default='free'))
        batch.add_column(sa.Column('stripe_customer_id', sa.String(length=100), nullable=True))
        batch.add_column(sa.Column('stripe_subscription_id', sa.String(length=100), nullable=True))
        batch.add_column(sa.Column('subscription_status', sa.String(length=30), nullable=True))
