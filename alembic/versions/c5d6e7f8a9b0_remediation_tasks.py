"""Remediation tasks: assign findings, due dates.

Revision ID: c5d6e7f8a9b0
Revises: b4c5d6e7f8a9
"""
import sqlalchemy as sa

from alembic import op

revision = "c5d6e7f8a9b0"
down_revision = "b4c5d6e7f8a9"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "remediation_tasks",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("tenant_id", sa.String(32), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("check_key", sa.String(40), nullable=True),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("assignee_id", sa.String(32), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_by", sa.String(320), nullable=True),
        sa.Column("closed_by", sa.String(320), nullable=True),
        sa.Column("closed_at", sa.DateTime(), nullable=True),
        sa.Column("reminded_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_remediation_tasks_tenant_id", "remediation_tasks", ["tenant_id"])
    op.create_index("ix_remediation_tasks_assignee_id", "remediation_tasks", ["assignee_id"])


def downgrade():
    op.drop_index("ix_remediation_tasks_assignee_id", "remediation_tasks")
    op.drop_index("ix_remediation_tasks_tenant_id", "remediation_tasks")
    op.drop_table("remediation_tasks")
