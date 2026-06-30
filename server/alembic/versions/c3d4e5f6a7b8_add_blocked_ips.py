"""blocked_ips table (Milestone 6 auto-response / IP blocklist)

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-06-30 13:00:00.000000
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, None] = 'b2c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'blocked_ips',
        sa.Column('ip', sa.String(length=64), nullable=False),
        sa.Column('reason', sa.String(length=128), nullable=True),
        sa.Column('rule_id', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('ip'),
    )
    op.create_index('ix_blocked_ips_created_at', 'blocked_ips', ['created_at'])


def downgrade() -> None:
    op.drop_index('ix_blocked_ips_created_at', table_name='blocked_ips')
    op.drop_table('blocked_ips')
