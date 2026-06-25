"""agents table + alert triage/MITRE columns

Revision ID: a1b2c3d4e5f6
Revises: 61f62372980c
Create Date: 2026-06-25 12:00:00.000000
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = '61f62372980c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'agents',
        sa.Column('agent_id', sa.String(length=128), nullable=False),
        sa.Column('first_seen', sa.DateTime(), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('version', sa.String(length=32), nullable=True),
        sa.Column('event_count', sa.Integer(), nullable=False, server_default='0'),
        sa.PrimaryKeyConstraint('agent_id'),
    )
    op.create_index(op.f('ix_agents_last_seen'), 'agents', ['last_seen'], unique=False)

    op.add_column('alerts', sa.Column('assignee', sa.String(length=128), nullable=True))
    op.add_column('alerts', sa.Column('note', sa.Text(), nullable=True))
    op.add_column('alerts', sa.Column('tags', sa.String(length=256), nullable=True))
    op.add_column('alerts', sa.Column('tactic', sa.String(length=64), nullable=True))
    op.add_column('alerts', sa.Column('technique', sa.String(length=32), nullable=True))


def downgrade() -> None:
    op.drop_column('alerts', 'technique')
    op.drop_column('alerts', 'tactic')
    op.drop_column('alerts', 'tags')
    op.drop_column('alerts', 'note')
    op.drop_column('alerts', 'assignee')
    op.drop_index(op.f('ix_agents_last_seen'), table_name='agents')
    op.drop_table('agents')
