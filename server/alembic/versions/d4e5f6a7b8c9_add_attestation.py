"""attestation_baselines + attestation_challenges (Milestone 7 — TPM 2.0 attestation)

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-07-01 10:00:00.000000
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, None] = 'c3d4e5f6a7b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'attestation_baselines',
        sa.Column('agent_id', sa.String(length=128), nullable=False),
        sa.Column('ak_pubkey', sa.Text(), nullable=False),
        sa.Column('pcrs', sa.JSON(), nullable=False),
        sa.Column('selection', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('agent_id'),
    )
    op.create_table(
        'attestation_challenges',
        sa.Column('agent_id', sa.String(length=128), nullable=False),
        sa.Column('nonce', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('agent_id'),
    )


def downgrade() -> None:
    op.drop_table('attestation_challenges')
    op.drop_table('attestation_baselines')
