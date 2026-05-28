"""Add capabilities to container challenge

Revision ID: a1d6c8e9f2b3
Revises:
Create Date: 2026-05-27
"""

import sqlalchemy as sa

from CTFd.plugins.migrations import get_columns_for_table

revision = "a1d6c8e9f2b3"
down_revision = None
branch_labels = None
depends_on = None


def upgrade(op=None):
    columns = get_columns_for_table(
        op=op, table_name="container_challenge_model", names_only=True
    )
    if "capabilities" not in columns:
        op.add_column(
            "container_challenge_model",
            sa.Column("capabilities", sa.Text(), nullable=True),
        )


def downgrade(op=None):
    columns = get_columns_for_table(
        op=op, table_name="container_challenge_model", names_only=True
    )
    if "capabilities" in columns:
        op.drop_column("container_challenge_model", "capabilities")
