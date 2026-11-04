"""Add bounded per-challenge resource limits

Revision ID: d5e7f901a2b3
Revises: c4a6c92f1d5b
Create Date: 2026-07-27
"""

import sqlalchemy as sa

from CTFd.plugins.migrations import get_columns_for_table

revision = "d5e7f901a2b3"
down_revision = "c4a6c92f1d5b"
branch_labels = None
depends_on = None


RESOURCE_COLUMNS = {
    "memory_limit_mb": sa.Column(
        "memory_limit_mb",
        sa.Integer(),
        nullable=True,
    ),
    "cpu_limit": sa.Column(
        "cpu_limit",
        sa.Float(),
        nullable=True,
    ),
    "pids_limit": sa.Column(
        "pids_limit",
        sa.Integer(),
        nullable=True,
    ),
    "tmpfs_size_mb": sa.Column(
        "tmpfs_size_mb",
        sa.Integer(),
        nullable=True,
    ),
}


def upgrade(op=None):
    columns = get_columns_for_table(
        op=op,
        table_name="container_challenge_model",
        names_only=True,
    )
    for name, column in RESOURCE_COLUMNS.items():
        if name not in columns:
            op.add_column("container_challenge_model", column)


def downgrade(op=None):
    columns = get_columns_for_table(
        op=op,
        table_name="container_challenge_model",
        names_only=True,
    )
    for name in reversed(RESOURCE_COLUMNS):
        if name in columns:
            op.drop_column("container_challenge_model", name)
