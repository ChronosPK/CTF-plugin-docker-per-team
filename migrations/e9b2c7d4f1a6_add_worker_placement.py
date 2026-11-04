"""Add durable Docker worker placement.

Revision ID: e9b2c7d4f1a6
Revises: d5e7f901a2b3
"""

import sqlalchemy as sa

from CTFd.plugins.migrations import get_columns_for_table


revision = "e9b2c7d4f1a6"
down_revision = "d5e7f901a2b3"
branch_labels = None
depends_on = None


def _index_names(inspector, table_name):
    return {index["name"] for index in inspector.get_indexes(table_name)}


def _unique_names(inspector, table_name):
    return {item["name"] for item in inspector.get_unique_constraints(table_name)}


def upgrade(op=None):
    columns = get_columns_for_table(op=op, table_name="container_info_model", names_only=True)
    if "worker_id" not in columns:
        # The explicit compatibility value makes old live rows auditable rather
        # than leaving an ambiguous null that could route to a random worker.
        op.add_column(
            "container_info_model",
            sa.Column("worker_id", sa.String(length=32), nullable=False, server_default="primary"),
        )
        op.alter_column("container_info_model", "worker_id", server_default=None)

    conn = op.get_bind()
    inspector = sa.inspect(conn)
    if "idx_container_info_worker" not in _index_names(inspector, "container_info_model"):
        op.create_index("idx_container_info_worker", "container_info_model", ["worker_id"])

    if "container_worker_placement_model" not in inspector.get_table_names():
        op.create_table(
            "container_worker_placement_model",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("event_id", sa.String(length=63), nullable=False),
            sa.Column("release_id", sa.String(length=63), nullable=False),
            sa.Column("scope_kind", sa.String(length=8), nullable=False),
            sa.Column("scope_id", sa.Integer(), nullable=False),
            sa.Column("worker_id", sa.String(length=32), nullable=False),
            sa.Column("assigned_at", sa.Integer(), nullable=False),
            sa.UniqueConstraint("event_id", "release_id", "scope_kind", "scope_id", name="uq_container_worker_placement_scope"),
        )
        op.create_index("idx_container_worker_placement_worker", "container_worker_placement_model", ["worker_id"])


def downgrade(op=None):
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    if "container_worker_placement_model" in inspector.get_table_names():
        op.drop_table("container_worker_placement_model")
    if "idx_container_info_worker" in _index_names(inspector, "container_info_model"):
        op.drop_index("idx_container_info_worker", table_name="container_info_model")
    columns = get_columns_for_table(op=op, table_name="container_info_model", names_only=True)
    if "worker_id" in columns:
        op.drop_column("container_info_model", "worker_id")
