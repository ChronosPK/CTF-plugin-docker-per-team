"""Add hostname and performance indexes

Revision ID: b9f3c7a1e4d2
Revises: a1d6c8e9f2b3
Create Date: 2026-05-27
"""

import sqlalchemy as sa

from CTFd.plugins.migrations import get_columns_for_table

revision = "b9f3c7a1e4d2"
down_revision = "a1d6c8e9f2b3"
branch_labels = None
depends_on = None


def _index_names(inspector, table_name):
    return {index["name"] for index in inspector.get_indexes(table_name)}


def _unique_names(inspector, table_name):
    return {constraint["name"] for constraint in inspector.get_unique_constraints(table_name)}


def upgrade(op=None):
    columns = get_columns_for_table(
        op=op, table_name="container_info_model", names_only=True
    )
    if "hostname" not in columns:
        op.add_column(
            "container_info_model",
            sa.Column("hostname", sa.String(length=255), nullable=True),
        )

    conn = op.get_bind()
    inspector = sa.inspect(conn)

    info_indexes = _index_names(inspector, "container_info_model")
    info_uniques = _unique_names(inspector, "container_info_model")

    if "idx_container_info_team_challenge" not in info_indexes:
        op.create_index(
            "idx_container_info_team_challenge",
            "container_info_model",
            ["team_id", "challenge_id"],
        )
    if "idx_container_info_user_challenge" not in info_indexes:
        op.create_index(
            "idx_container_info_user_challenge",
            "container_info_model",
            ["user_id", "challenge_id"],
        )
    if "idx_container_info_expires" not in info_indexes:
        op.create_index(
            "idx_container_info_expires",
            "container_info_model",
            ["expires"],
        )
    if "ix_container_info_model_hostname" not in info_indexes:
        op.create_index(
            "ix_container_info_model_hostname",
            "container_info_model",
            ["hostname"],
        )
    if "uq_container_info_challenge_team" not in info_uniques:
        op.create_unique_constraint(
            "uq_container_info_challenge_team",
            "container_info_model",
            ["challenge_id", "team_id"],
        )
    if "uq_container_info_challenge_user" not in info_uniques:
        op.create_unique_constraint(
            "uq_container_info_challenge_user",
            "container_info_model",
            ["challenge_id", "user_id"],
        )

    flag_indexes = _index_names(inspector, "container_flag_model")
    if "idx_container_flag_container_id" not in flag_indexes:
        op.create_index(
            "idx_container_flag_container_id",
            "container_flag_model",
            ["container_id"],
        )
    if "idx_container_flag_team_challenge" not in flag_indexes:
        op.create_index(
            "idx_container_flag_team_challenge",
            "container_flag_model",
            ["team_id", "challenge_id"],
        )
    if "idx_container_flag_user_challenge" not in flag_indexes:
        op.create_index(
            "idx_container_flag_user_challenge",
            "container_flag_model",
            ["user_id", "challenge_id"],
        )


def downgrade(op=None):
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    flag_indexes = _index_names(inspector, "container_flag_model")
    for index_name in (
        "idx_container_flag_user_challenge",
        "idx_container_flag_team_challenge",
        "idx_container_flag_container_id",
    ):
        if index_name in flag_indexes:
            op.drop_index(index_name, table_name="container_flag_model")

    info_uniques = _unique_names(inspector, "container_info_model")
    for unique_name in (
        "uq_container_info_challenge_user",
        "uq_container_info_challenge_team",
    ):
        if unique_name in info_uniques:
            op.drop_constraint(unique_name, "container_info_model", type_="unique")

    info_indexes = _index_names(inspector, "container_info_model")
    for index_name in (
        "ix_container_info_model_hostname",
        "idx_container_info_expires",
        "idx_container_info_user_challenge",
        "idx_container_info_team_challenge",
    ):
        if index_name in info_indexes:
            op.drop_index(index_name, table_name="container_info_model")

    columns = get_columns_for_table(
        op=op, table_name="container_info_model", names_only=True
    )
    if "hostname" in columns:
        op.drop_column("container_info_model", "hostname")
