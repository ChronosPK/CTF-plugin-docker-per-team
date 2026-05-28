"""Relax cheat log foreign keys

Revision ID: c4a6c92f1d5b
Revises: b9f3c7a1e4d2
Create Date: 2026-05-27
"""

import sqlalchemy as sa

revision = "c4a6c92f1d5b"
down_revision = "b9f3c7a1e4d2"
branch_labels = None
depends_on = None


def _foreign_keys(inspector, table_name):
    return {fk["name"]: fk for fk in inspector.get_foreign_keys(table_name)}


def _recreate_fk(op, name, local_col, remote_table, remote_col, ondelete=None):
    op.create_foreign_key(
        name,
        "container_cheat_log",
        remote_table,
        [local_col],
        [remote_col],
        ondelete=ondelete,
    )


def upgrade(op=None):
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    fks = _foreign_keys(inspector, "container_cheat_log")

    updates = (
        ("container_cheat_log_ibfk_2", "original_team_id", "teams", "id"),
        ("container_cheat_log_ibfk_3", "original_user_id", "users", "id"),
        ("container_cheat_log_ibfk_4", "second_team_id", "teams", "id"),
        ("container_cheat_log_ibfk_5", "second_user_id", "users", "id"),
    )

    for name, local_col, remote_table, remote_col in updates:
        fk = fks.get(name)
        if fk and fk.get("options", {}).get("ondelete") != "SET NULL":
            op.drop_constraint(name, "container_cheat_log", type_="foreignkey")
            _recreate_fk(op, name, local_col, remote_table, remote_col, ondelete="SET NULL")


def downgrade(op=None):
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    fks = _foreign_keys(inspector, "container_cheat_log")

    updates = (
        ("container_cheat_log_ibfk_2", "original_team_id", "teams", "id"),
        ("container_cheat_log_ibfk_3", "original_user_id", "users", "id"),
        ("container_cheat_log_ibfk_4", "second_team_id", "teams", "id"),
        ("container_cheat_log_ibfk_5", "second_user_id", "users", "id"),
    )

    for name, local_col, remote_table, remote_col in updates:
        fk = fks.get(name)
        if fk and fk.get("options", {}).get("ondelete") == "SET NULL":
            op.drop_constraint(name, "container_cheat_log", type_="foreignkey")
            _recreate_fk(op, name, local_col, remote_table, remote_col)
