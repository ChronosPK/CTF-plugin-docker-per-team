"""Bounded legacy-only plugin schema metadata.

This module is intentionally separate from the ORM metadata and from the
stable-random extension models.  Its table list is the sole permitted
``create_all`` input for a legacy install.  Startup integration remains gated
until the complete stable-random maintenance state machine is implemented.
"""

from __future__ import annotations

from typing import Final

from sqlalchemy import (
    Column,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.engine import Engine
from sqlalchemy.sql.sqltypes import Boolean, Float, String

from CTFd.models import Challenges, Teams, Users


LEGACY_MIGRATION_CEILING: Final = "d5e7f901a2b3"
LEGACY_TABLE_NAMES: Final = (
    "container_challenge_model",
    "container_info_model",
    "container_settings_model",
    "container_flag_model",
    "container_cheat_log",
)

# This metadata may contain only the five baseline plugin tables.  Parent CTFd
# columns are referenced directly from their own metadata rather than cloned
# as placeholder tables here.
legacy_bootstrap_metadata = MetaData()

container_challenge_model = Table(
    "container_challenge_model",
    legacy_bootstrap_metadata,
    Column(
        "id",
        Integer,
        ForeignKey(
            Challenges.__table__.c.id,
            name="container_challenge_model_ibfk_1",
            ondelete="CASCADE",
        ),
        primary_key=True,
    ),
    Column("image", Text),
    Column("port", Integer),
    Column("command", Text, default=""),
    Column("volumes", Text, default=""),
    Column("capabilities", Text, default=""),
    Column("connection_type", Text),
    Column("memory_limit_mb", Integer, nullable=True),
    Column("cpu_limit", Float, nullable=True),
    Column("pids_limit", Integer, nullable=True),
    Column("tmpfs_size_mb", Integer, nullable=True),
    Column("initial", Integer, default=0),
    Column("minimum", Integer, default=0),
    Column("decay", Integer, default=0),
    Column("flag_mode", Text, default="static"),
    Column("random_flag_length", Integer, default=10),
    Column("flag_prefix", Text, default=""),
    Column("flag_suffix", Text, default=""),
)

container_info_model = Table(
    "container_info_model",
    legacy_bootstrap_metadata,
    Column("container_id", String(512), primary_key=True),
    Column(
        "challenge_id",
        Integer,
        ForeignKey(
            Challenges.__table__.c.id,
            name="container_info_model_ibfk_1",
            ondelete="CASCADE",
        ),
        index=True,
    ),
    Column(
        "team_id",
        Integer,
        ForeignKey(
            Teams.__table__.c.id,
            name="container_info_model_ibfk_2",
            ondelete="CASCADE",
        ),
        index=True,
    ),
    Column(
        "user_id",
        Integer,
        ForeignKey(
            Users.__table__.c.id,
            name="container_info_model_ibfk_3",
            ondelete="CASCADE",
        ),
        index=True,
    ),
    Column("port", Integer),
    Column("hostname", String(255), index=True),
    Column("timestamp", Integer),
    Column("expires", Integer),
    Column("flag", Text, default=""),
    UniqueConstraint("challenge_id", "team_id", name="uq_container_info_challenge_team"),
    UniqueConstraint("challenge_id", "user_id", name="uq_container_info_challenge_user"),
    Index("idx_container_info_team_challenge", "team_id", "challenge_id"),
    Index("idx_container_info_user_challenge", "user_id", "challenge_id"),
    Index("idx_container_info_expires", "expires"),
)

container_settings_model = Table(
    "container_settings_model",
    legacy_bootstrap_metadata,
    Column("key", String(512), primary_key=True),
    Column("value", Text),
)

container_flag_model = Table(
    "container_flag_model",
    legacy_bootstrap_metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column(
        "challenge_id",
        Integer,
        ForeignKey(
            Challenges.__table__.c.id,
            name="container_flag_model_ibfk_1",
            ondelete="CASCADE",
        ),
    ),
    Column(
        "container_id",
        String(512),
        ForeignKey(
            container_info_model.c.container_id,
            name="container_flag_model_ibfk_2",
            ondelete="CASCADE",
        ),
        nullable=True,
    ),
    Column("flag", Text),
    Column(
        "user_id",
        Integer,
        ForeignKey(
            Users.__table__.c.id,
            name="container_flag_model_ibfk_3",
            ondelete="CASCADE",
        ),
    ),
    Column(
        "team_id",
        Integer,
        ForeignKey(
            Teams.__table__.c.id,
            name="container_flag_model_ibfk_4",
            ondelete="CASCADE",
        ),
    ),
    Column("used", Boolean, default=False),
    Index("idx_container_flag_container_id", "container_id"),
    Index("idx_container_flag_team_challenge", "team_id", "challenge_id"),
    Index("idx_container_flag_user_challenge", "user_id", "challenge_id"),
)

container_cheat_log = Table(
    "container_cheat_log",
    legacy_bootstrap_metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("reused_flag", Text),
    Column(
        "challenge_id",
        Integer,
        ForeignKey(
            Challenges.__table__.c.id,
            name="container_cheat_log_ibfk_1",
            ondelete="CASCADE",
        ),
    ),
    Column(
        "original_team_id",
        Integer,
        ForeignKey(
            Teams.__table__.c.id,
            name="container_cheat_log_ibfk_2",
            ondelete="SET NULL",
        ),
        nullable=True,
    ),
    Column(
        "original_user_id",
        Integer,
        ForeignKey(
            Users.__table__.c.id,
            name="container_cheat_log_ibfk_3",
            ondelete="SET NULL",
        ),
        nullable=True,
    ),
    Column(
        "second_team_id",
        Integer,
        ForeignKey(
            Teams.__table__.c.id,
            name="container_cheat_log_ibfk_4",
            ondelete="SET NULL",
        ),
        nullable=True,
    ),
    Column(
        "second_user_id",
        Integer,
        ForeignKey(
            Users.__table__.c.id,
            name="container_cheat_log_ibfk_5",
            ondelete="SET NULL",
        ),
        nullable=True,
    ),
    Column("timestamp", Integer),
)

legacy_tables: Final = (
    container_challenge_model,
    container_info_model,
    container_settings_model,
    container_flag_model,
    container_cheat_log,
)


def bootstrap_legacy_schema(engine: Engine) -> None:
    """Create only the five plugin baseline tables when they are absent."""

    legacy_bootstrap_metadata.create_all(
        bind=engine,
        tables=legacy_tables,
        checkfirst=True,
    )
