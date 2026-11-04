"""Read-only schema fingerprints for the bounded legacy plugin boundary.

This module deliberately imports neither the extension ORM models nor Flask/CTFd
runtime state.  It only reads ``information_schema`` through a supplied
SQLAlchemy connection.  It is a P2 foundation for the guarded bootstrap and
maintenance command; importing it must never create, alter, or write anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import json
import re
from typing import Any, Final, Mapping, Sequence

from sqlalchemy import text
from sqlalchemy.engine import Connection


LEGACY_SCHEMA_FINGERPRINT_VERSION: Final = "legacy_schema_fingerprint_v1"
CONFIG_STORAGE_FINGERPRINT_VERSION: Final = "config_marker_storage_fingerprint_v1"
LEGACY_MIGRATION_CEILING: Final = "d5e7f901a2b3"
LEGACY_TABLE_NAMES: Final = (
    "container_challenge_model",
    "container_cheat_log",
    "container_flag_model",
    "container_info_model",
    "container_settings_model",
)
KNOWN_EXTENSION_TABLE_NAMES: Final = (
    "container_flag_issuance_model",
    "container_flag_launch_attempt_model",
    "container_random_flag_format_model",
)
CONFIG_TABLE_NAME: Final = "config"
ALEMBIC_VERSION_KEY: Final = "docker_per_team_alembic_version"
MARKER_KEY: Final = "docker_per_team_stable_random_schema_v1"
MARKER_ANCHOR_KEY: Final = "docker_per_team_stable_random_schema_anchor_v1"


class LegacySchemaPreflightError(RuntimeError):
    """The live database does not match the explicit safe admission boundary."""


@dataclass(frozen=True)
class ConfigRecord:
    """A cardinality-checked configuration record without interpreting its value."""

    row_id: int
    value: str | None


@dataclass(frozen=True)
class LegacySchemaPreflight:
    """Read-only snapshots required before any migration or runtime admission."""

    config_storage: Mapping[str, Any]
    legacy_schema: Mapping[str, Any]
    alembic_version: ConfigRecord | None
    marker: ConfigRecord | None
    marker_anchor: ConfigRecord | None


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the sole UTF-8 representation used for every fingerprint."""

    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _rows(connection: Connection, statement: str, params: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    """Run a fixed read-only statement and normalize SQLAlchemy row mappings."""

    result = connection.execute(text(statement), params or {})
    return [dict(row._mapping) for row in result]


def _one_value(connection: Connection, statement: str) -> Any:
    rows = _rows(connection, statement)
    if len(rows) != 1 or len(rows[0]) != 1:
        raise LegacySchemaPreflightError("expected one scalar database result")
    return next(iter(rows[0].values()))


def mariadb_major_version(connection: Connection) -> str:
    """Read and pin the MariaDB major.minor series, rejecting another engine."""

    version = _one_value(connection, "SELECT VERSION() AS version")
    if not isinstance(version, str) or "MariaDB" not in version:
        raise LegacySchemaPreflightError("stable-random schema requires MariaDB")
    match = re.match(r"^(\d+)\.(\d+)\.", version)
    if not match:
        raise LegacySchemaPreflightError("unparseable MariaDB version")
    return f"{match.group(1)}.{match.group(2)}"


def _database_name(connection: Connection) -> str:
    value = _one_value(connection, "SELECT DATABASE() AS database_name")
    if not isinstance(value, str) or not value:
        raise LegacySchemaPreflightError("connection has no selected database")
    return value


def _normalize_columns(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    expected = {"column_name", "column_type", "is_nullable", "column_default", "extra", "ordinal_position"}
    if any(set(row) != expected for row in rows):
        raise LegacySchemaPreflightError("unexpected information_schema column result")
    ordered = sorted(rows, key=lambda row: int(row["ordinal_position"]))
    if [int(row["ordinal_position"]) for row in ordered] != list(range(1, len(ordered) + 1)):
        raise LegacySchemaPreflightError("non-contiguous information_schema column order")
    return [
        {
            "name": str(row["column_name"]),
            "type": str(row["column_type"]),
            "nullable": str(row["is_nullable"]) == "YES",
            "default": row["column_default"],
            "extra": str(row["extra"]),
        }
        for row in ordered
    ]


def _normalize_indexes(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    expected = {"index_name", "non_unique", "seq_in_index", "column_name"}
    if any(set(row) != expected for row in rows):
        raise LegacySchemaPreflightError("unexpected information_schema index result")
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row["index_name"]), []).append(row)
    indexes: list[dict[str, Any]] = []
    for name in sorted(grouped):
        items = sorted(grouped[name], key=lambda row: int(row["seq_in_index"]))
        if [int(row["seq_in_index"]) for row in items] != list(range(1, len(items) + 1)):
            raise LegacySchemaPreflightError("non-contiguous information_schema index order")
        non_unique_values = {int(row["non_unique"]) for row in items}
        if len(non_unique_values) != 1:
            raise LegacySchemaPreflightError("index has inconsistent uniqueness")
        if name == "PRIMARY":
            kind = "PRIMARY"
        elif non_unique_values == {0}:
            kind = "UNIQUE"
        elif non_unique_values == {1}:
            kind = "NONUNIQUE"
        else:
            raise LegacySchemaPreflightError("unexpected information_schema index uniqueness")
        indexes.append(
            {
                "name": name,
                "kind": kind,
                "columns": [str(row["column_name"]) for row in items],
            }
        )
    return indexes


def _normalize_foreign_keys(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    expected = {
        "constraint_name",
        "ordinal_position",
        "column_name",
        "referenced_table_name",
        "referenced_column_name",
        "update_rule",
        "delete_rule",
    }
    if any(set(row) != expected for row in rows):
        raise LegacySchemaPreflightError("unexpected information_schema foreign-key result")
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row["constraint_name"]), []).append(row)
    foreign_keys: list[dict[str, Any]] = []
    for name in sorted(grouped):
        items = sorted(grouped[name], key=lambda row: int(row["ordinal_position"]))
        if [int(row["ordinal_position"]) for row in items] != list(range(1, len(items) + 1)):
            raise LegacySchemaPreflightError("non-contiguous information_schema foreign-key order")
        parents = {str(row["referenced_table_name"]) for row in items}
        updates = {str(row["update_rule"]) for row in items}
        deletes = {str(row["delete_rule"]) for row in items}
        if len(parents) != 1 or len(updates) != 1 or len(deletes) != 1:
            raise LegacySchemaPreflightError("foreign key has inconsistent parent or rules")
        foreign_keys.append(
            {
                "name": name,
                "child_columns": [str(row["column_name"]) for row in items],
                "parent_table": next(iter(parents)),
                "parent_columns": [str(row["referenced_column_name"]) for row in items],
                "on_update": next(iter(updates)),
                "on_delete": next(iter(deletes)),
            }
        )
    return foreign_keys


def _table_snapshot(connection: Connection, table_name: str) -> dict[str, Any]:
    """Read columns, index order, and FK rules for one fixed current-schema table."""

    params = {"table_name": table_name}
    columns = _normalize_columns(
        _rows(
            connection,
            """
            SELECT COLUMN_NAME AS column_name, COLUMN_TYPE AS column_type,
                   IS_NULLABLE AS is_nullable, COLUMN_DEFAULT AS column_default,
                   EXTRA AS extra, ORDINAL_POSITION AS ordinal_position
              FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table_name
             ORDER BY ORDINAL_POSITION
            """,
            params,
        )
    )
    if not columns:
        raise LegacySchemaPreflightError(f"required table is absent: {table_name}")
    indexes = _normalize_indexes(
        _rows(
            connection,
            """
            SELECT INDEX_NAME AS index_name, NON_UNIQUE AS non_unique,
                   SEQ_IN_INDEX AS seq_in_index, COLUMN_NAME AS column_name
              FROM information_schema.STATISTICS
             WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table_name
             ORDER BY INDEX_NAME, SEQ_IN_INDEX
            """,
            params,
        )
    )
    foreign_keys = _normalize_foreign_keys(
        _rows(
            connection,
            """
            SELECT kcu.CONSTRAINT_NAME AS constraint_name,
                   kcu.ORDINAL_POSITION AS ordinal_position,
                   kcu.COLUMN_NAME AS column_name,
                   kcu.REFERENCED_TABLE_NAME AS referenced_table_name,
                   kcu.REFERENCED_COLUMN_NAME AS referenced_column_name,
                   rc.UPDATE_RULE AS update_rule,
                   rc.DELETE_RULE AS delete_rule
              FROM information_schema.KEY_COLUMN_USAGE AS kcu
              JOIN information_schema.REFERENTIAL_CONSTRAINTS AS rc
                ON rc.CONSTRAINT_SCHEMA = kcu.CONSTRAINT_SCHEMA
               AND rc.TABLE_NAME = kcu.TABLE_NAME
               AND rc.CONSTRAINT_NAME = kcu.CONSTRAINT_NAME
             WHERE kcu.TABLE_SCHEMA = DATABASE()
               AND kcu.TABLE_NAME = :table_name
               AND kcu.REFERENCED_TABLE_NAME IS NOT NULL
             ORDER BY kcu.CONSTRAINT_NAME, kcu.ORDINAL_POSITION
            """,
            params,
        )
    )
    return {
        "name": table_name,
        "columns": columns,
        "indexes": indexes,
        "foreign_keys": foreign_keys,
    }


def collect_config_storage_snapshot(connection: Connection) -> dict[str, Any]:
    return {
        "schema": CONFIG_STORAGE_FINGERPRINT_VERSION,
        "mariadb_major_version": mariadb_major_version(connection),
        "table": _table_snapshot(connection, CONFIG_TABLE_NAME),
    }


def collect_legacy_schema_snapshot(connection: Connection) -> dict[str, Any]:
    """Capture the exact five-table post-ceiling legacy boundary, read-only."""

    discovered = _rows(
        connection,
        """
        SELECT TABLE_NAME AS table_name
          FROM information_schema.TABLES
         WHERE TABLE_SCHEMA = DATABASE()
           AND TABLE_NAME LIKE 'container\\_%' ESCAPE '\\\\'
         ORDER BY TABLE_NAME
        """,
    )
    discovered_names = tuple(str(row["table_name"]) for row in discovered)
    if discovered_names != LEGACY_TABLE_NAMES:
        raise LegacySchemaPreflightError(
            "container plugin table inventory is not exactly the legacy boundary"
        )
    return {
        "schema": LEGACY_SCHEMA_FINGERPRINT_VERSION,
        "mariadb_major_version": mariadb_major_version(connection),
        "migration_ceiling": LEGACY_MIGRATION_CEILING,
        "tables": [_table_snapshot(connection, name) for name in LEGACY_TABLE_NAMES],
    }


def require_fixture(live: Mapping[str, Any], expected: Mapping[str, Any], *, label: str) -> str:
    """Return a verified fingerprint or fail closed without mutating the database."""

    if canonical_json_bytes(live) != canonical_json_bytes(expected):
        raise LegacySchemaPreflightError(f"{label} does not match the pinned fixture")
    return canonical_sha256(live)


def read_single_config_record(connection: Connection, key: str) -> ConfigRecord | None:
    """Read one reserved config key; zero rows is absent and every other count fails."""

    if key not in {ALEMBIC_VERSION_KEY, MARKER_KEY, MARKER_ANCHOR_KEY}:
        raise LegacySchemaPreflightError("unrecognized reserved config key")
    rows = _rows(
        connection,
        """
        SELECT id AS row_id, value AS value
          FROM config
         WHERE `key` = :key
         ORDER BY id
        """,
        {"key": key},
    )
    if not rows:
        return None
    if len(rows) != 1 or set(rows[0]) != {"row_id", "value"}:
        raise LegacySchemaPreflightError(f"reserved config key has invalid cardinality: {key}")
    row_id = rows[0]["row_id"]
    if not isinstance(row_id, int) or row_id <= 0:
        raise LegacySchemaPreflightError(f"reserved config key has invalid primary key: {key}")
    value = rows[0]["value"]
    if value is not None and not isinstance(value, str):
        raise LegacySchemaPreflightError(f"reserved config key has a non-text value: {key}")
    return ConfigRecord(row_id=row_id, value=value)


def collect_read_only_preflight(connection: Connection) -> LegacySchemaPreflight:
    """Collect every gated snapshot before bootstrap, migrations, or marker writes."""

    storage = collect_config_storage_snapshot(connection)
    legacy = collect_legacy_schema_snapshot(connection)
    return LegacySchemaPreflight(
        config_storage=storage,
        legacy_schema=legacy,
        alembic_version=read_single_config_record(connection, ALEMBIC_VERSION_KEY),
        marker=read_single_config_record(connection, MARKER_KEY),
        marker_anchor=read_single_config_record(connection, MARKER_ANCHOR_KEY),
    )


FIXTURE_DIRECTORY: Final = Path(__file__).with_name("schema-fixtures")


def load_pinned_fixture(filename: str) -> dict[str, Any]:
    """Load one reviewed JSON fixture from the plugin-owned fixture directory."""

    allowed = {
        "config-marker-storage-v1.json",
        "legacy-schema-v1.json",
    }
    if filename not in allowed:
        raise LegacySchemaPreflightError("unrecognized schema fixture")
    try:
        loaded = json.loads((FIXTURE_DIRECTORY / filename).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LegacySchemaPreflightError("unreadable schema fixture") from exc
    if not isinstance(loaded, dict):
        raise LegacySchemaPreflightError("schema fixture is not an object")
    return loaded


def verify_read_only_preflight(
    connection: Connection,
    *,
    config_storage_fixture: Mapping[str, Any],
    legacy_schema_fixture: Mapping[str, Any],
) -> LegacySchemaPreflight:
    """Match both reviewed fixtures before any caller may mutate schema or config."""

    preflight = collect_read_only_preflight(connection)
    require_fixture(
        preflight.config_storage,
        config_storage_fixture,
        label="config marker storage",
    )
    require_fixture(
        preflight.legacy_schema,
        legacy_schema_fixture,
        label="legacy plugin schema",
    )
    return preflight
