"""Pure canonical state validation for the stable-random maintenance marker.

The maintenance command will own SQL writes.  This module has no database,
Docker, Flask, CTFd, or extension-model imports so it can be tested as a pure
fail-closed boundary before startup wiring exists.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
import re
from typing import Any, Mapping, Protocol


MARKER_CONTRACT = "stable-random-schema-v1"
ANCHOR_CONTRACT = "stable-random-schema-anchor-v1"
MARKER_KEY = "docker_per_team_stable_random_schema_v1"
ANCHOR_KEY = "docker_per_team_stable_random_schema_anchor_v1"
MIGRATION_CEILING = "d5e7f901a2b3"

PHASES = (
    "PREPARED_LEGACY",
    "S01_INFO_OWNER_SCOPE",
    "S02_INFO_OWNER_ID",
    "S03_INFO_MODE_SNAPSHOT",
    "S04_INFO_ISSUANCE_ID",
    "S05_INFO_ATTEMPT_ID",
    "S06_INFO_OWNER_LOOKUP_INDEX",
    "S07_DROP_INFO_CHALLENGE_CASCADE_FK",
    "S08_ADD_INFO_CHALLENGE_RESTRICT_FK",
    "S09_DROP_INFO_TEAM_CASCADE_FK",
    "S10_ADD_INFO_TEAM_RESTRICT_FK",
    "S11_DROP_INFO_USER_CASCADE_FK",
    "S12_ADD_INFO_USER_RESTRICT_FK",
    "S13_CONFIRM_NO_LEGACY_CONTAINER_STATE",
    "S14_INFO_OWNER_SCOPE_NOT_NULL",
    "S15_INFO_OWNER_ID_NOT_NULL",
    "S16_INFO_MODE_NOT_NULL",
    "S17_INFO_SCOPE_CHECK",
    "S18_INFO_LEGACY_OWNER_CHECK",
    "S19_INFO_MODE_ATTACHMENT_CHECK",
    "S20_INFO_NORMALIZED_OWNER_UNIQUE",
    "S21_INFO_ISSUANCE_UNIQUE",
    "S22_INFO_ATTEMPT_UNIQUE",
    "S23_FORMAT_TABLE",
    "S24_ISSUANCE_TABLE",
    "S25_ATTEMPT_TABLE",
    "S26_INFO_ISSUANCE_COMPOSITE_FK",
    "S27_INFO_ATTEMPT_COMPOSITE_FK",
    "S28_RANDOM_FORMAT_ROWS",
    "FINAL",
)

MARKER_FIELDS = frozenset(
    {
        "contract",
        "marker_row_id",
        "command_manifest_sha256",
        "legacy_schema_fingerprint",
        "phase",
        "phase_schema_sha256",
        "run_id",
        "created_at",
        "updated_at",
    }
)
ANCHOR_FIELDS = frozenset(
    {
        "contract",
        "marker_key",
        "marker_row_id",
        "run_id",
        "prepared_marker_sha256",
    }
)
_HEX_256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class MarkerValidationError(RuntimeError):
    """Malformed or mismatched durable marker state; callers must fail closed."""


class ConfigRecordLike(Protocol):
    row_id: int
    value: str | None


@dataclass(frozen=True)
class MarkerState:
    row_id: int
    raw: str
    document: Mapping[str, Any]


@dataclass(frozen=True)
class AnchorState:
    row_id: int
    raw: str
    document: Mapping[str, Any]


class StartupMode(str, Enum):
    LEGACY_ONLY = "legacy-only"
    MAINTENANCE = "maintenance-failed-closed"
    FINAL = "final"


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True)


def _parse_canonical_document(value: str | None, *, label: str) -> dict[str, Any]:
    if not isinstance(value, str):
        raise MarkerValidationError(f"{label} has no canonical JSON value")
    try:
        document = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise MarkerValidationError(f"{label} is not JSON") from exc
    if not isinstance(document, dict) or canonical_json(document) != value:
        raise MarkerValidationError(f"{label} is not canonical JSON")
    return document


def _positive_int(value: Any, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise MarkerValidationError(f"{label} must be a positive integer")
    return value


def _sha256_hex(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not _HEX_256_RE.fullmatch(value):
        raise MarkerValidationError(f"{label} must be lowercase SHA-256 hex")
    return value


def _timestamp(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not _UTC_TIMESTAMP_RE.fullmatch(value):
        raise MarkerValidationError(f"{label} must be a whole-second UTC timestamp")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise MarkerValidationError(f"{label} is not a real UTC timestamp") from exc
    return value


def validate_marker(record: ConfigRecordLike) -> MarkerState:
    row_id = _positive_int(record.row_id, label="marker physical row id")
    document = _parse_canonical_document(record.value, label="marker")
    if set(document) != MARKER_FIELDS:
        raise MarkerValidationError("marker has unexpected fields")
    if document["contract"] != MARKER_CONTRACT:
        raise MarkerValidationError("marker contract mismatch")
    if _positive_int(document["marker_row_id"], label="marker row id") != row_id:
        raise MarkerValidationError("marker JSON is not bound to its physical row")
    if document["phase"] not in PHASES:
        raise MarkerValidationError("marker phase is not declared")
    _sha256_hex(document["command_manifest_sha256"], label="command manifest")
    _sha256_hex(document["legacy_schema_fingerprint"], label="legacy schema fingerprint")
    _sha256_hex(document["phase_schema_sha256"], label="phase schema fingerprint")
    _sha256_hex(document["run_id"], label="run id")
    created = _timestamp(document["created_at"], label="marker creation time")
    updated = _timestamp(document["updated_at"], label="marker update time")
    if updated < created:
        raise MarkerValidationError("marker update time precedes creation")
    return MarkerState(row_id=row_id, raw=record.value, document=document)


def validate_anchor(record: ConfigRecordLike) -> AnchorState:
    row_id = _positive_int(record.row_id, label="anchor physical row id")
    document = _parse_canonical_document(record.value, label="anchor")
    if set(document) != ANCHOR_FIELDS:
        raise MarkerValidationError("anchor has unexpected fields")
    if document["contract"] != ANCHOR_CONTRACT:
        raise MarkerValidationError("anchor contract mismatch")
    if document["marker_key"] != MARKER_KEY:
        raise MarkerValidationError("anchor marker key mismatch")
    _positive_int(document["marker_row_id"], label="anchor marker row id")
    _sha256_hex(document["run_id"], label="anchor run id")
    _sha256_hex(document["prepared_marker_sha256"], label="anchor prepared marker hash")
    return AnchorState(row_id=row_id, raw=record.value, document=document)


def reconstructed_prepared_marker_sha256(
    marker: MarkerState,
    *,
    prepared_phase_schema_sha256: str,
) -> str:
    """Reconstruct the immutable first marker from a later marker's stable fields.

    The maintenance command writes the first PREPARED_LEGACY record with its
    update timestamp equal to creation time.  All later marker fields that
    describe identity stay immutable.  A reviewed fixture supplies the legacy
    phase fingerprint, so this reconstruction can be compared with the anchor
    after a restart without retaining a second copy of the marker value.
    """

    prepared_phase_schema_sha256 = _sha256_hex(
        prepared_phase_schema_sha256,
        label="prepared phase schema fingerprint",
    )
    prepared_document = dict(marker.document)
    prepared_document["phase"] = "PREPARED_LEGACY"
    prepared_document["phase_schema_sha256"] = prepared_phase_schema_sha256
    prepared_document["updated_at"] = prepared_document["created_at"]
    return hashlib.sha256(canonical_json(prepared_document).encode("ascii")).hexdigest()


def validate_anchor_marker_pair(
    marker_record: ConfigRecordLike,
    anchor_record: ConfigRecordLike,
    *,
    expected_prepared_marker_sha256: str | None = None,
) -> tuple[MarkerState, AnchorState]:
    """Validate the immutable first-marker binding for any later phase.

    The current row no longer contains the original PREPARED_LEGACY bytes after
    a phase transition.  Callers therefore must supply the independently
    reconstructed prepared-marker digest when validating a later phase.  The
    anchor alone is deliberately insufficient: trusting its stored digest
    without comparing it to that reconstruction would make a recreated marker
    pair appear valid after the first transition.
    """

    marker = validate_marker(marker_record)
    anchor = validate_anchor(anchor_record)
    if anchor.document["marker_row_id"] != marker.row_id:
        raise MarkerValidationError("anchor is bound to a different marker row")
    if anchor.document["run_id"] != marker.document["run_id"]:
        raise MarkerValidationError("anchor and marker run identities differ")
    if marker.document["phase"] == "PREPARED_LEGACY":
        expected = hashlib.sha256(marker.raw.encode("ascii")).hexdigest()
    else:
        expected = _sha256_hex(
            expected_prepared_marker_sha256,
            label="expected prepared marker digest",
        )
    if anchor.document["prepared_marker_sha256"] != expected:
        raise MarkerValidationError("anchor does not bind the prepared marker bytes")
    return marker, anchor


def classify_startup_mode(
    *,
    config_storage_matches: bool,
    legacy_schema_matches: bool,
    alembic_version: str | None,
    marker_record: ConfigRecordLike | None,
    anchor_record: ConfigRecordLike | None,
    final_schema_matches: bool,
    command_manifest_matches: bool,
    expected_prepared_marker_sha256: str | None = None,
) -> StartupMode:
    """Classify only the three P1 startup modes; anything uncertain is maintenance."""

    if not config_storage_matches or not legacy_schema_matches:
        return StartupMode.MAINTENANCE
    if alembic_version != MIGRATION_CEILING:
        return StartupMode.MAINTENANCE
    if marker_record is None and anchor_record is None:
        return StartupMode.LEGACY_ONLY
    if marker_record is None or anchor_record is None:
        return StartupMode.MAINTENANCE
    try:
        marker, _anchor = validate_anchor_marker_pair(
            marker_record,
            anchor_record,
            expected_prepared_marker_sha256=expected_prepared_marker_sha256,
        )
    except MarkerValidationError:
        return StartupMode.MAINTENANCE
    if (
        marker.document["phase"] == "FINAL"
        and final_schema_matches
        and command_manifest_matches
    ):
        return StartupMode.FINAL
    return StartupMode.MAINTENANCE
