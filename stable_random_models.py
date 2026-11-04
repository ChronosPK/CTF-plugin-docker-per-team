"""Schema-only foundation for stable random per-owner flag issuance.

This module deliberately has no plugin-bootstrap side effects.  The guarded
maintenance command is the only code allowed to create these tables; importing
the models merely registers their metadata once Final mode is admitted.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
from typing import Final

from sqlalchemy import (
    CheckConstraint,
    Column,
    Computed,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects import mysql

from CTFd.models import db


RANDOM_FLAG_ALGORITHM: Final = "ascii-alnum-csprng-v1"
ISSUANCE_STATES: Final = frozenset(
    {
        "RESERVED_UNEXPOSED",
        "RESERVED_EXPOSED",
        "ISSUED",
        "RETIRED",
    }
)
CURRENT_ISSUANCE_STATES: Final = frozenset(
    {
        "RESERVED_UNEXPOSED",
        "RESERVED_EXPOSED",
        "ISSUED",
    }
)
LAUNCH_ATTEMPT_STATES: Final = frozenset(
    {
        "PREPARED",
        "DISPATCHED",
        "ATTACHED",
        "CONTAINED",
        "CANCELLED",
        "AMBIGUOUS_BLOCKING",
    }
)
CURRENT_LAUNCH_ATTEMPT_STATES: Final = frozenset(
    {"PREPARED", "DISPATCHED", "AMBIGUOUS_BLOCKING"}
)

_FORMAT_ENCODING_DOMAIN: Final = b"csctf26:container-random-flag-format:v1\x00"
_MAX_FORMAT_COMPONENT_BYTES: Final = 512
_MAX_TOTAL_FORMAT_BYTES: Final = 512
_MAX_RANDOM_LENGTH: Final = 128


class StableRandomModelValidationError(ValueError):
    """A pure schema-format or lifecycle-state validation error."""


@dataclass(frozen=True)
class ValidatedRandomFlagFormat:
    """Validated immutable fields suitable for a format-row insert."""

    algorithm: str
    prefix: bytes
    suffix: bytes
    random_length: int
    total_length: int


def _require_integer(
    value: object,
    *,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StableRandomModelValidationError(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise StableRandomModelValidationError(
            f"{field} must be between {minimum} and {maximum}"
        )
    return value


def _require_ascii_bytes(value: object, *, field: str) -> bytes:
    if not isinstance(value, bytes):
        raise StableRandomModelValidationError(f"{field} must be bytes")
    if not value:
        raise StableRandomModelValidationError(f"{field} must not be empty")
    if len(value) > _MAX_FORMAT_COMPONENT_BYTES:
        raise StableRandomModelValidationError(f"{field} is too long")
    try:
        value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise StableRandomModelValidationError(f"{field} must be ASCII") from exc
    return value


def validate_random_flag_format(
    *,
    algorithm: object,
    prefix: object,
    suffix: object,
    random_length: object,
    total_length: object,
) -> ValidatedRandomFlagFormat:
    """Validate only the immutable, non-secret random-format contract."""

    if algorithm != RANDOM_FLAG_ALGORITHM:
        raise StableRandomModelValidationError("unsupported random flag algorithm")
    normalized_prefix = _require_ascii_bytes(prefix, field="prefix")
    normalized_suffix = _require_ascii_bytes(suffix, field="suffix")
    normalized_random_length = _require_integer(
        random_length,
        field="random_length",
        minimum=1,
        maximum=_MAX_RANDOM_LENGTH,
    )
    normalized_total_length = _require_integer(
        total_length,
        field="total_length",
        minimum=1,
        maximum=_MAX_TOTAL_FORMAT_BYTES,
    )
    expected_total_length = (
        len(normalized_prefix) + normalized_random_length + len(normalized_suffix)
    )
    if normalized_total_length != expected_total_length:
        raise StableRandomModelValidationError(
            "total_length does not match prefix, random_length, and suffix"
        )
    return ValidatedRandomFlagFormat(
        algorithm=RANDOM_FLAG_ALGORITHM,
        prefix=normalized_prefix,
        suffix=normalized_suffix,
        random_length=normalized_random_length,
        total_length=normalized_total_length,
    )


def _length_prefixed(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _unsigned_64(value: object, *, field: str) -> bytes:
    return _require_integer(
        value,
        field=field,
        minimum=1,
        maximum=(1 << 64) - 1,
    ).to_bytes(8, "big")


def canonical_format_encoding(
    *,
    format_id: object,
    challenge_id: object,
    algorithm: object,
    prefix: object,
    suffix: object,
    random_length: object,
    total_length: object,
) -> bytes:
    """Return the versioned, length-prefixed encoding bound by format_sha256.

    Each field name and each field value is length prefixed.  Integer values
    have a fixed eight-byte unsigned big-endian representation before their
    value prefix.  Including the surrogate and challenge IDs prevents a valid
    format snapshot from being copied to another row or challenge.
    """

    normalized = validate_random_flag_format(
        algorithm=algorithm,
        prefix=prefix,
        suffix=suffix,
        random_length=random_length,
        total_length=total_length,
    )
    fields = (
        (b"id", _unsigned_64(format_id, field="format_id")),
        (b"challenge_id", _unsigned_64(challenge_id, field="challenge_id")),
        (b"algorithm", normalized.algorithm.encode("ascii")),
        (b"prefix", normalized.prefix),
        (b"suffix", normalized.suffix),
        (
            b"random_length",
            normalized.random_length.to_bytes(8, "big"),
        ),
        (b"total_length", normalized.total_length.to_bytes(8, "big")),
    )
    return _FORMAT_ENCODING_DOMAIN + b"".join(
        _length_prefixed(name) + _length_prefixed(value) for name, value in fields
    )


def canonical_format_sha256(**format_fields: object) -> bytes:
    """Return the binary SHA-256 snapshot digest for validated format fields."""

    return hashlib.sha256(canonical_format_encoding(**format_fields)).digest()


def _validate_state(state: object, *, field: str, allowed: frozenset[str]) -> str:
    if not isinstance(state, str) or state not in allowed:
        raise StableRandomModelValidationError(f"unknown {field}")
    return state


def validate_issuance_state(state: object) -> str:
    """Validate a state literal without performing any lifecycle transition."""

    return _validate_state(
        state,
        field="issuance state",
        allowed=ISSUANCE_STATES,
    )


def validate_launch_attempt_state(state: object) -> str:
    """Validate a launch-attempt state literal without authorizing Docker work."""

    return _validate_state(
        state,
        field="launch attempt state",
        allowed=LAUNCH_ATTEMPT_STATES,
    )


class ContainerRandomFlagFormatModel(db.Model):
    """One immutable format snapshot per random container challenge."""

    __tablename__ = "container_random_flag_format_model"
    __table_args__ = (
        UniqueConstraint(
            "challenge_id",
            name="uq_crff_challenge",
        ),
        UniqueConstraint(
            "id",
            "challenge_id",
            "format_sha256",
            name="uq_crff_snapshot",
        ),
        CheckConstraint(
            "algorithm = 'ascii-alnum-csprng-v1'",
            name="ck_crff_algorithm",
        ),
        CheckConstraint(
            "OCTET_LENGTH(prefix) BETWEEN 1 AND 512 "
            "AND OCTET_LENGTH(suffix) BETWEEN 1 AND 512 "
            "AND prefix REGEXP '^[[:ascii:]]+$' "
            "AND suffix REGEXP '^[[:ascii:]]+$'",
            name="ck_crff_prefix_suffix",
        ),
        CheckConstraint(
            "random_length BETWEEN 1 AND 128",
            name="ck_crff_random_length",
        ),
        CheckConstraint(
            "total_length = OCTET_LENGTH(prefix) + random_length + "
            "OCTET_LENGTH(suffix) AND total_length <= 512",
            name="ck_crff_total_length",
        ),
        CheckConstraint(
            "OCTET_LENGTH(format_sha256) = 32",
            name="ck_crff_digest_length",
        ),
    )

    id = Column(mysql.BIGINT(unsigned=True), primary_key=True, autoincrement=True)
    challenge_id = Column(
        Integer,
        ForeignKey(
            "challenges.id",
            ondelete="RESTRICT",
            name="fk_crff_challenge_restrict",
        ),
        nullable=False,
    )
    algorithm = Column(
        mysql.VARCHAR(32, charset="ascii", collation="ascii_bin"),
        nullable=False,
    )
    prefix = Column(mysql.VARBINARY(512), nullable=False)
    suffix = Column(mysql.VARBINARY(512), nullable=False)
    random_length = Column(Integer, nullable=False)
    total_length = Column(Integer, nullable=False)
    format_sha256 = Column(mysql.BINARY(32), nullable=False)
    created_at = Column(
        mysql.DATETIME(fsp=6),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP(6)"),
    )


class ContainerFlagIssuanceModel(db.Model):
    """Retained candidate allocation record and sole random-validator source."""

    __tablename__ = "container_flag_issuance_model"
    __table_args__ = (
        UniqueConstraint(
            "challenge_id",
            "owner_scope",
            "current_owner_id",
            name="uq_crfi_current_owner",
        ),
        UniqueConstraint("flag", name="uq_crfi_flag"),
        UniqueConstraint("flag_sha256", name="uq_crfi_flag_sha256"),
        UniqueConstraint(
            "id",
            "challenge_id",
            "owner_scope",
            "owner_id",
            name="uq_crfi_attachment_parent",
        ),
        ForeignKeyConstraint(
            ["format_id", "challenge_id", "format_sha256"],
            [
                "container_random_flag_format_model.id",
                "container_random_flag_format_model.challenge_id",
                "container_random_flag_format_model.format_sha256",
            ],
            name="fk_crfi_format_snapshot",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "owner_scope IN ('team', 'user')",
            name="ck_crfi_owner_scope",
        ),
        CheckConstraint("owner_id > 0", name="ck_crfi_owner_positive"),
        CheckConstraint(
            "(owner_scope = 'team' AND team_owner_id = owner_id "
            "AND user_owner_id IS NULL) OR "
            "(owner_scope = 'user' AND user_owner_id = owner_id "
            "AND team_owner_id IS NULL)",
            name="ck_crfi_owner_reference",
        ),
        CheckConstraint(
            "OCTET_LENGTH(flag) BETWEEN 1 AND 512 "
            "AND OCTET_LENGTH(flag_sha256) = 32 "
            "AND OCTET_LENGTH(format_sha256) = 32",
            name="ck_crfi_binary_lengths",
        ),
        CheckConstraint(
            "state IN ('RESERVED_UNEXPOSED', 'RESERVED_EXPOSED', "
            "'ISSUED', 'RETIRED')",
            name="ck_crfi_state",
        ),
        CheckConstraint(
            "(state IN ('RESERVED_UNEXPOSED', 'RESERVED_EXPOSED') "
            "AND reservation_deadline IS NOT NULL AND issued_at IS NULL "
            "AND retired_at IS NULL AND retire_reason IS NULL) OR "
            "(state = 'ISSUED' AND reservation_deadline IS NULL "
            "AND issued_at IS NOT NULL AND retired_at IS NULL "
            "AND retire_reason IS NULL) OR "
            "(state = 'RETIRED' AND reservation_deadline IS NULL "
            "AND issued_at IS NULL AND retired_at IS NOT NULL "
            "AND OCTET_LENGTH(retire_reason) BETWEEN 1 AND 128)",
            name="ck_crfi_state_dates",
        ),
        Index(
            "idx_crfi_owner_state",
            "challenge_id",
            "owner_scope",
            "owner_id",
            "state",
        ),
        Index(
            "idx_crfi_format_snapshot",
            "format_id",
            "challenge_id",
            "format_sha256",
        ),
        Index("idx_crfi_team_owner", "team_owner_id"),
        Index("idx_crfi_user_owner", "user_owner_id"),
    )

    id = Column(mysql.BIGINT(unsigned=True), primary_key=True, autoincrement=True)
    challenge_id = Column(
        Integer,
        ForeignKey(
            "challenges.id",
            ondelete="RESTRICT",
            name="fk_crfi_challenge_restrict",
        ),
        nullable=False,
    )
    format_id = Column(mysql.BIGINT(unsigned=True), nullable=False)
    format_sha256 = Column(mysql.BINARY(32), nullable=False)
    owner_scope = Column(
        mysql.VARCHAR(4, charset="ascii", collation="ascii_bin"),
        nullable=False,
    )
    # CTFd 3.8 parent IDs are signed INT.  Positivity is enforced by a CHECK so
    # these FK columns remain type-compatible with teams.id and users.id.
    owner_id = Column(Integer, nullable=False)
    team_owner_id = Column(
        Integer,
        ForeignKey(
            "teams.id",
            ondelete="RESTRICT",
            name="fk_crfi_team_owner_restrict",
        ),
        nullable=True,
    )
    user_owner_id = Column(
        Integer,
        ForeignKey(
            "users.id",
            ondelete="RESTRICT",
            name="fk_crfi_user_owner_restrict",
        ),
        nullable=True,
    )
    flag = Column(mysql.VARBINARY(512), nullable=False)
    flag_sha256 = Column(mysql.BINARY(32), nullable=False)
    state = Column(
        mysql.VARCHAR(20, charset="ascii", collation="ascii_bin"),
        nullable=False,
    )
    current_owner_id = Column(
        Integer,
        Computed(
            "CASE WHEN state IN ('RESERVED_UNEXPOSED', 'RESERVED_EXPOSED', "
            "'ISSUED') THEN owner_id ELSE NULL END",
            persisted=True,
        ),
        nullable=True,
    )
    reservation_deadline = Column(mysql.DATETIME(fsp=6), nullable=True)
    issued_at = Column(mysql.DATETIME(fsp=6), nullable=True)
    retired_at = Column(mysql.DATETIME(fsp=6), nullable=True)
    retire_reason = Column(
        mysql.VARCHAR(128, charset="ascii", collation="ascii_bin"),
        nullable=True,
    )


class ContainerFlagLaunchAttemptModel(db.Model):
    """Durable one-current-attempt fence for every random Docker launch."""

    __tablename__ = "container_flag_launch_attempt_model"
    __table_args__ = (
        UniqueConstraint("current_issuance_id", name="uq_crfla_current_issuance"),
        UniqueConstraint("docker_name", name="uq_crfla_docker_name"),
        UniqueConstraint(
            "id",
            "issuance_id",
            "challenge_id",
            "owner_scope",
            "owner_id",
            name="uq_crfla_attachment_parent",
        ),
        ForeignKeyConstraint(
            ["issuance_id", "challenge_id", "owner_scope", "owner_id"],
            [
                "container_flag_issuance_model.id",
                "container_flag_issuance_model.challenge_id",
                "container_flag_issuance_model.owner_scope",
                "container_flag_issuance_model.owner_id",
            ],
            name="fk_crfla_issuance_parent",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "id REGEXP '^[0-9a-f]{32}$'",
            name="ck_crfla_id_hex",
        ),
        CheckConstraint("owner_id > 0", name="ck_crfla_owner_positive"),
        CheckConstraint(
            "OCTET_LENGTH(docker_name) BETWEEN 1 AND 128",
            name="ck_crfla_docker_name",
        ),
        CheckConstraint(
            "state IN ('PREPARED', 'DISPATCHED', 'ATTACHED', 'CONTAINED', "
            "'CANCELLED', 'AMBIGUOUS_BLOCKING')",
            name="ck_crfla_state",
        ),
        CheckConstraint(
            "(state = 'DISPATCHED' AND dispatch_authority_sha256 IS NOT NULL "
            "AND OCTET_LENGTH(dispatch_authority_sha256) = 32) OR "
            "(state <> 'DISPATCHED' AND dispatch_authority_sha256 IS NULL)",
            name="ck_crfla_dispatch_authority",
        ),
        CheckConstraint(
            "(state = 'PREPARED' AND deadline IS NOT NULL "
            "AND dispatched_at IS NULL AND attached_at IS NULL "
            "AND contained_at IS NULL AND disposition_reason IS NULL) OR "
            "(state = 'DISPATCHED' AND deadline IS NOT NULL "
            "AND dispatched_at IS NOT NULL AND attached_at IS NULL "
            "AND contained_at IS NULL AND disposition_reason IS NULL) OR "
            "(state = 'ATTACHED' AND dispatched_at IS NOT NULL "
            "AND attached_at IS NOT NULL AND contained_at IS NULL "
            "AND disposition_reason IS NULL) OR "
            "(state = 'CONTAINED' AND dispatched_at IS NOT NULL "
            "AND attached_at IS NULL AND contained_at IS NOT NULL "
            "AND OCTET_LENGTH(disposition_reason) BETWEEN 1 AND 128) OR "
            "(state = 'CANCELLED' AND dispatched_at IS NULL "
            "AND attached_at IS NULL AND contained_at IS NULL "
            "AND OCTET_LENGTH(disposition_reason) BETWEEN 1 AND 128) OR "
            "(state = 'AMBIGUOUS_BLOCKING' AND attached_at IS NULL "
            "AND OCTET_LENGTH(disposition_reason) BETWEEN 1 AND 128)",
            name="ck_crfla_state_dates",
        ),
        Index(
            "idx_crfla_issuance_owner",
            "issuance_id",
            "challenge_id",
            "owner_scope",
            "owner_id",
        ),
        Index("idx_crfla_state_deadline", "state", "deadline"),
    )

    id = Column(
        mysql.CHAR(32, charset="ascii", collation="ascii_bin"),
        primary_key=True,
    )
    issuance_id = Column(mysql.BIGINT(unsigned=True), nullable=False)
    challenge_id = Column(Integer, nullable=False)
    owner_scope = Column(
        mysql.VARCHAR(4, charset="ascii", collation="ascii_bin"),
        nullable=False,
    )
    owner_id = Column(Integer, nullable=False)
    docker_name = Column(
        mysql.VARCHAR(128, charset="ascii", collation="ascii_bin"),
        nullable=False,
    )
    state = Column(
        mysql.VARCHAR(20, charset="ascii", collation="ascii_bin"),
        nullable=False,
    )
    current_issuance_id = Column(
        mysql.BIGINT(unsigned=True),
        Computed(
            "CASE WHEN state IN ('PREPARED', 'DISPATCHED', "
            "'AMBIGUOUS_BLOCKING') THEN issuance_id ELSE NULL END",
            persisted=True,
        ),
        nullable=True,
    )
    deadline = Column(mysql.DATETIME(fsp=6), nullable=True)
    dispatched_at = Column(mysql.DATETIME(fsp=6), nullable=True)
    attached_at = Column(mysql.DATETIME(fsp=6), nullable=True)
    contained_at = Column(mysql.DATETIME(fsp=6), nullable=True)
    disposition_reason = Column(
        mysql.VARCHAR(128, charset="ascii", collation="ascii_bin"),
        nullable=True,
    )
    dispatch_authority_sha256 = Column(mysql.BINARY(32), nullable=True)
