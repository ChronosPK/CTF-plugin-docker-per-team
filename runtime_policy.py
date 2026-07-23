"""Fail-closed runtime identity and hardening policy for challenge containers.

This module deliberately has no Flask, CTFd, or Docker SDK imports so the policy
can be tested without booting the platform.  ``container_manager`` converts the
returned logging dictionary to ``docker.types.LogConfig`` at the SDK boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import math
import re
from typing import Mapping
from urllib.parse import urlsplit


IDENTITY_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
NETWORK_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
IMAGE_DIGEST_PATTERN = re.compile(r"@sha256:[0-9a-f]{64}$")
LOG_SIZE_PATTERN = re.compile(r"^[1-9][0-9]*[kmg]$")

REQUIRED_ENVIRONMENT = (
    "CTF_EVENT_ID",
    "CTF_RELEASE_ID",
    "CTF_TARGET_ID",
    "CTF_CHALLENGE_NETWORK",
    "CTF_IMAGE_PREFIX",
    "CTF_EGRESS_POLICY",
    "CTF_CHALLENGE_BIND_IP",
)
TARGET_IDS = {"local", "staging", "production"}
NON_RELEASE_IDS = {"development", "dev", "latest", "local", "unreleased"}
EGRESS_POLICIES = {"not-enforced", "worker-firewall-default-deny"}
EGRESS_ENFORCED_TARGET_IDS = {"staging", "production"}

REQUIRED_DAEMON_CAPABILITIES = {
    "MemoryLimit": "memory limits",
    "SwapLimit": "memory+swap limits",
    "CpuCfsPeriod": "CPU period limits",
    "CpuCfsQuota": "CPU quota limits",
    "PidsLimit": "PID limits",
}
LOCAL_RELAXABLE_DAEMON_CAPABILITIES = {"MemoryLimit", "SwapLimit"}
LOCAL_DAEMON_CAPABILITY_OVERRIDE_ENV = (
    "CTF_LOCAL_ALLOW_MISSING_DOCKER_MEMORY_LIMITS"
)

DEFAULT_MEMORY_MB = 1024
DEFAULT_CPU_LIMIT = 1.0
DEFAULT_PIDS_LIMIT = 512
DEFAULT_TMPFS_SIZE_MB = 256
DEFAULT_LOG_MAX_SIZE = "10m"
DEFAULT_LOG_MAX_FILES = 3
DEFAULT_START_TIMEOUT_SECONDS = 60


class RuntimePolicyError(ValueError):
    """Raised when runtime identity or hardening configuration is unsafe."""


def _required_value(environment: Mapping[str, str], name: str) -> str:
    value = str(environment.get(name, "") or "").strip()
    if not value:
        raise RuntimePolicyError(f"{name} is required for container runtime ownership")
    return value


def _validate_identity_component(value: str, *, field: str) -> str:
    if not IDENTITY_PATTERN.fullmatch(value):
        raise RuntimePolicyError(
            f"{field} must be a lowercase identifier using only letters, digits, '.', '_' or '-'"
        )
    return value


def _event_network_prefix(event_id: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", event_id).strip("_") + "_"


@dataclass(frozen=True)
class RuntimeIdentity:
    """Immutable event/target/release ownership supplied by the CTFd process."""

    event_id: str
    release_id: str
    target_id: str
    challenge_network: str
    image_prefix: str
    egress_policy: str
    challenge_bind_ip: str

    @classmethod
    def from_environment(cls, environment: Mapping[str, str]) -> "RuntimeIdentity":
        values = {
            name: _required_value(environment, name)
            for name in REQUIRED_ENVIRONMENT
        }
        event_id = _validate_identity_component(
            values["CTF_EVENT_ID"], field="CTF_EVENT_ID"
        )
        release_id = _validate_identity_component(
            values["CTF_RELEASE_ID"], field="CTF_RELEASE_ID"
        )
        target_id = _validate_identity_component(
            values["CTF_TARGET_ID"], field="CTF_TARGET_ID"
        )
        if target_id not in TARGET_IDS:
            raise RuntimePolicyError(
                "CTF_TARGET_ID must be one of local, staging, or production"
            )
        if target_id == "production" and release_id in NON_RELEASE_IDS:
            raise RuntimePolicyError(
                "Production requires an immutable release id, not a development placeholder"
            )

        challenge_network = values["CTF_CHALLENGE_NETWORK"]
        if not NETWORK_PATTERN.fullmatch(challenge_network):
            raise RuntimePolicyError(
                "CTF_CHALLENGE_NETWORK is not a valid Docker network name"
            )
        if not challenge_network.lower().startswith(_event_network_prefix(event_id)):
            raise RuntimePolicyError(
                "CTF_CHALLENGE_NETWORK must be namespaced by CTF_EVENT_ID"
            )

        image_prefix = values["CTF_IMAGE_PREFIX"]
        if (
            any(character.isspace() for character in image_prefix)
            or image_prefix.startswith(('"', "'", "\\", "/"))
            or not image_prefix.endswith("/")
        ):
            raise RuntimePolicyError(
                "CTF_IMAGE_PREFIX must be a normalized repository prefix ending in '/'"
            )

        egress_policy = values["CTF_EGRESS_POLICY"]
        if egress_policy not in EGRESS_POLICIES:
            raise RuntimePolicyError(
                "CTF_EGRESS_POLICY must be one of not-enforced or "
                "worker-firewall-default-deny"
            )
        if (
            target_id in EGRESS_ENFORCED_TARGET_IDS
            and egress_policy != "worker-firewall-default-deny"
        ):
            raise RuntimePolicyError(
                "Staging and production require a verified default-deny worker "
                "firewall (CTF_EGRESS_POLICY=worker-firewall-default-deny)"
            )

        challenge_bind_ip = values["CTF_CHALLENGE_BIND_IP"]
        try:
            parsed_bind_ip = ipaddress.ip_address(challenge_bind_ip)
        except ValueError as error:
            raise RuntimePolicyError(
                "CTF_CHALLENGE_BIND_IP must be a literal IP address"
            ) from error
        if parsed_bind_ip.version != 4:
            raise RuntimePolicyError(
                "CTF_CHALLENGE_BIND_IP currently supports IPv4 only"
            )

        return cls(
            event_id=event_id,
            release_id=release_id,
            target_id=target_id,
            challenge_network=challenge_network,
            image_prefix=image_prefix,
            egress_policy=egress_policy,
            challenge_bind_ip=str(parsed_bind_ip),
        )

    def labels(self) -> dict[str, str]:
        return {
            "ctfd.event_id": self.event_id,
            "ctfd.release_id": self.release_id,
            "ctfd.target_id": self.target_id,
            "ctfd.egress_policy": self.egress_policy,
            "ctfd.challenge_bind_ip": self.challenge_bind_ip,
        }

    def owns_labels(self, labels: Mapping[str, str] | None) -> bool:
        return bool(labels) and all(
            labels.get(key) == value
            for key, value in {
                "ctfd.event_id": self.event_id,
                "ctfd.target_id": self.target_id,
            }.items()
        )


def allow_limited_local_daemon(
    environment: Mapping[str, str],
    identity: RuntimeIdentity,
) -> bool:
    """Parse the narrowly scoped, local-only Docker capability override."""

    raw_value = str(
        environment.get(LOCAL_DAEMON_CAPABILITY_OVERRIDE_ENV, "") or ""
    ).strip().lower()
    if raw_value not in {"", "false", "true"}:
        raise RuntimePolicyError(
            f"{LOCAL_DAEMON_CAPABILITY_OVERRIDE_ENV} must be true or false"
        )
    enabled = raw_value == "true"
    if enabled and identity.target_id != "local":
        raise RuntimePolicyError(
            f"{LOCAL_DAEMON_CAPABILITY_OVERRIDE_ENV} is permitted only for local targets"
        )
    return enabled


def validate_daemon_capabilities(
    info: Mapping[str, object],
    *,
    identity: RuntimeIdentity | None = None,
    allow_limited_local: bool = False,
) -> dict[str, bool]:
    """Require every promised worker control, with one explicit local exception."""

    capabilities = {
        key: info.get(key) is True for key in REQUIRED_DAEMON_CAPABILITIES
    }
    missing_keys = {key for key, enabled in capabilities.items() if not enabled}
    if (
        missing_keys
        and allow_limited_local
        and identity is not None
        and identity.target_id == "local"
        and missing_keys.issubset(LOCAL_RELAXABLE_DAEMON_CAPABILITIES)
    ):
        return capabilities

    missing = [
        description
        for key, description in REQUIRED_DAEMON_CAPABILITIES.items()
        if not capabilities[key]
    ]
    if missing:
        raise RuntimePolicyError(
            "Docker worker cannot enforce required controls: " + ", ".join(missing)
        )
    return capabilities


def account_rate_limit_key(
    *,
    scope_id: int,
    is_team: bool,
    endpoint: str,
    key_prefix: str = "docker-per-team:rate-v2",
) -> str:
    """Build a rate-limit key that cannot couple unrelated NAT users."""

    try:
        normalized_scope_id = int(scope_id)
    except (TypeError, ValueError) as error:
        raise RuntimePolicyError("Rate-limit account id must be an integer") from error
    if normalized_scope_id <= 0:
        raise RuntimePolicyError("Rate-limit account id must be positive")
    normalized_endpoint = str(endpoint or "").strip()
    if not normalized_endpoint:
        raise RuntimePolicyError("Rate-limit endpoint is required")
    scope = "team" if is_team else "user"
    return (
        f"{str(key_prefix or 'docker-per-team:rate-v2').strip()}:"
        f"{scope}:{normalized_scope_id}:{normalized_endpoint}"
    )


def validate_challenge_network_attributes(
    attrs: Mapping[str, object],
    identity: RuntimeIdentity,
) -> None:
    """Validate a direct-mode event network from Docker's inspect attributes."""

    if attrs.get("Name") != identity.challenge_network:
        raise RuntimePolicyError("Docker returned the wrong challenge network")
    if attrs.get("Driver") != "bridge":
        raise RuntimePolicyError(
            "Direct-mode challenge network must use the Docker bridge driver"
        )
    if attrs.get("Internal") is not False:
        raise RuntimePolicyError(
            "Direct-mode challenge ports require a non-internal Docker bridge"
        )

    options = attrs.get("Options")
    if not isinstance(options, Mapping) or str(
        options.get("com.docker.network.bridge.enable_icc", "")
    ).lower() != "false":
        raise RuntimePolicyError(
            "Challenge network must disable inter-container communication"
        )

    labels = attrs.get("Labels")
    if not isinstance(labels, Mapping):
        raise RuntimePolicyError("Challenge network is missing ownership labels")
    if labels.get("ctfd.event_id") != identity.event_id:
        raise RuntimePolicyError(
            "Challenge network event label does not match CTF_EVENT_ID"
        )
    if labels.get("ctfd.network_role") != "challenge":
        raise RuntimePolicyError(
            "Challenge network is missing ctfd.network_role=challenge"
        )
    if labels.get("ctfd.egress_policy") != identity.egress_policy:
        raise RuntimePolicyError(
            "Challenge network egress label does not match CTF_EGRESS_POLICY"
        )


def validate_image_reference(image: str, identity: RuntimeIdentity) -> str:
    """Reject malformed images and require a digest on production targets."""

    value = str(image or "").strip()
    if not value or any(character.isspace() for character in value):
        raise RuntimePolicyError("Container image reference is missing or contains whitespace")
    if value.startswith(('"', "'", "\\")) or value.endswith(('"', "'", "\\")):
        raise RuntimePolicyError("Container image reference contains stray quoting")
    if not value.startswith(identity.image_prefix):
        raise RuntimePolicyError(
            "Container image reference is outside this event's CTF_IMAGE_PREFIX"
        )
    if identity.target_id == "production" and not IMAGE_DIGEST_PATTERN.search(value):
        raise RuntimePolicyError(
            "Production container images must be referenced by @sha256 digest"
        )
    return value


def validate_docker_endpoint(value: str, identity: RuntimeIdentity) -> str:
    """Require a deliberate local socket or authenticated remote SSH worker."""

    endpoint = str(value or "").strip()
    if not endpoint:
        raise RuntimePolicyError("Docker Base URL must be configured")
    if identity.target_id == "local":
        if endpoint == "unix:///var/run/docker.sock":
            return endpoint
    if not endpoint.startswith("ssh://"):
        if identity.target_id in EGRESS_ENFORCED_TARGET_IDS:
            raise RuntimePolicyError(
                "Staging and production require an authenticated ssh:// Docker worker"
            )
        return endpoint

    parsed = urlsplit(endpoint)
    if (
        parsed.scheme != "ssh"
        or not parsed.hostname
        or not parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise RuntimePolicyError(
            "Docker SSH endpoint must be ssh://user@host[:port] without "
            "password, path, query, or fragment"
        )
    return endpoint


def _positive_int(settings: Mapping[str, str], key: str, default: int) -> int:
    raw_value = settings.get(key, default)
    try:
        value = int(raw_value)
    except (TypeError, ValueError) as error:
        raise RuntimePolicyError(f"{key} must be an integer") from error
    if value <= 0:
        raise RuntimePolicyError(f"{key} must be greater than zero")
    return value


def _positive_float(settings: Mapping[str, str], key: str, default: float) -> float:
    raw_value = settings.get(key, default)
    try:
        value = float(raw_value)
    except (TypeError, ValueError) as error:
        raise RuntimePolicyError(f"{key} must be a number") from error
    if not math.isfinite(value) or value <= 0:
        raise RuntimePolicyError(f"{key} must be greater than zero")
    return value


def build_hardening_profile(settings: Mapping[str, str]) -> dict:
    """Build the Docker SDK kwargs that every challenge container receives."""

    memory_mb = _positive_int(
        settings, "container_maxmemory", DEFAULT_MEMORY_MB
    )
    cpu_limit = _positive_float(
        settings, "container_maxcpu", DEFAULT_CPU_LIMIT
    )
    pids_limit = _positive_int(
        settings, "container_pids_limit", DEFAULT_PIDS_LIMIT
    )
    tmpfs_size_mb = _positive_int(
        settings, "container_tmpfs_size_mb", DEFAULT_TMPFS_SIZE_MB
    )
    log_max_files = _positive_int(
        settings, "container_log_max_files", DEFAULT_LOG_MAX_FILES
    )
    log_max_size = str(
        settings.get("container_log_max_size", DEFAULT_LOG_MAX_SIZE) or ""
    ).strip().lower()
    if not LOG_SIZE_PATTERN.fullmatch(log_max_size):
        raise RuntimePolicyError(
            "container_log_max_size must be a positive size ending in k, m, or g"
        )

    return {
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "read_only": True,
        "tmpfs": {
            "/tmp": (
                "rw,noexec,nosuid,nodev,"
                f"size={tmpfs_size_mb}m,mode=1777"
            )
        },
        "pids_limit": pids_limit,
        "mem_limit": f"{memory_mb}m",
        "memswap_limit": f"{memory_mb}m",
        "cpu_period": 100000,
        "cpu_quota": int(cpu_limit * 100000),
        "init": True,
        "log_config": {
            "type": "json-file",
            "config": {
                "max-size": log_max_size,
                "max-file": str(log_max_files),
            },
        },
    }


def get_start_timeout_seconds(settings: Mapping[str, str]) -> int:
    return _positive_int(
        settings,
        "container_start_timeout_seconds",
        DEFAULT_START_TIMEOUT_SECONDS,
    )


def public_runtime_fingerprint(
    identity: RuntimeIdentity,
    settings: Mapping[str, str],
) -> dict:
    """Return the non-secret runtime identity/policy used by remote doctors."""

    profile = build_hardening_profile(settings)
    return {
        "event_id": identity.event_id,
        "release_id": identity.release_id,
        "target_id": identity.target_id,
        "challenge_network": identity.challenge_network,
        "image_prefix": identity.image_prefix,
        "egress_policy": identity.egress_policy,
        "challenge_bind_ip": identity.challenge_bind_ip,
        "policy": {
            "read_only": profile["read_only"],
            "cap_drop": profile["cap_drop"],
            "security_opt": profile["security_opt"],
            "max_containers": _positive_int(
                settings,
                "max_containers",
                3,
            ),
            "pids_limit": profile["pids_limit"],
            "memory_limit": profile["mem_limit"],
            "cpu_quota": profile["cpu_quota"],
            "cpu_period": profile["cpu_period"],
            "tmpfs": profile["tmpfs"],
            "init": profile["init"],
            "log_config": profile["log_config"],
        },
    }
