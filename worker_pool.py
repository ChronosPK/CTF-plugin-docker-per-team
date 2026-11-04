"""Fail-closed worker inventory for the placement-aware launcher.

The module is deliberately free of Flask, CTFd and Docker SDK imports.  It
turns process configuration into an immutable inventory before any Docker
connection is attempted.  An absent pool preserves the existing one-worker
deployment; a present pool is all-or-nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Mapping, Sequence

from .runtime_policy import (
    RuntimeIdentity,
    RuntimePolicyError,
    validate_docker_endpoint,
)


WORKER_POOL_ENV = "CTF_DOCKER_WORKERS_JSON"
WORKER_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


@dataclass(frozen=True)
class WorkerSpec:
    """One independently owned Docker worker and player entry route."""

    worker_id: str
    docker_base_url: str
    docker_hostname: str
    max_active_instances: int
    identity: RuntimeIdentity


def _required_string(raw: object, name: str) -> str:
    value = str(raw or "").strip()
    if not value:
        raise RuntimePolicyError(f"worker {name} is required")
    return value


def _hostname(value: object) -> str:
    hostname = _required_string(value, "docker_hostname").rstrip(".")
    if not HOSTNAME_PATTERN.fullmatch(hostname):
        raise RuntimePolicyError("worker docker_hostname must be a DNS hostname")
    return hostname.lower()


def _positive_int(raw: object, name: str) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError) as error:
        raise RuntimePolicyError(f"worker {name} must be an integer") from error
    if value <= 0:
        raise RuntimePolicyError(f"worker {name} must be greater than zero")
    return value


def _worker_identity(base: RuntimeIdentity, item: Mapping[str, object]) -> RuntimeIdentity:
    network = _required_string(item.get("challenge_network"), "challenge_network")
    bind_ip = _required_string(item.get("challenge_bind_ip"), "challenge_bind_ip")
    # RuntimeIdentity validates both the event namespace and literal IPv4 bind
    # address.  It is re-created rather than trusting inventory strings.
    return RuntimeIdentity.from_environment(
        {
            "CTF_EVENT_ID": base.event_id,
            "CTF_RELEASE_ID": base.release_id,
            "CTF_TARGET_ID": base.target_id,
            "CTF_CHALLENGE_NETWORK": network,
            "CTF_IMAGE_PREFIX": base.image_prefix,
            "CTF_EGRESS_POLICY": base.egress_policy,
            "CTF_CHALLENGE_BIND_IP": bind_ip,
        }
    )


def _parse_item(item: object, base_identity: RuntimeIdentity) -> WorkerSpec:
    if not isinstance(item, Mapping):
        raise RuntimePolicyError("each Docker worker must be a JSON object")
    worker_id = _required_string(item.get("worker_id"), "worker_id")
    if not WORKER_ID_PATTERN.fullmatch(worker_id):
        raise RuntimePolicyError("worker worker_id must be a lowercase DNS-style identifier")
    identity = _worker_identity(base_identity, item)
    docker_base_url = validate_docker_endpoint(
        _required_string(item.get("docker_base_url"), "docker_base_url"),
        identity,
    )
    return WorkerSpec(
        worker_id=worker_id,
        docker_base_url=docker_base_url,
        docker_hostname=_hostname(item.get("docker_hostname")),
        max_active_instances=_positive_int(
            item.get("max_active_instances"), "max_active_instances"
        ),
        identity=identity,
    )


def load_worker_pool(
    environment: Mapping[str, str],
    base_identity: RuntimeIdentity,
    settings: Mapping[str, object],
) -> tuple[WorkerSpec, ...]:
    """Load worker inventory, retaining a safe named one-worker fallback.

    The fallback avoids an unsafe implicit migration: current deployments only
    need to name their existing worker once when they intentionally enable a
    multi-worker pool.  An explicitly present pool never falls back.
    """

    encoded = str(environment.get(WORKER_POOL_ENV, "") or "").strip()
    if not encoded:
        endpoint = validate_docker_endpoint(
            _required_string(settings.get("docker_base_url"), "docker_base_url"),
            base_identity,
        )
        hostname = str(settings.get("docker_hostname", "") or "").strip()
        return (
            WorkerSpec(
                worker_id="primary",
                docker_base_url=endpoint,
                docker_hostname=hostname.rstrip(".").lower(),
                max_active_instances=_positive_int(
                    settings.get("worker_max_active_instances", 800),
                    "worker_max_active_instances",
                ),
                identity=base_identity,
            ),
        )

    try:
        raw_pool = json.loads(encoded)
    except json.JSONDecodeError as error:
        raise RuntimePolicyError(f"{WORKER_POOL_ENV} must be valid JSON") from error
    if not isinstance(raw_pool, Sequence) or isinstance(raw_pool, (str, bytes)):
        raise RuntimePolicyError(f"{WORKER_POOL_ENV} must be a non-empty JSON array")
    if not raw_pool:
        raise RuntimePolicyError(f"{WORKER_POOL_ENV} must not be empty")

    pool = tuple(_parse_item(item, base_identity) for item in raw_pool)
    ids = [worker.worker_id for worker in pool]
    networks = [worker.identity.challenge_network for worker in pool]
    endpoints = [worker.docker_base_url for worker in pool]
    hostnames = [worker.docker_hostname for worker in pool]
    for label, values in (
        ("worker_id", ids),
        ("challenge_network", networks),
        ("docker_base_url", endpoints),
        ("docker_hostname", hostnames),
    ):
        if len(values) != len(set(values)):
            raise RuntimePolicyError(f"Docker worker {label} values must be unique")
    return pool


def worker_by_id(pool: Sequence[WorkerSpec], worker_id: str) -> WorkerSpec:
    """Resolve a durable placement without silently defaulting to another worker."""

    for worker in pool:
        if worker.worker_id == worker_id:
            return worker
    raise RuntimePolicyError("container placement refers to an unknown Docker worker")
