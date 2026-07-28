"""Dependency-free Docker container startup health gate."""

from __future__ import annotations

import time
from typing import Callable


class ContainerHealthError(RuntimeError):
    """Raised when a challenge container cannot become healthy."""


def wait_until_healthy(
    container,
    timeout_seconds: int,
    *,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    poll_seconds: float = 0.25,
) -> None:
    """Block until Docker reports healthy, or fail on exit/unhealthy/timeout."""

    deadline = monotonic() + timeout_seconds
    while monotonic() < deadline:
        container.reload()
        state = container.attrs.get("State", {}) or {}
        status = str(state.get("Status", "")).lower()
        if status in {"dead", "exited", "removing"}:
            raise ContainerHealthError(
                f"Challenge container exited during startup (status={status})"
            )

        health_status = str(
            (state.get("Health") or {}).get("Status", "")
        ).lower()
        if health_status == "healthy":
            return
        if health_status == "unhealthy":
            raise ContainerHealthError(
                "Challenge container failed its health check"
            )
        sleep(poll_seconds)

    raise ContainerHealthError(
        "Challenge container did not become healthy before the startup timeout"
    )
