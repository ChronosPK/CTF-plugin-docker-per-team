"""Pure placement decisions for sharded Docker workers.

Persistence is intentionally outside this module.  Callers must store a first
placement transactionally and use that stored worker for every later lifecycle
operation; hashing is only the initial choice among currently eligible workers.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Iterable, Sequence

from .runtime_policy import RuntimePolicyError
from .worker_pool import WorkerSpec


SCOPE_KINDS = frozenset({"team", "user"})


@dataclass(frozen=True)
class PlacementKey:
    event_id: str
    release_id: str
    scope_kind: str
    scope_id: int

    def canonical_bytes(self) -> bytes:
        if self.scope_kind not in SCOPE_KINDS:
            raise RuntimePolicyError("container placement scope must be team or user")
        if isinstance(self.scope_id, bool) or not isinstance(self.scope_id, int) or self.scope_id <= 0:
            raise RuntimePolicyError("container placement scope id must be positive")
        return "\x00".join(
            (self.event_id, self.release_id, self.scope_kind, str(self.scope_id))
        ).encode("ascii")


def choose_initial_worker(
    key: PlacementKey,
    workers: Sequence[WorkerSpec],
    *,
    eligible_worker_ids: Iterable[str],
) -> WorkerSpec:
    """Choose only among explicitly healthy/admitted workers.

    The stable digest makes a first placement repeatable for a fixed inventory,
    but callers must persist it immediately.  Re-hashing after worker-pool
    changes is prohibited by the lifecycle contract.
    """

    allowed = frozenset(str(worker_id) for worker_id in eligible_worker_ids)
    candidates = sorted(
        (worker for worker in workers if worker.worker_id in allowed),
        key=lambda worker: worker.worker_id,
    )
    if not candidates:
        raise RuntimePolicyError("no healthy Docker worker has launch capacity")
    digest = hashlib.sha256(key.canonical_bytes()).digest()
    return candidates[int.from_bytes(digest[:8], "big") % len(candidates)]


def require_persisted_worker(
    worker_id: object,
    workers: Sequence[WorkerSpec],
) -> WorkerSpec:
    """Resolve a stored placement; never silently migrate an active scope."""

    value = str(worker_id or "").strip()
    if not value:
        raise RuntimePolicyError("container is missing its durable worker placement")
    for worker in workers:
        if worker.worker_id == value:
            return worker
    raise RuntimePolicyError("container placement refers to an unavailable Docker worker")
