"""Worker-specific Docker client registry.

Only this registry may choose a Docker client from durable worker identity.
It deliberately has no Docker import so it can be tested with a strict client
factory and reused by the runtime manager.
"""

from __future__ import annotations

from typing import Callable, Mapping, Sequence

from .runtime_policy import RuntimePolicyError
from .worker_pool import WorkerSpec, worker_by_id


class WorkerClientRegistry:
    def __init__(self, workers: Sequence[WorkerSpec], client_factory: Callable[[WorkerSpec], object]):
        if not workers:
            raise RuntimePolicyError("Docker worker inventory must not be empty")
        self._workers = tuple(workers)
        self._factory = client_factory
        self._clients: dict[str, object] = {}

    def worker(self, worker_id: object) -> WorkerSpec:
        return worker_by_id(self._workers, str(worker_id or "").strip())

    def client(self, worker_id: object) -> object:
        worker = self.worker(worker_id)
        client = self._clients.get(worker.worker_id)
        if client is None:
            client = self._factory(worker)
            if client is None:
                raise RuntimePolicyError("Docker worker client factory returned no client")
            self._clients[worker.worker_id] = client
        return client

    def close_all(self) -> None:
        for client in self._clients.values():
            close = getattr(client, "close", None)
            if callable(close):
                close()
        self._clients.clear()

    def connected_worker_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._clients))
