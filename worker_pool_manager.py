"""Placement-aware facade for independently isolated Docker workers.

The legacy :class:`ContainerManager` deliberately owns exactly one Docker
client.  This facade keeps that useful invariant by giving every worker a
dedicated child manager; it never swaps a shared client according to a request.
The database is the source of truth for a team/user placement and for the
worker that owns an already-created instance.
"""

from __future__ import annotations

import atexit
import os
import time

from apscheduler.schedulers import SchedulerNotRunningError
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from CTFd.models import db

from .container_manager import ContainerException, ContainerManager
from .helpers import cleanup_container_records
from .models import ContainerInfoModel, ContainerWorkerPlacementModel
from .placement import PlacementKey, choose_initial_worker, require_persisted_worker
from .runtime_policy import RuntimeIdentity, RuntimePolicyError, get_start_timeout_seconds, public_runtime_fingerprint
from .worker_pool import WorkerSpec, load_worker_pool


class WorkerPoolContainerManager:
    """Route launches and lifecycle actions by immutable database placement."""

    def __init__(self, settings, app):
        try:
            self.identity = RuntimeIdentity.from_environment(os.environ)
            self.worker_pool = load_worker_pool(os.environ, self.identity, settings)
        except RuntimePolicyError as err:
            raise ContainerException(str(err)) from err
        self.settings = dict(settings)
        self.app = app
        self.expiration_seconds = self._expiration_seconds(self.settings)
        try:
            self.start_timeout_seconds = get_start_timeout_seconds(self.settings)
        except RuntimePolicyError as err:
            raise ContainerException(str(err)) from err
        self._managers = {
            worker.worker_id: self._new_worker_manager(worker) for worker in self.worker_pool
        }
        self.connection_error = "Connection deferred until a container action is requested."

    @staticmethod
    def _expiration_seconds(settings) -> int:
        try:
            minutes = int(settings.get("container_expiration", 0))
        except (TypeError, ValueError) as err:
            raise ContainerException("Container expiration must be an integer") from err
        if minutes <= 0:
            raise ContainerException("Container expiration must be greater than zero")
        return minutes * 60

    def _new_worker_manager(self, worker: WorkerSpec) -> ContainerManager:
        return ContainerManager(
            self._worker_settings(worker),
            self.app,
            worker_spec=worker,
            manage_expiration=False,
        )

    def _worker_settings(self, worker: WorkerSpec) -> dict:
        values = dict(self.settings)
        values.update(
            {
                "docker_base_url": worker.docker_base_url,
                "docker_hostname": worker.docker_hostname,
                "challenge_network": worker.identity.challenge_network,
            }
        )
        return values

    def _shutdown_expiration_scheduler(self):
        try:
            self.expiration_scheduler.shutdown()
        except (SchedulerNotRunningError, AttributeError):
            pass

    @staticmethod
    def validate_settings(settings):
        """Validate every declared worker, not merely the legacy endpoint."""
        try:
            base_identity = RuntimeIdentity.from_environment(os.environ)
            workers = load_worker_pool(os.environ, base_identity, settings)
        except RuntimePolicyError as err:
            raise ContainerException(str(err)) from err
        for worker in workers:
            worker_settings = dict(settings)
            worker_settings.update(
                {
                    "docker_base_url": worker.docker_base_url,
                    "docker_hostname": worker.docker_hostname,
                    "challenge_network": worker.identity.challenge_network,
                }
            )
            manager = ContainerManager(
                worker_settings, None, worker_spec=worker, manage_expiration=False
            )
            try:
                manager.initialize_connection(worker_settings, None)
            finally:
                manager._mark_connection_failure(ContainerException("settings validation complete"))

    def _known_worker_ids(self) -> set[str]:
        rows = ContainerWorkerPlacementModel.query.with_entities(
            ContainerWorkerPlacementModel.worker_id
        ).distinct().all()
        active_rows = ContainerInfoModel.query.with_entities(
            ContainerInfoModel.worker_id
        ).distinct().all()
        return {str(row[0]) for row in rows + active_rows if row[0]}

    def initialize_connection(self, settings, app) -> None:
        try:
            candidate_identity = RuntimeIdentity.from_environment(os.environ)
            candidate_pool = load_worker_pool(os.environ, candidate_identity, settings)
        except RuntimePolicyError as err:
            raise ContainerException(str(err)) from err
        candidate_ids = {worker.worker_id for worker in candidate_pool}
        missing = sorted(self._known_worker_ids() - candidate_ids)
        if missing:
            raise ContainerException(
                "Docker worker inventory cannot remove durable placements: " + ", ".join(missing)
            )

        self._shutdown_expiration_scheduler()
        for manager in self._managers.values():
            manager._mark_connection_failure(ContainerException("worker inventory reloaded"))
        self.identity = candidate_identity
        self.worker_pool = candidate_pool
        self.settings = dict(settings)
        self.app = app
        self.expiration_seconds = self._expiration_seconds(self.settings)
        try:
            self.start_timeout_seconds = get_start_timeout_seconds(self.settings)
        except RuntimePolicyError as err:
            raise ContainerException(str(err)) from err
        self._managers = {
            worker.worker_id: self._new_worker_manager(worker) for worker in self.worker_pool
        }
        try:
            for worker in self.worker_pool:
                self._managers[worker.worker_id].initialize_connection(
                    self._worker_settings(worker), app
                )
        except Exception as err:
            self.connection_error = str(err)
            raise

        self.connection_error = None
        self.expiration_scheduler = BackgroundScheduler()
        self.expiration_scheduler.add_job(
            func=self.kill_expired_containers,
            args=(app,),
            trigger="interval",
            seconds=5,
        )
        self.expiration_scheduler.start()
        atexit.register(self._shutdown_expiration_scheduler)

    def _with_advisory_lock(self, name, func):
        engine = db.engine
        dialect_name = getattr(getattr(engine, "dialect", None), "name", "")
        if dialect_name not in {"mysql", "mariadb"}:
            return func()
        connection = engine.connect()
        try:
            acquired = connection.execute(
                text("SELECT GET_LOCK(:name, :timeout)"), {"name": name, "timeout": 65}
            ).scalar()
            if acquired != 1:
                return None
            return func()
        finally:
            try:
                connection.execute(text("SELECT RELEASE_LOCK(:name)"), {"name": name})
            finally:
                connection.close()

    def _scope_key(self, xid, is_team) -> PlacementKey:
        return PlacementKey(
            event_id=self.identity.event_id,
            release_id=self.identity.release_id,
            scope_kind="team" if is_team else "user",
            scope_id=int(xid),
        )

    def _reserved_instances_per_scope(self) -> int:
        """Return the configured per-account instance budget.

        A worker assignment is durable for its team/user.  Therefore, a first
        placement must reserve the account's whole active-container allowance,
        rather than admitting only the one challenge that happened to launch
        first.  Otherwise three concurrent first launches can make a worker
        exceed its advertised cap even when aggregate capacity was sufficient.
        Changing this setting during an event is deliberately not a capacity
        expansion mechanism; release configuration must keep this cap stable
        while durable placements are active.
        """
        try:
            value = int(self.settings.get("max_containers", 3))
        except (TypeError, ValueError) as err:
            raise ContainerException("Container maximum must be an integer") from err
        if value <= 0:
            raise ContainerException("Container maximum must be greater than zero")
        return value

    def _worker_for_scope(self, xid, is_team) -> WorkerSpec:
        key = self._scope_key(xid, is_team)

        def select_or_create():
            # ``create_container`` has already performed read-only account and
            # challenge lookups before it waits for this *global* admission
            # lock.  Under MariaDB's default REPEATABLE READ isolation, that
            # session can therefore retain a snapshot from before another
            # team committed its placement.  Capacity must be computed after
            # acquiring the lock from a fresh snapshot; otherwise concurrent
            # first launches can select a worker that is already full.
            # No write is pending at this point (the placement is created
            # below), so this cannot discard an admission decision.
            db.session.rollback()
            placement = ContainerWorkerPlacementModel.query.filter_by(
                event_id=key.event_id,
                release_id=key.release_id,
                scope_kind=key.scope_kind,
                scope_id=key.scope_id,
            ).first()
            if placement is not None:
                try:
                    return require_persisted_worker(placement.worker_id, self.worker_pool)
                except RuntimePolicyError as err:
                    raise ContainerException(str(err)) from err

            now = int(time.time())
            reserved_per_scope = self._reserved_instances_per_scope()
            eligible_loads = []
            for worker in self.worker_pool:
                # Rows are the admission ledger.  We intentionally count an
                # expired-but-not-yet-pruned row conservatively until the
                # expiry job has removed it.
                active = ContainerInfoModel.query.filter(
                    ContainerInfoModel.worker_id == worker.worker_id,
                    ContainerInfoModel.expires > now,
                ).count()
                # A durable placement must reserve every instance the account
                # is allowed to start.  Counting only active rows makes the
                # first of three parallel launches appear to cost one slot;
                # the same team can then overflow an otherwise full worker.
                # Existing pre-placement rows remain a conservative floor.
                reserved = (
                    ContainerWorkerPlacementModel.query.filter_by(
                        event_id=key.event_id,
                        release_id=key.release_id,
                        worker_id=worker.worker_id,
                    ).count()
                    * reserved_per_scope
                )
                committed_load = max(active, reserved)
                if committed_load + reserved_per_scope <= worker.max_active_instances:
                    eligible_loads.append((committed_load, worker.worker_id))
            # Teams retain one durable worker, so each new team may create up
            # to the per-team container cap on that worker.  A hash across all
            # non-full workers has avoidable statistical skew and can reject a
            # 600x3 launch even though aggregate capacity is exactly 1,800.
            # Select only the least-loaded eligible workers; the existing
            # digest remains a deterministic tie-breaker and the persisted row
            # prevents later migration.
            eligible = []
            if eligible_loads:
                minimum_load = min(load for load, _ in eligible_loads)
                eligible = [
                    worker_id
                    for load, worker_id in eligible_loads
                    if load == minimum_load
                ]
            try:
                worker = choose_initial_worker(key, self.worker_pool, eligible_worker_ids=eligible)
            except RuntimePolicyError as err:
                raise ContainerException(str(err)) from err
            db.session.add(
                ContainerWorkerPlacementModel(
                    event_id=key.event_id,
                    release_id=key.release_id,
                    scope_kind=key.scope_kind,
                    scope_id=key.scope_id,
                    worker_id=worker.worker_id,
                    assigned_at=now,
                )
            )
            try:
                db.session.commit()
            except IntegrityError:
                # The unique constraint is the final authority under a
                # concurrent first launch for the same team/user.  MySQL
                # advisory locks normally serialize admissions, but a caller
                # must remain correct if a concurrent request crosses a
                # process or connection boundary that has not acquired this
                # process's lock.  Never retry a different placement: discard
                # our transaction and adopt the durable winner.
                db.session.rollback()
                placement = ContainerWorkerPlacementModel.query.filter_by(
                    event_id=key.event_id,
                    release_id=key.release_id,
                    scope_kind=key.scope_kind,
                    scope_id=key.scope_id,
                ).first()
                if placement is None:
                    raise ContainerException(
                        "worker placement conflicted but no durable placement was found"
                    )
                try:
                    return require_persisted_worker(placement.worker_id, self.worker_pool)
                except RuntimePolicyError as err:
                    raise ContainerException(str(err)) from err
            return worker

        worker = self._with_advisory_lock("docker-per-team:worker-placement-admission", select_or_create)
        if worker is None:
            raise ContainerException("Could not acquire worker admission lock. Please retry.")
        return worker

    def _manager_for_record(self, container_id: str) -> ContainerManager | None:
        record = ContainerInfoModel.query.filter_by(container_id=container_id).first()
        if record is None:
            return None
        manager = self._managers.get(record.worker_id)
        if manager is None:
            raise ContainerException("Container placement refers to an unavailable Docker worker")
        return manager

    def create_container(self, challenge, xid, is_team):
        worker = self._worker_for_scope(xid, is_team)
        return self._managers[worker.worker_id].create_container(challenge, xid, is_team)

    def is_container_running(self, container_id: str) -> bool:
        manager = self._manager_for_record(container_id)
        return False if manager is None else manager.is_container_running(container_id)

    def get_container_port(self, container_id: str):
        manager = self._manager_for_record(container_id)
        return None if manager is None else manager.get_container_port(container_id)

    def kill_container(self, container_id: str):
        manager = self._manager_for_record(container_id)
        if manager is not None:
            return manager.kill_container(container_id)

    def kill_expired_containers(self, app):
        with app.app_context():
            def cleanup():
                now = int(time.time())
                for record in ContainerInfoModel.query.filter(ContainerInfoModel.expires <= now).all():
                    try:
                        self.kill_container(record.container_id)
                    except ContainerException:
                        # Do not delete the DB evidence when an isolated worker
                        # is unavailable; the next expiry pass can retry it.
                        continue
            self._with_advisory_lock("docker-per-team:expire-scan", cleanup)

    def get_running_container_ids(self) -> set[str]:
        running = set()
        for manager in self._managers.values():
            running.update(manager.get_running_container_ids())
        return running

    def get_images(self):
        image_sets = [set(manager.get_images() or []) for manager in self._managers.values()]
        return sorted(set.intersection(*image_sets)) if image_sets else []

    def is_connected(self) -> bool:
        try:
            if any(manager.client is None for manager in self._managers.values()):
                self.initialize_connection(self.settings, self.app)
            return all(manager.is_connected() for manager in self._managers.values())
        except Exception as err:
            self.connection_error = str(err)
            return False

    def runtime_fingerprint(self) -> dict:
        fingerprint = public_runtime_fingerprint(self.identity, self.settings)
        fingerprint["container_service"] = {
            "connected": self.is_connected(),
            "status": "ready" if self.connection_error is None else "unavailable",
            "error": self.connection_error,
            "worker_count": len(self.worker_pool),
            "workers": [
                {
                    "worker_id": worker.worker_id,
                    "hostname": worker.docker_hostname,
                    "max_active_instances": worker.max_active_instances,
                    "connected": self._managers[worker.worker_id].client is not None,
                }
                for worker in self.worker_pool
            ],
        }
        return fingerprint
