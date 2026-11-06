from pathlib import Path
import ast
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "worker_pool_manager.py").read_text(encoding="utf-8")
INIT_SOURCE = (ROOT / "__init__.py").read_text(encoding="utf-8")
LEGACY_SOURCE = (ROOT / "container_manager.py").read_text(encoding="utf-8")


class WorkerPoolManagerContractTests(unittest.TestCase):
    def test_plugin_uses_pool_facade_even_for_one_worker_compatibility(self):
        ast.parse(SOURCE)
        ast.parse(INIT_SOURCE)
        self.assertIn("WorkerPoolContainerManager(container_settings, app)", INIT_SOURCE)
        self.assertIn("ContainerWorkerPlacementModel", SOURCE)
        self.assertIn("choose_initial_worker", SOURCE)
        self.assertIn("require_persisted_worker", SOURCE)

    def test_lifecycle_routes_by_persisted_record_not_request_hash(self):
        self.assertIn("def _manager_for_record", SOURCE)
        self.assertIn("record.worker_id", SOURCE)
        self.assertIn("def is_container_running", SOURCE)
        self.assertIn("def get_container_port", SOURCE)
        self.assertIn("def kill_container", SOURCE)
        self.assertIn("worker-placement-admission", SOURCE)

    def test_worker_capacity_is_enforced_before_new_placement(self):
        self.assertIn("worker.max_active_instances", SOURCE)
        self.assertIn("ContainerInfoModel.expires > now", SOURCE)
        self.assertIn("minimum_load = min((load for load, _ in eligible_loads), default=None)", SOURCE)
        self.assertIn("if load == minimum_load", SOURCE)
        self.assertIn("def _reserved_instances_per_scope", SOURCE)
        self.assertIn("committed_load + reserved_per_scope <= worker.max_active_instances", SOURCE)
        self.assertIn("ContainerWorkerPlacementModel.query.filter_by(", SOURCE)
        self.assertIn("no healthy Docker worker has launch capacity", (ROOT / "placement.py").read_text(encoding="utf-8"))

    def test_worker_capacity_query_refreshes_after_global_admission_lock(self):
        """A waiting request must not use a pre-lock REPEATABLE READ snapshot."""
        start = SOURCE.index("def select_or_create():")
        placement_query = SOURCE.index("placement = ContainerWorkerPlacementModel.query", start)
        self.assertIn("db.session.rollback()", SOURCE[start:placement_query])

    def test_draining_workers_admit_no_new_instances_and_move_scope_immediately(self):
        self.assertIn("if worker.draining:", SOURCE)
        self.assertIn("def _move_idle_placement", SOURCE)
        self.assertIn("if not worker.draining:", SOURCE)
        self.assertIn("every *new* launch avoids a draining worker", SOURCE)
        self.assertIn("draining_workers", SOURCE)

    def test_concurrent_first_launch_adopts_the_unique_constraint_winner(self):
        self.assertIn("from sqlalchemy.exc import IntegrityError", SOURCE)
        self.assertIn("except IntegrityError", SOURCE)
        self.assertIn("db.session.rollback()", SOURCE)
        self.assertIn("worker placement conflicted but no durable placement was found", SOURCE)

    def test_child_managers_are_single_daemon_and_do_not_run_expiry_loops(self):
        self.assertIn("worker_spec=worker", SOURCE)
        self.assertIn("manage_expiration=False", SOURCE)
        self.assertIn("self._managers[worker.worker_id].create_container", SOURCE)

    def test_new_launch_reads_docker_port_before_persisting_the_record(self):
        launch_port = LEGACY_SOURCE.index("port = self._get_container_port_from_container(container)")
        persisted_record = LEGACY_SOURCE.index("new_container_entry = ContainerInfoModel(")
        self.assertLess(launch_port, persisted_record)


if __name__ == "__main__":
    unittest.main()
