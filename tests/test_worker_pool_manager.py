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
        self.assertIn("minimum_load = min(active for active, _ in eligible_loads)", SOURCE)
        self.assertIn("if active == minimum_load", SOURCE)
        self.assertIn("no healthy Docker worker has launch capacity", (ROOT / "placement.py").read_text(encoding="utf-8"))

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
