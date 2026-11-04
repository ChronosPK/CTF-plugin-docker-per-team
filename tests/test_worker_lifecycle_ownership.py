from pathlib import Path
import ast
import unittest


SOURCE = (Path(__file__).resolve().parents[1] / "container_manager.py").read_text(encoding="utf-8")


class WorkerLifecycleOwnershipTests(unittest.TestCase):
    def test_lifecycle_checks_persisted_worker_against_docker_label(self):
        ast.parse(SOURCE)
        self.assertIn('observed_worker_id != worker_id', SOURCE)
        self.assertIn('worker_id == "primary"', SOURCE)
        self.assertIn("bound to another Docker worker", SOURCE)
        self.assertGreaterEqual(SOURCE.count("worker_id=container_info.worker_id"), 2)


if __name__ == "__main__":
    unittest.main()
