from pathlib import Path
import ast
import unittest


SOURCE = (Path(__file__).resolve().parents[1] / "container_manager.py").read_text(encoding="utf-8")


class WorkerPoolIntegrationGuardTests(unittest.TestCase):
    def test_manager_imports_and_validates_worker_pool_before_docker_use(self):
        ast.parse(SOURCE)
        self.assertIn("from .worker_pool import load_worker_pool", SOURCE)
        self.assertGreaterEqual(SOURCE.count("load_worker_pool("), 2)
        self.assertIn("Multi-worker Docker inventory is not enabled", SOURCE)
        self.assertIn("placement-aware ", SOURCE)
        self.assertIn("lifecycle routing is installed", SOURCE)


if __name__ == "__main__":
    unittest.main()
