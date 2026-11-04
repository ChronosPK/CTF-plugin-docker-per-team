from pathlib import Path
import ast
import unittest


SOURCE = (Path(__file__).resolve().parents[1] / "container_manager.py").read_text(encoding="utf-8")


class WorkerPoolIntegrationGuardTests(unittest.TestCase):
    def test_legacy_manager_refuses_to_multiplex_a_shared_client(self):
        ast.parse(SOURCE)
        self.assertIn("from .worker_pool import load_worker_pool", SOURCE)
        self.assertGreaterEqual(SOURCE.count("load_worker_pool("), 2)
        self.assertIn("Multi-worker Docker inventory requires WorkerPoolContainerManager", SOURCE)
        self.assertIn("WorkerPoolContainerManager.validate_settings(settings)", SOURCE)


if __name__ == "__main__":
    unittest.main()
