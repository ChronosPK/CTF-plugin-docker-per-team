from pathlib import Path
import ast
import unittest


SOURCE = (Path(__file__).resolve().parents[1] / "container_manager.py").read_text(encoding="utf-8")


class WorkerInstanceOwnershipTests(unittest.TestCase):
    def test_worker_id_is_labelled_persisted_and_returned(self):
        ast.parse(SOURCE)
        self.assertIn('"ctfd.worker_id": self.worker_pool[0].worker_id', SOURCE)
        self.assertIn('worker_id=self.worker_pool[0].worker_id', SOURCE)
        self.assertIn('"worker_id": new_container_entry.worker_id', SOURCE)


if __name__ == "__main__":
    unittest.main()
