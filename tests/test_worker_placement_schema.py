from pathlib import Path
import ast
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WorkerPlacementSchemaTests(unittest.TestCase):
    def test_model_has_durable_scope_unique_constraint_and_instance_worker(self):
        source = (ROOT / "legacy_models.py").read_text(encoding="utf-8")
        self.assertIn("class ContainerWorkerPlacementModel", source)
        self.assertIn("uq_container_worker_placement_scope", source)
        self.assertIn('worker_id = db.Column(db.String(32), nullable=False, default="primary", index=True)', source)

    def test_migration_is_chained_and_backfills_named_compatibility_worker(self):
        path = ROOT / "migrations" / "e9b2c7d4f1a6_add_worker_placement.py"
        source = path.read_text(encoding="utf-8")
        ast.parse(source)
        self.assertIn('down_revision = "d5e7f901a2b3"', source)
        self.assertIn('server_default="primary"', source)
        self.assertIn('"container_worker_placement_model"', source)
        self.assertIn('"idx_container_info_worker"', source)


if __name__ == "__main__":
    unittest.main()
