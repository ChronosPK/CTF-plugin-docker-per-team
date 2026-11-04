from pathlib import Path
import ast
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ConnectionPayloadBindingTests(unittest.TestCase):
    def test_payload_prefers_persisted_instance_hostname(self):
        source = (ROOT / "helpers.py").read_text(encoding="utf-8")
        ast.parse(source)
        self.assertIn("def build_connection_payload(container_manager, challenge, port, expires, *, hostname=None)", source)
        self.assertIn("persisted_hostname or configured_hostname or request_hostname", source)
        self.assertGreaterEqual(source.count("hostname=running_container.hostname"), 3)
        self.assertIn('hostname=created_container.get("hostname")', source)

    def test_container_record_and_create_result_preserve_worker_entry(self):
        source = (ROOT / "container_manager.py").read_text(encoding="utf-8")
        ast.parse(source)
        self.assertIn('hostname=(self.settings.get("docker_hostname", "") or "").strip() or None', source)
        self.assertIn('"hostname": new_container_entry.hostname', source)


if __name__ == "__main__":
    unittest.main()
