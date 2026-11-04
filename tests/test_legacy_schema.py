from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "legacy_schema.py"
FIXTURE_DIRECTORY = MODULE_PATH.with_name("schema-fixtures")


def load_module():
    module_name = "docker_per_team_legacy_schema_test"
    spec = importlib.util.spec_from_file_location(module_name, MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    previous = sys.modules.get(module_name)
    try:
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        if previous is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous


legacy_schema = load_module()


class FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def __iter__(self):
        for row in self._rows:
            yield type("Row", (), {"_mapping": row})()


class FakeConnection:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def execute(self, statement, params):
        self.calls.append((statement.text, dict(params)))
        return FakeResult(self.rows)


class LegacySchemaCanonicalTests(unittest.TestCase):
    def test_fixture_files_are_canonical_json_and_have_stable_hashes(self):
        expected = {
            "config-marker-storage-v1.json": {
                "file": "b01de8afbd7efb5737450d7f43e9907ef7f68e4d70b3be4dd379fe81001258a4",
                "canonical": "1c71f407fd22394769fb2d0dca99f08eae2a28f7a71464bc655e0815f899ec97",
            },
            "legacy-schema-v1.json": {
                "file": "a17bd428eb535ef0ad71c96c577144cd7e5d21997df2ae34aec777277fe70355",
                "canonical": "4bc632d9e73b6e1ceabc93a557db67752f9b773608537d53b3de7ef4f793ac0a",
            },
        }
        for name, digests in expected.items():
            with self.subTest(name=name):
                raw = (FIXTURE_DIRECTORY / name).read_bytes()
                parsed = json.loads(raw)
                self.assertEqual(legacy_schema.canonical_json_bytes(parsed) + b"\n", raw)
                self.assertEqual(digests["file"], __import__("hashlib").sha256(raw).hexdigest())
                self.assertEqual(digests["canonical"], legacy_schema.canonical_sha256(parsed))

    def test_fixture_loader_is_allowlisted(self):
        storage = legacy_schema.load_pinned_fixture("config-marker-storage-v1.json")
        self.assertEqual(legacy_schema.CONFIG_STORAGE_FINGERPRINT_VERSION, storage["schema"])
        legacy = legacy_schema.load_pinned_fixture("legacy-schema-v1.json")
        self.assertEqual(legacy_schema.LEGACY_SCHEMA_FINGERPRINT_VERSION, legacy["schema"])
        with self.assertRaises(legacy_schema.LegacySchemaPreflightError):
            legacy_schema.load_pinned_fixture("../other.json")

    def test_canonical_representation_is_key_order_independent_and_mismatch_fails_closed(self):
        first = {"b": [2, 1], "a": {"x": True, "y": None}}
        second = {"a": {"y": None, "x": True}, "b": [2, 1]}
        self.assertEqual(legacy_schema.canonical_json_bytes(first), legacy_schema.canonical_json_bytes(second))
        self.assertEqual(legacy_schema.canonical_sha256(first), legacy_schema.require_fixture(first, second, label="test"))
        with self.assertRaises(legacy_schema.LegacySchemaPreflightError):
            legacy_schema.require_fixture(first, {"a": "changed"}, label="test")

    def test_reserved_config_key_reader_requires_exactly_one_positive_row(self):
        one = FakeConnection([{"row_id": 9, "value": "state"}])
        record = legacy_schema.read_single_config_record(one, legacy_schema.MARKER_KEY)
        self.assertEqual(9, record.row_id)
        self.assertEqual("state", record.value)
        self.assertIn("SELECT id AS row_id", one.calls[0][0])
        self.assertEqual({"key": legacy_schema.MARKER_KEY}, one.calls[0][1])

        self.assertIsNone(
            legacy_schema.read_single_config_record(
                FakeConnection([]), legacy_schema.MARKER_ANCHOR_KEY
            )
        )
        for rows in (
            [{"row_id": 0, "value": None}],
            [{"row_id": 1, "value": None}, {"row_id": 2, "value": None}],
        ):
            with self.subTest(rows=rows):
                with self.assertRaises(legacy_schema.LegacySchemaPreflightError):
                    legacy_schema.read_single_config_record(FakeConnection(rows), legacy_schema.MARKER_KEY)
        with self.assertRaises(legacy_schema.LegacySchemaPreflightError):
            legacy_schema.read_single_config_record(FakeConnection([]), "unrelated")

    def test_module_has_no_runtime_or_extension_import_surface(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("stable_random_models", source)
        self.assertNotIn("ContainerManager", source)
        self.assertNotIn("from CTFd", source)
        self.assertNotIn("app.db", source)
        self.assertNotIn("create_all", source)


if __name__ == "__main__":
    unittest.main()
