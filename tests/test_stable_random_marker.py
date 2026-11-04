from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import types
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "stable_random_marker.py"


def load_module():
    name = "docker_per_team_stable_random_marker_test"
    spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    previous = sys.modules.get(name)
    try:
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous


marker_module = load_module()


def record(row_id: int, value: str):
    return types.SimpleNamespace(row_id=row_id, value=value)


def marker_document(row_id=41, phase="PREPARED_LEGACY", run_id="a" * 64):
    return {
        "contract": marker_module.MARKER_CONTRACT,
        "marker_row_id": row_id,
        "command_manifest_sha256": "b" * 64,
        "legacy_schema_fingerprint": "c" * 64,
        "phase": phase,
        "phase_schema_sha256": "d" * 64,
        "run_id": run_id,
        "created_at": "2026-09-28T00:00:00Z",
        "updated_at": "2026-09-28T00:00:00Z",
    }


def valid_pair(row_id=41, phase="PREPARED_LEGACY"):
    prepared_value = marker_module.canonical_json(marker_document(row_id=row_id))
    marker_value = (
        prepared_value
        if phase == "PREPARED_LEGACY"
        else marker_module.canonical_json(
            dict(
                marker_document(row_id=row_id, phase=phase),
                updated_at="2026-09-28T00:00:01Z",
            )
        )
    )
    anchor_value = marker_module.canonical_json(
        {
            "contract": marker_module.ANCHOR_CONTRACT,
            "marker_key": marker_module.MARKER_KEY,
            "marker_row_id": row_id,
            "run_id": "a" * 64,
            "prepared_marker_sha256": hashlib.sha256(prepared_value.encode("ascii")).hexdigest(),
        }
    )
    return (
        record(row_id, marker_value),
        record(99, anchor_value),
        hashlib.sha256(prepared_value.encode("ascii")).hexdigest(),
    )


class StableRandomMarkerTests(unittest.TestCase):
    def test_prepared_pair_is_canonical_and_identity_bound(self):
        marker, anchor, _prepared_hash = valid_pair()
        got_marker, got_anchor = marker_module.validate_anchor_marker_pair(marker, anchor)
        self.assertEqual(marker.row_id, got_marker.row_id)
        self.assertEqual(anchor.row_id, got_anchor.row_id)

    def test_marker_rejects_noncanonical_json_and_physical_id_mismatch(self):
        marker, _anchor, _prepared_hash = valid_pair()
        noncanonical = marker.value.replace(",", ", ", 1)
        with self.assertRaises(marker_module.MarkerValidationError):
            marker_module.validate_marker(record(marker.row_id, noncanonical))
        with self.assertRaises(marker_module.MarkerValidationError):
            marker_module.validate_marker(record(marker.row_id + 1, marker.value))

    def test_anchor_rejects_recreated_marker_and_changed_prepared_bytes(self):
        marker, anchor, _prepared_hash = valid_pair()
        recreated, _anchor, _recreated_hash = valid_pair(row_id=42)
        with self.assertRaises(marker_module.MarkerValidationError):
            marker_module.validate_anchor_marker_pair(recreated, anchor)
        changed = marker_module.canonical_json(dict(marker_document(), updated_at="2026-09-28T00:00:01Z"))
        with self.assertRaises(marker_module.MarkerValidationError):
            marker_module.validate_anchor_marker_pair(record(41, changed), anchor)

    def test_final_mode_preserves_prepared_anchor_and_requires_every_admission_input(self):
        marker, anchor, prepared_hash = valid_pair(phase="FINAL")
        kwargs = dict(
            config_storage_matches=True,
            legacy_schema_matches=True,
            alembic_version=marker_module.MIGRATION_CEILING,
            marker_record=marker,
            anchor_record=anchor,
            final_schema_matches=True,
            command_manifest_matches=True,
            expected_prepared_marker_sha256=prepared_hash,
        )
        self.assertEqual(marker_module.StartupMode.FINAL, marker_module.classify_startup_mode(**kwargs))
        for field in ("config_storage_matches", "legacy_schema_matches", "final_schema_matches", "command_manifest_matches"):
            with self.subTest(field=field):
                changed = dict(kwargs, **{field: False})
                self.assertEqual(marker_module.StartupMode.MAINTENANCE, marker_module.classify_startup_mode(**changed))
        self.assertEqual(
            marker_module.StartupMode.MAINTENANCE,
            marker_module.classify_startup_mode(**dict(kwargs, alembic_version="wrong")),
        )
        self.assertEqual(
            marker_module.StartupMode.MAINTENANCE,
            marker_module.classify_startup_mode(
                **dict(kwargs, expected_prepared_marker_sha256="e" * 64)
            ),
        )
        self.assertEqual(
            marker_module.StartupMode.MAINTENANCE,
            marker_module.classify_startup_mode(
                **dict(kwargs, expected_prepared_marker_sha256=None)
            ),
        )

    def test_only_clean_absence_is_legacy_only(self):
        kwargs = dict(
            config_storage_matches=True,
            legacy_schema_matches=True,
            alembic_version=marker_module.MIGRATION_CEILING,
            marker_record=None,
            anchor_record=None,
            final_schema_matches=False,
            command_manifest_matches=False,
        )
        self.assertEqual(marker_module.StartupMode.LEGACY_ONLY, marker_module.classify_startup_mode(**kwargs))
        marker, _anchor, _prepared_hash = valid_pair()
        self.assertEqual(
            marker_module.StartupMode.MAINTENANCE,
            marker_module.classify_startup_mode(**dict(kwargs, marker_record=marker)),
        )

    def test_later_phase_requires_reconstructed_prepared_digest(self):
        marker, anchor, prepared_hash = valid_pair(phase="S01_INFO_OWNER_SCOPE")
        self.assertEqual(
            prepared_hash,
            marker_module.reconstructed_prepared_marker_sha256(
                marker_module.validate_marker(marker),
                prepared_phase_schema_sha256="d" * 64,
            ),
        )
        marker_module.validate_anchor_marker_pair(
            marker,
            anchor,
            expected_prepared_marker_sha256=prepared_hash,
        )
        with self.assertRaises(marker_module.MarkerValidationError):
            marker_module.validate_anchor_marker_pair(marker, anchor)
        with self.assertRaises(marker_module.MarkerValidationError):
            marker_module.validate_anchor_marker_pair(
                marker,
                anchor,
                expected_prepared_marker_sha256="f" * 64,
            )

    def test_reconstruction_rejects_non_digest_phase_fingerprint(self):
        marker, _anchor, _prepared_hash = valid_pair(phase="S02_INFO_OWNER_ID")
        with self.assertRaises(marker_module.MarkerValidationError):
            marker_module.reconstructed_prepared_marker_sha256(
                marker_module.validate_marker(marker),
                prepared_phase_schema_sha256="not-a-digest",
            )

    def test_marker_rejects_impossible_calendar_timestamp_and_run_mismatch(self):
        marker, anchor, prepared_hash = valid_pair()
        impossible = marker_module.canonical_json(
            dict(marker_document(), created_at="2026-02-30T00:00:00Z")
        )
        with self.assertRaises(marker_module.MarkerValidationError):
            marker_module.validate_marker(record(marker.row_id, impossible))
        changed_run = marker_module.canonical_json(
            dict(marker_document(), run_id="f" * 64)
        )
        with self.assertRaises(marker_module.MarkerValidationError):
            marker_module.validate_anchor_marker_pair(
                record(marker.row_id, changed_run),
                anchor,
                expected_prepared_marker_sha256=prepared_hash,
            )

    def test_module_has_no_runtime_or_database_imports(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        for forbidden in ("from CTFd", "sqlalchemy", "ContainerManager", "stable_random_models", "import docker", "from docker"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
