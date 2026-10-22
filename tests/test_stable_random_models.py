from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys
import types
import unittest

from sqlalchemy import Column, Integer, MetaData, Table
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import declarative_base
from sqlalchemy.schema import CreateTable


MODULE_PATH = Path(__file__).resolve().parents[1] / "stable_random_models.py"


def load_models_module():
    """Load only the extension metadata against a minimal CTFd-model stub.

    The test intentionally does not import the plugin package, call its load
    hook, create a Flask app, or execute any create_all operation.
    """

    metadata = MetaData()
    Table("challenges", metadata, Column("id", Integer, primary_key=True))
    Table("teams", metadata, Column("id", Integer, primary_key=True))
    Table("users", metadata, Column("id", Integer, primary_key=True))
    model_base = declarative_base(metadata=metadata)

    ctfd_module = types.ModuleType("CTFd")
    ctfd_module.__path__ = []
    ctfd_models_module = types.ModuleType("CTFd.models")
    ctfd_models_module.db = types.SimpleNamespace(Model=model_base)

    module_name = "docker_per_team_stable_random_models_test"
    saved_modules = {
        name: sys.modules.get(name)
        for name in ("CTFd", "CTFd.models", module_name)
    }
    try:
        sys.modules["CTFd"] = ctfd_module
        sys.modules["CTFd.models"] = ctfd_models_module
        spec = importlib.util.spec_from_file_location(module_name, MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        for name, saved in saved_modules.items():
            if saved is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = saved


stable_random_models = load_models_module()


def constraint_names(table):
    return {constraint.name for constraint in table.constraints if constraint.name}


class StableRandomSchemaMetadataTests(unittest.TestCase):
    def test_exact_extension_table_names_and_format_snapshot_key(self):
        format_table = stable_random_models.ContainerRandomFlagFormatModel.__table__
        self.assertEqual(format_table.name, "container_random_flag_format_model")
        self.assertEqual(
            {
                "id",
                "challenge_id",
                "algorithm",
                "prefix",
                "suffix",
                "random_length",
                "total_length",
                "format_sha256",
                "created_at",
            },
            set(format_table.c.keys()),
        )
        self.assertTrue(format_table.c.format_sha256.type.__class__ is mysql.BINARY)
        self.assertIn("uq_crff_challenge", constraint_names(format_table))
        self.assertIn("uq_crff_snapshot", constraint_names(format_table))
        challenge_fk = next(iter(format_table.foreign_key_constraints))
        self.assertEqual("RESTRICT", challenge_fk.ondelete)
        self.assertEqual(
            ["challenges.id"],
            [element.target_fullname for element in challenge_fk.elements],
        )

    def test_issuance_metadata_fences_owner_candidate_and_format_snapshot(self):
        issuance_table = stable_random_models.ContainerFlagIssuanceModel.__table__
        self.assertEqual(issuance_table.name, "container_flag_issuance_model")
        self.assertEqual(512, issuance_table.c.flag.type.length)
        self.assertEqual(32, issuance_table.c.flag_sha256.type.length)
        self.assertIsNotNone(issuance_table.c.current_owner_id.computed)
        self.assertIn("RESERVED_EXPOSED", issuance_table.c.current_owner_id.computed.sqltext.text)
        names = constraint_names(issuance_table)
        self.assertTrue(
            {
                "uq_crfi_current_owner",
                "uq_crfi_flag",
                "uq_crfi_flag_sha256",
                "uq_crfi_attachment_parent",
                "fk_crfi_format_snapshot",
                "fk_crfi_challenge_restrict",
                "fk_crfi_team_owner_restrict",
                "fk_crfi_user_owner_restrict",
            }.issubset(names)
        )
        snapshot_fk = next(
            constraint
            for constraint in issuance_table.foreign_key_constraints
            if constraint.name == "fk_crfi_format_snapshot"
        )
        self.assertEqual("RESTRICT", snapshot_fk.ondelete)
        self.assertEqual(
            ["format_id", "challenge_id", "format_sha256"],
            [element.parent.name for element in snapshot_fk.elements],
        )
        self.assertEqual(
            [
                "container_random_flag_format_model.id",
                "container_random_flag_format_model.challenge_id",
                "container_random_flag_format_model.format_sha256",
            ],
            [element.target_fullname for element in snapshot_fk.elements],
        )
        self.assertIn(
            "idx_crfi_owner_state",
            {index.name for index in issuance_table.indexes},
        )

    def test_attempt_metadata_has_current_fence_and_composite_parent(self):
        attempt_table = stable_random_models.ContainerFlagLaunchAttemptModel.__table__
        self.assertEqual(attempt_table.name, "container_flag_launch_attempt_model")
        self.assertEqual(32, attempt_table.c.id.type.length)
        self.assertIsNotNone(attempt_table.c.current_issuance_id.computed)
        self.assertIn(
            "AMBIGUOUS_BLOCKING",
            attempt_table.c.current_issuance_id.computed.sqltext.text,
        )
        names = constraint_names(attempt_table)
        self.assertTrue(
            {
                "uq_crfla_current_issuance",
                "uq_crfla_docker_name",
                "uq_crfla_attachment_parent",
                "fk_crfla_issuance_parent",
            }.issubset(names)
        )
        parent_fk = next(iter(attempt_table.foreign_key_constraints))
        self.assertEqual("RESTRICT", parent_fk.ondelete)
        self.assertEqual(
            ["issuance_id", "challenge_id", "owner_scope", "owner_id"],
            [element.parent.name for element in parent_fk.elements],
        )
        self.assertIn(
            "idx_crfla_issuance_owner",
            {index.name for index in attempt_table.indexes},
        )

    def test_mysql_ddl_retains_binary_generated_and_restrict_shape(self):
        ddl = str(
            CreateTable(
                stable_random_models.ContainerFlagIssuanceModel.__table__
            ).compile(dialect=mysql.dialect())
        )
        self.assertIn("VARBINARY(512)", ddl)
        self.assertIn("BINARY(32)", ddl)
        self.assertIn("GENERATED ALWAYS AS", ddl)
        self.assertIn("ON DELETE RESTRICT", ddl)


class StableRandomCanonicalHelperTests(unittest.TestCase):
    FORMAT_FIELDS = {
        "format_id": 7,
        "challenge_id": 11,
        "algorithm": "ascii-alnum-csprng-v1",
        "prefix": b"CSCTF{",
        "suffix": b"}",
        "random_length": 24,
        "total_length": 31,
    }

    def test_canonical_encoding_and_hash_are_stable_and_row_bound(self):
        encoded = stable_random_models.canonical_format_encoding(**self.FORMAT_FIELDS)
        digest = stable_random_models.canonical_format_sha256(**self.FORMAT_FIELDS)
        self.assertEqual(digest, hashlib.sha256(encoded).digest())
        self.assertEqual(
            "b5109f4cd3ad228cf6d2fc3f2a09ab0d3744884858195a81f573fa9d3ea8558f",
            digest.hex(),
        )
        changed_row = dict(self.FORMAT_FIELDS, format_id=8)
        self.assertNotEqual(
            digest,
            stable_random_models.canonical_format_sha256(**changed_row),
        )

    def test_format_helper_rejects_noncanonical_inputs(self):
        invalid_cases = (
            dict(self.FORMAT_FIELDS, algorithm="other-v1"),
            dict(self.FORMAT_FIELDS, prefix=b"\xff"),
            dict(self.FORMAT_FIELDS, prefix="CSCTF{"),
            dict(self.FORMAT_FIELDS, total_length=30),
            dict(self.FORMAT_FIELDS, random_length=True),
            dict(self.FORMAT_FIELDS, challenge_id=0),
        )
        for invalid_fields in invalid_cases:
            with self.subTest(fields=set(invalid_fields)):
                with self.assertRaises(
                    stable_random_models.StableRandomModelValidationError
                ):
                    stable_random_models.canonical_format_sha256(**invalid_fields)

    def test_state_helpers_allow_only_declared_literals(self):
        self.assertEqual(
            "ISSUED",
            stable_random_models.validate_issuance_state("ISSUED"),
        )
        self.assertEqual(
            "AMBIGUOUS_BLOCKING",
            stable_random_models.validate_launch_attempt_state(
                "AMBIGUOUS_BLOCKING"
            ),
        )
        with self.assertRaises(stable_random_models.StableRandomModelValidationError):
            stable_random_models.validate_issuance_state("issued")
        with self.assertRaises(stable_random_models.StableRandomModelValidationError):
            stable_random_models.validate_launch_attempt_state("RETIRED")


if __name__ == "__main__":
    unittest.main()
