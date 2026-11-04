from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

from sqlalchemy import Column, Integer, MetaData, Table
from sqlalchemy.dialects import mysql
from sqlalchemy.schema import CreateTable


MODULE_PATH = Path(__file__).resolve().parents[1] / "legacy_bootstrap.py"


def load_bootstrap_module():
    """Load only bounded bootstrap metadata with real parent-table references."""

    parent_metadata = MetaData()

    class Challenges:
        __table__ = Table("challenges", parent_metadata, Column("id", Integer, primary_key=True))

    class Teams:
        __table__ = Table("teams", parent_metadata, Column("id", Integer, primary_key=True))

    class Users:
        __table__ = Table("users", parent_metadata, Column("id", Integer, primary_key=True))

    ctfd_module = types.ModuleType("CTFd")
    ctfd_module.__path__ = []
    models_module = types.ModuleType("CTFd.models")
    models_module.Challenges = Challenges
    models_module.Teams = Teams
    models_module.Users = Users

    module_name = "docker_per_team_legacy_bootstrap_test"
    saved = {name: sys.modules.get(name) for name in ("CTFd", "CTFd.models", module_name)}
    try:
        sys.modules["CTFd"] = ctfd_module
        sys.modules["CTFd.models"] = models_module
        spec = importlib.util.spec_from_file_location(module_name, MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        for name, previous in saved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


legacy_bootstrap = load_bootstrap_module()


class LegacyBootstrapTests(unittest.TestCase):
    def test_metadata_has_only_the_five_legacy_plugin_tables(self):
        self.assertEqual(
            {
                "container_challenge_model",
                "container_info_model",
                "container_settings_model",
                "container_flag_model",
                "container_cheat_log",
            },
            set(legacy_bootstrap.legacy_bootstrap_metadata.tables),
        )
        self.assertEqual(
            legacy_bootstrap.LEGACY_TABLE_NAMES,
            tuple(table.name for table in legacy_bootstrap.legacy_tables),
        )
        self.assertEqual("d5e7f901a2b3", legacy_bootstrap.LEGACY_MIGRATION_CEILING)
        self.assertNotIn("stable_random_models", legacy_bootstrap.__dict__)

    def test_foreign_key_actions_and_legacy_indexes_match_baseline_contract(self):
        info = legacy_bootstrap.container_info_model
        info_actions = {
            fk.name: fk.ondelete for fk in info.foreign_key_constraints
        }
        self.assertEqual(
            {
                "container_info_model_ibfk_1": "CASCADE",
                "container_info_model_ibfk_2": "CASCADE",
                "container_info_model_ibfk_3": "CASCADE",
            },
            info_actions,
        )
        self.assertTrue(
            {
                "uq_container_info_challenge_team",
                "uq_container_info_challenge_user",
                "idx_container_info_team_challenge",
                "idx_container_info_user_challenge",
                "idx_container_info_expires",
            }.issubset(
                {
                    item.name
                    for item in (*info.constraints, *info.indexes)
                    if item.name
                }
            )
        )
        cheat_actions = {
            fk.name: fk.ondelete
            for fk in legacy_bootstrap.container_cheat_log.foreign_key_constraints
        }
        self.assertEqual("CASCADE", cheat_actions["container_cheat_log_ibfk_1"])
        for name in (
            "container_cheat_log_ibfk_2",
            "container_cheat_log_ibfk_3",
            "container_cheat_log_ibfk_4",
            "container_cheat_log_ibfk_5",
        ):
            self.assertEqual("SET NULL", cheat_actions[name])

    def test_bootstrap_calls_create_all_with_the_bounded_table_tuple_only(self):
        engine = object()
        with patch.object(legacy_bootstrap.legacy_bootstrap_metadata, "create_all") as create_all:
            legacy_bootstrap.bootstrap_legacy_schema(engine)
        create_all.assert_called_once_with(
            bind=engine,
            tables=legacy_bootstrap.legacy_tables,
            checkfirst=True,
        )

    def test_mysql_ddl_contains_no_extension_table_reference(self):
        ddl = "\n".join(
            str(CreateTable(table).compile(dialect=mysql.dialect()))
            for table in legacy_bootstrap.legacy_tables
        )
        self.assertNotIn("container_random_flag", ddl)
        self.assertNotIn("container_flag_issuance", ddl)
        self.assertNotIn("container_flag_launch_attempt", ddl)
        self.assertIn("ON DELETE CASCADE", ddl)
        self.assertIn("ON DELETE SET NULL", ddl)


if __name__ == "__main__":
    unittest.main()
