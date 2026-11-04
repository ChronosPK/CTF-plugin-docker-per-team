from __future__ import annotations

import ast
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "container_manager.py"


class DeferredConnectionTests(unittest.TestCase):
    def test_constructor_does_not_connect_to_docker(self):
        module = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        manager = next(
            node for node in module.body if isinstance(node, ast.ClassDef) and node.name == "ContainerManager"
        )
        constructor = next(
            node for node in manager.body if isinstance(node, ast.FunctionDef) and node.name == "__init__"
        )
        calls = [
            node.func.attr
            for node in ast.walk(constructor)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        ]

        self.assertNotIn("initialize_connection", calls)


if __name__ == "__main__":
    unittest.main()
