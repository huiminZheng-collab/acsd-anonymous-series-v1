import ast
import pathlib
import unittest

import claim_derivation


ROOT = pathlib.Path(__file__).resolve().parent
PRODUCTION_GRANTERS = (
    "acsd.py",
    "event_disclosure.py",
    "identity_disclosure.py",
    "verify_pec.py",
)


class TestTrustedKernelArchitecture(unittest.TestCase):
    def test_decision_core_has_no_io_crypto_or_application_imports(self):
        source = pathlib.Path(claim_derivation.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".")[0])
        self.assertEqual(
            imported_roots,
            {"__future__", "dataclasses", "enum", "re", "typing"},
        )

    def test_every_public_granting_path_depends_on_decision_core(self):
        for name in PRODUCTION_GRANTERS:
            with self.subTest(module=name):
                source = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn("claim_derivation", source)

    def test_production_code_does_not_append_grants_by_string(self):
        wire_claims = set(claim_derivation.WIRE_TO_CLAIM)
        for name in PRODUCTION_GRANTERS:
            tree = ast.parse((ROOT / name).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if not isinstance(node.func, ast.Attribute) or node.func.attr != "append":
                    continue
                if not node.args or not isinstance(node.args[0], ast.Constant):
                    continue
                self.assertNotIn(
                    node.args[0].value,
                    wire_claims,
                    msg=f"{name} manually appends a security claim",
                )


if __name__ == "__main__":
    unittest.main()
