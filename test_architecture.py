import ast
import pathlib
import unittest

import bundle_validation
import canonical_json
import claim_derivation
import lineage_verification_transcript
import verification_transcript


ROOT = pathlib.Path(__file__).resolve().parent
PRODUCTION_GRANTERS = (
    "acsd.py",
    "event_disclosure.py",
    "identity_disclosure.py",
    "lineage_verification_transcript.py",
    "verify_pec.py",
    "verification_transcript.py",
)


class TestTrustedKernelArchitecture(unittest.TestCase):
    @staticmethod
    def imported_roots(module):
        source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                roots.add(node.module.split(".")[0])
        return roots

    def test_canonical_json_layer_has_only_standard_library_dependencies(self):
        self.assertEqual(
            self.imported_roots(canonical_json),
            {"hashlib", "json", "re"},
        )

    def test_bundle_validation_depends_only_on_canonical_json(self):
        self.assertEqual(
            self.imported_roots(bundle_validation),
            {"canonical_json"},
        )

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

    def test_transcript_checker_is_pure_and_depends_only_on_claim_core(self):
        source = pathlib.Path(verification_transcript.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".")[0])
        self.assertEqual(
            imported_roots,
            {"__future__", "re", "typing", "claim_derivation"},
        )

    def test_lineage_transcript_checker_is_pure_and_depends_only_on_claim_core(self):
        source = pathlib.Path(
            lineage_verification_transcript.__file__
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".")[0])
        self.assertEqual(
            imported_roots,
            {"__future__", "re", "claim_derivation"},
        )

    def test_every_public_granting_path_depends_on_decision_core(self):
        for name in PRODUCTION_GRANTERS:
            with self.subTest(module=name):
                source = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn("claim_derivation", source)

    def test_pec_facades_delegate_to_one_bundle_validator(self):
        for name in ("acsd.py", "pec_core.py"):
            with self.subTest(module=name):
                source = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn("validate_pec_bundle(", source)
                self.assertNotIn("CLAIM_POLICY_DUPLICATE", source)

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
