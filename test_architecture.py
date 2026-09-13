import ast
import pathlib
import unittest

import bundle_validation
import canonical_json
import cli_output
import claim_derivation
import legacy_adapter
import lineage_verification_transcript
import pec_core
import protocol_objects
import release_adapter
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

    def test_release_projection_is_a_pure_canonical_adapter(self):
        self.assertEqual(
            self.imported_roots(release_adapter),
            {"canonical_json"},
        )

    def test_protocol_object_layer_has_no_io_crypto_or_cli_dependencies(self):
        roots = self.imported_roots(protocol_objects)
        self.assertEqual(
            roots,
            {
                "bundle_validation",
                "canonical_json",
                "claim_derivation",
                "hashlib",
                "key_identity",
                "release_adapter",
                "uuid",
            },
        )
        self.assertTrue(
            {
                "acsd",
                "cose",
                "cryptography",
                "json",
                "pathlib",
                "subprocess",
                "tsa",
            }.isdisjoint(roots)
        )
        cli_source = (ROOT / "acsd.py").read_text(encoding="utf-8")
        for name in (
            "build_release",
            "build_governance",
            "build_pec",
            "build_lineage_transition",
            "build_approval_target",
            "check_approval_target",
            "check_bindings",
            "lineage_authority_of",
            "lineage_claim_subject",
        ):
            self.assertNotIn(f"def {name}(", cli_source)

    def test_legacy_io_is_confined_to_the_named_adapter(self):
        self.assertEqual(
            self.imported_roots(legacy_adapter),
            {
                "canonical_json",
                "hashlib",
                "json",
                "pathlib",
                "release_adapter",
                "subprocess",
            },
        )
        roots = self.imported_roots(pec_core)
        self.assertEqual(
            roots,
            {
                "bundle_validation",
                "canonical_json",
                "hashlib",
                "legacy_adapter",
                "release_adapter",
            },
        )
        self.assertTrue({"json", "pathlib", "subprocess"}.isdisjoint(roots))

    def test_cli_output_contract_has_no_application_dependencies(self):
        self.assertEqual(self.imported_roots(cli_output), {"json"})
        source = (ROOT / "acsd.py").read_text(encoding="utf-8")
        self.assertIn("from cli_output import (", source)
        self.assertNotIn("def emit_json(", source)
        self.assertNotIn("def emit_human(", source)

    def test_live_application_uses_release_adapter_not_compatibility_name(self):
        for name in (
            "acsd.py",
            "generate_demo.py",
            "generate_lineage_demo.py",
            "lineage_verification_certificate.py",
            "verify_pec.py",
        ):
            with self.subTest(module=name):
                source = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn("adapt_release", source)
                self.assertNotIn("adapt_v1_release", source)

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
        for name in ("protocol_objects.py", "pec_core.py"):
            with self.subTest(module=name):
                source = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn("validate_pec_bundle(", source)
                self.assertNotIn("CLAIM_POLICY_DUPLICATE", source)
        cli_source = (ROOT / "acsd.py").read_text(encoding="utf-8")
        self.assertIn("from protocol_objects import (", cli_source)
        self.assertNotIn("CLAIM_POLICY_DUPLICATE", cli_source)

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
