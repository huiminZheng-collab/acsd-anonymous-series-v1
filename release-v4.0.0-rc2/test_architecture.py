import ast
import pathlib
import unittest

import artifact_io
import appraisal_transcript
import bundle_validation
import canonical_json
import cli_output
import claim_derivation
import key_material
import legacy_adapter
import lineage_adapter
import lineage_verification_transcript
import linkability_audit
import pec_core
import protocol_objects
import release_verifier
import release_adapter
import verification_transcript


ROOT = pathlib.Path(__file__).resolve().parent
PRODUCTION_GRANTERS = (
    "event_disclosure.py",
    "identity_disclosure.py",
    "lineage_verification_transcript.py",
    "release_verifier.py",
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

    def test_linkability_audit_is_an_io_free_release_projection(self):
        self.assertEqual(
            self.imported_roots(linkability_audit),
            {"canonical_json", "release_adapter"},
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

    def test_adapter_and_verifier_dependencies_flow_toward_the_kernel(self):
        self.assertEqual(
            self.imported_roots(artifact_io),
            {"canonical_json", "json", "pathlib"},
        )
        self.assertEqual(
            self.imported_roots(key_material),
            {"canonical_json", "cryptography", "key_identity", "pathlib"},
        )
        self.assertEqual(
            self.imported_roots(lineage_adapter),
            {
                "artifact_io",
                "canonical_json",
                "cose",
                "key_identity",
                "key_material",
                "protocol_objects",
                "release_adapter",
            },
        )
        verifier_roots = self.imported_roots(release_verifier)
        self.assertEqual(
            verifier_roots,
            {
                "approval_set",
                "approval_delegation_adapter",
                "appraisal_transcript",
                "artifact_io",
                "canonical_json",
                "claim_derivation",
                "cli_output",
                "cose",
                "hashlib",
                "key_identity",
                "key_material",
                "lineage_adapter",
                "package_manifest",
                "pathlib",
                "protocol_objects",
                "re",
                "release_adapter",
                "tsa",
            },
        )
        for module in (artifact_io, key_material, lineage_adapter, release_verifier):
            self.assertNotIn("acsd", self.imported_roots(module))

    def test_appraisal_transcript_is_a_pure_wire_boundary(self):
        self.assertEqual(
            self.imported_roots(appraisal_transcript),
            {"__future__", "canonical_json", "claim_derivation", "typing"},
        )
        source = pathlib.Path(release_verifier.__file__).read_text(encoding="utf-8")
        self.assertIn("appraisal_transcript.derive(transcript)", source)
        self.assertNotIn("claim_core.derive(", source)

    def test_cli_has_no_embedded_adapter_or_release_verifier_definitions(self):
        source = (ROOT / "acsd.py").read_text(encoding="utf-8")
        for name in (
            "read_canonical",
            "write_canonical",
            "path_is_within",
            "load_private_key",
            "load_public_key_bytes",
            "load_bound_public_key",
            "check_release_key_paths",
            "load_lineage_structure",
            "verify_lineage_authorization",
            "validate_receipt_report",
            "verify_release_dir",
        ):
            self.assertNotIn(f"def {name}(", source)

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

    def test_formal_appraisal_has_one_declarative_compatibility_relation(self):
        scoped = (ROOT / "formal/ACSD/ScopedClaims.lean").read_text(
            encoding="utf-8"
        )
        appraisal = (ROOT / "formal/ACSD/Appraisal.lean").read_text(
            encoding="utf-8"
        )
        self.assertEqual(scoped.count("inductive Compatible"), 1)
        self.assertIn("abbrev AppraisalRule := Compatible", appraisal)
        self.assertNotIn("inductive AppraisalRule", appraisal)
        self.assertIn("theorem appraisalDerives_refines_abstract", appraisal)

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
