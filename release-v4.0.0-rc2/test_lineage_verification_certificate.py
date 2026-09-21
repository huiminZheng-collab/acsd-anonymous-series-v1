import copy
import hashlib
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest

import claim_derivation
import generate_lineage_demo
import lineage_verification_certificate
import lineage_verification_transcript


ROOT = pathlib.Path(__file__).resolve().parent
DEMO = ROOT / "demo-lineage"
CHECKED = ROOT / "design" / "lineage_verification_certificate_demo.json"


def certificate():
    return json.loads(CHECKED.read_bytes())


def derive(value):
    raw = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8") + b"\n"
    return lineage_verification_transcript.derive(
        value, hashlib.sha256(raw).hexdigest()
    )


class TestLineageVerificationCertificate(unittest.TestCase):
    def test_checked_fixture_is_deterministically_reproducible(self):
        with tempfile.TemporaryDirectory() as raw:
            generated = pathlib.Path(raw) / "lineage"
            generate_lineage_demo.generate(generated)
            expected = {
                path.relative_to(DEMO).as_posix(): path.read_bytes()
                for path in DEMO.rglob("*") if path.is_file()
            }
            actual = {
                path.relative_to(generated).as_posix(): path.read_bytes()
                for path in generated.rglob("*") if path.is_file()
            }
            self.assertEqual(actual, expected)

    def test_python_node_and_checked_certificate_agree(self):
        expected = lineage_verification_certificate.encoded(DEMO) + b"\n"
        self.assertEqual(expected, CHECKED.read_bytes())
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js unavailable")
        result = subprocess.run(
            [node, str(ROOT / "design" / "lineage_verification_certificate.cjs"),
             str(DEMO)], capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stdout, expected)

    def test_closed_transition_derives_only_exact_authorized_successor(self):
        result = derive(certificate())
        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0].claim.kind, claim_derivation.ClaimKind.AUTHORIZED_SUCCESSOR
        )
        subject = result[0].claim.subject
        self.assertEqual(subject.parent_version, 1)
        self.assertEqual(subject.child_version, 2)

    def test_each_authorization_dependency_is_required(self):
        mutations = []
        value = certificate()
        del value["signature_facts"][1]
        mutations.append(("missing predecessor", value))

        value = certificate()
        value["signature_facts"][1]["payload_digest"] = "0" * 64
        mutations.append(("wrong transition payload", value))

        value = certificate()
        item = next(entry for entry in value["inputs"]
                    if entry["role"] == "predecessor-authorization-cose")
        item["sha256"] = "0" * 64
        mutations.append(("wrong predecessor input", value))

        value = certificate()
        value["lineage_edge"]["child"]["bound_transition_digest"] = "0" * 64
        mutations.append(("unbound transition", value))

        value = certificate()
        value["approval_set"]["lineage_authorizations"][0]["cose_sha256"] = "0" * 64
        mutations.append(("approval set mismatch", value))

        value = certificate()
        value["policy"]["permitted_outcomes"].remove("AUTHORIZED_SUCCESSOR")
        mutations.append(("policy absence", value))

        value = certificate()
        value["lineage_edge"]["child"]["version"] = 4
        mutations.append(("nonconsecutive child", value))

        for name, mutated in mutations:
            with self.subTest(name=name):
                self.assertEqual(derive(mutated), ())


if __name__ == "__main__":
    unittest.main()
