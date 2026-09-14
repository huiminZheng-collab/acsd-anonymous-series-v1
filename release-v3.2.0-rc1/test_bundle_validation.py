import copy
import json
import pathlib
import unittest

import acsd
from bundle_validation import new_disclosure_policy
from canonical_json import digest
from pec_core import validate_pec
from release_adapter import adapt_release


ROOT = pathlib.Path(__file__).resolve().parent


def load(relative):
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


class TestUnifiedBundleValidation(unittest.TestCase):
    def setUp(self):
        self.release = load("demo-lineage/release/release.json")
        self.governance = load("demo-lineage/governance/statement.json")
        self.pec = load("demo-lineage/pec/pec.json")
        self.parent_pec = load("demo-lineage/lineage/parent-pec.json")
        self.adapted = adapt_release(self.release)
        self.approvals = list(self.adapted["author_key_ids"])

    def cli_validation(self, pec, governance=None, release=None):
        return acsd.check_bindings(
            pec,
            self.adapted,
            self.governance if governance is None else governance,
            self.release if release is None else release,
        )

    def reference_validation(self, pec):
        return validate_pec(
            pec,
            self.approvals,
            self.adapted,
            {"digest": digest(self.governance)},
            self.parent_pec,
        )

    def test_both_public_facades_accept_the_same_v3_bundle(self):
        cli = self.cli_validation(self.pec)
        reference = self.reference_validation(self.pec)
        self.assertEqual(cli, reference)
        self.assertEqual(cli["pec_digest"], digest(self.pec))

    def test_default_disclosure_policy_is_not_shared_mutable_state(self):
        first = new_disclosure_policy()
        first["event_kinds"]["dialogue_snapshot"]["modes"].append("poison")
        self.assertNotEqual(first, new_disclosure_policy())
        self.cli_validation(self.pec)

    def test_shared_mutations_have_identical_first_error_codes(self):
        cases = []

        def case(name, code, mutate):
            cases.append((name, code, mutate))

        case("release", "SUBJECT_RELEASE_MISMATCH",
             lambda value: value["subject"].update(release_digest="0" * 64))
        case("work", "SUBJECT_WORK_ID_MISMATCH",
             lambda value: value["subject"].update(work_id="urn:uuid:other"))
        case("governance", "GOVERNANCE_BINDING_MISMATCH",
             lambda value: value["governance"].update(statement_digest="0" * 64))
        case("manuscript", "GOVERNANCE_BINDING_MISMATCH",
             lambda value: value["governance"].update(manuscript_sha256="0" * 64))
        case("key-order", "GOVERNANCE_BINDING_MISMATCH",
             lambda value: value["governance"].update(
                 required_pec_approval_key_ids=["0" * 64]
             ))
        case("issuer", "PEC_ISSUER_UNAUTHORIZED",
             lambda value: value.update(issuer_key_id="0" * 64))
        case("event-chain", "EVENT_CHAIN_BROKEN",
             lambda value: value["events"].append({
                 "schema": "acsd-pec-event/v0.1",
                 "sequence": 1,
                 "event_id": "bad-first-event",
                 "previous_event_digest": None,
                 "kind": "research_note_snapshot",
                 "commitment": {
                     "scheme": "salted-sha256-v1",
                     "digest": "0" * 64,
                     "disclosure_class": "sealed",
                 },
             }))
        case("non-claim", "CLAIM_POLICY_INCOMPLETE",
             lambda value: value["claim_policy"]["global_non_claims"].pop())
        case("duplicate-outcome", "CLAIM_POLICY_DUPLICATE",
             lambda value: value["claim_policy"]["permitted_outcomes"].append(
                 value["claim_policy"]["permitted_outcomes"][0]
             ))
        case("unknown-outcome", "CLAIM_POLICY_UNKNOWN_OUTCOME",
             lambda value: value["claim_policy"]["permitted_outcomes"].append(
                 "UNDECLARED_OUTCOME"
             ))
        case("disclosure-policy", "DISCLOSURE_POLICY_INVALID",
             lambda value: value["disclosure_policy"].update(schema="wrong"))
        case("time-capability", "CLAIM_POLICY_CAPABILITY_MISMATCH",
             lambda value: value["claim_policy"]["required_capabilities"].update(
                 APPROVAL_SET_EXISTED_NOT_AFTER=["wrong"]
             ))
        case("lineage-capability", "CLAIM_POLICY_CAPABILITY_MISMATCH",
             lambda value: value["claim_policy"]["required_capabilities"].update(
                 AUTHORIZED_SUCCESSOR=["wrong"]
             ))

        for name, expected, mutate in cases:
            with self.subTest(case=name):
                value = copy.deepcopy(self.pec)
                mutate(value)
                with self.assertRaises(ValueError) as cli_error:
                    self.cli_validation(value)
                with self.assertRaises(ValueError) as reference_error:
                    self.reference_validation(value)
                self.assertEqual(str(cli_error.exception), expected)
                self.assertEqual(str(reference_error.exception), expected)

    def test_cli_facade_retains_release_governance_checks(self):
        governance = copy.deepcopy(self.governance)
        governance["byline"][0]["role"] = "unauthorized-role-change"
        pec = copy.deepcopy(self.pec)
        pec["governance"]["statement_digest"] = digest(governance)
        with self.assertRaisesRegex(ValueError, "GOVERNANCE_BYLINE_MISMATCH"):
            self.cli_validation(pec, governance=governance)


if __name__ == "__main__":
    unittest.main()
