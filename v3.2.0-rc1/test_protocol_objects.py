import unittest

import acsd
import protocol_objects


class TestProtocolObjects(unittest.TestCase):
    @staticmethod
    def team():
        return {
            "schema": protocol_objects.TEAM_SCHEMA,
            "authors": [{
                "key_id": "a" * 64,
                "role": "first",
                "corresponding": True,
                "contributions": [],
            }],
        }

    def test_acsd_preserves_public_builder_and_validator_names(self):
        names = (
            "build_release",
            "build_governance",
            "build_pec",
            "build_lineage_transition",
            "build_approval_target",
            "check_approval_target",
            "check_bindings",
            "lineage_authority_of",
            "lineage_claim_subject",
        )
        for name in names:
            with self.subTest(name=name):
                self.assertIs(getattr(acsd, name), getattr(protocol_objects, name))

    def test_default_ai_declarations_do_not_share_mutable_lists(self):
        team = self.team()
        team["authors"][0]["contributions"] = ["conceptualization"]
        first_release = protocol_objects.build_release(
            "urn:uuid:first",
            "1" * 64,
            "paper/first.txt",
            team,
        )
        second_release = protocol_objects.build_release(
            "urn:uuid:second",
            "2" * 64,
            "paper/second.txt",
            team,
        )
        governance = protocol_objects.build_governance(
            "urn:uuid:third",
            "3" * 64,
            self.team(),
        )
        first_release["ai_use"]["purposes"].append("drafting")
        first_release["authors"][0]["contributions"].append("writing")
        self.assertEqual(second_release["ai_use"]["purposes"], [])
        self.assertEqual(governance["ai_use_declaration"]["purposes"], [])
        self.assertEqual(
            second_release["authors"][0]["contributions"],
            ["conceptualization"],
        )
        self.assertEqual(team["authors"][0]["contributions"], ["conceptualization"])


if __name__ == "__main__":
    unittest.main()
