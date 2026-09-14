import unittest

import acsd
import artifact_io
import key_material
import lineage_adapter
import release_verifier


class TestAdapterFacades(unittest.TestCase):
    def test_acsd_preserves_existing_adapter_and_verifier_names(self):
        owners = {
            "read_canonical": artifact_io,
            "write_canonical": artifact_io,
            "path_is_within": artifact_io,
            "load_private_key": key_material,
            "load_public_key_bytes": key_material,
            "public_pem": key_material,
            "load_certificate_der": key_material,
            "load_bound_public_key": key_material,
            "check_release_key_paths": key_material,
            "load_lineage_structure": lineage_adapter,
            "verify_lineage_authorization": lineage_adapter,
            "validate_receipt_report": release_verifier,
            "verify_release_dir": release_verifier,
        }
        for name, owner in owners.items():
            with self.subTest(name=name):
                self.assertIs(getattr(acsd, name), getattr(owner, name))


if __name__ == "__main__":
    unittest.main()
