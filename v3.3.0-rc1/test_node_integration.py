import os, pathlib, unittest
from pec_core import verify_v1_package_with_node

V1_ROOT = pathlib.Path(os.environ.get('ACSD_V1_ROOT', pathlib.Path(__file__).resolve().parent / 'v1-fixture'))

class TestNodeIntegration(unittest.TestCase):
  @unittest.skipUnless((V1_ROOT / 'verify-standalone.cjs').exists(), 'v1 fixture workspace unavailable')
  def test_audited_v1_verifier(self):
    root = V1_ROOT
    report = verify_v1_package_with_node(root/'artifacts/standalone-packages/p-v1.json', root/'verify-standalone.cjs')
    self.assertTrue(report['release_valid'])
    self.assertEqual(report['endorsements_expected'], 2)

if __name__ == '__main__': unittest.main()
