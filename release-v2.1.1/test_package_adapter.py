import json, os, pathlib, unittest
from pec_core import validate_v1_standalone_package

V1_ROOT = pathlib.Path(os.environ.get('ACSD_V1_ROOT', pathlib.Path(__file__).resolve().parent / 'v1-fixture'))

class TestPackageAdapter(unittest.TestCase):
  @unittest.skipUnless((V1_ROOT / 'artifacts/standalone-packages/p-v1.json').exists(), 'v1 fixture workspace unavailable')
  def test_real_package_bindings(self):
    root = V1_ROOT
    p = json.loads((root/'artifacts/standalone-packages/p-v1.json').read_text())
    x = validate_v1_standalone_package(p, root)
    self.assertEqual(x['author_key_ids'], ['p-slot-1','p-slot-2'])

if __name__ == '__main__': unittest.main()
