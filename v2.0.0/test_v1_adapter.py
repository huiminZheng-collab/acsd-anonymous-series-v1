import json, os, pathlib, unittest
from pec_core import adapt_v1_release

V1_ROOT = pathlib.Path(os.environ.get('ACSD_V1_ROOT', pathlib.Path(__file__).resolve().parent.parent))

class TestV1Adapter(unittest.TestCase):
  @unittest.skipUnless((V1_ROOT / 'artifact/artifacts/releases/p-v1.json').exists(), 'v1 fixture workspace unavailable')
  def test_published_release_projection(self):
    p = V1_ROOT / 'artifact/artifacts/releases/p-v1.json'
    x = adapt_v1_release(json.loads(p.read_text(encoding='utf-8')))
    self.assertEqual(x['author_key_ids'], ['p-slot-1', 'p-slot-2'])
    self.assertEqual(len(x['digest']), 64)

if __name__ == '__main__': unittest.main()
