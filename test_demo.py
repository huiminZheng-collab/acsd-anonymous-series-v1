import tempfile, unittest, pathlib, json
from generate_demo import generate
from pec_core import digest
from verify_demo import verify_demo
from verify_pec import verify_package

class TestDemo(unittest.TestCase):
  def test_roundtrip(self):
    with tempfile.TemporaryDirectory() as d:
      _root, pd=generate(d); p=json.loads((pathlib.Path(d)/'pec.json').read_text())
      self.assertEqual(digest(p), pd)
      self.assertEqual(verify_demo(d), 14)
      self.assertEqual(verify_package(d)['status'], 'VALID')

if __name__ == '__main__': unittest.main()
