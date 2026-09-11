import tempfile, unittest, pathlib, json
from generate_demo import generate
from pec_core import digest, verify_dialogue_window
from verify_demo import verify_demo

class TestDemo(unittest.TestCase):
  def test_roundtrip(self):
    with tempfile.TemporaryDirectory() as d:
      root, pd=generate(d); p=json.loads((pathlib.Path(d)/'pec.json').read_text()); x=json.loads((pathlib.Path(d)/'dialogue-disclosure.json').read_text())
      self.assertEqual(digest(p), pd); w=[{'index':z['index'],'bytes':z['bytes'].encode(),'salt':bytes.fromhex(z['salt']),'path':z['path']} for z in x['opened_material']]
      self.assertTrue(verify_dialogue_window(root,w))
      self.assertEqual(verify_demo(d), 2)

if __name__ == '__main__': unittest.main()
