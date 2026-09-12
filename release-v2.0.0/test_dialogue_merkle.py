import unittest
from pec_core import dialogue_root, dialogue_proof, verify_dialogue_window

class TestDialogueMerkle(unittest.TestCase):
  def test_contiguous_window(self):
    turns=[{"bytes":x.encode(),"salt":bytes([i])*32} for i,x in enumerate(['a','b','c','d'])]
    root=dialogue_root(turns)
    w=[{"index":i,"bytes":turns[i]['bytes'],"salt":turns[i]['salt'],'path':dialogue_proof(turns,i)} for i in (1,2)]
    self.assertTrue(verify_dialogue_window(root,w))
  def test_noncontiguous_rejected(self):
    turns=[{"bytes":x.encode(),"salt":bytes([i])*32} for i,x in enumerate(['a','b','c'])]
    w=[{"index":0,"bytes":turns[0]['bytes'],"salt":turns[0]['salt'],'path':dialogue_proof(turns,0)},
       {"index":2,"bytes":turns[2]['bytes'],"salt":turns[2]['salt'],'path':dialogue_proof(turns,2)}]
    with self.assertRaisesRegex(ValueError,'DISCLOSURE_WINDOW_INVALID'): verify_dialogue_window(dialogue_root(turns),w)
  def test_tampered_leaf_rejected(self):
    turns=[{"bytes":x.encode(),"salt":bytes([i])*32} for i,x in enumerate(['a','b','c','d'])]
    w=[{"index":1,"bytes":b'X',"salt":turns[1]['salt'],'path':dialogue_proof(turns,1)}]
    with self.assertRaisesRegex(ValueError,'DISCLOSURE_BINDING_MISMATCH'): verify_dialogue_window(dialogue_root(turns),w)

if __name__ == '__main__': unittest.main()
