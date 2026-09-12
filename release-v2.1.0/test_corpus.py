import unittest
from fixtures import corpus, evaluate_case

class TestCorpus(unittest.TestCase):
  def test_attack_matrix(self):
    release, governance, cases = corpus()
    seen = set()
    for name, evaluator, expected in cases:
      self.assertNotIn(name, seen, f"duplicate case name {name}")
      seen.add(name)
      self.assertEqual(evaluate_case(name, evaluator), expected, name)
    # the frozen plan has 17 cases; the two series-layer cases are documented
    # out of scope for the v0.1 PEC layer
    self.assertGreaterEqual(len(cases), 15, "corpus should cover the implementable TEST-PLAN matrix")

if __name__ == '__main__': unittest.main()
