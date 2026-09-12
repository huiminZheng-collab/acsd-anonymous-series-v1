import unittest
from fixtures import corpus, evaluate_case

class TestCorpus(unittest.TestCase):
  def test_attack_matrix(self):
    r,g,cases=corpus(); expected={"valid":"VALID","role-order-mutated":"GOVERNANCE_BINDING_MISMATCH","missing-approval":"PEC_APPROVAL_MISSING","event-chain-broken":"EVENT_CHAIN_BROKEN","social-claim-injected":"SOCIAL_CLAIM_FORBIDDEN"}
    for name,(p,a) in cases.items(): self.assertEqual(evaluate_case(name,p,a,r,g), expected[name], name)

if __name__ == '__main__': unittest.main()
