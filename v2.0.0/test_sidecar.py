import unittest, copy
from pec_core import digest, verify_sidecar_subject
from test_pec_core import fixture

class TestSidecar(unittest.TestCase):
  def test_exact_subject_and_capability(self):
    _r,_g,p=fixture(); p['claim_policy']['required_capabilities']={'EXTERNALLY_NOT_AFTER':['rfc3161-exact-pec-imprint']}; p['claim_policy']['permitted_outcomes'].append('EXTERNALLY_NOT_AFTER')
    s={'pec_digest':digest(p),'capability':'rfc3161-exact-pec-imprint'}
    self.assertTrue(verify_sidecar_subject(s,p,'EXTERNALLY_NOT_AFTER'))
  def test_replay_rejected(self):
    _r,_g,p=fixture(); p['claim_policy']['required_capabilities']={'EXTERNALLY_NOT_AFTER':['rfc3161-exact-pec-imprint']}; p['claim_policy']['permitted_outcomes'].append('EXTERNALLY_NOT_AFTER')
    s={'pec_digest':'0'*64,'capability':'rfc3161-exact-pec-imprint'}
    with self.assertRaisesRegex(ValueError,'RECEIPT_SUBJECT_MISMATCH'): verify_sidecar_subject(s,p,'EXTERNALLY_NOT_AFTER')

if __name__ == '__main__': unittest.main()
