import copy
import unittest
from pec_core import canonical, digest, validate_pec, verify_disclosure

def fixture():
    release = {"digest": "a"*64, "content_sha256": "b"*64, "author_key_ids": ["k1", "k2"], "work_id": "w"}
    governance = {"digest": "c"*64}
    pec = {"schema":"acsd-pec/v0.1", "pec_id":"p", "subject":{"work_id":"w","release_digest":release["digest"]},
      "governance":{"statement_digest":governance["digest"],"manuscript_sha256":release["content_sha256"],"required_pec_approval_key_ids":["k1","k2"]},
      "events":[{"sequence":0,"event_id":"e","previous_event_digest":None,"kind":"research_note_snapshot"}],
      "issuer_key_id":"k1",
      "claim_policy":{"permitted_outcomes":["KEY_ASSENT"],"global_non_claims":["natural_person_authorship","contribution_truth","originality_truth","legal_nonrepudiation","peer_review"]}}
    return release, governance, pec

class TestPECCore(unittest.TestCase):
  def test_canonical_stable(self):
    self.assertEqual(canonical({"b":1,"a":2}), b'{"a":2,"b":1}')
    with self.assertRaisesRegex(ValueError, "FLOAT_FORBIDDEN"): canonical({"x": 1.5})
    with self.assertRaisesRegex(ValueError, "NONASCII_KEY"): canonical({"键": 1})

  def test_canonical_nonascii_value_kept_verbatim(self):
    # Non-ASCII string VALUES must stay raw UTF-8 bytes (ensure_ascii=False),
    # matching the v1 reference (generate.py) and the Node verifier
    # (JSON.stringify). Escaping would split the canonical byte image.
    self.assertEqual(canonical({"label": "匿名"}), '{"label":"匿名"}'.encode("utf-8"))

  def test_canonical_rejects_lone_surrogate(self):
    lone = chr(0xD800)  # unpaired high surrogate
    with self.assertRaisesRegex(ValueError, "LONE_SURROGATE"): canonical({"s": lone})

  def test_canonical_rejects_tuple(self):
    # Tuples are not a JSON type; json.dumps silently coerces them, so the
    # canonical contract must reject them explicitly (v1 behavior).
    with self.assertRaisesRegex(ValueError, "JSON_TYPE_FORBIDDEN"): canonical({"a": (1, 2)})

  def test_valid_and_disclosure(self):
    r,g,p = fixture(); result=validate_pec(p,["k1","k2"],r,g)
    d={"pec_digest":result["pec_digest"],"event_id":"e","event_sequence":0,"kind":"research_note_snapshot","approval_key_ids":["k1"]}
    self.assertTrue(verify_disclosure(d,p,p["events"][0]))

  def test_disclosure_requires_unanimity(self):
    r,g,p = fixture(); result=validate_pec(p,["k1","k2"],r,g)
    d={"pec_digest":result["pec_digest"],"event_id":"e","event_sequence":0,"kind":"research_note_snapshot","approval_key_ids":["k1"]}
    with self.assertRaisesRegex(ValueError, "DISCLOSURE_APPROVAL_MISSING"):
      verify_disclosure(d,p,p["events"][0],["k1","k2"])

  def test_rejections(self):
    for mutator, code in [(lambda p:p["governance"].update(required_pec_approval_key_ids=["k2","k1"]),"GOVERNANCE_BINDING_MISMATCH"),(lambda p:p["events"][0].update(sequence=2),"EVENT_CHAIN_BROKEN")]:
      r,g,p=fixture(); mutator(p)
      with self.assertRaisesRegex(ValueError, code): validate_pec(p,["k1","k2"],r,g)

  def test_unknown_and_duplicate_outcomes_rejected(self):
    r,g,p=fixture(); p["claim_policy"]["permitted_outcomes"]=["KEY_ASSENT","MADE_UP"]
    with self.assertRaisesRegex(ValueError, "CLAIM_POLICY_UNKNOWN_OUTCOME"): validate_pec(p,["k1","k2"],r,g)
    r,g,p=fixture(); p["claim_policy"]["permitted_outcomes"]=["KEY_ASSENT","KEY_ASSENT"]
    with self.assertRaisesRegex(ValueError, "CLAIM_POLICY_DUPLICATE"): validate_pec(p,["k1","k2"],r,g)

  def test_issuer_and_event_id_binding(self):
    r,g,p=fixture(); p['issuer_key_id']='attacker'
    with self.assertRaisesRegex(ValueError, 'PEC_ISSUER_UNAUTHORIZED'): validate_pec(p,['k1','k2'],r,g)
    r,g,p=fixture(); p['events'].append(dict(p['events'][0], sequence=1, previous_event_digest=digest(p['events'][0])))
    with self.assertRaisesRegex(ValueError, 'EVENT_CHAIN_BROKEN'): validate_pec(p,['k1','k2'],r,g)

  def test_predecessor_binding(self):
    r,g,p=fixture(); old=copy.deepcopy(p); p["subject"]["predecessor_pec_digest"]=digest(old)
    self.assertTrue(validate_pec(p,["k1","k2"],r,g,old))
    with self.assertRaisesRegex(ValueError, "PREDECESSOR_MISMATCH"): validate_pec(p,["k1","k2"],r,g,{**old,"pec_id":"other"})

if __name__ == '__main__': unittest.main()
