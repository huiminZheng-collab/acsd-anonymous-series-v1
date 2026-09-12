import copy
from pec_core import digest, validate_pec, verify_disclosure

def valid_fixture():
    release = {"digest":"a"*64,"content_sha256":"b"*64,"author_key_ids":["k1","k2"]}
    governance = {"digest":"c"*64}
    pec = {"schema":"acsd-pec/v0.1","pec_id":"pec-demo-01",
      "subject":{"work_id":"urn:uuid:demo","release_digest":release["digest"]},
      "governance":{"statement_digest":governance["digest"],"manuscript_sha256":release["content_sha256"],"required_pec_approval_key_ids":["k1","k2"]},"issuer_key_id":"k1",
      "events":[{"sequence":0,"event_id":"event-01","previous_event_digest":None,"kind":"research_note_snapshot","commitment":{"scheme":"salted-sha256-v1","digest":"d"*64,"disclosure_class":"sealed"}}],
      "claim_policy":{"permitted_outcomes":["KEY_ASSENT","COMMITTED_EVIDENCE_MATCH"],"global_non_claims":["natural_person_authorship","contribution_truth","originality_truth","legal_nonrepudiation","peer_review"]}}
    return release, governance, pec

def corpus():
    r,g,p = valid_fixture()
    cases = {"valid": (p, ["k1","k2"])}
    q=copy.deepcopy(p); q["governance"]["required_pec_approval_key_ids"]=["k2","k1"]; cases["role-order-mutated"]=(q,["k1","k2"])
    q=copy.deepcopy(p); cases["missing-approval"]=(q,["k1"])
    q=copy.deepcopy(p); q["events"][0]["sequence"]=1; cases["event-chain-broken"]=(q,["k1","k2"])
    q=copy.deepcopy(p); q["claim_policy"]["permitted_outcomes"].append("NATURAL_PERSON_AUTHORSHIP"); cases["social-claim-injected"]=(q,["k1","k2"])
    return r,g,cases

def evaluate_case(name, pec, approvals, release, governance):
    try:
        validate_pec(pec, approvals, release, governance)
        return "VALID" if name == "valid" else "UNEXPECTED_VALID"
    except ValueError as e:
        return str(e)
