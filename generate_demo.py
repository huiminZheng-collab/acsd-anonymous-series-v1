import json, pathlib
import hashlib
from pec_core import canonical, digest, dialogue_root, dialogue_proof, validate_pec, verify_dialogue_window

def generate(out='demo'):
    out=pathlib.Path(out); out.mkdir(parents=True, exist_ok=True)
    turns=[{"bytes":x.encode(),"salt":bytes([i])*32} for i,x in enumerate(['initial idea','formalization','counterexample','revision'])]
    root=dialogue_root(turns)
    release={"digest":"a"*64,"content_sha256":"b"*64,"author_key_ids":["k1","k2"]}
    governance={"digest":"c"*64}
    pec={"schema":"acsd-pec/v0.1","pec_id":"pec-demo-01","subject":{"work_id":"urn:uuid:demo","release_digest":release['digest']},
      "governance":{"statement_digest":governance['digest'],"manuscript_sha256":release['content_sha256'],"required_pec_approval_key_ids":["k1","k2"]},"issuer_key_id":"k1",
      "events":[{"schema":"acsd-pec-event/v0.1","sequence":0,"event_id":"dialogue-01","previous_event_digest":None,"kind":"dialogue_snapshot","commitment":{"scheme":"merkle-dialogue-v1","digest":root,"disclosure_class":"revealable"}}],
      "claim_policy":{"permitted_outcomes":["KEY_ASSENT","GOVERNANCE_ASSENT","COMMITTED_EVIDENCE_MATCH"],"global_non_claims":["natural_person_authorship","contribution_truth","originality_truth","legal_nonrepudiation","peer_review"]}}
    validate_pec(pec,['k1','k2'],release,governance)
    disclosure={"schema":"acsd-pec-disclosure/v0.1","pec_digest":digest(pec),"event_id":"dialogue-01","event_sequence":0,"kind":"dialogue_snapshot","disclosure_mode":"dialogue_window",
      "opened_material":[{"index":i,"bytes":turns[i]['bytes'].decode(),"salt":turns[i]['salt'].hex(),"path":dialogue_proof(turns,i)} for i in (1,2)],"approval_key_ids":["k1","k2"]}
    (out/'pec.json').write_bytes(canonical(pec)+b'\n'); (out/'dialogue-disclosure.json').write_bytes(canonical(disclosure)+b'\n')
    entries=[]
    for name in ('pec.json','dialogue-disclosure.json'):
        entries.append(f"{hashlib.sha256((out/name).read_bytes()).hexdigest()}  {name}")
    (out/'MANIFEST.sha256').write_bytes(('\n'.join(entries)+'\n').encode('ascii'))
    return root, digest(pec)

if __name__ == '__main__':
    root, pd=generate(); print(json.dumps({'pec_digest':pd,'dialogue_root':root,'status':'VALID'}, indent=2))
