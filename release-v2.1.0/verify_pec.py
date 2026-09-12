import json, pathlib
from pec_core import digest, verify_dialogue_window
from verify_demo import verify_demo

def verify_package(root='demo'):
    root=pathlib.Path(root); entries=verify_demo(root)
    pec=json.loads((root/'pec.json').read_text(encoding='utf-8'))
    disclosure=json.loads((root/'dialogue-disclosure.json').read_text(encoding='utf-8'))
    if disclosure['pec_digest'] != digest(pec): raise ValueError('DISCLOSURE_BINDING_MISMATCH')
    event=next(e for e in pec['events'] if e['event_id']==disclosure['event_id'])
    if event['commitment']['scheme'] != 'merkle-dialogue-v1': raise ValueError('COMMITMENT_SCHEME_MISMATCH')
    window=[{'index':x['index'],'bytes':x['bytes'].encode(),'salt':bytes.fromhex(x['salt']),'path':x['path']} for x in disclosure['opened_material']]
    verify_dialogue_window(event['commitment']['digest'], window)
    required=pec['governance']['required_pec_approval_key_ids']
    if sorted(disclosure['approval_key_ids']) != sorted(required): raise ValueError('DISCLOSURE_APPROVAL_MISSING')
    return {'manifest_entries':entries,'pec_digest':digest(pec),'granted_outcomes':['KEY_ASSENT','GOVERNANCE_ASSENT','COMMITTED_EVIDENCE_MATCH'],'non_claims':pec['claim_policy']['global_non_claims'],'status':'VALID'}

if __name__ == '__main__': print(json.dumps(verify_package(), indent=2))
