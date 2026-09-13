import json, pathlib, sys

from cryptography.hazmat.primitives import serialization

from event_disclosure import verify_event_disclosure
from pec_core import digest
from verify_demo import verify_demo

def verify_package(root='demo'):
    root=pathlib.Path(root); entries=verify_demo(root)
    pec=json.loads((root/'pec.json').read_text(encoding='utf-8'))
    disclosure=json.loads((root/'dialogue-disclosure.json').read_text(encoding='utf-8'))
    required=pec['governance']['required_pec_approval_key_ids']
    public_keys = {
        key_id: serialization.load_pem_public_key(
            (root / f'public-keys/{key_id}.pub').read_bytes()
        )
        for key_id in required
    }
    signatures = {
        key_id: (root / f'disclosure-approvals/{key_id}.cose').read_bytes()
        for key_id in required
    }
    verify_event_disclosure(disclosure, pec, public_keys, signatures)
    return {'manifest_entries':entries,'pec_digest':digest(pec),'granted_outcomes':['KEY_ASSENT','GOVERNANCE_ASSENT','COMMITTED_EVIDENCE_MATCH'],'non_claims':pec['claim_policy']['global_non_claims'],'status':'VALID'}

if __name__ == '__main__':
    print(json.dumps(verify_package(sys.argv[1] if len(sys.argv) > 1 else 'demo'), indent=2))
