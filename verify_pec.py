import hashlib
import json
import pathlib
import sys

from cryptography.hazmat.primitives import serialization

import cose
import claim_derivation as claim_core
from acsd import check_approval_target, check_bindings
from canonical_json import canonical, digest
from event_disclosure import verify_event_disclosure
from release_adapter import adapt_release
from verify_demo import verify_demo

def verify_package(root='demo'):
    root=pathlib.Path(root); entries=verify_demo(root)
    release=json.loads((root/'release.json').read_text(encoding='utf-8'))
    governance=json.loads((root/'governance.json').read_text(encoding='utf-8'))
    pec=json.loads((root/'pec.json').read_text(encoding='utf-8'))
    target=json.loads((root/'approval-target.json').read_text(encoding='utf-8'))
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
    adapted = adapt_release(release)
    check_bindings(pec, adapted, governance, release)
    check_approval_target(target, release, governance, pec, adapted)
    for key_id in required:
        cose.cose_verify(
            (root / f'release-approvals/{key_id}.cose').read_bytes(),
            public_keys[key_id],
            expected_payload=canonical(target),
        )
    approval_evidence = claim_core.AppraisedEvidence(
        claim_core.EvidenceKind.UNANIMOUS_APPROVAL,
        claim_core.ApprovalTargetSubject(digest(target)),
        digest({
            "target_digest": digest(target),
            "approval_certificate_digests": [
                {
                    "key_id": key_id,
                    "sha256": hashlib.sha256(
                        (root / f"release-approvals/{key_id}.cose").read_bytes()
                    ).hexdigest(),
                }
                for key_id in sorted(required)
            ],
        }),
    )
    approval_derivations = claim_core.derive(
        [approval_evidence],
        claim_core.permitted_claims(pec["claim_policy"]["permitted_outcomes"]),
    )
    disclosure_result = verify_event_disclosure(
        disclosure, pec, public_keys, signatures,
        accepted_pec_digest=digest(pec),
    )
    granted_outcomes = list(claim_core.wire_outcomes(approval_derivations))
    granted_outcomes.append(disclosure_result["outcome"])
    return {
        'manifest_entries': entries,
        'pec_digest': digest(pec),
        'granted_outcomes': granted_outcomes,
        'event_result': disclosure_result,
        'non_claims': pec['claim_policy']['global_non_claims'],
        'status': 'VALID',
    }

if __name__ == '__main__':
    print(json.dumps(verify_package(sys.argv[1] if len(sys.argv) > 1 else 'demo'), indent=2))
