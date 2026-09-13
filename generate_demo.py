import hashlib
import argparse
import json
import pathlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import cose
import approval_set
import identity_disclosure
from acsd import build_approval_target
from canonical_json import canonical, digest
from event_disclosure import DEFAULT_POLICY, key_id_of
from package_manifest import write_manifest
from pec_core import (
    dialogue_proof,
    dialogue_root,
    validate_pec,
)
from release_adapter import adapt_release

# Deterministic demo identity: a stable WorkID keeps the generated fixture
# reproducible byte-for-byte (the real CLI will randomize per invocation).
WORK_ID = "urn:uuid:1f6f0a1e-2b3c-4d5e-8f90-0a1b2c3d4e5f"
# Public test vectors only: deterministic demo keys make the fixture exactly
# reproducible.  They are intentionally not suitable for real releases.
DEMO_KEYS = [
    Ed25519PrivateKey.from_private_bytes(bytes([0x11]) * 32),
    Ed25519PrivateKey.from_private_bytes(bytes([0x22]) * 32),
]
AUTHOR_1, AUTHOR_2 = [key_id_of(key.public_key()) for key in DEMO_KEYS]

# Exact manuscript bytes. Its SHA-256 is real and is bound into the release,
# the governance statement, and the PEC. No authorship / originality / time
# claim is implied.
MANUSCRIPT = (
    "ACSD demonstration manuscript (v1).\n"
    "This exact content is byte-hashed; its SHA-256 digest is bound into the\n"
    "release object, the authorship governance statement, and the provenance\n"
    "evidence capsule. No authorship, originality, or time claim is implied.\n"
).encode("utf-8")


def build_release(content_sha256: str) -> dict:
    return {
        "schema": "acsd-v1.6.0-paper-release/v1",
        "work_id": WORK_ID,
        "slot": {"line": "main", "version": 1, "work_id": WORK_ID},
        "content": {"path": "manuscript.txt", "sha256": content_sha256},
        "authors": [
            {
                "slot": 1,
                "key_id": AUTHOR_1,
                "role": "co-first",
                "corresponding": False,
                "contributions": ["conceptualization", "writing-original-draft"],
                "issuer": f"urn:acsd:pseudonym:{AUTHOR_1[:12]}",
                "kid_hex": AUTHOR_1[:16],
                "public_key_path": f"public-keys/{AUTHOR_1}.pub",
            },
            {
                "slot": 2,
                "key_id": AUTHOR_2,
                "role": "co-first",
                "corresponding": True,
                "contributions": ["methodology", "writing-review-editing"],
                "issuer": f"urn:acsd:pseudonym:{AUTHOR_2[:12]}",
                "kid_hex": AUTHOR_2[:16],
                "public_key_path": f"public-keys/{AUTHOR_2}.pub",
            },
        ],
        "citation_witnesses": [],
        "reference_work_ids": [],
        "ai_use": {"used": False, "purposes": [], "tools": [], "human_review_key_ids": []},
        "parent_release_id": None,
        "issued_at": 0,  # no time claim in the demo
        "standalone_semantics": (
            "Every listed author key endorses this exact release payload; "
            "series membership is optional."
        ),
    }


def build_governance(content_sha256: str) -> dict:
    return {
        "schema": "acsd-v1.6.0-authorship-governance/v1",
        "work_id": WORK_ID,
        "manuscript_sha256": content_sha256,
        "byline": [
            {"key_id": AUTHOR_1, "slot": 1, "role": "co-first"},
            {"key_id": AUTHOR_2, "slot": 2, "role": "co-first"},
        ],
        "corresponding_author": {"key_id": AUTHOR_2},
        "ai_use_declaration": {
            "used": False,
            "purposes": [],
            "tools": [],
            "human_review_key_ids": [],
        },
    }


def generate(out="demo"):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)

    content_sha256 = hashlib.sha256(MANUSCRIPT).hexdigest()
    release = build_release(content_sha256)
    adapted = adapt_release(release)  # the projection the PEC binds
    governance = build_governance(content_sha256)
    gov_digest = digest(governance)
    ai_digest = digest(governance["ai_use_declaration"])

    # Research-process evidence: a salted Merkle dialogue over four turns.
    turns = [
        {"bytes": x.encode(), "salt": bytes([i]) * 32}
        for i, x in enumerate(["initial idea", "formalization", "counterexample", "revision"])
    ]
    root = dialogue_root(turns)

    pec = {
        "schema": "acsd-pec/v0.3",
        "pec_id": "pec-demo-01",
        "subject": {
            "work_id": WORK_ID,
            "release_digest": adapted["digest"],
            "version": "v1",
            "line": "main",
            "predecessor_pec_digest": None,
            "series_package_digest": None,
        },
        "governance": {
            "statement_digest": gov_digest,
            "manuscript_sha256": content_sha256,
            "required_pec_approval_key_ids": sorted(adapted["author_key_ids"]),
            "ai_use_declaration_digest": ai_digest,
        },
        "events": [
            {
                "schema": "acsd-pec-event/v0.1",
                "sequence": 0,
                "event_id": "dialogue-01",
                "previous_event_digest": None,
                "kind": "dialogue_snapshot",
                "commitment": {
                    "scheme": "merkle-dialogue-v1",
                    "digest": root,
                    "disclosure_class": "revealable",
                },
            }
        ],
        "disclosure_policy": DEFAULT_POLICY,
        "claim_policy": {
            "permitted_outcomes": [
                "KEY_ASSENT", "GOVERNANCE_ASSENT", "COMMITTED_EVIDENCE_MATCH",
                "SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION",
                "APPROVAL_SET_EXISTED_NOT_AFTER",
            ],
            "required_capabilities": {
                "APPROVAL_SET_EXISTED_NOT_AFTER": [
                    "rfc3161-exact-approval-set-imprint"
                ]
            },
            "global_non_claims": [
                "natural_person_authorship",
                "contribution_truth",
                "originality_truth",
                "legal_nonrepudiation",
                "peer_review",
            ],
        },
        "issuer_key_id": AUTHOR_1,
    }
    validate_pec(pec, [AUTHOR_1, AUTHOR_2], adapted, {"digest": gov_digest})
    approval_target = build_approval_target(release, governance, pec)

    disclosure = {
        "schema": "acsd-event-disclosure/v1",
        "pec_digest": digest(pec),
        "event_id": "dialogue-01",
        "event_sequence": 0,
        "kind": "dialogue_snapshot",
        "disclosure_mode": "dialogue_window",
        "opened_material": [
            {
                "index": i,
                "bytes": turns[i]["bytes"].decode(),
                "salt": turns[i]["salt"].hex(),
                "path": dialogue_proof(turns, i),
            }
            for i in (1, 2)
        ],
    }
    identity = identity_disclosure.build(
        release, 1, "Demo Author One",
        persistent_identifier="https://example.invalid/acsd/demo-author-one",
        publication_ref=None,
    )

    (out / "manuscript.txt").write_bytes(MANUSCRIPT)
    (out / "release.json").write_bytes(canonical(release) + b"\n")
    (out / "governance.json").write_bytes(canonical(governance) + b"\n")
    (out / "pec.json").write_bytes(canonical(pec) + b"\n")
    (out / "dialogue-disclosure.json").write_bytes(canonical(disclosure) + b"\n")
    (out / "public-keys").mkdir(exist_ok=True)
    (out / "release-approvals").mkdir(exist_ok=True)
    (out / "disclosure-approvals").mkdir(exist_ok=True)
    (out / "identity").mkdir(exist_ok=True)
    (out / "approval").mkdir(exist_ok=True)
    (out / "approval-target.json").write_bytes(canonical(approval_target) + b"\n")
    for key in DEMO_KEYS:
        key_id = key_id_of(key.public_key())
        (out / "public-keys" / f"{key_id}.pub").write_bytes(
            key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        (out / "disclosure-approvals" / f"{key_id}.cose").write_bytes(
            cose.cose_sign1(canonical(disclosure), key)
        )
        (out / "release-approvals" / f"{key_id}.cose").write_bytes(
            cose.cose_sign1(canonical(approval_target), key)
        )
    (out / "identity" / "slot-1.json").write_bytes(canonical(identity) + b"\n")
    (out / "identity" / "slot-1.cose").write_bytes(
        cose.cose_sign1(canonical(identity), DEMO_KEYS[0])
    )
    approval_set_obj = approval_set.build_from_signatures(
        approval_target,
        {
            key_id: (out / "release-approvals" / f"{key_id}.cose").read_bytes()
            for key_id in (AUTHOR_1, AUTHOR_2)
        },
        {},
    )
    (out / "approval" / "approval-set.json").write_bytes(
        canonical(approval_set_obj) + b"\n"
    )
    write_manifest(out)
    return root, digest(pec)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("out", nargs="?", default="demo")
    args = parser.parse_args()
    root, pd = generate(args.out)
    print(json.dumps({"pec_digest": pd, "dialogue_root": root, "status": "VALID"}, indent=2))
