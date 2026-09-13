"""Claim-free byte-level certificate for one authorized ACSD lineage edge."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib

from cryptography.hazmat.primitives import serialization

import approval_set
import cose
from acsd import (
    check_approval_target,
    check_bindings,
    check_release_key_paths,
    load_bound_public_key,
    load_lineage_structure,
    verify_lineage_authorization,
)
from canonical_json import canonical, digest, require
from key_identity import key_id_of
from release_adapter import adapt_release


SCHEMA = "acsd-lineage-verification-certificate/v1"


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_canonical(root: pathlib.Path, relative: str):
    raw = (root / relative).read_bytes()
    payload = raw[:-1] if raw.endswith(b"\n") else raw
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("LINEAGE_CERT_JSON_INVALID:" + relative) from exc
    require(canonical(value) == payload, "LINEAGE_CERT_JSON_NONCANONICAL:" + relative)
    return value, raw, payload


def _authority(value):
    return {"key_ids": value["key_ids"], "threshold": value["threshold"]}


def build(root: pathlib.Path) -> dict:
    root = pathlib.Path(root)
    release, release_raw, _ = _read_canonical(root, "release/release.json")
    governance, governance_raw, _ = _read_canonical(
        root, "governance/statement.json"
    )
    pec, pec_raw, _ = _read_canonical(root, "pec/pec.json")
    target, target_raw, target_payload = _read_canonical(root, "approval/target.json")
    set_object, set_raw, _ = _read_canonical(root, "approval/approval-set.json")
    parent_release, parent_release_raw, _ = _read_canonical(
        root, "lineage/parent-release.json"
    )
    parent_pec, parent_pec_raw, _ = _read_canonical(
        root, "lineage/parent-pec.json"
    )
    transition, transition_raw, transition_payload = _read_canonical(
        root, "lineage/transition.json"
    )

    adapted = adapt_release(release)
    check_release_key_paths(release)
    check_bindings(pec, adapted, governance, release)
    lineage = load_lineage_structure(root, release, governance, pec)
    require(lineage is not None, "LINEAGE_CERT_GENESIS")
    check_approval_target(
        target, release, governance, pec, adapted, transition
    )
    require(
        "AUTHORIZED_SUCCESSOR" in pec["claim_policy"]["permitted_outcomes"],
        "LINEAGE_CERT_POLICY",
    )

    inputs = [
        {"role": "parent-release", "path": "lineage/parent-release.json",
         "sha256": _sha256(parent_release_raw)},
        {"role": "parent-pec", "path": "lineage/parent-pec.json",
         "sha256": _sha256(parent_pec_raw)},
        {"role": "child-release", "path": "release/release.json",
         "sha256": _sha256(release_raw)},
        {"role": "child-governance", "path": "governance/statement.json",
         "sha256": _sha256(governance_raw)},
        {"role": "child-pec", "path": "pec/pec.json", "sha256": _sha256(pec_raw)},
        {"role": "child-approval-target", "path": "approval/target.json",
         "sha256": _sha256(target_raw)},
        {"role": "lineage-transition", "path": "lineage/transition.json",
         "sha256": _sha256(transition_raw)},
        {"role": "approval-set", "path": "approval/approval-set.json",
         "sha256": _sha256(set_raw)},
    ]
    facts = []
    child_signatures = {}
    child_keys = sorted(adapted["author_key_ids"])
    for key_id in child_keys:
        public_relative = f"public-keys/{key_id}.pub"
        cose_relative = f"approvals/{key_id}.cose"
        public_raw = (root / public_relative).read_bytes()
        cose_raw = (root / cose_relative).read_bytes()
        public_key = serialization.load_pem_public_key(public_raw)
        require(key_id_of(public_key) == key_id, "PUBLIC_KEY_ID_MISMATCH")
        cose.cose_verify(cose_raw, public_key, expected_payload=target_payload)
        child_signatures[key_id] = cose_raw
        inputs.extend([
            {"role": "child-public-key", "path": public_relative,
             "sha256": _sha256(public_raw)},
            {"role": "child-approval-cose", "path": cose_relative,
             "sha256": _sha256(cose_raw)},
        ])
        facts.append({
            "purpose": "child-approval",
            "key_id": key_id,
            "payload_digest": digest(target),
            "cose_digest": _sha256(cose_raw),
            "public_key_digest": _sha256(public_raw),
        })

    lineage_result = verify_lineage_authorization(root, lineage, set(child_keys))
    require(
        lineage_result["status"] in {
            "AUTHORIZED_CONTINUATION", "AUTHORIZED_TRANSITION"
        },
        "LINEAGE_CERT_UNAUTHORIZED",
    )
    separate = lineage["parent_authority"] != lineage["child_authority"]
    require(
        separate == (lineage_result["status"] == "AUTHORIZED_TRANSITION"),
        "LINEAGE_CERT_MODE",
    )
    predecessor_signatures = {}
    if separate:
        for key_id in lineage_result["valid"]:
            public_relative = f"lineage/parent-public-keys/{key_id}.pub"
            cose_relative = f"lineage/authorizations/{key_id}.cose"
            public_raw = (root / public_relative).read_bytes()
            cose_raw = (root / cose_relative).read_bytes()
            public_key = serialization.load_pem_public_key(public_raw)
            require(key_id_of(public_key) == key_id, "PUBLIC_KEY_ID_MISMATCH")
            cose.cose_verify(cose_raw, public_key, expected_payload=transition_payload)
            predecessor_signatures[key_id] = cose_raw
            inputs.extend([
                {"role": "parent-public-key", "path": public_relative,
                 "sha256": _sha256(public_raw)},
                {"role": "predecessor-authorization-cose", "path": cose_relative,
                 "sha256": _sha256(cose_raw)},
            ])
            facts.append({
                "purpose": "predecessor-authorization",
                "key_id": key_id,
                "payload_digest": digest(transition),
                "cose_digest": _sha256(cose_raw),
                "public_key_digest": _sha256(public_raw),
            })

    approval_set.verify_from_signatures(
        set_object, target, child_signatures, predecessor_signatures
    )
    inputs.sort(key=lambda item: (item["path"], item["role"]))
    facts.sort(key=lambda item: (item["purpose"], item["key_id"]))
    parent = transition["parent"]
    child = transition["child"]
    return {
        "schema": SCHEMA,
        "inputs": inputs,
        "policy": {
            "pec_digest": digest(pec),
            "permitted_outcomes": pec["claim_policy"]["permitted_outcomes"],
        },
        "lineage_edge": {
            "work_id_digest": _sha256(transition["work_id"].encode("utf-8")),
            "transition_digest": digest(transition),
            "transition_input_digest": _sha256(transition_raw),
            "transition_kind": transition["kind"],
            "authorization_mode": "transition" if separate else "continuity",
            "parent": {
                "release_digest": parent["release_digest"],
                "pec_digest": parent["pec_digest"],
                "line_digest": _sha256(parent["line"].encode("utf-8")),
                "version": parent["version"],
                "authority": _authority(parent["authority"]),
                "release_input_digest": _sha256(parent_release_raw),
                "pec_input_digest": _sha256(parent_pec_raw),
            },
            "child": {
                "release_digest": child["release_digest"],
                "pec_digest": child["pec_digest"],
                "line_digest": _sha256(child["line"].encode("utf-8")),
                "version": child["version"],
                "authority": _authority(child["authority"]),
                "approval_target_digest": digest(target),
                "bound_transition_digest": target["lineage_transition_digest"],
                "release_input_digest": _sha256(release_raw),
                "governance_input_digest": _sha256(governance_raw),
                "pec_input_digest": _sha256(pec_raw),
                "approval_target_input_digest": _sha256(target_raw),
            },
        },
        "approval_set": {
            "approval_target_digest": set_object["approval_target_digest"],
            "author_approvals": set_object["author_approvals"],
            "lineage_authorizations": set_object["lineage_authorizations"],
            "input_digest": _sha256(set_raw),
        },
        "signature_facts": facts,
    }


def encoded(root: pathlib.Path) -> bytes:
    return canonical(build(root))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle")
    parser.add_argument("--output")
    args = parser.parse_args()
    output = encoded(pathlib.Path(args.bundle)) + b"\n"
    if args.output:
        pathlib.Path(args.output).write_bytes(output)
    else:
        import sys
        sys.stdout.buffer.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
