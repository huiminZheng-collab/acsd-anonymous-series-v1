"""Filesystem and signature adapter for one exact ACSD lineage edge."""

import cose
from artifact_io import read_canonical
from canonical_json import canonical, digest, require
from key_identity import key_id_of
from key_material import load_public_key_bytes
from protocol_objects import build_lineage_transition, lineage_authority_of
from release_adapter import adapt_release


def load_lineage_structure(root, release, governance, pec):
    """Validate an optional parent-to-child edge, excluding signatures."""
    adapted = adapt_release(release)
    parent_id = release.get("parent_release_id")
    predecessor_pec = pec["subject"].get("predecessor_pec_digest")
    if parent_id is None:
        require(adapted["version"] == 1, "LINEAGE_GENESIS_VERSION")
        require(predecessor_pec is None, "PREDECESSOR_MISMATCH")
        return None

    lineage_root = root / "lineage"
    parent_release = read_canonical(lineage_root / "parent-release.json")
    parent_pec = read_canonical(lineage_root / "parent-pec.json")
    transition = read_canonical(lineage_root / "transition.json")
    parent = adapt_release(parent_release)
    require(
        parent_id == "urn:sha256:" + parent["digest"],
        "PARENT_RELEASE_MISMATCH",
    )
    require(parent["work_id"] == adapted["work_id"], "LINEAGE_WORK_ID_MISMATCH")
    if parent["line"] == adapted["line"]:
        require(
            adapted["version"] == parent["version"] + 1,
            "LINEAGE_VERSION_NOT_CONSECUTIVE",
        )
    else:
        require(adapted["version"] == 1, "LINEAGE_BRANCH_VERSION")
    require(predecessor_pec == digest(parent_pec), "PREDECESSOR_MISMATCH")
    expected = build_lineage_transition(
        parent_release,
        parent_pec,
        release,
        governance,
        pec,
    )
    require(transition == expected, "LINEAGE_TRANSITION_MISMATCH")
    return {
        "parent_release": parent_release,
        "parent_pec": parent_pec,
        "transition": transition,
        "parent_authority": lineage_authority_of(parent_release),
        "child_authority": lineage_authority_of(release),
    }


def verify_lineage_authorization(root, lineage, valid_child_approvals):
    """Verify authority continuity for one exact parent-to-child edge."""
    if lineage is None:
        return {"status": "GENESIS", "required": 0, "valid": []}
    old = lineage["parent_authority"]
    new = lineage["child_authority"]
    old_keys = set(old["key_ids"])
    if old == new:
        inherited = sorted(old_keys.intersection(valid_child_approvals))
        require(len(inherited) >= old["threshold"], "UNAUTHORIZED_SUCCESSOR")
        return {
            "status": "AUTHORIZED_CONTINUATION",
            "required": old["threshold"],
            "valid": inherited,
        }

    authorization_dir = root / "lineage/authorizations"
    if authorization_dir.exists():
        for path in authorization_dir.glob("*.cose"):
            require(path.stem in old_keys, "LINEAGE_AUTHORIZATION_UNKNOWN_KEY")
    valid = []
    payload = canonical(lineage["transition"])
    for key_id in old["key_ids"]:
        approval_path = authorization_dir / f"{key_id}.cose"
        if not approval_path.is_file():
            continue
        public_key_path = root / f"lineage/parent-public-keys/{key_id}.pub"
        try:
            public_key = load_public_key_bytes(public_key_path.read_bytes())
            require(key_id_of(public_key) == key_id, "PUBLIC_KEY_ID_MISMATCH")
            cose.cose_verify(
                approval_path.read_bytes(),
                public_key,
                expected_payload=payload,
            )
        except FileNotFoundError:
            raise ValueError("PARENT_PUBLIC_KEY_MISSING")
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError("LINEAGE_AUTHORIZATION_SIGNATURE_INVALID") from exc
        valid.append(key_id)
    require(len(valid) >= old["threshold"], "UNAUTHORIZED_SUCCESSOR")
    return {
        "status": "AUTHORIZED_TRANSITION",
        "required": old["threshold"],
        "valid": valid,
    }
