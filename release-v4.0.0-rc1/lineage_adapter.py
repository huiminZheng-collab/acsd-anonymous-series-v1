"""Filesystem and signature adapter for one exact ACSD lineage edge."""

import cose
from artifact_io import read_canonical
from canonical_json import canonical, digest, require
from key_identity import key_id_of
from key_material import load_public_key_bytes
from protocol_objects import (
    build_lineage_transition,
    lineage_authority_of,
    online_lineage_authority,
    recovery_authority_of,
)
from release_adapter import adapt_release


def _key_files(root, relative, authority, *, code):
    """Require an exact key-id-to-public-key directory for one authority."""
    location = root / relative
    expected_ids = [] if authority is None else authority["key_ids"]
    actual_names = (
        sorted(path.name for path in location.iterdir())
        if location.is_dir()
        else []
    )
    require(
        actual_names == [f"{key_id}.pub" for key_id in expected_ids],
        code,
    )
    for key_id in expected_ids:
        public_key = load_public_key_bytes((location / f"{key_id}.pub").read_bytes())
        require(key_id_of(public_key) == key_id, "PUBLIC_KEY_ID_MISMATCH")


def _authorization_paths(root, relative):
    location = root / relative
    if not location.exists():
        return []
    require(location.is_dir(), "LINEAGE_AUTHORIZATION_DIRECTORY_INVALID")
    entries = sorted(location.iterdir())
    require(
        all(path.is_file() and path.suffix == ".cose" for path in entries),
        "LINEAGE_AUTHORIZATION_FILE_SET_INVALID",
    )
    return entries


def _verify_authorization_quorum(
    root,
    *,
    transition,
    authority,
    authorization_directory,
    public_key_directory,
    unknown_key_code,
):
    authority_keys = set(authority["key_ids"])
    paths = _authorization_paths(root, authorization_directory)
    for path in paths:
        require(path.stem in authority_keys, unknown_key_code)
    valid = []
    payload = canonical(transition)
    for key_id in authority["key_ids"]:
        approval_path = root / authorization_directory / f"{key_id}.cose"
        if not approval_path.is_file():
            continue
        public_key_path = root / public_key_directory / f"{key_id}.pub"
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
    require(len(valid) >= authority["threshold"], "UNAUTHORIZED_SUCCESSOR")
    return valid


def load_lineage_structure(root, release, governance, pec):
    """Validate an optional parent-to-child edge, excluding signatures."""
    adapted = adapt_release(release)
    child_recovery = recovery_authority_of(release)
    _key_files(
        root,
        "recovery-public-keys",
        child_recovery,
        code="RECOVERY_PUBLIC_KEY_FILE_SET_MISMATCH",
    )
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
    parent_recovery = recovery_authority_of(parent_release)
    _key_files(
        root,
        "lineage/parent-recovery-public-keys",
        parent_recovery,
        code="PARENT_RECOVERY_PUBLIC_KEY_FILE_SET_MISMATCH",
    )
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
        "parent_recovery_authority": parent_recovery,
    }


def verify_lineage_authorization(root, lineage, valid_child_approvals):
    """Verify authority continuity for one exact parent-to-child edge."""
    if lineage is None:
        return {
            "status": "GENESIS",
            "method": "genesis",
            "required": 0,
            "valid": [],
            "authorization_directory": None,
        }
    old = lineage["parent_authority"]
    new = lineage["child_authority"]
    old_keys = set(old["key_ids"])
    ordinary_paths = _authorization_paths(root, "lineage/authorizations")
    recovery_paths = _authorization_paths(root, "lineage/recovery-authorizations")
    require(
        not (ordinary_paths and recovery_paths),
        "LINEAGE_AUTHORIZATION_METHOD_AMBIGUOUS",
    )
    if old == new:
        require(not ordinary_paths and not recovery_paths, "UNEXPECTED_LINEAGE_AUTHORIZATION")
        inherited = sorted(old_keys.intersection(valid_child_approvals))
        require(len(inherited) >= old["threshold"], "UNAUTHORIZED_SUCCESSOR")
        return {
            "status": "AUTHORIZED_CONTINUATION",
            "method": "continuity",
            "required": old["threshold"],
            "valid": inherited,
            "authorization_directory": None,
        }

    if recovery_paths:
        recovery = lineage["parent_recovery_authority"]
        require(recovery is not None, "RECOVERY_AUTHORITY_NOT_PRECOMMITTED")
        require(
            online_lineage_authority(old) != online_lineage_authority(new),
            "RECOVERY_REQUIRES_ONLINE_AUTHORITY_CHANGE",
        )
        valid = _verify_authorization_quorum(
            root,
            transition=lineage["transition"],
            authority=recovery,
            authorization_directory="lineage/recovery-authorizations",
            public_key_directory="lineage/parent-recovery-public-keys",
            unknown_key_code="RECOVERY_AUTHORIZATION_UNKNOWN_KEY",
        )
        return {
            "status": "RECOVERY_AUTHORIZED_TRANSITION",
            "method": "recovery",
            "required": recovery["threshold"],
            "valid": valid,
            "authorization_directory": "lineage/recovery-authorizations",
        }

    valid = _verify_authorization_quorum(
        root,
        transition=lineage["transition"],
        authority=old,
        authorization_directory="lineage/authorizations",
        public_key_directory="lineage/parent-public-keys",
        unknown_key_code="LINEAGE_AUTHORIZATION_UNKNOWN_KEY",
    )
    return {
        "status": "AUTHORIZED_TRANSITION",
        "method": "predecessor",
        "required": old["threshold"],
        "valid": valid,
        "authorization_directory": "lineage/authorizations",
    }
