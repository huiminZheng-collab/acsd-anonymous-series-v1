#!/usr/bin/env python3
"""Compare ACSD lineage decisions with a minimal detached-signature baseline.

This is a controlled mechanism comparison, not a GnuPG, OpenTimestamps,
archive, deployment, or usability benchmark.  Both paths use Ed25519 so the
smallest discriminating variable is explicit predecessor authorization.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


DESIGN = pathlib.Path(__file__).resolve().parent
ROOT = DESIGN.parent
ACSD = ROOT / "acsd.py"
SCHEMA = "acsd-adjacent-baseline-evaluation/v1"


def _invoke(*args: object, expected: int = 0) -> dict:
    result = subprocess.run(
        [sys.executable, str(ACSD), *map(str, args), "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    try:
        payload = json.loads(result.stdout)
    except ValueError as exc:
        raise AssertionError(result.stderr or result.stdout) from exc
    if result.returncode != expected:
        raise AssertionError(
            f"command {args!r} returned {result.returncode}, expected "
            f"{expected}: {result.stderr or result.stdout}"
        )
    return payload


def _keygen(root: pathlib.Path, name: str) -> dict:
    return _invoke(
        "keygen", "--name", name, "--out-dir", root / "private-keys"
    )["data"]


def _team_file(root: pathlib.Path, name: str, key: dict) -> pathlib.Path:
    team = {
        "schema": "acsd-team/v1",
        "authors": [{
            "key_id": key["key_id"],
            "public_key": key["public_key"],
            "role": "sole",
            "corresponding": True,
        }],
    }
    path = root / name
    path.write_text(json.dumps(team), encoding="utf-8")
    return path


def _verify_detached(
    public_key: Ed25519PublicKey, content: bytes, signature: bytes
) -> bool:
    try:
        public_key.verify(signature, content)
        return True
    except InvalidSignature:
        return False


def _manual_transition_payload(
    parent: bytes,
    child: bytes,
    child_public_key: Ed25519PublicKey,
) -> bytes:
    """A small unambiguous baseline statement, not an ACSD object."""
    child_key = child_public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return (
        b"manual-predecessor-transition-v1\x00"
        + hashlib.sha256(parent).digest()
        + hashlib.sha256(child).digest()
        + child_key
    )


def _manual_transition_authorized(
    predecessor_public_key: Ed25519PublicKey,
    parent: bytes,
    child_public_key: Ed25519PublicKey,
    child: bytes,
    child_signature: bytes,
    transition_signature: bytes,
) -> bool:
    transition = _manual_transition_payload(parent, child, child_public_key)
    return (
        _verify_detached(child_public_key, child, child_signature)
        and _verify_detached(
            predecessor_public_key, transition, transition_signature
        )
    )


def _write_detached_case(
    root: pathlib.Path,
    name: str,
    content: bytes,
    private_key: Ed25519PrivateKey,
) -> tuple[bytes, Ed25519PublicKey]:
    public_key = private_key.public_key()
    signature = private_key.sign(content)
    case = root / name
    case.mkdir(parents=True)
    (case / "paper.bin").write_bytes(content)
    (case / "paper.sig").write_bytes(signature)
    (case / "signer.pub").write_bytes(public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ))
    return signature, public_key


def _file_count(root: pathlib.Path) -> int:
    return sum(1 for path in root.rglob("*") if path.is_file())


def _bare_signature_cases(work: pathlib.Path) -> dict:
    original = Ed25519PrivateKey.generate()
    rotated = Ed25519PrivateKey.generate()
    attacker = Ed25519PrivateKey.generate()
    parent = b"Anonymous parent manuscript.\n"
    same_key_child = b"Legitimate same-key second version.\n"
    rotated_child = b"Legitimate rotated-key second version.\n"
    attacker_child = b"Attacker-controlled apparent second version.\n"

    bare = work / "bare-detached-signatures"
    parent_signature, original_public = _write_detached_case(
        bare, "parent", parent, original
    )
    same_signature, _ = _write_detached_case(
        bare, "same-key-child", same_key_child, original
    )
    rotated_signature, rotated_public = _write_detached_case(
        bare, "rotated-key-child", rotated_child, rotated
    )
    attacker_signature, attacker_public = _write_detached_case(
        bare, "attacker-child", attacker_child, attacker
    )
    transition = _manual_transition_payload(
        parent, rotated_child, rotated_public
    )
    transition_signature = original.sign(transition)
    (bare / "rotated-key-child" / "transition.bin").write_bytes(transition)
    (bare / "rotated-key-child" / "transition.sig").write_bytes(
        transition_signature
    )

    return {
        "exact_bytes": {
            "original_content": (
                "VALID_SIGNATURE" if _verify_detached(
                    original_public, parent, parent_signature
                ) else "INVALID_SIGNATURE"
            ),
            "mutated_content": (
                "VALID_SIGNATURE" if _verify_detached(
                    original_public, parent + b"mutation", parent_signature
                ) else "INVALID_SIGNATURE"
            ),
        },
        "same_key_successor": {
            "self_declared_child_key_policy": (
                "VALID_SIGNATURE" if _verify_detached(
                    original_public, same_key_child, same_signature
                ) else "INVALID_SIGNATURE"
            ),
            "predecessor_key_pin_policy": (
                "VALID_SIGNATURE" if _verify_detached(
                    original_public, same_key_child, same_signature
                ) else "INVALID_SIGNATURE"
            ),
        },
        "authorized_key_rotation": {
            "self_declared_child_key_policy": (
                "VALID_SIGNATURE" if _verify_detached(
                    rotated_public, rotated_child, rotated_signature
                ) else "INVALID_SIGNATURE"
            ),
            "predecessor_key_pin_policy": (
                "VALID_SIGNATURE" if _verify_detached(
                    original_public, rotated_child, rotated_signature
                ) else "INVALID_SIGNATURE"
            ),
            "manual_predecessor_transition_policy": (
                "AUTHORIZED_TRANSITION" if _manual_transition_authorized(
                    original_public,
                    parent,
                    rotated_public,
                    rotated_child,
                    rotated_signature,
                    transition_signature,
                ) else "UNAUTHORIZED_SUCCESSOR"
            ),
        },
        "fresh_key_capture": {
            "self_declared_child_key_policy": (
                "VALID_SIGNATURE" if _verify_detached(
                    attacker_public, attacker_child, attacker_signature
                ) else "INVALID_SIGNATURE"
            ),
            "predecessor_key_pin_policy": (
                "VALID_SIGNATURE" if _verify_detached(
                    original_public, attacker_child, attacker_signature
                ) else "INVALID_SIGNATURE"
            ),
            "manual_predecessor_transition_policy": (
                "AUTHORIZED_TRANSITION" if _manual_transition_authorized(
                    original_public,
                    parent,
                    attacker_public,
                    attacker_child,
                    attacker_signature,
                    transition_signature,
                ) else "UNAUTHORIZED_SUCCESSOR"
            ),
        },
        "artifact_counts": {
            "files_per_self_contained_signed_object": 3,
            "manual_transition_additional_files": 2,
            "total_files_for_four_objects": _file_count(bare),
        },
    }


def _acsd_cases(work: pathlib.Path) -> dict:
    original = _keygen(work, "original")
    rotated = _keygen(work, "rotated")
    attacker = _keygen(work, "attacker")

    parent_paper = work / "parent.txt"
    parent_paper.write_text("Anonymous parent manuscript.\n", encoding="utf-8")
    parent = work / "acsd-parent"
    _invoke(
        "release", parent_paper,
        "--key", original["private_key"], "--out", parent,
    )
    parent_result = _invoke("verify", parent)

    tampered = work / "acsd-parent-tampered"
    shutil.copytree(parent, tampered)
    content_path = next((tampered / "paper").iterdir())
    content_path.write_bytes(content_path.read_bytes() + b"mutation")
    tampered_result = _invoke("verify", tampered, expected=1)

    same_paper = work / "same-key-child.txt"
    same_paper.write_text(
        "Legitimate same-key second version.\n", encoding="utf-8"
    )
    same_child = work / "acsd-same-key-child"
    _invoke(
        "revise", parent, same_paper,
        "--key", original["private_key"], "--out", same_child,
    )
    same_result = _invoke("verify", same_child)["data"]

    rotated_paper = work / "rotated-key-child.txt"
    rotated_paper.write_text(
        "Legitimate rotated-key second version.\n", encoding="utf-8"
    )
    rotated_child = work / "acsd-rotated-key-child"
    _invoke(
        "revise", parent, rotated_paper,
        "--key", rotated["private_key"],
        "--parent-key", original["private_key"],
        "--out", rotated_child,
    )
    rotated_result = _invoke("verify", rotated_child)["data"]

    attacker_paper = work / "attacker-child.txt"
    attacker_paper.write_text(
        "Attacker-controlled apparent second version.\n", encoding="utf-8"
    )
    attacker_child = work / "acsd-attacker-child"
    attacker_team = _team_file(work, "attacker-team.json", attacker)
    _invoke(
        "init", attacker_paper, "--team", attacker_team,
        "--parent", parent, "--out", attacker_child,
    )
    _invoke(
        "approve", attacker_child, "--key", attacker["private_key"]
    )
    attack_result = _invoke("verify", attacker_child, expected=1)
    attack_finalize = _invoke("finalize", attacker_child, expected=5)

    return {
        "exact_bytes": {
            "original_content": parent_result["message"],
            "mutated_content": tampered_result["data"]["error_code"].split(
                ":", 1
            )[0],
        },
        "same_key_successor": same_result["lineage_status"],
        "authorized_key_rotation": rotated_result["lineage_status"],
        "fresh_key_capture": {
            "verification": attack_result["data"]["lineage_status"],
            "finalization": attack_finalize["message"],
        },
        "artifact_counts": {
            "parent_release_files": _file_count(parent),
            "same_key_child_files": _file_count(same_child),
            "rotated_key_child_files": _file_count(rotated_child),
            "unfinalized_attacker_child_files": _file_count(attacker_child),
        },
    }


def run_experiment() -> dict:
    with tempfile.TemporaryDirectory() as temporary:
        work = pathlib.Path(temporary)
        report = {
            "schema": SCHEMA,
            "evidence_classification": "empirical-controlled-mechanism-comparison",
            "smallest_discriminating_object": (
                "one parent plus same-key, authorized-rotation, and "
                "fresh-attacker-key n+1 candidates"
            ),
            "baseline": {
                "name": "minimal-detached-ed25519",
                "same_signature_primitive": True,
                "policies": [
                    "verify against the child-declared public key",
                    "pin the predecessor public key",
                    "require a predecessor-signed exact transition",
                ],
            },
            "bare_signature": _bare_signature_cases(work),
            "acsd": _acsd_cases(work),
            "observations": [
                "both mechanisms reject mutation of signed exact bytes",
                "a child-declared-key policy accepts both legitimate rotation and fresh-key capture at the signature layer",
                "a predecessor-key pin rejects both legitimate rotation and fresh-key capture",
                "a manual exact predecessor-signed transition and ACSD both distinguish the authorized rotation from transition replay onto the attacker child",
                "ACSD packages this authorization with canonical objects, threshold governance, approval-set closure, and typed claims rather than inventing a new signature primitive",
            ],
            "non_claims": [
                "not a GnuPG usability or performance benchmark",
                "not an OpenTimestamps, RFC3161-provider, Software Heritage, or Zenodo comparison run",
                "not a user study or production deployment",
                "not a proof that every possible detached-signature composition has this tradeoff",
            ],
        }
        expected = {
            "bare_exact_original": "VALID_SIGNATURE",
            "bare_exact_mutated": "INVALID_SIGNATURE",
            "bare_same_self": "VALID_SIGNATURE",
            "bare_same_pin": "VALID_SIGNATURE",
            "bare_rotation_self": "VALID_SIGNATURE",
            "bare_rotation_pin": "INVALID_SIGNATURE",
            "bare_rotation_transition": "AUTHORIZED_TRANSITION",
            "bare_attack_self": "VALID_SIGNATURE",
            "bare_attack_pin": "INVALID_SIGNATURE",
            "bare_attack_transition": "UNAUTHORIZED_SUCCESSOR",
            "acsd_parent": "VALID",
            "acsd_mutated": "MANIFEST_HASH_MISMATCH",
            "acsd_same": "AUTHORIZED_CONTINUATION",
            "acsd_rotation": "AUTHORIZED_TRANSITION",
            "acsd_attack": "UNAUTHORIZED_SUCCESSOR",
            "acsd_attack_finalize": "LINEAGE_AUTHORIZATION_INCOMPLETE",
        }
        actual = {
            "bare_exact_original": report["bare_signature"]["exact_bytes"]["original_content"],
            "bare_exact_mutated": report["bare_signature"]["exact_bytes"]["mutated_content"],
            "bare_same_self": report["bare_signature"]["same_key_successor"]["self_declared_child_key_policy"],
            "bare_same_pin": report["bare_signature"]["same_key_successor"]["predecessor_key_pin_policy"],
            "bare_rotation_self": report["bare_signature"]["authorized_key_rotation"]["self_declared_child_key_policy"],
            "bare_rotation_pin": report["bare_signature"]["authorized_key_rotation"]["predecessor_key_pin_policy"],
            "bare_rotation_transition": report["bare_signature"]["authorized_key_rotation"]["manual_predecessor_transition_policy"],
            "bare_attack_self": report["bare_signature"]["fresh_key_capture"]["self_declared_child_key_policy"],
            "bare_attack_pin": report["bare_signature"]["fresh_key_capture"]["predecessor_key_pin_policy"],
            "bare_attack_transition": report["bare_signature"]["fresh_key_capture"]["manual_predecessor_transition_policy"],
            "acsd_parent": report["acsd"]["exact_bytes"]["original_content"],
            "acsd_mutated": report["acsd"]["exact_bytes"]["mutated_content"],
            "acsd_same": report["acsd"]["same_key_successor"],
            "acsd_rotation": report["acsd"]["authorized_key_rotation"],
            "acsd_attack": report["acsd"]["fresh_key_capture"]["verification"],
            "acsd_attack_finalize": report["acsd"]["fresh_key_capture"]["finalization"],
        }
        if actual != expected:
            raise AssertionError(json.dumps(actual, indent=2, sort_keys=True))
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-report", type=pathlib.Path,
        help="fail unless the experiment equals this checked-in JSON report",
    )
    args = parser.parse_args()
    report = run_experiment()
    if args.check_report is not None:
        expected = json.loads(args.check_report.read_text(encoding="utf-8"))
        if report != expected:
            raise AssertionError(
                f"adjacent-baseline report drifted from {args.check_report}"
            )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
