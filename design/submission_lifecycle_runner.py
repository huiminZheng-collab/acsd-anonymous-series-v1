#!/usr/bin/env python3
"""Exercise the submission/revision/unblinding choreography with the public CLI.

The runner deliberately does not model a venue as a trusted authority.  It
checks only the protocol-visible facts: a rejection represented by no ACSD
action leaves the public release unchanged; a scientific revision is an
authorized successor; and an explicit per-slot publication crosswalk remains
an author-key assertion rather than evidence of venue acceptance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

DESIGN = pathlib.Path(__file__).resolve().parent
ROOT = DESIGN.parent
sys.path.insert(0, str(ROOT))

import identity_disclosure  # noqa: E402
from artifact_io import read_canonical, write_canonical  # noqa: E402
from key_material import load_bound_public_key  # noqa: E402


ACSD = ROOT / "acsd.py"
SCHEMA = "acsd-submission-lifecycle-evaluation/v1"
PUBLICATION_REF = "urn:example:proceedings:paper-123"


def _invoke(*args: str, expected: int = 0) -> dict:
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
            f"command {args!r} returned {result.returncode}, expected {expected}: "
            f"{result.stderr or result.stdout}"
        )
    return payload


def _keygen(root: pathlib.Path, name: str) -> dict:
    return _invoke(
        "keygen", "--name", name, "--out-dir", root / "private-keys"
    )["data"]


def _tree_digest(root: pathlib.Path) -> str:
    outer = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        outer.update(len(relative).to_bytes(8, "big"))
        outer.update(relative)
        body = path.read_bytes()
        outer.update(len(body).to_bytes(8, "big"))
        outer.update(body)
    return outer.hexdigest()


def run_experiment() -> dict:
    with tempfile.TemporaryDirectory() as temporary:
        work = pathlib.Path(temporary)
        first = _keygen(work, "slot-1")
        second = _keygen(work, "slot-2")

        manuscript_v1 = work / "anonymous-v1.txt"
        manuscript_v1.write_text(
            "Anonymous submission candidate.\n", encoding="utf-8"
        )
        release_v1 = work / "release-v1"
        _invoke(
            "release", manuscript_v1,
            "--key", first["private_key"],
            "--key", second["private_key"],
            "--out", release_v1,
        )

        # A venue rejection is intentionally not an ACSD state transition.
        # Running the read-only verifier is the only action in this case.
        rejection_before = _tree_digest(release_v1)
        parent_verification = _invoke("verify", release_v1)["data"]
        rejection_after = _tree_digest(release_v1)

        manuscript_v2 = work / "revised-v2.txt"
        manuscript_v2.write_text(
            "Scientifically revised submission candidate.\n", encoding="utf-8"
        )
        release_v2 = work / "release-v2"
        revision_created = _invoke(
            "revise", release_v1, manuscript_v2,
            "--key", first["private_key"],
            "--key", second["private_key"],
            "--out", release_v2,
        )["data"]
        revision_verified = _invoke("verify", release_v2)["data"]

        sidecars = work / "publication-crosswalks"
        absent_before_explicit_action = not sidecars.exists()
        signed = []
        for slot, key, display_name in (
            (1, first, "Example Author One"),
            (2, second, "Example Author Two"),
        ):
            created = _invoke(
                "disclose-identity", release_v2,
                "--key", key["private_key"],
                "--display-name", display_name,
                "--publication-ref", PUBLICATION_REF,
                "--out", sidecars,
            )["data"]
            body_path = pathlib.Path(created["disclosure"])
            signature_path = pathlib.Path(created["signature"])
            verified = _invoke(
                "verify-identity", release_v2,
                "--disclosure", body_path,
                "--signature", signature_path,
            )["data"]
            if verified["author_slot"] != slot:
                raise AssertionError("unexpected disclosed slot")
            signed.append((read_canonical(body_path), signature_path.read_bytes()))

        release = read_canonical(release_v2 / "release" / "release.json")
        public_keys = {
            author["key_id"]: load_bound_public_key(release_v2, author["key_id"])
            for author in release["authors"]
        }
        byline = identity_disclosure.verify_set(signed, release, public_keys)

        replay_body = sidecars / "identity-slot-1.json"
        replay_signature = sidecars / "identity-slot-1.cose"
        wrong_release = _invoke(
            "verify-identity", release_v1,
            "--disclosure", replay_body,
            "--signature", replay_signature,
            expected=1,
        )

        altered = read_canonical(replay_body)
        altered["publication_ref"] = "urn:example:proceedings:substituted"
        altered_path = work / "altered-publication-crosswalk.json"
        write_canonical(altered_path, altered)
        altered_result = _invoke(
            "verify-identity", release_v2,
            "--disclosure", altered_path,
            "--signature", replay_signature,
            expected=1,
        )

        report = {
            "schema": SCHEMA,
            "cases": {
                "rejection_out_of_band": {
                    "protocol_action": "none",
                    "release_tree_unchanged": rejection_before == rejection_after,
                    "release_still_valid": parent_verification["state"]
                    in {"finalized", "finalized-untimestamped"},
                },
                "revision_after_rejection": {
                    "version": revision_created["version"],
                    "lineage_status": revision_verified["lineage_status"],
                    "authorized_successor_derived": "AUTHORIZED_SUCCESSOR"
                    in revision_verified["granted_outcomes"],
                },
                "explicit_publication_crosswalk": {
                    "sidecar_absent_before_explicit_action": absent_before_explicit_action,
                    "byline_status": byline["status"],
                    "disclosed_slots": byline["disclosed_slots"],
                    "shared_publication_ref": byline["shared_publication_ref"],
                    "publication_acceptance_derived": False,
                    "publication_acceptance_listed_as_non_claim":
                    "publication_acceptance_verified" in byline["non_claims"],
                },
                "adverse": {
                    "cross_release_replay": wrong_release["message"],
                    "mutated_publication_ref": altered_result["message"],
                },
            },
        }

        expected = {
            "schema": SCHEMA,
            "cases": {
                "rejection_out_of_band": {
                    "protocol_action": "none",
                    "release_tree_unchanged": True,
                    "release_still_valid": True,
                },
                "revision_after_rejection": {
                    "version": 2,
                    "lineage_status": "AUTHORIZED_CONTINUATION",
                    "authorized_successor_derived": True,
                },
                "explicit_publication_crosswalk": {
                    "sidecar_absent_before_explicit_action": True,
                    "byline_status": "FULL_BYLINE_KEY_ASSENT",
                    "disclosed_slots": [1, 2],
                    "shared_publication_ref": PUBLICATION_REF,
                    "publication_acceptance_derived": False,
                    "publication_acceptance_listed_as_non_claim": True,
                },
                "adverse": {
                    "cross_release_replay": "IDENTITY_RELEASE_MISMATCH",
                    "mutated_publication_ref": "COSE_PAYLOAD_MISMATCH",
                },
            },
        }
        if report != expected:
            raise AssertionError(json.dumps(report, indent=2, sort_keys=True))
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-report",
        type=pathlib.Path,
        help="fail unless the experiment equals this checked-in JSON report",
    )
    args = parser.parse_args()
    report = run_experiment()
    if args.check_report is not None:
        expected = json.loads(args.check_report.read_text(encoding="utf-8"))
        if report != expected:
            raise AssertionError(
                f"lifecycle report drifted from {args.check_report}"
            )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
