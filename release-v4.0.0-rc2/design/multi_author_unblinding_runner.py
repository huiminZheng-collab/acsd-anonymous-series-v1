#!/usr/bin/env python3
"""Exercise partial/full three-author unblinding through the public CLI."""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import subprocess
import sys
import tempfile


DESIGN = pathlib.Path(__file__).resolve().parent
ROOT = DESIGN.parent
sys.path.insert(0, str(ROOT))

from artifact_io import read_canonical, write_canonical  # noqa: E402


ACSD = ROOT / "acsd.py"
SCHEMA = "acsd-multi-author-unblinding-evaluation/v1"
PUBLICATION_REF = "urn:example:proceedings:three-author-paper"


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


def _identity_set(
    release: pathlib.Path,
    disclosures: list[pathlib.Path],
    signatures: list[pathlib.Path],
    *,
    require_full: bool = False,
    expected: int = 0,
) -> dict:
    args = ["verify-identity-set", release]
    for path in disclosures:
        args.extend(["--disclosure", path])
    for path in signatures:
        args.extend(["--signature", path])
    if require_full:
        args.append("--require-full-byline")
    return _invoke(*args, expected=expected)


def run_experiment() -> dict:
    with tempfile.TemporaryDirectory() as temporary:
        work = pathlib.Path(temporary)
        keys = []
        for index in range(1, 4):
            keys.append(_invoke(
                "keygen", "--name", f"slot-{index}",
                "--out-dir", work / "private-keys",
            )["data"])

        manuscript = work / "three-author-paper.txt"
        manuscript.write_text("Three-author anonymous paper.\n", encoding="utf-8")
        release = work / "release"
        release_args = ["release", manuscript]
        for key in keys:
            release_args.extend(["--key", key["private_key"]])
        release_args.extend(["--out", release])
        _invoke(*release_args)

        sidecars = work / "identity-sidecars"
        disclosures = []
        signatures = []
        for index, key in enumerate(keys, 1):
            created = _invoke(
                "disclose-identity", release,
                "--key", key["private_key"],
                "--display-name", f"Example Author {index}",
                "--publication-ref", PUBLICATION_REF,
                "--out", sidecars,
            )["data"]
            disclosures.append(pathlib.Path(created["disclosure"]))
            signatures.append(pathlib.Path(created["signature"]))

        one = _identity_set(release, disclosures[:1], signatures[:1])["data"]
        two = _identity_set(release, disclosures[:2], signatures[:2])["data"]
        two_required = _identity_set(
            release, disclosures[:2], signatures[:2],
            require_full=True, expected=5,
        )
        full = _identity_set(
            release, disclosures, signatures, require_full=True
        )["data"]
        duplicate = _identity_set(
            release,
            [disclosures[0], disclosures[0]],
            [signatures[0], signatures[0]],
            expected=1,
        )

        changed_name = copy.deepcopy(read_canonical(disclosures[0]))
        changed_name["identity_assertion"]["display_name"] = "Substituted Name"
        changed_name_path = work / "changed-name.json"
        write_canonical(changed_name_path, changed_name)
        changed_name_result = _identity_set(
            release, [changed_name_path], [signatures[0]], expected=1
        )

        contribution = copy.deepcopy(read_canonical(disclosures[0]))
        contribution["contributions"] = ["Conceptualization"]
        contribution_path = work / "identity-with-contribution.json"
        write_canonical(contribution_path, contribution)
        contribution_result = _identity_set(
            release, [contribution_path], [signatures[0]], expected=1
        )

        report = {
            "schema": SCHEMA,
            "coverage": {
                "one_of_three": {
                    "status": one["status"],
                    "slots": one["disclosed_slots"],
                },
                "two_of_three": {
                    "status": two["status"],
                    "slots": two["disclosed_slots"],
                    "require_full_exit": two_required["exit_code"],
                },
                "three_of_three": {
                    "status": full["status"],
                    "slots": full["disclosed_slots"],
                    "shared_publication_ref": full["shared_publication_ref"],
                    "contribution_truth_listed_as_non_claim":
                    "contribution_truth_verified" in full["non_claims"],
                },
            },
            "adverse": {
                "duplicate_slot": duplicate["message"],
                "changed_name": changed_name_result["message"],
                "smuggled_contribution": contribution_result["message"],
            },
        }
        expected = {
            "schema": SCHEMA,
            "coverage": {
                "one_of_three": {
                    "status": "PARTIAL_BYLINE_KEY_ASSENT",
                    "slots": [1],
                },
                "two_of_three": {
                    "status": "PARTIAL_BYLINE_KEY_ASSENT",
                    "slots": [1, 2],
                    "require_full_exit": 5,
                },
                "three_of_three": {
                    "status": "FULL_BYLINE_KEY_ASSENT",
                    "slots": [1, 2, 3],
                    "shared_publication_ref": PUBLICATION_REF,
                    "contribution_truth_listed_as_non_claim": True,
                },
            },
            "adverse": {
                "duplicate_slot": "VERIFIED_IDENTITY_SLOT_EQUIVOCATION",
                "changed_name": "COSE_PAYLOAD_MISMATCH",
                "smuggled_contribution": "IDENTITY_DISCLOSURE_FIELDS",
            },
        }
        if report != expected:
            raise AssertionError(json.dumps(report, indent=2, sort_keys=True))
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
                f"multi-author report drifted from {args.check_report}"
            )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
