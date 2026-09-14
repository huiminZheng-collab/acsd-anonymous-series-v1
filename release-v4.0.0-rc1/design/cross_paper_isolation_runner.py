#!/usr/bin/env python3
"""Exercise disclosure scope and public-key linkability across releases."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile


DESIGN = pathlib.Path(__file__).resolve().parent
ROOT = DESIGN.parent
ACSD = ROOT / "acsd.py"
SCHEMA = "acsd-cross-paper-isolation-evaluation/v1"


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


def _release(
    root: pathlib.Path,
    name: str,
    text: str,
    private_key: pathlib.Path,
) -> pathlib.Path:
    manuscript = root / f"{name}.txt"
    manuscript.write_text(text, encoding="utf-8")
    release = root / f"release-{name}"
    _invoke("release", manuscript, "--key", private_key, "--out", release)
    return release


def _release_record(root: pathlib.Path) -> dict:
    return json.loads(
        (root / "release" / "release.json").read_text(encoding="utf-8")
    )


def run_experiment() -> dict:
    with tempfile.TemporaryDirectory() as temporary:
        work = pathlib.Path(temporary)
        reused = _keygen(work, "reused-across-papers")
        independent = _keygen(work, "independent-paper")

        release_a = _release(
            work,
            "a",
            "First anonymous paper.\n",
            reused["private_key"],
        )
        release_b = _release(
            work,
            "b",
            "Unrelated anonymous paper using the same public key.\n",
            reused["private_key"],
        )
        release_c = _release(
            work,
            "c",
            "Unrelated anonymous paper using an independent public key.\n",
            independent["private_key"],
        )

        record_a = _release_record(release_a)
        record_b = _release_record(release_b)
        record_c = _release_record(release_c)
        key_a = record_a["authors"][0]["key_id"]
        key_b = record_b["authors"][0]["key_id"]
        key_c = record_c["authors"][0]["key_id"]

        sidecars = work / "identity-sidecars"
        created = _invoke(
            "disclose-identity",
            release_a,
            "--key",
            reused["private_key"],
            "--display-name",
            "Example Author",
            "--out",
            sidecars,
        )["data"]
        disclosure = pathlib.Path(created["disclosure"])
        signature = pathlib.Path(created["signature"])
        accepted_a = _invoke(
            "verify-identity",
            release_a,
            "--disclosure",
            disclosure,
            "--signature",
            signature,
        )["data"]
        rejected_b = _invoke(
            "verify-identity",
            release_b,
            "--disclosure",
            disclosure,
            "--signature",
            signature,
            expected=1,
        )
        same_key_audit = _invoke(
            "audit-key-reuse", release_a, release_b
        )["data"]
        strict_audit = _invoke(
            "audit-key-reuse", release_a, release_b,
            "--fail-on-cross-work", expected=1,
        )
        independent_key_audit = _invoke(
            "audit-key-reuse", release_a, release_c
        )["data"]

        report = {
            "schema": SCHEMA,
            "same_public_key": {
                "key_id_equal": key_a == key_b,
                "publicly_linkable_by_key_id": key_a == key_b,
                "release_a_identity_assent": accepted_a["status"],
                "release_b_scope_replay": rejected_b["message"],
                "release_b_identity_assent_derived": False,
                "cli_audit_status": same_key_audit["status"],
                "strict_cli_message": strict_audit["message"],
            },
            "independent_public_keys": {
                "key_id_equal": key_a == key_c,
                "public_key_equality_link": key_a == key_c,
                "cli_audit_status": independent_key_audit["status"],
            },
            "boundary": {
                "exact_release_scope_formally_modeled": True,
                "unlinkability_with_reused_public_key_claimed": False,
                "recommended_default": "independent-key-per-unrelated-lineage",
            },
        }
        expected = {
            "schema": SCHEMA,
            "same_public_key": {
                "key_id_equal": True,
                "publicly_linkable_by_key_id": True,
                "release_a_identity_assent":
                    "SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION",
                "release_b_scope_replay": "IDENTITY_RELEASE_MISMATCH",
                "release_b_identity_assent_derived": False,
                "cli_audit_status": "CROSS_WORK_KEY_REUSE_DETECTED",
                "strict_cli_message": "CROSS_WORK_KEY_REUSE_DETECTED",
            },
            "independent_public_keys": {
                "key_id_equal": False,
                "public_key_equality_link": False,
                "cli_audit_status": "NO_CROSS_WORK_KEY_REUSE",
            },
            "boundary": {
                "exact_release_scope_formally_modeled": True,
                "unlinkability_with_reused_public_key_claimed": False,
                "recommended_default": "independent-key-per-unrelated-lineage",
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
                f"cross-paper isolation report drifted from {args.check_report}"
            )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
