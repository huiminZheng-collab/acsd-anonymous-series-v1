#!/usr/bin/env python3
"""Exercise the smallest precommitted-recovery and residual-fork boundary."""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile


DESIGN = pathlib.Path(__file__).resolve().parent
ROOT = DESIGN.parent
ACSD = ROOT / "acsd.py"
SCHEMA = "acsd-precommitted-recovery-evaluation/v1"


def _invoke(*args: object, expected: int = 0) -> dict:
    result = subprocess.run(
        [sys.executable, str(ACSD), *map(str, args), "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    payload = json.loads(result.stdout)
    if result.returncode != expected:
        raise AssertionError(
            f"command {args!r} returned {result.returncode}, expected "
            f"{expected}: {result.stderr or result.stdout}"
        )
    return payload


def _keygen(root: pathlib.Path, name: str) -> dict:
    data = _invoke(
        "keygen", "--name", name, "--out-dir", root / "keys"
    )["data"]
    data["public_key_path"] = str(root / "keys" / f"{name}.pub")
    return data


def _team(root: pathlib.Path, name: str, key: dict) -> pathlib.Path:
    path = root / f"{name}-team.json"
    path.write_text(json.dumps({
        "schema": "acsd-team/v1",
        "authors": [{
            "key_id": key["key_id"],
            "public_key": key["public_key"],
            "role": "sole",
            "corresponding": True,
        }],
    }), encoding="utf-8")
    return path


def _draft(
    root: pathlib.Path,
    parent: pathlib.Path,
    author: dict,
    name: str,
) -> pathlib.Path:
    paper = root / f"{name}.txt"
    paper.write_text(f"Exact candidate {name}.\n", encoding="utf-8")
    child = root / name
    _invoke(
        "init", paper, "--team", _team(root, name, author),
        "--parent", parent, "--out", child,
    )
    _invoke("approve", child, "--key", author["private_key"])
    return child


def run_experiment() -> dict:
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        alice = _keygen(root, "alice-online")
        bob = _keygen(root, "bob-recovered")
        carol = _keygen(root, "carol-online-rotation")
        dave = _keygen(root, "dave-replay-target")
        guardian_one = _keygen(root, "guardian-one")
        guardian_two = _keygen(root, "guardian-two")
        mallory = _keygen(root, "mallory-uncommitted")

        parent_paper = root / "parent.txt"
        parent_paper.write_text("Parent precommitting two recovery keys.\n", encoding="utf-8")
        parent = root / "parent"
        _invoke(
            "release", parent_paper,
            "--key", alice["private_key"],
            "--recovery-public-key", guardian_one["public_key_path"],
            "--recovery-public-key", guardian_two["public_key_path"],
            "--recovery-threshold", 2,
            "--out", parent,
        )

        recovered_paper = root / "recovered.txt"
        recovered_paper.write_text("Recovery-authorized exact child.\n", encoding="utf-8")
        recovered = root / "recovered"
        _invoke(
            "revise", parent, recovered_paper,
            "--key", bob["private_key"],
            "--recovery-key", guardian_one["private_key"],
            "--recovery-key", guardian_two["private_key"],
            "--out", recovered,
        )
        recovered_result = _invoke("verify", recovered)["data"]

        insufficient = _draft(root, parent, dave, "insufficient")
        _invoke(
            "recover", insufficient,
            "--key", guardian_one["private_key"],
        )
        insufficient_result = _invoke("finalize", insufficient, expected=5)

        unknown = _draft(root, parent, dave, "unknown")
        unknown_result = _invoke(
            "recover", unknown, "--key", mallory["private_key"], expected=1
        )

        replay = _draft(root, parent, dave, "replay")
        for guardian in (guardian_one, guardian_two):
            shutil.copyfile(
                recovered / f"lineage/recovery-authorizations/{guardian['key_id']}.cose",
                replay / f"lineage/recovery-authorizations/{guardian['key_id']}.cose",
            )
        replay_result = _invoke("verify", replay, expected=1)

        mixed = _draft(root, parent, dave, "mixed")
        _invoke("authorize", mixed, "--key", alice["private_key"])
        mixed_result = _invoke(
            "recover", mixed, "--key", guardian_one["private_key"], expected=3
        )

        recovery_only_paper = root / "recovery-only.txt"
        recovery_only_paper.write_text(
            "Attempted recovery-only authority update.\n", encoding="utf-8"
        )
        recovery_only_result = _invoke(
            "revise", parent, recovery_only_paper,
            "--key", alice["private_key"],
            "--recovery-key", guardian_one["private_key"],
            "--recovery-key", guardian_two["private_key"],
            "--recovery-public-key", mallory["public_key_path"],
            "--out", root / "recovery-only",
            expected=3,
        )

        online_paper = root / "online.txt"
        online_paper.write_text("Ordinary online-authorized exact child.\n", encoding="utf-8")
        online = root / "online"
        _invoke(
            "revise", parent, online_paper,
            "--key", carol["private_key"],
            "--parent-key", alice["private_key"],
            "--out", online,
        )
        online_result = _invoke("verify", online)["data"]
        fork_result = _invoke("compare-successors", online, recovered)["data"]

        plain_paper = root / "plain-parent.txt"
        plain_paper.write_text("Parent without recovery precommitment.\n", encoding="utf-8")
        plain_parent = root / "plain-parent"
        _invoke(
            "release", plain_paper,
            "--key", alice["private_key"], "--out", plain_parent,
        )
        absent = _draft(root, plain_parent, dave, "absent")
        absent_result = _invoke(
            "recover", absent, "--key", guardian_one["private_key"], expected=1
        )

        report = {
            "schema": SCHEMA,
            "evidence_classification": "empirical-executable-protocol-test",
            "recovery_quorum": {
                "configured": "2-of-2",
                "lineage_status": recovered_result["lineage_status"],
                "method": recovered_result["lineage_authorization_method"],
                "authorized_successor": (
                    "AUTHORIZED_SUCCESSOR" in recovered_result["granted_outcomes"]
                ),
            },
            "insufficient_quorum": {
                "message": insufficient_result["message"],
                "method": insufficient_result["data"]["authorization_method"],
                "required_threshold": insufficient_result["data"]["required_threshold"],
            },
            "uncommitted_guardian": unknown_result["message"],
            "no_precommit_parent": absent_result["message"],
            "cross_child_replay": replay_result["data"]["error_code"],
            "mixed_methods": mixed_result["message"],
            "recovery_only_change": recovery_only_result["message"],
            "residual_same_slot_fork": {
                "ordinary_status": online_result["lineage_status"],
                "recovery_status": recovered_result["lineage_status"],
                "conflict": fork_result["conflict"],
                "winner": fork_result["winner"],
            },
            "non_claims": [
                "does not erase an earlier valid signature or transition",
                "does not prove that an offline verifier has every competing edge",
                "does not select a global head without a transparency or pinning policy",
                "does not establish recovery-key custody or guardian honesty",
            ],
        }
        expected = {
            "status": "RECOVERY_AUTHORIZED_TRANSITION",
            "method": "recovery",
            "successor": True,
            "incomplete": "LINEAGE_AUTHORIZATION_INCOMPLETE",
            "unknown": "UNKNOWN_RECOVERY_AUTHORITY_KEY",
            "absent": "RECOVERY_AUTHORITY_NOT_PRECOMMITTED",
            "replay": "COSE_PAYLOAD_MISMATCH",
            "mixed": "LINEAGE_AUTHORIZATION_METHOD_AMBIGUOUS",
            "recovery_only": "RECOVERY_REQUIRES_ONLINE_AUTHORITY_CHANGE",
            "online": "AUTHORIZED_TRANSITION",
            "conflict": True,
            "winner": None,
        }
        actual = {
            "status": report["recovery_quorum"]["lineage_status"],
            "method": report["recovery_quorum"]["method"],
            "successor": report["recovery_quorum"]["authorized_successor"],
            "incomplete": report["insufficient_quorum"]["message"],
            "unknown": report["uncommitted_guardian"],
            "absent": report["no_precommit_parent"],
            "replay": report["cross_child_replay"],
            "mixed": report["mixed_methods"],
            "recovery_only": report["recovery_only_change"],
            "online": report["residual_same_slot_fork"]["ordinary_status"],
            "conflict": report["residual_same_slot_fork"]["conflict"],
            "winner": report["residual_same_slot_fork"]["winner"],
        }
        if actual != expected:
            raise AssertionError(json.dumps(actual, indent=2, sort_keys=True))
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
                f"precommitted-recovery report drifted from {args.check_report}"
            )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
