#!/usr/bin/env python3
"""Scripted role-based workflow evaluation; not a human-subject study."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
ACSD = ROOT / "acsd.py"
sys.path.insert(0, str(ROOT))

from package_manifest import build_manifest_text  # noqa: E402


class Session:
    def __init__(self):
        self.commands = []

    def run(self, *args, expected=0):
        started = time.perf_counter()
        result = subprocess.run(
            [sys.executable, str(ACSD), *args, "--json"],
            capture_output=True,
            text=True,
        )
        elapsed_ms = (time.perf_counter() - started) * 1000
        self.commands.append({
            "command": args[0],
            "elapsed_ms": round(elapsed_ms, 3),
            "exit_code": result.returncode,
        })
        if result.returncode != expected:
            raise AssertionError(
                f"{args!r}: expected {expected}, got {result.returncode}: "
                f"{result.stdout} {result.stderr}"
            )
        return json.loads(result.stdout)


def keygen(session, key_dir, name):
    return session.run(
        "keygen", "--name", name, "--out-dir", str(key_dir)
    )["data"]


def initialize_three_author_candidate(session, root, authors, name):
    paper = root / f"{name}.txt"
    paper.write_text(
        f"Scripted three-author candidate: {name}.\n", encoding="utf-8"
    )
    release = root / f"{name}-release"
    args = ["init", str(paper)]
    for author in authors:
        args.extend(["--public-key", author["public_key_path"]])
    args.extend([
        "--role", "first-author",
        "--role", "co-author",
        "--role", "senior-author",
        "--corresponding", "3",
        "--contribution", "1:conceptualization",
        "--contribution", "2:software",
        "--contribution", "3:supervision",
        "--ai-tool", "scripted-model",
        "--ai-purpose", "brainstorming",
        "--ai-reviewed-by", "1",
        "--out", str(release),
        "--allow-delegated-approval",
    ])
    session.run(*args)
    return release


def make_responses(session, root, release, authors, name, delegate=None):
    requests = root / f"{name}-requests"
    responses = root / f"{name}-responses"
    responses.mkdir()
    exported = session.run(
        "export-approval-requests", str(release), "--out", str(requests)
    )["data"]
    by_key = {author["key_id"]: author for author in authors}
    for entry in exported["requests"]:
        author = by_key[entry["author_key_id"]]
        args = [
            "respond-approval-request", str(requests / entry["path"]),
            "--key", author["private_key"],
            "--out", str(responses / entry["path"]),
            "--yes",
        ]
        if delegate is not None and author is authors[1]:
            args.extend(["--delegate-public-key", delegate["public_key_path"]])
        session.run(*args)
    return requests, responses


def evaluate():
    session = Session()
    with tempfile.TemporaryDirectory(prefix="acsd-scripted-roles-") as directory:
        root = pathlib.Path(directory)
        keys = root / "keys"
        authors = []
        for name in ("alice", "bob", "carol"):
            author = keygen(session, keys, name)
            author["public_key_path"] = str(keys / f"{name}.pub")
            authors.append(author)
        delegate = keygen(session, keys, "coordinator-agent")
        delegate["public_key_path"] = str(keys / "coordinator-agent.pub")

        happy_start = len(session.commands)
        release = initialize_three_author_candidate(
            session, root, authors, "happy"
        )
        _, responses = make_responses(
            session, root, release, authors, "happy", delegate=delegate
        )
        session.run(
            "coordinator-finalize", str(release),
            "--responses-dir", str(responses),
            "--delegate-key", delegate["private_key"],
            "--allow-untimestamped",
        )
        verified = session.run("verify", str(release))["data"]
        if "AUTHORIZED_TARGET_APPROVAL" not in verified["granted_outcomes"]:
            raise AssertionError("mixed delegated outcome missing")
        happy_commands = session.commands[happy_start:]

        rollback_start = len(session.commands)
        attacked = initialize_three_author_candidate(
            session, root, authors, "rollback"
        )
        _, attacked_responses = make_responses(
            session, root, attacked, authors, "rollback"
        )
        victim = sorted(attacked_responses.iterdir())[-1]
        signature = victim / "approval.cose"
        raw = bytearray(signature.read_bytes())
        raw[-1] ^= 1
        signature.write_bytes(bytes(raw))
        (victim / "MANIFEST.sha256").write_bytes(
            build_manifest_text(victim).encode("ascii")
        )
        rejected = session.run(
            "import-approval-responses", str(attacked),
            "--from-dir", str(attacked_responses), expected=1,
        )
        if not rejected["data"].get("original_unchanged"):
            raise AssertionError("failed batch did not report rollback semantics")
        state = session.run("inspect", str(attacked))["data"]
        if state["received_approvals"]:
            raise AssertionError("failed batch partially mutated the live candidate")
        rollback_commands = session.commands[rollback_start:]

    return {
        "schema": "acsd-scripted-role-evaluation/v1",
        "study_type": "scripted-role-based-evaluation",
        "human_participants": 0,
        "production_deployments": 0,
        "external_services_contacted": 0,
        "claims": {
            "human_usability": False,
            "production_adoption": False,
            "workflow_executability": True,
            "transactional_rejection": True,
        },
        "happy_path": {
            "authors": 3,
            "direct_approvals": 2,
            "exact_delegations": 1,
            "commands_after_key_setup": len(happy_commands),
            "author_confirmations_modeled": 3,
            "request_packages": 3,
            "response_packages": 3,
            "manual_json_edits": 0,
            "private_key_transfers": 0,
            "manually_copied_protocol_identifiers": 0,
            "final_time_evidence": "explicitly-untimestamped-test-only",
            "elapsed_ms": round(sum(item["elapsed_ms"] for item in happy_commands), 3),
        },
        "adversarial_rollback": {
            "attack": "last response signature changed; transport manifest regenerated",
            "commands_after_key_setup": len(rollback_commands),
            "batch_accepted": False,
            "live_approvals_after_rejection": 0,
            "elapsed_ms": round(sum(item["elapsed_ms"] for item in rollback_commands), 3),
        },
        "commands": session.commands,
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", help="optional JSON report path")
    args = parser.parse_args(argv)
    report = evaluate()
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        pathlib.Path(args.out).write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
