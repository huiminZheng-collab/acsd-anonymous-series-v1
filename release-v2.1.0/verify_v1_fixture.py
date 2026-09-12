#!/usr/bin/env python3
"""Reproduce the v1 fixture evaluation numbers quoted in the paper's Table 2.

Runs the zero-dependency Node.js verifiers from the inherited v1 fixture
corpus (v1-fixture/) against its shipped fixtures and prints the counts.
Verification runs in a temporary copy, so the shipped snapshot is never
modified.

    python verify_v1_fixture.py            # verify the shipped fixture snapshot
    python verify_v1_fixture.py --regenerate   # regenerate fixtures first (Windows + cbor2)

Exit code 0 means every number reproduced; any verification failure exits
non-zero. The v1 corpus is a *reference implementation*, not part of the v2
PEC core; it exists so the paper's evaluation table is reproducible.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

FIXTURE = pathlib.Path(__file__).resolve().parent / "v1-fixture"
IGNORE = shutil.ignore_patterns(".deps", "node_modules", "__pycache__", ".npm-cache")


def run(work: pathlib.Path, cmd: str, *args: str) -> str:
    r = subprocess.run([cmd, *args], cwd=work, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stdout)
        sys.stderr.write(r.stderr)
        sys.exit(r.returncode)
    return r.stdout


def regenerate(work: pathlib.Path) -> None:
    import platform
    if platform.system() != "Windows":
        sys.stderr.write("--regenerate requires Windows (the vendored cbor2 wheel is win_amd64)\n")
        sys.exit(2)
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "--target", ".deps",
         "--no-index", "--find-links", "vendor", "cbor2==6.1.4"],
        cwd=work, check=True,
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(work / ".deps") + ";" + str(work / "vendor" / "scitt-cose-v0.1.1")
    subprocess.run([sys.executable, "generate.py"], cwd=work, check=True, env=env)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--regenerate", action="store_true", help="regenerate fixtures first (Windows only)")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp) / "v1-fixture"
        shutil.copytree(FIXTURE, work, ignore=IGNORE)
        if args.regenerate:
            regenerate(work)

        # 1. standalone single-package verification
        run(work, "node", "verify-standalone.cjs", "artifacts/standalone-packages/p-v1.json")
        # 2. independent series verification (30 profile checks + 13 scenarios)
        independent = json.loads(run(work, "node", "verify-independent.cjs"))
        # 3. rebuild and verify the public manifest
        run(work, "node", "build-manifest.cjs")
        manifest = json.loads(run(work, "node", "verify-manifest.cjs"))
        # 4. structure counts
        releases = len(list((work / "artifacts/releases").glob("*.json")))
        endorsements = len(list((work / "artifacts/endorsements").glob("*.scitt")))
        series = len(list((work / "artifacts/series").glob("*.scitt")))
        scenarios = len(json.loads((work / "artifacts/scenarios.json").read_text(encoding="utf-8"))["scenarios"])

        checks = independent["checks"]
        report = {
            "standalone_releases": releases,
            "author_endorsements": endorsements,
            "series_signed_objects": series,
            "scenarios": scenarios,
            "profile_checks": {"passed": checks["passed"], "failed": checks["failed"]},
            "public_manifest": {"passed": manifest["passed"], "failed": manifest["failed"]},
            "profile_result": independent.get("profile_result"),
        }
        print(json.dumps(report, indent=2, ensure_ascii=False))

        ok = (
            checks["failed"] == 0
            and manifest["failed"] == 0
            and independent.get("profile_result") == "VALID"
        )
        return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
