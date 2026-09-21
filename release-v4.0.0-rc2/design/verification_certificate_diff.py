"""Check Python/Node agreement on frozen v1/v2/v3 certificates."""

from __future__ import annotations

import pathlib
import os
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent
PROJECT = ROOT.parent
sys.path.insert(0, str(ROOT))

from verification_certificate import encoded  # noqa: E402


def main() -> int:
    fingerprint = "32e841a95cc1164101ffde41298ef2fc75c1c4372ef095e88a6bbd47dfb191fc"
    fixture = ROOT / "rfc3161-approval-set-fixture"
    for version, options, checked_name in (
        ("v1", {}, "verification_certificate_demo.json"),
        ("v2", {"include_identity": True}, "verification_certificate_demo_v2.json"),
        ("v3", {
            "time_fixture": fixture,
            "trusted_tsa_fingerprint": fingerprint,
            "external_authority": True,
        }, "verification_certificate_demo_v3.json"),
    ):
        python_bytes = encoded(PROJECT / "demo", **options) + b"\n"
        command = [
            "node", str(ROOT / "verification_certificate.cjs"), str(PROJECT / "demo")
        ]
        if version == "v2":
            command.append("--include-identity")
        if version == "v3":
            command.extend([
                "--time-fixture", str(fixture),
                "--trusted-tsa-fingerprint", fingerprint,
                "--external-authority",
            ])
        environment = dict(os.environ)
        environment["ACSD_PYTHON"] = sys.executable
        node = subprocess.run(
            command, cwd=PROJECT, capture_output=True, env=environment
        )
        if node.returncode:
            sys.stderr.buffer.write(node.stderr)
            return node.returncode
        checked = (ROOT / checked_name).read_bytes()
        if python_bytes != node.stdout or python_bytes != checked:
            print(f"{version} certificate differs across adapters or checked evidence",
                  file=sys.stderr)
            return 2
    print("verification-certificate: Python/Node v1/v2/v3 canonical transcripts PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
