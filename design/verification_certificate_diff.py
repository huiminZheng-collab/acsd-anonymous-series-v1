"""Check Python/Node agreement on frozen v1 and identity-aware v2 certificates."""

from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent
PROJECT = ROOT.parent
sys.path.insert(0, str(ROOT))

from verification_certificate import encoded  # noqa: E402


def main() -> int:
    for version, include_identity, checked_name in (
        ("v1", False, "verification_certificate_demo.json"),
        ("v2", True, "verification_certificate_demo_v2.json"),
    ):
        python_bytes = encoded(
            PROJECT / "demo", include_identity=include_identity
        ) + b"\n"
        command = [
            "node", str(ROOT / "verification_certificate.cjs"), str(PROJECT / "demo")
        ]
        if include_identity:
            command.append("--include-identity")
        node = subprocess.run(command, cwd=PROJECT, capture_output=True)
        if node.returncode:
            sys.stderr.buffer.write(node.stderr)
            return node.returncode
        checked = (ROOT / checked_name).read_bytes()
        if python_bytes != node.stdout or python_bytes != checked:
            print(f"{version} certificate differs across adapters or checked evidence",
                  file=sys.stderr)
            return 2
    print("verification-certificate: Python/Node v1/v2 canonical transcripts PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
