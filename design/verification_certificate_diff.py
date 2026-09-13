"""Check Python/Node agreement on the frozen verification certificate."""

from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent
PROJECT = ROOT.parent
sys.path.insert(0, str(ROOT))

from verification_certificate import encoded  # noqa: E402


def main() -> int:
    python_bytes = encoded(PROJECT / "demo") + b"\n"
    node = subprocess.run(
        ["node", str(ROOT / "verification_certificate.cjs"), str(PROJECT / "demo")],
        cwd=PROJECT, capture_output=True,
    )
    if node.returncode:
        sys.stderr.buffer.write(node.stderr)
        return node.returncode
    checked = (ROOT / "verification_certificate_demo.json").read_bytes()
    if python_bytes != node.stdout or python_bytes != checked:
        print("verification certificate differs across adapters or checked evidence",
              file=sys.stderr)
        return 2
    print("verification-certificate: Python/Node canonical fact transcript PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
