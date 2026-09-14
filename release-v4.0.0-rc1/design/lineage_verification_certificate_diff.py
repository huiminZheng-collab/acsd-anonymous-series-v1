"""Check independent Python/Node agreement on the lineage certificate."""

from __future__ import annotations

import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parent
PROJECT = ROOT.parent
sys.path.insert(0, str(PROJECT))

from lineage_verification_certificate import encoded  # noqa: E402


def main() -> int:
    expected = encoded(PROJECT / "demo-lineage") + b"\n"
    node = subprocess.run(
        ["node", str(ROOT / "lineage_verification_certificate.cjs"),
         str(PROJECT / "demo-lineage")],
        cwd=PROJECT, capture_output=True,
    )
    if node.returncode:
        sys.stderr.buffer.write(node.stderr)
        return node.returncode
    checked = (ROOT / "lineage_verification_certificate_demo.json").read_bytes()
    if expected != node.stdout or expected != checked:
        print("lineage certificate differs across adapters or checked evidence",
              file=sys.stderr)
        return 2
    print("lineage-certificate: Python/Node canonical transcript PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
