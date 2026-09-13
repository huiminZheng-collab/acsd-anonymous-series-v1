#!/usr/bin/env python3
"""Authoritative read-only ACSD engineering gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parent
WHEEL_INPUTS = (
    "pyproject.toml", "README.md", "LICENSE", "acsd.py", "acsd_version.py", "approval_set.py",
    "cose.py", "event_disclosure.py", "identity_disclosure.py",
    "package_manifest.py", "pec_core.py", "tsa.py",
)


def _workspace_files():
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT, check=True, capture_output=True,
    )
    return [
        ROOT / name.decode("utf-8")
        for name in result.stdout.split(b"\0") if name
    ]


def _snapshot():
    return {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in _workspace_files() if path.is_file()
    }


def _run(label, command, *, cwd=ROOT, env=None):
    result = subprocess.run(
        command, cwd=cwd, env=env, text=True, encoding="utf-8",
        errors="replace", capture_output=True,
    )
    if result.returncode:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise RuntimeError(f"{label} failed with exit code {result.returncode}")
    return {"name": label, "status": "PASS"}


def _find_lake():
    configured = os.environ.get("ACSD_LAKE")
    if configured:
        return pathlib.Path(configured)
    found = shutil.which("lake")
    if found:
        return pathlib.Path(found)
    candidate = pathlib.Path.home() / ".elan" / "bin" / ("lake.exe" if os.name == "nt" else "lake")
    return candidate if candidate.is_file() else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-formal", action="store_true")
    args = parser.parse_args()
    before = _snapshot()
    env = dict(os.environ)
    env["ACSD_SKIP_NETWORK"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    checks = []
    with tempfile.TemporaryDirectory() as temporary:
        temp = pathlib.Path(temporary)
        checks.append(_run("python-unit", [sys.executable, "-m", "unittest", "-q"], env=env))
        checks.append(_run("canonical-differential", [sys.executable, "design/canonical_diff_runner.py"], env=env))
        checks.append(_run("canonical-fuzz", [sys.executable, "design/canonical_fuzz_runner.py"], env=env))
        checks.append(_run("scaling-smoke", [sys.executable, "design/benchmark_core.py"], env=env))
        checks.append(_run("v1-fixture", [sys.executable, "verify_v1_fixture.py"], env=env))
        demo = temp / "demo"
        checks.append(_run("demo-generate", [sys.executable, "generate_demo.py", str(demo)], env=env))
        checks.append(_run("demo-verify", [sys.executable, "verify_pec.py", str(demo)], env=env))
        evidence = temp / "evidence-package"
        checks.append(_run(
            "evidence-package-build",
            [sys.executable, "build_release.py", "--out", str(evidence)], env=env,
        ))
        checks.append(_run(
            "evidence-package-manifest",
            [sys.executable, "verify_release.py", str(evidence)], env=env,
        ))
        checks.append(_run(
            "evidence-package-demo",
            [sys.executable, str(evidence / "verify_pec.py"), str(evidence / "demo")],
            cwd=evidence, env=env,
        ))
        wheel_dir = temp / "wheel"
        wheel_dir.mkdir()
        wheel_source = temp / "wheel-source"
        wheel_source.mkdir()
        for relative in WHEEL_INPUTS:
            shutil.copy2(ROOT / relative, wheel_source / relative)
        checks.append(_run(
            "wheel-build",
            [sys.executable, "-m", "pip", "wheel", str(wheel_source), "--no-deps", "--no-build-isolation", "--wheel-dir", str(wheel_dir)],
            cwd=temp, env=env,
        ))
        install_dir = temp / "installed"
        wheel = next(wheel_dir.glob("*.whl"))
        checks.append(_run(
            "wheel-install",
            [sys.executable, "-m", "pip", "install", str(wheel), "--no-deps", "--target", str(install_dir)],
            cwd=temp, env=env,
        ))
        installed_env = dict(env)
        installed_env["PYTHONPATH"] = str(install_dir)
        checks.append(_run(
            "installed-cli-import",
            [sys.executable, "-c", "import acsd,acsd_version; assert acsd.__version__ == acsd_version.__version__"],
            cwd=temp, env=installed_env,
        ))
        if not args.skip_formal:
            lake = _find_lake()
            if lake is None:
                raise RuntimeError("formal check requires lake; set ACSD_LAKE")
            formal_copy = temp / "formal"
            shutil.copytree(ROOT / "formal", formal_copy, ignore=shutil.ignore_patterns(".lake"))
            lean_env = dict(env)
            if lake.parent.name == "bin" and lake.parent.parent.name == ".elan":
                lean_env.setdefault("ELAN_HOME", str(lake.parent.parent))
            checks.append(_run("lean-build", [str(lake), "build"], cwd=formal_copy, env=lean_env))
            checks.append(_run(
                "lean-axiom-audit", [str(lake), "env", "lean", "AxiomAudit.lean"],
                cwd=formal_copy, env=lean_env,
            ))
    after = _snapshot()
    if before != after:
        changed = sorted(set(before) ^ set(after) | {
            name for name in set(before) & set(after) if before[name] != after[name]
        })
        raise RuntimeError("read-only gate mutated workspace: " + ", ".join(changed))
    checks.append({"name": "workspace-byte-identity", "status": "PASS"})
    print(json.dumps({"status": "PASS", "checks": checks}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
