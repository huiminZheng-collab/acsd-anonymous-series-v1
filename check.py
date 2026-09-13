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
import venv


ROOT = pathlib.Path(__file__).resolve().parent
WHEEL_INPUTS = (
    "pyproject.toml", "README.md", "LICENSE", "acsd.py", "acsd_version.py", "approval_set.py",
    "claim_derivation.py", "cose.py", "event_disclosure.py", "identity_disclosure.py",
    "package_manifest.py", "pec_core.py", "tsa.py", "verification_transcript.py",
)


def _tree_paths():
    """Return the complete tree except Git's private object database.

    Ignored caches are intentionally included: a read-only gate must notice a
    newly created .pyc, build directory, symlink, or empty directory too.
    """
    paths = []
    for directory, names, files in os.walk(ROOT, topdown=True, followlinks=False):
        base = pathlib.Path(directory)
        if base == ROOT and ".git" in names:
            names.remove(".git")
        for name in names + files:
            paths.append(base / name)
    return paths


def _snapshot():
    result = {}
    for path in _tree_paths():
        relative = path.relative_to(ROOT).as_posix()
        mode = path.lstat().st_mode & 0o777
        if path.is_symlink():
            result[relative] = f"SYMLINK:{mode:o}:" + os.readlink(path)
        elif path.is_file():
            result[relative] = f"FILE:{mode:o}:" + hashlib.sha256(path.read_bytes()).hexdigest()
        elif path.is_dir():
            result[relative] = f"DIR:{mode:o}"
        else:
            result[relative] = f"OTHER:{mode:o}"
    return result


def _python_in(venv_dir: pathlib.Path) -> pathlib.Path:
    return venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _acsd_in(venv_dir: pathlib.Path) -> pathlib.Path:
    return venv_dir / ("Scripts/acsd.exe" if os.name == "nt" else "bin/acsd")


def _installed_cli_e2e(temp: pathlib.Path, wheel: pathlib.Path, env):
    venv_dir = temp / "venv"
    venv.EnvBuilder(with_pip=True, system_site_packages=True).create(venv_dir)
    python = _python_in(venv_dir)
    acsd = _acsd_in(venv_dir)
    _run(
        "wheel-install",
        [str(python), "-m", "pip", "install", str(wheel), "--no-deps"],
        cwd=temp,
        env=env,
    )
    _run("installed-cli-version", [str(acsd), "--version"], cwd=temp, env=env)
    e2e = temp / "installed-cli-e2e"
    e2e.mkdir()
    paper = e2e / "paper.txt"
    paper.write_text("Installed ACSD command-line end-to-end check.\n", encoding="utf-8")
    keys = e2e / "keys"
    release = e2e / "release"
    _run(
        "installed-cli-keygen",
        [str(acsd), "keygen", "--name", "author", "--out-dir", str(keys)],
        cwd=e2e,
        env=env,
    )
    _run(
        "installed-cli-release",
        [
            str(acsd), "release", str(paper), "--key", str(keys / "author.key"),
            "--out", str(release),
        ],
        cwd=e2e,
        env=env,
    )
    _run(
        "installed-cli-verify",
        [str(acsd), "verify", str(release)],
        cwd=e2e,
        env=env,
    )
    return {"name": "installed-cli-e2e", "status": "PASS"}


def _common_checks(checks, temp, env):
    """Checks that must run both in a source checkout and a fresh artifact."""
    checks.append(_run("python-unit", [sys.executable, "-m", "unittest", "-q"], env=env))
    checks.append(_run("canonical-differential", [sys.executable, "design/canonical_diff_runner.py"], env=env))
    checks.append(_run("canonical-fuzz", [sys.executable, "design/canonical_fuzz_runner.py"], env=env))
    checks.append(_run("semantic-confusion", [sys.executable, "design/semantic_confusion_runner.py"], env=env))
    checks.append(_run(
        "verification-certificate-differential",
        [sys.executable, "design/verification_certificate_diff.py"], env=env,
    ))
    checks.append(_run("scaling-smoke", [sys.executable, "design/benchmark_core.py"], env=env))
    checks.append(_run("v1-fixture", [sys.executable, "verify_v1_fixture.py"], env=env))
    demo = temp / "demo"
    checks.append(_run("demo-generate", [sys.executable, "generate_demo.py", str(demo)], env=env))
    checks.append(_run("demo-verify", [sys.executable, "verify_pec.py", str(demo)], env=env))


def _formal_checks(checks, temp, env):
    lake = _find_lake()
    if lake is None:
        raise RuntimeError("formal check requires lake; set ACSD_LAKE")
    formal_copy = temp / "formal"
    shutil.copytree(ROOT / "formal", formal_copy, ignore=shutil.ignore_patterns(".lake"))
    lean_env = dict(env)
    if lake.parent.name == "bin" and lake.parent.parent.name == ".elan":
        lean_env.setdefault("ELAN_HOME", str(lake.parent.parent))
    checks.append(_run("lean-build", [str(lake), "build"], cwd=formal_copy, env=lean_env))
    checker = formal_copy / ".lake" / "build" / "bin" / (
        "acsd-transcript-checker.exe" if os.name == "nt" else "acsd-transcript-checker"
    )
    checks.append(_run(
        "lean-transcript-differential",
        [sys.executable, str(ROOT / "design/lean_transcript_diff.py"),
         "--checker", str(checker)],
        cwd=ROOT, env=lean_env,
    ))
    checks.append(_run(
        "lean-axiom-audit", [str(lake), "env", "lean", "AxiomAudit.lean"],
        cwd=formal_copy, env=lean_env,
    ))


def _source_checks(checks, temp, env):
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
    checks.append(_run(
        "evidence-package-self-check",
        [sys.executable, str(evidence / "check.py"), "--artifact", "--skip-formal"],
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
    wheel = next(wheel_dir.glob("*.whl"))
    checks.append(_installed_cli_e2e(temp, wheel, env))


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
    parser.add_argument(
        "--artifact", action="store_true",
        help="verify a fresh immutable evidence package without source-only build steps",
    )
    args = parser.parse_args()
    artifact_mode = args.artifact or (
        (ROOT / "MANIFEST.sha256").is_file() and not (ROOT / ".git").exists()
    )
    if artifact_mode:
        if not (ROOT / "MANIFEST.sha256").is_file():
            raise RuntimeError("artifact mode requires MANIFEST.sha256 at the package root")
    before = _snapshot()
    env = dict(os.environ)
    env["ACSD_SKIP_NETWORK"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    checks = []
    with tempfile.TemporaryDirectory() as temporary:
        temp = pathlib.Path(temporary)
        if artifact_mode:
            checks.append(_run(
                "artifact-manifest-before",
                [sys.executable, "verify_release.py", "."], env=env,
            ))
        _common_checks(checks, temp, env)
        if not artifact_mode:
            _source_checks(checks, temp, env)
        if not args.skip_formal:
            _formal_checks(checks, temp, env)
        if artifact_mode:
            checks.append(_run(
                "artifact-manifest-after",
                [sys.executable, "verify_release.py", "."], env=env,
            ))
    after = _snapshot()
    if before != after:
        changed = sorted(set(before) ^ set(after) | {
            name for name in set(before) & set(after) if before[name] != after[name]
        })
        raise RuntimeError("read-only gate mutated workspace: " + ", ".join(changed))
    checks.append({
        "name": "artifact-byte-identity" if artifact_mode else "workspace-byte-identity",
        "status": "PASS",
    })
    print(json.dumps({"status": "PASS", "checks": checks}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
