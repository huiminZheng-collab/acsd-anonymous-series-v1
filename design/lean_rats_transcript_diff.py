#!/usr/bin/env python3
"""Differentially compare the bounded RATS transcript in Python and Lean."""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parent
PROJECT = ROOT.parent
sys.path.insert(0, str(ROOT))

import rats_appraisal_transcript as rats  # noqa: E402


SUBJECT = {
    "token": 101, "attester": 102, "measurement": 103, "reference": 104,
    "nonce": 105, "verifier": 106, "policy": 107,
}


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def python_result(transcript: dict) -> dict:
    return {
        "schema": rats.RESULT_SCHEMA,
        "outcomes": list(rats.derive(transcript)),
    }


def run_lean(checker: pathlib.Path, raw: bytes, directory: pathlib.Path):
    path = directory / "rats-appraisal-transcript.json"
    path.write_bytes(raw)
    return subprocess.run(
        [str(checker), str(path)], cwd=PROJECT,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )


def cases(base: dict):
    yield "valid-complete", copy.deepcopy(base)

    value = copy.deepcopy(base)
    value["policy"]["permitted_outcomes"] = []
    yield "policy-denied", value

    for kind in rats.FACT_ORDER:
        value = copy.deepcopy(base)
        value["evidence"] = [item for item in value["evidence"] if item["kind"] != kind]
        for index, item in enumerate(value["evidence"]):
            item["index"] = index
        yield f"missing-{kind.lower()}", value

    for kind in rats.FACT_ORDER:
        value = copy.deepcopy(base)
        item = next(entry for entry in value["evidence"] if entry["kind"] == kind)
        field = rats.FACT_FIELDS[kind][-1]
        item[field] += 500
        yield f"substituted-{kind.lower()}", value

    value = copy.deepcopy(base)
    value["evidence"][0]["index"] = 1
    yield "wrong-index", value

    value = copy.deepcopy(base)
    value["evidence"][1]["index"] = True
    yield "boolean-index", value

    value = copy.deepcopy(base)
    value["evidence"][0]["kind"] = "UNKNOWN"
    yield "unknown-kind", value

    value = copy.deepcopy(base)
    value["evidence"][0]["extra"] = True
    yield "extra-evidence-field", value

    value = copy.deepcopy(base)
    value["evidence"][0], value["evidence"][1] = value["evidence"][1], value["evidence"][0]
    yield "wrong-kind-order", value

    value = copy.deepcopy(base)
    value["subject"]["nonce"] = 0
    yield "zero-subject-identifier", value

    value = copy.deepcopy(base)
    value["subject"]["nonce"] = True
    yield "boolean-subject-identifier", value

    value = copy.deepcopy(base)
    value["subject"]["nonce"] = rats.MAX_SAFE_INTEGER + 1
    yield "unsafe-subject-identifier", value

    value = copy.deepcopy(base)
    value["policy"]["permitted_outcomes"] = [rats.OUTCOME, rats.OUTCOME]
    yield "duplicate-policy-outcome", value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checker", required=True, type=pathlib.Path)
    args = parser.parse_args()
    checker = args.checker.resolve()
    base = rats.build(True, SUBJECT, rats.complete_evidence(SUBJECT))
    compared = 0
    with tempfile.TemporaryDirectory() as temporary:
        directory = pathlib.Path(temporary)
        for name, transcript in cases(base):
            raw = canonical_bytes(transcript)
            try:
                expected = python_result(transcript)
                python_error = None
            except ValueError as exc:
                expected = None
                python_error = str(exc)
            lean = run_lean(checker, raw, directory)
            if python_error is not None:
                if lean.returncode == 0:
                    raise AssertionError(
                        f"{name}: Python rejected {python_error}, Lean accepted {lean.stdout}"
                    )
            else:
                if lean.returncode != 0:
                    raise AssertionError(f"{name}: Lean rejected {lean.stderr.strip()}")
                actual = json.loads(lean.stdout)
                if actual != expected:
                    raise AssertionError(
                        f"{name}: Python/Lean mismatch\n{expected!r}\n{actual!r}"
                    )
            compared += 1

        noncanonical = json.dumps(base, indent=2, ensure_ascii=False).encode("utf-8")
        if run_lean(checker, noncanonical, directory).returncode == 0:
            raise AssertionError("noncanonical RATS transcript accepted by Lean")
        compared += 1

    print(f"lean-rats-transcript-differential: {compared}/{compared} cases PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
