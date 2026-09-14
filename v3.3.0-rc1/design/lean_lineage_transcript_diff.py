#!/usr/bin/env python3
"""Differentially compare Python and Lean lineage-certificate appraisal."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parent
PROJECT = ROOT.parent
sys.path.insert(0, str(PROJECT))

import claim_derivation as claims  # noqa: E402
import lineage_verification_transcript  # noqa: E402


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8") + b"\n"


def digest_nat(value: str) -> str:
    return str(int(value, 16))


def subject_json(subject: claims.Subject) -> dict:
    if not isinstance(subject, claims.LineageSubject):
        raise AssertionError("unexpected non-lineage subject")
    return {
        "kind": "lineage-edge",
        "work_id_digest_nat": digest_nat(subject.work_id_digest),
        "parent_release_digest_nat": digest_nat(subject.parent_release_digest),
        "parent_pec_digest_nat": digest_nat(subject.parent_pec_digest),
        "parent_line_digest_nat": digest_nat(subject.parent_line_digest),
        "parent_version": subject.parent_version,
        "child_release_digest_nat": digest_nat(subject.child_release_digest),
        "child_pec_digest_nat": digest_nat(subject.child_pec_digest),
        "child_line_digest_nat": digest_nat(subject.child_line_digest),
        "child_version": subject.child_version,
        "transition_digest_nat": digest_nat(subject.transition_digest),
    }


def python_result(certificate: dict, certificate_digest: str) -> dict:
    derivations = lineage_verification_transcript.derive(
        certificate, certificate_digest
    )
    normalized = [{
        "kind": claims.CLAIM_TO_WIRE[item.claim.kind],
        "subject": subject_json(item.claim.subject),
        "supporting_certificate_digests_nat": [
            digest_nat(value) for value in item.supporting_certificate_digests
        ],
    } for item in derivations]
    return {
        "schema": "acsd-lean-transcript-result/v1",
        "certificate_digest_nat": digest_nat(certificate_digest),
        "claims": normalized,
    }


def run_lean(checker: pathlib.Path, raw: bytes, directory: pathlib.Path):
    path = directory / "lineage-certificate.json"
    path.write_bytes(raw)
    certificate_digest = hashlib.sha256(raw).hexdigest()
    return subprocess.run(
        [str(checker), str(path), certificate_digest],
        cwd=PROJECT, capture_output=True, text=True, encoding="utf-8",
        errors="replace",
    )


def mutations(base: dict):
    yield "valid-team-change", copy.deepcopy(base)

    value = copy.deepcopy(base)
    index = next(i for i, item in enumerate(value["signature_facts"])
                 if item["purpose"] == "predecessor-authorization")
    del value["signature_facts"][index]
    yield "missing-predecessor-authorization", value

    value = copy.deepcopy(base)
    item = next(item for item in value["signature_facts"]
                if item["purpose"] == "predecessor-authorization")
    item["payload_digest"] = "0" * 64
    yield "predecessor-payload-substitution", value

    value = copy.deepcopy(base)
    item = next(item for item in value["inputs"]
                if item["role"] == "predecessor-authorization-cose")
    item["sha256"] = "0" * 64
    yield "predecessor-cose-input-substitution", value

    value = copy.deepcopy(base)
    item = next(item for item in value["inputs"]
                if item["role"] == "parent-public-key")
    item["sha256"] = "0" * 64
    yield "parent-public-key-input-substitution", value

    value = copy.deepcopy(base)
    index = next(i for i, item in enumerate(value["signature_facts"])
                 if item["purpose"] == "child-approval")
    del value["signature_facts"][index]
    yield "missing-child-approval", value

    value = copy.deepcopy(base)
    value["lineage_edge"]["child"]["bound_transition_digest"] = "0" * 64
    yield "unbound-transition", value

    value = copy.deepcopy(base)
    value["approval_set"]["lineage_authorizations"][0]["cose_sha256"] = "0" * 64
    yield "approval-set-lineage-substitution", value

    value = copy.deepcopy(base)
    value["policy"]["permitted_outcomes"].remove("AUTHORIZED_SUCCESSOR")
    yield "policy-absence", value

    value = copy.deepcopy(base)
    value["lineage_edge"]["child"]["version"] += 1
    yield "nonconsecutive-child", value

    value = copy.deepcopy(base)
    value["lineage_edge"]["authorization_mode"] = "continuity"
    yield "mode-substitution", value

    value = copy.deepcopy(base)
    value["lineage_edge"]["transition_kind"] = "continuation"
    yield "transition-kind-substitution", value

    value = copy.deepcopy(base)
    item = next(item for item in value["inputs"]
                if item["role"] == "lineage-transition")
    item["sha256"] = "0" * 64
    yield "transition-input-substitution", value

    value = copy.deepcopy(base)
    value["unexpected"] = True
    yield "unexpected-field", value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checker", required=True, type=pathlib.Path)
    args = parser.parse_args()
    checker = args.checker.resolve()
    base = json.loads(
        (ROOT / "lineage_verification_certificate_demo.json").read_bytes()
    )
    compared = 0
    with tempfile.TemporaryDirectory() as temporary:
        directory = pathlib.Path(temporary)
        for name, certificate in mutations(base):
            raw = canonical(certificate)
            certificate_digest = hashlib.sha256(raw).hexdigest()
            try:
                expected = python_result(certificate, certificate_digest)
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
                    raise AssertionError(
                        f"{name}: Lean rejected: {lean.stderr.strip()}"
                    )
                actual = json.loads(lean.stdout)
                if actual != expected:
                    raise AssertionError(
                        f"{name}: Python/Lean mismatch\n{expected!r}\n{actual!r}"
                    )
            compared += 1

        noncanonical = json.dumps(base, indent=2).encode("utf-8")
        lean = run_lean(checker, noncanonical, directory)
        if lean.returncode == 0:
            raise AssertionError("noncanonical lineage JSON was accepted by Lean")
        compared += 1

    print(f"lean-lineage-transcript-differential: {compared}/{compared} cases PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
