"""Differentially compare Python and Lean transcript appraisal.

The Python and Node adapters already agree on the claim-free canonical JSON.
This runner mutates that checked transcript, lets each structural checker parse
it independently, and compares complete scoped derivations rather than outcome
names alone.
"""

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
import verification_transcript  # noqa: E402


def canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8") + b"\n"


def digest_nat(value: str) -> str:
    return str(int(value, 16))


def subject_json(subject: claims.Subject) -> dict:
    if isinstance(subject, claims.ApprovalTargetSubject):
        return {
            "kind": "approval-target",
            "target_digest_nat": digest_nat(subject.target_digest),
        }
    if isinstance(subject, claims.ApprovalSetTimeSubject):
        return {
            "kind": "approval-set-time",
            "set_digest_nat": digest_nat(subject.approval_set_digest),
            "not_after_utc": subject.not_after_utc,
        }
    if isinstance(subject, claims.ApprovalTargetTimeSubject):
        return {
            "kind": "approval-target-time",
            "target_digest_nat": digest_nat(subject.target_digest),
            "not_after_utc": subject.not_after_utc,
        }
    if isinstance(subject, claims.EventSubject):
        return {
            "kind": "event-window",
            "pec_digest_nat": digest_nat(subject.pec_digest),
            "event_id": subject.event_id,
            "event_sequence": subject.event_sequence,
            "commitment_digest_nat": digest_nat(subject.commitment_digest),
            "first_index": subject.first_index,
            "last_index": subject.last_index,
        }
    if isinstance(subject, claims.IdentitySubject):
        return {
            "kind": "identity-assertion",
            "release_digest_nat": digest_nat(subject.release_digest),
            "author_slot": subject.author_slot,
            "key_id_nat": digest_nat(subject.author_key_id),
            "assertion_digest_nat": digest_nat(subject.assertion_digest),
        }
    raise AssertionError("unexpected claim subject in v1 transcript")


def python_result(certificate: dict, certificate_digest: str) -> dict:
    derivations = verification_transcript.derive(certificate, certificate_digest)
    normalized = []
    for derivation in derivations:
        normalized.append({
            "kind": claims.CLAIM_TO_WIRE[derivation.claim.kind],
            "subject": subject_json(derivation.claim.subject),
            "supporting_certificate_digests_nat": [
                digest_nat(item) for item in derivation.supporting_certificate_digests
            ],
        })
    return {
        "schema": "acsd-lean-transcript-result/v1",
        "certificate_digest_nat": digest_nat(certificate_digest),
        "claims": normalized,
    }


def run_lean(checker: pathlib.Path, raw: bytes, directory: pathlib.Path):
    path = directory / "certificate.json"
    path.write_bytes(raw)
    certificate_digest = hashlib.sha256(raw).hexdigest()
    return subprocess.run(
        [str(checker), str(path), certificate_digest],
        cwd=PROJECT, capture_output=True, text=True, encoding="utf-8",
        errors="replace",
    )


def mutations(base: dict):
    yield "valid", copy.deepcopy(base)

    value = copy.deepcopy(base)
    del value["signature_facts"][0]
    yield "missing-author-signature", value

    value = copy.deepcopy(base)
    index = next(i for i, item in enumerate(value["signature_facts"])
                 if item["purpose"] == "event-disclosure")
    del value["signature_facts"][index]
    yield "missing-event-signature", value

    value = copy.deepcopy(base)
    value["merkle_facts"].append(copy.deepcopy(value["merkle_facts"][0]))
    yield "extra-merkle-fact", value

    value = copy.deepcopy(base)
    value["signature_facts"][0]["payload_digest"] = "0" * 64
    yield "approval-payload-substitution", value

    value = copy.deepcopy(base)
    value["signature_facts"].insert(1, copy.deepcopy(value["signature_facts"][0]))
    yield "duplicate-approval-signature", value

    value = copy.deepcopy(base)
    item = next(entry for entry in value["inputs"]
                if entry["role"] == "author-approval-cose")
    item["sha256"] = "0" * 64
    yield "approval-cose-input-substitution", value

    value = copy.deepcopy(base)
    value["event_disclosure"]["pec_digest"] = "0" * 64
    yield "event-pec-substitution", value

    value = copy.deepcopy(base)
    value["policy"]["pec_digest"] = "0" * 64
    yield "policy-pec-substitution", value

    value = copy.deepcopy(base)
    value["approval_target"]["required_key_ids"] = []
    yield "empty-approval-keys", value

    value = copy.deepcopy(base)
    value["event_disclosure"]["required_key_ids"] = []
    yield "empty-event-keys", value

    value = copy.deepcopy(base)
    value["event_disclosure"]["event_sequence"] = 9_007_199_254_740_992
    yield "unsafe-event-sequence", value

    value = copy.deepcopy(base)
    value["event_disclosure"]["event_id"] = "对话-α"
    yield "unicode-event-id", value

    value = copy.deepcopy(base)
    value["identity_assertions"] = [{}]
    yield "unsupported-extension", value

    value = copy.deepcopy(base)
    value["unexpected"] = True
    yield "unexpected-field", value


def identity_mutations(base: dict):
    yield "identity-v2-valid", copy.deepcopy(base)

    value = copy.deepcopy(base)
    value["identity_assertions"][0]["author_slot"] = 2
    yield "identity-slot-substitution", value

    value = copy.deepcopy(base)
    value["identity_assertions"][0]["author_key_id"] = (
        value["release_context"]["author_slots"][1]["key_id"]
    )
    yield "identity-key-substitution", value

    value = copy.deepcopy(base)
    item = next(entry for entry in value["inputs"]
                if entry["role"] == "identity-disclosure-cose")
    item["sha256"] = "0" * 64
    yield "identity-cose-input-substitution", value

    value = copy.deepcopy(base)
    signature = next(entry for entry in value["signature_facts"]
                     if entry["purpose"] == "identity-disclosure")
    signature["payload_digest"] = "0" * 64
    yield "identity-payload-substitution", value

    value = copy.deepcopy(base)
    value["identity_assertions"][0]["release_digest"] = "0" * 64
    yield "identity-release-substitution", value

    value = copy.deepcopy(base)
    value["policy"]["permitted_outcomes"].remove(
        "SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION"
    )
    yield "identity-policy-absence", value

    value = copy.deepcopy(base)
    value["identity_assertions"].append(copy.deepcopy(value["identity_assertions"][0]))
    yield "identity-slot-conflict", value

    value = copy.deepcopy(base)
    value["identity_assertions"][0]["author_slot"] = 0
    yield "identity-zero-slot", value

    value = copy.deepcopy(base)
    value["release_context"]["author_slots"][1]["key_id"] = (
        value["release_context"]["author_slots"][0]["key_id"]
    )
    yield "release-duplicate-author-key", value


def time_mutations(base: dict):
    yield "time-v3-valid", copy.deepcopy(base)

    value = copy.deepcopy(base)
    item = next(entry for entry in value["inputs"] if entry["role"] == "time-response")
    item["sha256"] = "0" * 64
    yield "time-response-input-substitution", value

    value = copy.deepcopy(base)
    value["approval_set"]["author_approvals"][0]["cose_sha256"] = "0" * 64
    yield "time-approval-entry-substitution", value

    value = copy.deepcopy(base)
    value["timestamp_facts"][0]["authority_class"] = "local-test"
    yield "time-local-authority", value

    value = copy.deepcopy(base)
    value["trusted_inputs"][0]["signer_fingerprint"] = "0" * 64
    yield "time-trust-pin-substitution", value

    value = copy.deepcopy(base)
    value["approval_set"]["approval_target_digest"] = "0" * 64
    yield "time-target-substitution", value

    value = copy.deepcopy(base)
    value["policy"]["permitted_outcomes"].remove("APPROVAL_SET_EXISTED_NOT_AFTER")
    yield "time-policy-absence", value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checker", required=True, type=pathlib.Path)
    args = parser.parse_args()
    checker = args.checker.resolve()
    base = json.loads((ROOT / "verification_certificate_demo.json").read_bytes())
    identity_base = json.loads(
        (ROOT / "verification_certificate_demo_v2.json").read_bytes()
    )
    time_base = json.loads(
        (ROOT / "verification_certificate_demo_v3.json").read_bytes()
    )
    compared = 0
    with tempfile.TemporaryDirectory() as temporary:
        directory = pathlib.Path(temporary)
        cases = (
            list(mutations(base)) + list(identity_mutations(identity_base))
            + list(time_mutations(time_base))
        )
        for name, certificate in cases:
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
                actual["claims"] = sorted(
                    actual["claims"], key=lambda item: (item["kind"], repr(item["subject"]))
                )
                expected["claims"] = sorted(
                    expected["claims"], key=lambda item: (item["kind"], repr(item["subject"]))
                )
                if actual != expected:
                    raise AssertionError(
                        f"{name}: Python/Lean mismatch\n{expected!r}\n{actual!r}"
                    )
            compared += 1

        for label, value in (("v1", base), ("v2", identity_base), ("v3", time_base)):
            noncanonical = json.dumps(value, indent=2).encode("utf-8")
            lean = run_lean(checker, noncanonical, directory)
            if lean.returncode == 0:
                raise AssertionError(f"noncanonical {label} JSON was accepted by Lean")
            compared += 1

    print(f"lean-transcript-differential: {compared}/{compared} cases PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
