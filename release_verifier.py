"""Offline ACSD release verification orchestration.

This module appraises exact bytes through the filesystem, COSE, lineage,
manifest, and RFC 3161 adapters, then delegates every grant to the typed claim
kernel.  It is deliberately independent of CLI parsing and authoring commands.
"""

import hashlib
import re
from pathlib import Path

import approval_set
import appraisal_transcript
import claim_derivation as claim_core
import cose
import tsa
from artifact_io import read_canonical
from canonical_json import canonical, digest, require
from cli_output import EXIT_INCOMPLETE, EXIT_OK, EXIT_VERIFY_FAIL
from key_identity import KEY_ID_RE
from key_material import check_release_key_paths, load_bound_public_key
from lineage_adapter import load_lineage_structure, verify_lineage_authorization
from package_manifest import payload_path, verify_manifest
from protocol_objects import (
    PEC_SCHEMA,
    check_approval_target,
    check_bindings,
    lineage_claim_subject,
)
from release_adapter import adapt_release


def validate_receipt_report(report):
    expected_fields = {
        "schema",
        "subject",
        "subject_digest",
        "nonce",
        "tsa_url",
        "tsa_cert_fingerprint",
        "capability",
    }
    require(
        isinstance(report, dict) and set(report) == expected_fields,
        "RECEIPT_REPORT_FIELDS",
    )
    require(
        report.get("schema") == "acsd-receipt-report/v1",
        "RECEIPT_REPORT_SCHEMA",
    )
    require(
        isinstance(report.get("subject"), str)
        and isinstance(report.get("subject_digest"), str)
        and KEY_ID_RE.fullmatch(report["subject_digest"])
        and isinstance(report.get("nonce"), str)
        and re.fullmatch(r"[0-9a-f]{32}", report["nonce"])
        and isinstance(report.get("tsa_url"), str)
        and bool(report["tsa_url"])
        and isinstance(report.get("tsa_cert_fingerprint"), str)
        and KEY_ID_RE.fullmatch(report["tsa_cert_fingerprint"])
        and isinstance(report.get("capability"), str),
        "RECEIPT_REPORT_INVALID",
    )


def verify_release_dir(
    root,
    trusted_tsa_cert_der=None,
    trusted_tsa_fingerprint=None,
    allow_local_test_tsa=False,
    require_external_time=False,
    expected_parent_release_id=None,
    include_appraisal_transcript=False,
):
    """Verify one release directory without mutating it."""
    root = Path(root)
    # Validate the closed package before interpreting attacker-controlled paths
    # or signed objects. A present manifest cannot be downgraded via state.json.
    manifest_path = root / "MANIFEST.sha256"
    if manifest_path.exists() or manifest_path.is_symlink():
        try:
            verify_manifest(root)
        except (OSError, UnicodeError, ValueError) as exc:
            return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": str(exc)}

    state = read_canonical(root / "state.json")
    release = read_canonical(root / "release/release.json")
    governance = read_canonical(root / "governance/statement.json")
    pec = read_canonical(root / "pec/pec.json")
    target = read_canonical(root / "approval/target.json")
    adapted = adapt_release(release)
    check_release_key_paths(release)
    try:
        content_file = payload_path(root, release["content"]["path"])
        content_bytes = content_file.read_bytes()
    except (OSError, ValueError) as exc:
        return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": str(exc)}
    if hashlib.sha256(content_bytes).hexdigest() != release["content"]["sha256"]:
        return EXIT_VERIFY_FAIL, "TAMPERED", {
            "error_code": "CONTENT_DIGEST_MISMATCH"
        }
    try:
        check_bindings(pec, adapted, governance, release)
        lineage = load_lineage_structure(root, release, governance, pec)
        transition = lineage["transition"] if lineage is not None else None
        check_approval_target(
            target,
            release,
            governance,
            pec,
            adapted,
            transition,
        )
    except ValueError as exc:
        return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": str(exc)}

    key_ids = sorted(adapted["author_key_ids"])
    target_bytes = canonical(target)
    valid = {}
    approval_certificate_digests = {}
    for key_id in key_ids:
        approval_path = root / f"approvals/{key_id}.cose"
        try:
            public_key = load_bound_public_key(root, key_id)
        except ValueError as exc:
            return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": str(exc)}
        if not approval_path.exists():
            continue
        try:
            approval_bytes = approval_path.read_bytes()
            cose.cose_verify(
                approval_bytes,
                public_key,
                expected_payload=target_bytes,
            )
            valid[key_id] = True
            approval_certificate_digests[key_id] = hashlib.sha256(
                approval_bytes
            ).hexdigest()
        except ValueError as exc:
            return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": str(exc)}
        except Exception:
            return EXIT_VERIFY_FAIL, "TAMPERED", {
                "error_code": "APPROVAL_SIGNATURE_INVALID"
            }
    missing = [key_id for key_id in key_ids if not valid.get(key_id)]
    permitted = pec["claim_policy"]["permitted_outcomes"]
    claim_core.permitted_claims(permitted)
    appraised_evidence = []
    data = {
        "work_id": adapted["work_id"],
        "release_digest": adapted["digest"],
        "parent_release_id": release.get("parent_release_id"),
        "pec_digest": digest(pec),
        "approval_target_digest": digest(target),
        "state": state.get("state"),
        "missing_approvals": missing,
        "granted_outcomes": [],
        "non_claims": pec["claim_policy"]["global_non_claims"],
    }

    def refresh_granted_outcomes():
        transcript = appraisal_transcript.build(permitted, appraised_evidence)
        derivations = appraisal_transcript.derive(transcript)
        data["granted_outcomes"] = list(claim_core.wire_outcomes(derivations))
        if include_appraisal_transcript:
            data["appraisal_transcript"] = transcript

    refresh_granted_outcomes()
    if missing:
        return EXIT_INCOMPLETE, "INCOMPLETE", data
    if (
        expected_parent_release_id is not None
        and release.get("parent_release_id") != expected_parent_release_id
    ):
        return EXIT_VERIFY_FAIL, "TAMPERED", {
            **data,
            "error_code": "PARENT_PIN_MISMATCH",
        }
    try:
        lineage_result = verify_lineage_authorization(root, lineage, set(valid))
    except ValueError as exc:
        if str(exc) == "UNAUTHORIZED_SUCCESSOR":
            data["lineage_status"] = "UNAUTHORIZED_SUCCESSOR"
            return (
                EXIT_VERIFY_FAIL,
                "VALID_OBJECT_BUT_UNAUTHORIZED_SUCCESSOR",
                data,
            )
        return EXIT_VERIFY_FAIL, "TAMPERED", {
            **data,
            "error_code": str(exc),
        }
    data["lineage_status"] = lineage_result["status"]
    data["lineage_anchor_status"] = (
        "GENESIS"
        if lineage is None
        else "PIN_MATCHED"
        if expected_parent_release_id is not None
        else "UNPINNED_EXACT_PARENT"
    )
    separate_lineage_keys = (
        lineage_result["valid"]
        if lineage is not None
        and lineage["parent_authority"] != lineage["child_authority"]
        else []
    )
    approval_set_path = root / "approval/approval-set.json"
    approval_set_obj = None
    if approval_set_path.exists():
        try:
            approval_set_obj = read_canonical(approval_set_path)
            approval_set.verify(
                approval_set_obj,
                root,
                target,
                key_ids,
                separate_lineage_keys,
            )
        except (OSError, ValueError) as exc:
            return EXIT_VERIFY_FAIL, "TAMPERED", {
                **data,
                "error_code": str(exc),
            }
        data["approval_set_digest"] = digest(approval_set_obj)
    elif pec.get("schema") == PEC_SCHEMA and state.get("state") in (
        "finalized",
        "finalized-untimestamped",
    ):
        return EXIT_VERIFY_FAIL, "TAMPERED", {
            **data,
            "error_code": "APPROVAL_SET_MISSING",
        }

    approval_support_digest = (
        digest(approval_set_obj)
        if approval_set_obj is not None
        else digest({
            "target_digest": digest(target),
            "approval_certificate_digests": [
                {
                    "key_id": key_id,
                    "sha256": approval_certificate_digests[key_id],
                }
                for key_id in key_ids
            ],
        })
    )
    appraised_evidence.append(claim_core.AppraisedEvidence(
        claim_core.EvidenceKind.UNANIMOUS_APPROVAL,
        claim_core.ApprovalTargetSubject(digest(target)),
        approval_support_digest,
    ))
    if lineage is not None and approval_set_obj is not None:
        appraised_evidence.append(claim_core.AppraisedEvidence(
            claim_core.EvidenceKind.LINEAGE_AUTHORIZATION,
            lineage_claim_subject(lineage),
            digest(approval_set_obj),
        ))

    refresh_granted_outcomes()

    # Current releases timestamp the complete approval set. Legacy PECs retain
    # target-only semantics and cannot be upgraded to approval-set existence.
    timestamp_response_path = root / "receipts/response.tsr"
    if timestamp_response_path.exists():
        report = read_canonical(root / "receipts/report.json")
        validate_receipt_report(report)
        if pec.get("schema") == PEC_SCHEMA:
            if approval_set_obj is None:
                return EXIT_VERIFY_FAIL, "TAMPERED", {
                    "error_code": "APPROVAL_SET_MISSING"
                }
            subject_path = "approval/approval-set.json"
            subject_digest = digest(approval_set_obj)
            capability = "rfc3161-exact-approval-set-imprint"
        else:
            subject_path = "approval/target.json"
            subject_digest = digest(target)
            capability = "rfc3161-exact-approval-target-imprint"
        subject_digest_bytes = bytes.fromhex(subject_digest)
        if (
            report.get("subject") != subject_path
            or report.get("subject_digest") != subject_digest
            or report.get("capability") != capability
        ):
            return EXIT_VERIFY_FAIL, "TAMPERED", {
                "error_code": "RECEIPT_REPORT_BINDING_MISMATCH"
            }
        timestamp_query = tsa.parse_tsq(
            (root / "receipts/request.tsq").read_bytes()
        )
        if timestamp_query["imprint"] != subject_digest_bytes:
            return EXIT_VERIFY_FAIL, "TAMPERED", {
                "error_code": "TSQ_IMPRINT_MISMATCH"
            }
        if int(report.get("nonce", ""), 16) != timestamp_query["nonce"]:
            return EXIT_VERIFY_FAIL, "TAMPERED", {
                "error_code": "TSQ_NONCE_MISMATCH"
            }

        is_local_test = report.get("tsa_url") == "local"
        verification_certificate = trusted_tsa_cert_der
        verification_fingerprint = trusted_tsa_fingerprint
        allow_self_signed = False
        if is_local_test and allow_local_test_tsa:
            verification_certificate = (
                root / "receipts/tsa-cert.der"
            ).read_bytes()
            allow_self_signed = True
        if verification_certificate is None and verification_fingerprint is None:
            data["timestamp_status"] = "PRESENT_UNVERIFIED_NO_EXTERNAL_TRUST"
            if require_external_time:
                return EXIT_INCOMPLETE, "EXTERNAL_TIME_UNVERIFIED", data
        else:
            try:
                timestamp_info = tsa.verify_tsr(
                    timestamp_response_path.read_bytes(),
                    subject_digest_bytes,
                    trusted_cert_der=verification_certificate,
                    trusted_fingerprint=verification_fingerprint,
                    expected_nonce=timestamp_query["nonce"],
                    allow_self_signed=allow_self_signed,
                )
            except ValueError as exc:
                return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": str(exc)}
            data["timestamp_status"] = (
                "LOCAL_TEST_VERIFIED" if is_local_test else "EXTERNAL_PIN_VERIFIED"
            )
            data["timestamp_gen_time"] = timestamp_info["genTime"].isoformat()
            data["timestamp_signer_fingerprint"] = timestamp_info[
                "signer_fingerprint"
            ]
            if not is_local_test:
                if pec.get("schema") == PEC_SCHEMA:
                    time_kind = claim_core.EvidenceKind.APPROVAL_SET_TIMESTAMP
                    time_subject = claim_core.ApprovalSetTimeSubject(
                        subject_digest,
                        timestamp_info["genTime"].isoformat(),
                    )
                    expected_outcome = "APPROVAL_SET_EXISTED_NOT_AFTER"
                else:
                    time_kind = claim_core.EvidenceKind.APPROVAL_TARGET_TIMESTAMP
                    time_subject = claim_core.ApprovalTargetTimeSubject(
                        subject_digest,
                        timestamp_info["genTime"].isoformat(),
                    )
                    expected_outcome = "EXTERNALLY_NOT_AFTER"
                appraised_evidence.append(claim_core.AppraisedEvidence(
                    time_kind,
                    time_subject,
                    hashlib.sha256(
                        timestamp_response_path.read_bytes()
                    ).hexdigest(),
                ))
                refresh_granted_outcomes()
                if (
                    expected_outcome not in data["granted_outcomes"]
                    and require_external_time
                ):
                    return EXIT_INCOMPLETE, "EXTERNAL_TIME_NOT_AUTHORIZED", data
    elif require_external_time:
        return EXIT_INCOMPLETE, "EXTERNAL_TIME_MISSING", data
    if not manifest_path.exists() and state.get("state") in (
        "finalized",
        "finalized-untimestamped",
    ):
        return EXIT_VERIFY_FAIL, "TAMPERED", {"error_code": "MANIFEST_MISSING"}
    return EXIT_OK, "VALID", data
