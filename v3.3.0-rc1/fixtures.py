"""Deterministic corpus covering the frozen TEST-PLAN attack matrix.

Each corpus case is a (name, evaluator, expected) triple where the evaluator
is a zero-argument closure that builds its inputs, runs the relevant verifier
(validate_pec, verify_legacy_disclosure_metadata, verify_dialogue_window, or
verify_sidecar_subject), and returns "VALID" or the rejection error code.

The two series-layer cases from TEST-PLAN (exclusive-slot-double-sign ->
EQUIVOCATION, and missing-sidecar -> INDETERMINATE) are not implemented here:
they are v1 series-layer states, not v0.1 PEC acceptance predicates.
"""
import copy

from pec_core import (
    digest,
    dialogue_proof,
    dialogue_root,
    validate_pec,
    verify_dialogue_window,
    verify_legacy_disclosure_metadata,
    verify_sidecar_subject,
)

AUTHOR_KEYS = ["k1", "k2"]
WORK_ID = "urn:uuid:demo"
NON_CLAIMS = [
    "natural_person_authorship",
    "contribution_truth",
    "originality_truth",
    "legal_nonrepudiation",
    "peer_review",
]
RFC3161_CAPABILITY = "rfc3161-exact-approval-target-imprint"
APPROVAL_TARGET_DIGEST = "d" * 64


def _build_events(datas):
    events = []
    previous = None
    for i, data in enumerate(datas):
        e = {"sequence": i, "previous_event_digest": previous, **data}
        events.append(e)
        previous = digest(e)
    return events


def valid_fixture():
    release = {
        "digest": "a" * 64,
        "content_sha256": "b" * 64,
        "author_key_ids": AUTHOR_KEYS,
        "work_id": WORK_ID,
    }
    governance = {
        "schema": "acsd-v1.6.0-authorship-governance/v1",
        "work_id": WORK_ID,
        "manuscript_sha256": "b" * 64,
        "byline": [
            {"key_id": "k1", "slot": 1, "role": "co-first"},
            {"key_id": "k2", "slot": 2, "role": "co-first"},
        ],
        "corresponding_author": {"key_id": "k1"},
        "ai_use_declaration": {"used": False},
    }
    turns = [
        {"bytes": b"turn-0", "salt": bytes([0xA1]) * 32},
        {"bytes": b"turn-1", "salt": bytes([0xA2]) * 32},
        {"bytes": b"turn-2", "salt": bytes([0xA3]) * 32},
    ]
    root = dialogue_root(turns)
    events = _build_events([
        {"event_id": "git-01", "kind": "git_commit_snapshot",
         "commitment": {"scheme": "salted-sha256-v1", "digest": "c" * 64, "disclosure_class": "sealed"}},
        {"event_id": "dialogue-01", "kind": "dialogue_window",
         "commitment": {"scheme": "salted-sha256-v1", "digest": root, "disclosure_class": "sealed"}},
    ])
    pec = {
        "schema": "acsd-pec/v0.1",
        "pec_id": "pec-demo-01",
        "subject": {"work_id": WORK_ID, "release_digest": release["digest"]},
        "governance": {
            "statement_digest": digest(governance),
            "manuscript_sha256": release["content_sha256"],
            "required_pec_approval_key_ids": AUTHOR_KEYS,
            "ai_use_declaration_digest": digest(governance["ai_use_declaration"]),
        },
        "issuer_key_id": "k1",
        "events": events,
        "claim_policy": {
            "permitted_outcomes": ["KEY_ASSENT", "GOVERNANCE_ASSENT", "EXTERNALLY_NOT_AFTER"],
            "global_non_claims": NON_CLAIMS,
            "required_capabilities": {"EXTERNALLY_NOT_AFTER": [RFC3161_CAPABILITY]},
        },
    }
    return release, governance, pec, turns


def _run(fn):
    try:
        fn()
        return "VALID"
    except ValueError as e:
        return str(e)


def _eval_validate(pec, approvals, release, governance):
    validate_pec(pec, approvals, release, {"digest": digest(governance)})


def corpus():
    release, governance, pec, turns = valid_fixture()
    dialogue_event = pec["events"][1]
    cases = []

    # --- validate_pec cases ---
    cases.append(("pec-v1-valid", lambda: _run(lambda: _eval_validate(pec, AUTHOR_KEYS, release, governance)), "VALID"))

    def _role_order():
        g = copy.deepcopy(governance)
        g["byline"] = [g["byline"][1], g["byline"][0]]
        _eval_validate(pec, AUTHOR_KEYS, release, g)
    cases.append(("role-order-mutated", lambda: _run(_role_order), "GOVERNANCE_BINDING_MISMATCH"))

    def _corresponding():
        g = copy.deepcopy(governance)
        g["corresponding_author"] = {"key_id": "k2"}
        _eval_validate(pec, AUTHOR_KEYS, release, g)
    cases.append(("corresponding-mutated", lambda: _run(_corresponding), "GOVERNANCE_BINDING_MISMATCH"))

    def _ai():
        g = copy.deepcopy(governance)
        g["ai_use_declaration"] = {"used": True}
        _eval_validate(pec, AUTHOR_KEYS, release, g)
    cases.append(("ai-disclosure-mutated", lambda: _run(_ai), "GOVERNANCE_BINDING_MISMATCH"))

    def _social():
        p = copy.deepcopy(pec)
        p["claim_policy"]["permitted_outcomes"].append("NATURAL_PERSON_AUTHORSHIP")
        _eval_validate(p, AUTHOR_KEYS, release, governance)
    cases.append(("social-claim-injected", lambda: _run(_social), "CLAIM_POLICY_UNKNOWN_OUTCOME"))

    cases.append(("missing-approval", lambda: _run(lambda: _eval_validate(pec, ["k1"], release, governance)), "PEC_APPROVAL_MISSING"))

    def _broken():
        p = copy.deepcopy(pec)
        p["events"][0]["sequence"] = 2
        _eval_validate(p, AUTHOR_KEYS, release, governance)
    cases.append(("event-chain-broken", lambda: _run(_broken), "EVENT_CHAIN_BROKEN"))

    def _v2():
        old = copy.deepcopy(pec)
        new = copy.deepcopy(pec)
        new["pec_id"] = "pec-demo-02"
        new["subject"]["predecessor_pec_digest"] = digest(old)
        extra = {"event_id": "git-02", "kind": "git_commit_snapshot",
                 "commitment": {"scheme": "salted-sha256-v1", "digest": "d" * 64, "disclosure_class": "sealed"}}
        new["events"] = _build_events([dict(e) for e in new["events"]][:2] + [extra])
        validate_pec(new, AUTHOR_KEYS, release, {"digest": digest(governance)}, predecessor_pec=old)
    cases.append(("pec-v2-valid", lambda: _run(_v2), "VALID"))

    # --- legacy disclosure-metadata cases ---
    git_event = pec["events"][0]
    valid_disclosure = {
        "pec_digest": digest(pec),
        "event_id": "git-01",
        "event_sequence": 0,
        "kind": "git_commit_snapshot",
        "approval_key_ids": list(AUTHOR_KEYS),
    }

    def _foreign_git():
        foreign_pec = copy.deepcopy(pec)
        foreign_pec["pec_id"] = "pec-other"
        foreign_pec["events"][0]["event_id"] = "git-foreign"
        d = dict(valid_disclosure, pec_digest=digest(foreign_pec))
        verify_legacy_disclosure_metadata(d, pec, git_event)
    cases.append(("foreign-git-disclosure", lambda: _run(_foreign_git), "DISCLOSURE_BINDING_MISMATCH"))

    def _single_author():
        d = dict(valid_disclosure, approval_key_ids=["k1"])
        verify_legacy_disclosure_metadata(d, pec, git_event, required_approval_key_ids=AUTHOR_KEYS)
    cases.append(("single-author-disclosure", lambda: _run(_single_author), "DISCLOSURE_APPROVAL_MISSING"))

    # --- verify_dialogue_window cases ---
    root = dialogue_event["commitment"]["digest"]

    def _window():
        return [
            {"index": i, "bytes": turns[i]["bytes"], "salt": turns[i]["salt"], "path": dialogue_proof(turns, i)}
            for i in range(len(turns))
        ]

    def _foreign_dialogue():
        other_turns = [{"bytes": b"other", "salt": bytes([0xEE]) * 32}]
        verify_dialogue_window(root, [{"index": 0, "bytes": other_turns[0]["bytes"],
                                       "salt": other_turns[0]["salt"], "path": dialogue_proof(other_turns, 0)}])
    cases.append(("foreign-dialogue-disclosure", lambda: _run(_foreign_dialogue), "DISCLOSURE_BINDING_MISMATCH"))

    def _wrong_salt():
        w = _window()
        w[0]["salt"] = bytes([0xFF]) * 32
        verify_dialogue_window(root, w)
    cases.append(("wrong-salt", lambda: _run(_wrong_salt), "DISCLOSURE_BINDING_MISMATCH"))

    def _noncontiguous():
        w = _window()
        verify_dialogue_window(root, [w[0], w[2]])
    cases.append(("noncontiguous-dialogue", lambda: _run(_noncontiguous), "DISCLOSURE_WINDOW_INVALID"))

    # --- verify_sidecar_subject cases ---
    def _git_time():
        verify_sidecar_subject({"subject_digest": APPROVAL_TARGET_DIGEST, "capability": "git-timestamp"}, pec, "EXTERNALLY_NOT_AFTER", APPROVAL_TARGET_DIGEST)
    cases.append(("git-time-upgrade", lambda: _run(_git_time), "TIME_CAPABILITY_MISSING"))

    def _witness_time():
        verify_sidecar_subject({"subject_digest": APPROVAL_TARGET_DIGEST, "capability": "witness-observation"}, pec, "EXTERNALLY_NOT_AFTER", APPROVAL_TARGET_DIGEST)
    cases.append(("witness-time-upgrade", lambda: _run(_witness_time), "TIME_CAPABILITY_MISSING"))

    def _valid_sidecar():
        verify_sidecar_subject({"subject_digest": APPROVAL_TARGET_DIGEST, "capability": RFC3161_CAPABILITY}, pec, "EXTERNALLY_NOT_AFTER", APPROVAL_TARGET_DIGEST)
    cases.append(("valid-rfc3161-sidecar", lambda: _run(_valid_sidecar), "VALID"))

    def _replayed():
        verify_sidecar_subject({"subject_digest": "0" * 64, "capability": RFC3161_CAPABILITY}, pec, "EXTERNALLY_NOT_AFTER", APPROVAL_TARGET_DIGEST)
    cases.append(("receipt-replayed-to-v2", lambda: _run(_replayed), "RECEIPT_SUBJECT_MISMATCH"))

    return release, governance, cases


def evaluate_case(name, evaluator):
    return evaluator()
