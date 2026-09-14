"""Pure validation of PEC bindings, policy, governance, and event structure."""

from canonical_json import digest, require


CURRENT_PEC_SCHEMA = "acsd-pec/v0.3"
LEGACY_PEC_SCHEMAS = frozenset({"acsd-pec/v0.1", "acsd-pec/v0.2"})
PEC_SCHEMAS = LEGACY_PEC_SCHEMAS | {CURRENT_PEC_SCHEMA}
GOVERNANCE_SCHEMA = "acsd-v1.6.0-authorship-governance/v1"

GLOBAL_NON_CLAIMS = (
    "natural_person_authorship",
    "contribution_truth",
    "originality_truth",
    "legal_nonrepudiation",
    "peer_review",
)
REQUIRED_NON_CLAIMS = frozenset(GLOBAL_NON_CLAIMS)
ALLOWED_OUTCOMES = frozenset({
    "KEY_ASSENT",
    "GOVERNANCE_ASSENT",
    "COMMITTED_EVIDENCE_MATCH",
    "EXTERNALLY_NOT_AFTER",
    "APPROVAL_SET_EXISTED_NOT_AFTER",
    "SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION",
    "AUTHORIZED_SUCCESSOR",
})

def new_disclosure_policy():
    """Return a fresh policy object so callers cannot mutate validator state."""
    return {
        "schema": "acsd-disclosure-policy/v1",
        "event_kinds": {
            "dialogue_snapshot": {
                "modes": ["dialogue_window"],
                "authorization": "all-release-authors",
            }
        }
    }


DEFAULT_DISCLOSURE_POLICY = new_disclosure_policy()


def validate_event_chain(events):
    previous = None
    event_ids = set()
    for sequence, event in enumerate(events):
        require(event["sequence"] == sequence, "EVENT_CHAIN_BROKEN")
        require(event["event_id"] not in event_ids, "EVENT_CHAIN_BROKEN")
        event_ids.add(event["event_id"])
        require(event["previous_event_digest"] == previous, "EVENT_CHAIN_BROKEN")
        previous = digest(event)


def validate_claim_policy(pec):
    policy = pec["claim_policy"]
    require(
        REQUIRED_NON_CLAIMS.issubset(set(policy["global_non_claims"])),
        "CLAIM_POLICY_INCOMPLETE",
    )
    outcomes = policy.get("permitted_outcomes", [])
    require(len(outcomes) == len(set(outcomes)), "CLAIM_POLICY_DUPLICATE")
    require(
        set(outcomes).issubset(ALLOWED_OUTCOMES),
        "CLAIM_POLICY_UNKNOWN_OUTCOME",
    )
    required = policy.get("required_capabilities", {})
    if pec.get("schema") == CURRENT_PEC_SCHEMA:
        require(
            pec.get("disclosure_policy") == new_disclosure_policy(),
            "DISCLOSURE_POLICY_INVALID",
        )
        require(
            required.get("APPROVAL_SET_EXISTED_NOT_AFTER")
            == ["rfc3161-exact-approval-set-imprint"],
            "CLAIM_POLICY_CAPABILITY_MISMATCH",
        )
        if "AUTHORIZED_SUCCESSOR" in outcomes:
            require(
                required.get("AUTHORIZED_SUCCESSOR")
                == ["predecessor-authority-exact-transition"],
                "CLAIM_POLICY_CAPABILITY_MISMATCH",
            )
    elif "EXTERNALLY_NOT_AFTER" in outcomes:
        require(
            required.get("EXTERNALLY_NOT_AFTER")
            == ["rfc3161-exact-approval-target-imprint"],
            "CLAIM_POLICY_CAPABILITY_MISMATCH",
        )
    return tuple(outcomes)


def _validate_release_governance(adapted, governance, release, current_pec):
    require(governance.get("schema") == GOVERNANCE_SCHEMA, "GOVERNANCE_SCHEMA")
    require(
        governance.get("work_id") == adapted["work_id"],
        "GOVERNANCE_WORK_ID_MISMATCH",
    )
    expected_byline = [{
        "key_id": author.get("key_id"),
        "slot": author.get("slot"),
        "role": author.get("role"),
    } for author in release.get("authors", [])]
    require(governance.get("byline") == expected_byline, "GOVERNANCE_BYLINE_MISMATCH")
    corresponding = [
        author.get("key_id")
        for author in release.get("authors", [])
        if author.get("corresponding") is True
    ]
    require(len(corresponding) == 1, "RELEASE_CORRESPONDING_AUTHOR_INVALID")
    require(
        governance.get("corresponding_author") == {"key_id": corresponding[0]},
        "GOVERNANCE_CORRESPONDING_AUTHOR_MISMATCH",
    )
    if current_pec:
        require(
            governance.get("ai_use_declaration") == release.get("ai_use"),
            "AI_USE_BINDING_MISMATCH",
        )


def validate_pec_bundle(
    pec,
    adapted,
    governance_digest,
    *,
    governance=None,
    release=None,
    approvals=None,
    predecessor_pec=None,
    check_predecessor=False,
    require_slot_bindings=False,
):
    """Validate all shared PEC semantics without filesystem or cryptography."""
    schema = pec.get("schema")
    require(schema in PEC_SCHEMAS, "PEC_SCHEMA")
    subject = pec["subject"]
    pec_governance = pec["governance"]
    require(
        subject["release_digest"] == adapted["digest"],
        "SUBJECT_RELEASE_MISMATCH",
    )
    require(subject["work_id"] == adapted["work_id"], "SUBJECT_WORK_ID_MISMATCH")
    if require_slot_bindings:
        require(
            subject.get("version") == f"v{adapted['version']}",
            "SUBJECT_VERSION_MISMATCH",
        )
        require(subject.get("line") == adapted["line"], "SUBJECT_LINE_MISMATCH")
    require(
        pec_governance["statement_digest"] == governance_digest,
        "GOVERNANCE_BINDING_MISMATCH",
    )
    require(
        pec_governance["manuscript_sha256"] == adapted["content_sha256"],
        "GOVERNANCE_BINDING_MISMATCH",
    )
    keys = sorted(adapted["author_key_ids"])
    require(
        pec_governance["required_pec_approval_key_ids"] == keys,
        "GOVERNANCE_BINDING_MISMATCH",
    )
    if approvals is not None:
        require(sorted(approvals) == keys, "PEC_APPROVAL_MISSING")
    require(pec.get("issuer_key_id") in keys, "PEC_ISSUER_UNAUTHORIZED")
    require(
        len(adapted["author_key_ids"]) == len(set(adapted["author_key_ids"])),
        "RELEASE_DUPLICATE_AUTHOR_KEY",
    )
    if governance is not None:
        require(
            pec_governance["ai_use_declaration_digest"]
            == digest(governance["ai_use_declaration"]),
            "AI_USE_BINDING_MISMATCH",
        )
    if release is not None:
        _validate_release_governance(
            adapted, governance, release, schema == CURRENT_PEC_SCHEMA
        )
    if check_predecessor:
        predecessor = subject.get("predecessor_pec_digest")
        if predecessor is not None:
            require(
                predecessor_pec is not None and predecessor == digest(predecessor_pec),
                "PREDECESSOR_MISMATCH",
            )
    validate_event_chain(pec.get("events", []))
    outcomes = validate_claim_policy(pec)
    return {"pec_digest": digest(pec), "permitted_outcomes": outcomes}
