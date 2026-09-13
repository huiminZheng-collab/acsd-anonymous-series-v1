"""Small, dependency-free PEC reference core.

This module deliberately models authenticated approvals as an input set; the
ACSD envelope verifier remains the cryptographic boundary.
"""
import hashlib, json, re, subprocess
from pathlib import Path

HEX = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_OUTCOMES = {
    "KEY_ASSENT", "GOVERNANCE_ASSENT", "COMMITTED_EVIDENCE_MATCH",
    "EXTERNALLY_NOT_AFTER",
    "APPROVAL_SET_EXISTED_NOT_AFTER",
    "SLOT_KEY_ASSENT_TO_IDENTITY_ASSERTION",
    "AUTHORIZED_SUCCESSOR",
}
REQUIRED_NON_CLAIMS = {
    "natural_person_authorship", "contribution_truth", "originality_truth",
    "legal_nonrepudiation", "peer_review",
}

def _check_json(value, depth=0):
    if depth > 200: raise ValueError("JSON_TOO_DEEP")
    if isinstance(value, bool) or value is None: return
    if isinstance(value, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
            raise ValueError("LONE_SURROGATE")
        return
    if isinstance(value, int):
        if abs(value) > 9007199254740991: raise ValueError("UNSAFE_INTEGER")
        return
    if isinstance(value, float): raise ValueError("FLOAT_FORBIDDEN")
    if isinstance(value, list):
        for item in value: _check_json(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str): raise ValueError("JSON_KEY_TYPE_FORBIDDEN")
            if any(ord(c) > 127 for c in key): raise ValueError("NONASCII_KEY")
            _check_json(item, depth + 1)
        return
    raise ValueError("JSON_TYPE_FORBIDDEN")

def canonical(obj):
    _check_json(obj)
    # ensure_ascii=False matches the v1 reference (generate.py) and the Node
    # verifier (JSON.stringify), which both keep non-ASCII string values as raw
    # UTF-8 bytes. Escaping them here would split the canonical byte image.
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

def digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()

def require(cond, code):
    if not cond: raise ValueError(code)

def adapt_v1_release(release):
    """Project the published ACSD v1 release shape into PEC bindings."""
    require(release.get("schema") in {
        "acsd-v1.6.0-paper-release/v1", "acsd-v3-paper-release/v1"
    }, "RELEASE_SCHEMA")
    return {"digest": digest(release), "content_sha256": release["content"]["sha256"],
            "author_key_ids": [a["key_id"] for a in release["authors"]],
            "work_id": release["work_id"], "version": release["slot"]["version"],
            "line": release["slot"]["line"]}

def validate_v1_standalone_package(package, root, envelope_verifier=None):
    """Validate file/digest bindings before handing COSE envelopes to v1 code."""
    require(package.get("schema") == "acsd-v1.6.0-standalone-paper-package/v1", "PACKAGE_SCHEMA")
    base = Path(root)
    release_path = base / package["release_path"]
    release = json.loads(release_path.read_text(encoding="utf-8"))
    adapted = adapt_v1_release(release)
    require(package["release_id"] == "urn:sha256:" + adapted["digest"], "PACKAGE_RELEASE_MISMATCH")
    seen = set()
    for endorsement in package["endorsements"]:
        require(endorsement["author_key_id"] in adapted["author_key_ids"], "ENDORSEMENT_AUTHOR_MISMATCH")
        require(endorsement["author_key_id"] not in seen, "ENDORSEMENT_DUPLICATE")
        seen.add(endorsement["author_key_id"])
        raw = (base / endorsement["path"]).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == endorsement["sha256"], "ENDORSEMENT_DIGEST_MISMATCH")
        if envelope_verifier is not None: require(envelope_verifier(raw, endorsement["author_key_id"], package["release_id"]), "ENDORSEMENT_SIGNATURE_INVALID")
    require(seen == set(adapted["author_key_ids"]), "ENDORSEMENT_SET_INCOMPLETE")
    return adapted

def verify_v1_package_with_node(package_path, verifier_script):
    """Delegate COSE_Sign1 verification to the audited zero-dependency v1 verifier."""
    verifier_script = Path(verifier_script).resolve(); package_path = Path(package_path).resolve()
    result = subprocess.run(["node", str(verifier_script), str(package_path.relative_to(verifier_script.parent))],
                            cwd=verifier_script.parent, capture_output=True, text=True, check=False)
    require(result.returncode == 0, "ENDORSEMENT_SIGNATURE_INVALID")
    report = json.loads(result.stdout)
    require(report.get("release_valid") is True and report.get("forbidden_or_undeclared_reads") == 0,
            "ENDORSEMENT_SIGNATURE_INVALID")
    return report

def validate_pec(pec, approvals, release, governance, predecessor_pec=None):
    require(pec.get("schema") in {"acsd-pec/v0.1", "acsd-pec/v0.2", "acsd-pec/v0.3"}, "PEC_SCHEMA")
    body_digest = digest(pec)
    subject, gov = pec["subject"], pec["governance"]
    require(HEX.fullmatch(subject["release_digest"]), "RELEASE_DIGEST")
    require(subject["release_digest"] == release["digest"], "SUBJECT_RELEASE_MISMATCH")
    require(subject["work_id"] == release["work_id"], "SUBJECT_WORK_ID_MISMATCH")
    require(gov["statement_digest"] == governance["digest"], "GOVERNANCE_BINDING_MISMATCH")
    require(gov["manuscript_sha256"] == release["content_sha256"], "GOVERNANCE_BINDING_MISMATCH")
    keys = sorted(release["author_key_ids"])
    require(gov["required_pec_approval_key_ids"] == keys, "GOVERNANCE_BINDING_MISMATCH")
    require(sorted(approvals) == keys, "PEC_APPROVAL_MISSING")
    require(pec.get("issuer_key_id") in keys, "PEC_ISSUER_UNAUTHORIZED")
    predecessor = subject.get("predecessor_pec_digest")
    if predecessor is not None:
        require(predecessor_pec is not None and predecessor == digest(predecessor_pec), "PREDECESSOR_MISMATCH")
    events = pec.get("events", [])
    previous = None
    event_ids = set()
    for i, event in enumerate(events):
        require(event["sequence"] == i, "EVENT_CHAIN_BROKEN")
        require(event["event_id"] not in event_ids, "EVENT_CHAIN_BROKEN")
        event_ids.add(event["event_id"])
        require(event["previous_event_digest"] == previous, "EVENT_CHAIN_BROKEN")
        previous = digest(event)
    policy = pec["claim_policy"]
    require(REQUIRED_NON_CLAIMS.issubset(set(policy["global_non_claims"])), "CLAIM_POLICY_INCOMPLETE")
    outcomes = policy.get("permitted_outcomes", [])
    require(len(outcomes) == len(set(outcomes)), "CLAIM_POLICY_DUPLICATE")
    require(set(outcomes).issubset(ALLOWED_OUTCOMES), "CLAIM_POLICY_UNKNOWN_OUTCOME")
    if pec.get("schema") == "acsd-pec/v0.3":
        from event_disclosure import validate_policy
        validate_policy(pec.get("disclosure_policy"))
        capabilities = policy.get("required_capabilities", {}).get(
            "APPROVAL_SET_EXISTED_NOT_AFTER"
        )
        require(
            capabilities == ["rfc3161-exact-approval-set-imprint"],
            "CLAIM_POLICY_CAPABILITY_MISMATCH",
        )
        if "AUTHORIZED_SUCCESSOR" in outcomes:
            require(
                policy.get("required_capabilities", {}).get("AUTHORIZED_SUCCESSOR")
                == ["predecessor-authority-exact-transition"],
                "CLAIM_POLICY_CAPABILITY_MISMATCH",
            )
    elif "EXTERNALLY_NOT_AFTER" in outcomes:
        capabilities = policy.get("required_capabilities", {}).get("EXTERNALLY_NOT_AFTER")
        require(capabilities == ["rfc3161-exact-approval-target-imprint"], "CLAIM_POLICY_CAPABILITY_MISMATCH")
    return {"pec_digest": body_digest, "permitted_outcomes": tuple(outcomes)}

def verify_legacy_disclosure_metadata(disclosure, pec, event, required_approval_key_ids=None):
    """Legacy metadata-only fixture check; never establishes a scoped claim.

    This function intentionally performs no signature or opening validation.
    New code must use event_disclosure.verify_event_disclosure.
    """
    require(disclosure["pec_digest"] == digest(pec), "DISCLOSURE_BINDING_MISMATCH")
    require(disclosure["event_id"] == event["event_id"], "DISCLOSURE_BINDING_MISMATCH")
    require(disclosure["event_sequence"] == event["sequence"], "DISCLOSURE_BINDING_MISMATCH")
    require(disclosure["kind"] == event["kind"], "DISCLOSURE_BINDING_MISMATCH")
    approved = disclosure.get("approval_key_ids", [])
    require(len(approved) > 0, "DISCLOSURE_APPROVAL_MISSING")
    if required_approval_key_ids is not None:
        require(sorted(approved) == sorted(required_approval_key_ids), "DISCLOSURE_APPROVAL_MISSING")
    return True

def _leaf(index, turn, salt):
    raw = b"ACSD-PEC-DIALOGUE-LEAF-v1\0" + index.to_bytes(8, "big") + salt + turn
    return hashlib.sha256(raw).digest()

def dialogue_root(turns):
    """Return Merkle root and salted leaves for an ordered dialogue."""
    leaves = [_leaf(i, t["bytes"], t["salt"]) for i, t in enumerate(turns)]
    if not leaves: raise ValueError("DIALOGUE_EMPTY")
    level = leaves[:]
    while len(level) > 1:
        if len(level) % 2: level.append(level[-1])
        level = [hashlib.sha256(b"ACSD-PEC-DIALOGUE-NODE-v1\0" + level[i] + level[i+1]).digest() for i in range(0,len(level),2)]
    return level[0].hex()

def dialogue_proof(turns, index):
    """Generate a left/right sibling path for one dialogue leaf."""
    if not 0 <= index < len(turns): raise ValueError("DIALOGUE_INDEX")
    level = [_leaf(i, t["bytes"], t["salt"]) for i, t in enumerate(turns)]
    path = []; position = index
    while len(level) > 1:
        if len(level) % 2: level.append(level[-1])
        sibling = position ^ 1
        path.append([level[sibling].hex(), "R" if position % 2 == 0 else "L"])
        level = [hashlib.sha256(b"ACSD-PEC-DIALOGUE-NODE-v1\0" + level[i] + level[i+1]).digest() for i in range(0,len(level),2)]
        position //= 2
    return path

def verify_dialogue_window(root_hex, window):
    """Verify contiguous indexed leaves and their Merkle paths against root."""
    require(HEX.fullmatch(root_hex), "DIALOGUE_ROOT")
    require(window and all(window[i]["index"] + 1 == window[i+1]["index"] for i in range(len(window)-1)), "DISCLOSURE_WINDOW_INVALID")
    for item in window:
        require(
            isinstance(item.get("index"), int)
            and not isinstance(item.get("index"), bool)
            and item["index"] >= 0
            and isinstance(item.get("bytes"), bytes)
            and isinstance(item.get("salt"), bytes)
            and len(item["salt"]) == 32
            and isinstance(item.get("path"), list)
            and len(item["path"]) <= 256,
            "DISCLOSURE_OPENING_INVALID",
        )
        node = _leaf(item["index"], item["bytes"], item["salt"])
        index = item["index"]
        for step in item["path"]:
            require(
                isinstance(step, list) and len(step) == 2
                and isinstance(step[0], str) and HEX.fullmatch(step[0])
                and step[1] in {"L", "R"},
                "DISCLOSURE_OPENING_INVALID",
            )
            sibling, side = step
            sibling = bytes.fromhex(sibling)
            node = hashlib.sha256(b"ACSD-PEC-DIALOGUE-NODE-v1\0" + (node+sibling if side == "R" else sibling+node)).digest()
            index //= 2
        require(node.hex() == root_hex, "DISCLOSURE_BINDING_MISMATCH")
    return True

def verify_sidecar_subject(sidecar, pec, outcome, approval_target_digest):
    """Check sidecar scope and policy capability before cryptographic adapter use."""
    require(HEX.fullmatch(approval_target_digest), "RECEIPT_SUBJECT_MISMATCH")
    require(sidecar.get("subject_digest") == approval_target_digest, "RECEIPT_SUBJECT_MISMATCH")
    policy = pec["claim_policy"]
    require(outcome in ALLOWED_OUTCOMES, "CLAIM_NOT_AUTHORIZED")
    require(outcome in policy.get("permitted_outcomes", []), "CLAIM_NOT_AUTHORIZED")
    capability = sidecar.get("capability")
    required = policy.get("required_capabilities", {}).get(outcome, [])
    time_outcomes = {"EXTERNALLY_NOT_AFTER", "APPROVAL_SET_EXISTED_NOT_AFTER"}
    require(capability in required, "TIME_CAPABILITY_MISSING" if outcome in time_outcomes else "CLAIM_NOT_AUTHORIZED")
    return True
