"""Strict, research-only adapter for the bounded RATS appraisal instance.

This is deliberately outside the ACSD package and CLI.  It models only the
canonical boundary between already-appraised facts and the five-premise Lean
instance; it neither parses EAT nor verifies COSE nor reports device safety.
"""

from __future__ import annotations

from typing import Iterable, Mapping, Tuple


SCHEMA = "acsd-rats-appraisal-transcript/v1"
RESULT_SCHEMA = "acsd-rats-lean-result/v1"
OUTCOME = "APPRAISAL_RESULT"
MAX_SAFE_INTEGER = 9_007_199_254_740_991
SUBJECT_FIELDS = (
    "token", "attester", "measurement", "reference", "nonce", "verifier", "policy",
)
FACT_ORDER = (
    "TOKEN_SIGNATURE", "MEASUREMENT_BINDING", "FRESHNESS_BINDING",
    "REFERENCE_VALUE", "VERIFIER_AUTHORIZATION",
)
FACT_FIELDS = {
    "TOKEN_SIGNATURE": ("token", "attester"),
    "MEASUREMENT_BINDING": ("token", "measurement"),
    "FRESHNESS_BINDING": ("token", "nonce"),
    "REFERENCE_VALUE": ("measurement", "reference"),
    "VERIFIER_AUTHORIZATION": ("verifier", "policy"),
}


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError(code)


def _fields(value: object, expected: Iterable[str], code: str) -> dict:
    _require(isinstance(value, dict) and set(value) == set(expected), code)
    return value


def _positive_nat(value: object, code: str) -> int:
    _require(
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 < value <= MAX_SAFE_INTEGER,
        code,
    )
    return value


def _nonnegative_nat(value: object, code: str) -> int:
    _require(
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_SAFE_INTEGER,
        code,
    )
    return value


def subject_from_wire(value: object) -> dict:
    subject = _fields(value, SUBJECT_FIELDS, "RATS_TRANSCRIPT_SUBJECT")
    return {field: _positive_nat(subject[field], "RATS_TRANSCRIPT_SUBJECT") for field in SUBJECT_FIELDS}


def fact_from_wire(value: object) -> dict:
    _require(isinstance(value, dict), "RATS_TRANSCRIPT_EVIDENCE_ITEM")
    kind = value.get("kind")
    _require(kind in FACT_FIELDS, "RATS_TRANSCRIPT_EVIDENCE_KIND")
    fields = FACT_FIELDS[kind]
    item = _fields(value, ("index", "kind", *fields), "RATS_TRANSCRIPT_EVIDENCE_ITEM")
    return {
        "index": _nonnegative_nat(item["index"], "RATS_TRANSCRIPT_EVIDENCE_INDEX"),
        "kind": kind,
        **{field: _positive_nat(item[field], "RATS_TRANSCRIPT_EVIDENCE_ITEM") for field in fields},
    }


def complete_evidence(subject: Mapping[str, int]) -> Tuple[dict, ...]:
    complete_subject = subject_from_wire(dict(subject))
    return tuple(
        {"kind": kind, **{field: complete_subject[field] for field in FACT_FIELDS[kind]}}
        for kind in FACT_ORDER
    )


def build(
    permitted: bool, subject: Mapping[str, int], evidence: Iterable[Mapping[str, object]],
) -> dict:
    _require(isinstance(permitted, bool), "RATS_TRANSCRIPT_POLICY")
    complete_subject = subject_from_wire(dict(subject))
    raw_facts = []
    for fact in evidence:
        _require(isinstance(fact, Mapping), "RATS_TRANSCRIPT_EVIDENCE_ITEM")
        kind = fact.get("kind")
        _require(kind in FACT_FIELDS, "RATS_TRANSCRIPT_EVIDENCE_KIND")
        raw_facts.append({"kind": kind, **{field: fact[field] for field in FACT_FIELDS[kind]}})
    raw_facts.sort(key=lambda item: FACT_ORDER.index(item["kind"]))
    entries = [{"index": index, **item} for index, item in enumerate(raw_facts)]
    result = {
        "schema": SCHEMA,
        "policy": {"permitted_outcomes": [OUTCOME] if permitted else []},
        "subject": complete_subject,
        "evidence": entries,
    }
    parse(result)
    return result


def parse(value: object) -> Tuple[bool, dict, Tuple[dict, ...]]:
    transcript = _fields(
        value, {"schema", "policy", "subject", "evidence"}, "RATS_TRANSCRIPT_FIELDS"
    )
    _require(transcript["schema"] == SCHEMA, "RATS_TRANSCRIPT_SCHEMA")
    policy = _fields(transcript["policy"], {"permitted_outcomes"}, "RATS_TRANSCRIPT_POLICY")
    outcomes = policy["permitted_outcomes"]
    _require(outcomes in ([], [OUTCOME]), "RATS_TRANSCRIPT_POLICY")
    subject = subject_from_wire(transcript["subject"])
    raw_evidence = transcript["evidence"]
    _require(isinstance(raw_evidence, list), "RATS_TRANSCRIPT_EVIDENCE")
    evidence = tuple(fact_from_wire(item) for item in raw_evidence)
    _require(
        [item["index"] for item in evidence] == list(range(len(evidence))),
        "RATS_TRANSCRIPT_EVIDENCE_ORDER",
    )
    kinds = [item["kind"] for item in evidence]
    _require(
        kinds == [kind for kind in FACT_ORDER if kind in kinds],
        "RATS_TRANSCRIPT_EVIDENCE_ORDER",
    )
    return outcomes == [OUTCOME], subject, evidence


def derive(value: object) -> Tuple[dict, ...]:
    permitted, subject, evidence = parse(value)
    supplied = {
        (item["kind"], tuple((field, item[field]) for field in FACT_FIELDS[item["kind"]]))
        for item in evidence
    }
    required = {
        (kind, tuple((field, subject[field]) for field in FACT_FIELDS[kind]))
        for kind in FACT_ORDER
    }
    if permitted and required <= supplied:
        return ({"kind": OUTCOME, "subject": subject},)
    return ()
