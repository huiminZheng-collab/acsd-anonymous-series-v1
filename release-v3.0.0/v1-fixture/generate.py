#!/usr/bin/env python3
"""Generate ACSD v1.6.0 standalone-paper and anonymous-series DAG fixtures."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT / ".deps"))
sys.path.insert(0, str(PROJECT / "vendor" / "scitt-cose-v0.1.1"))

import cbor2  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402
from scitt_cose import build_signed_statement, parse_signed_statement  # noqa: E402

ARTIFACTS = PROJECT / "artifacts"
CONTENTS = ARTIFACTS / "contents"
RELEASES = ARTIFACTS / "releases"
ENDORSEMENTS = ARTIFACTS / "endorsements"
PACKAGES = ARTIFACTS / "standalone-packages"
SERIES = ARTIFACTS / "series"
OBSERVATIONS = ARTIFACTS / "observations"
NEGATIVE_FIXTURES = ARTIFACTS / "negative-fixtures"
PUBLIC_KEYS = ARTIFACTS / "public-keys"
PRIVATE = PROJECT / "private-test-keys"
EVIDENCE = PROJECT / "evidence"
for directory in (CONTENTS, RELEASES, ENDORSEMENTS, PACKAGES, SERIES, OBSERVATIONS, NEGATIVE_FIXTURES, PUBLIC_KEYS, PRIVATE, EVIDENCE):
    directory.mkdir(parents=True, exist_ok=True)

PAPER_CONTENT_TYPE = "application/vnd.acsd.paper-release+json"
SERIES_CONTENT_TYPE = "application/vnd.acsd.series-bundle+json"
ROTATION_CONTENT_TYPE = "application/vnd.acsd.series-key-rotation+json"
OBSERVATION_CONTENT_TYPE = "application/vnd.acsd.local-observation+json"
SERIES_ID = "urn:acsd:series:7d8798d1-50af-4f50-9d1d-e43e5f73d028"
COPY_SERIES_ID = "urn:acsd:series:bb641e89-bf3e-4b2f-a043-71ecbc17d703"
WORK_P = "urn:uuid:f405e129-f725-4232-ab92-5d18766ca42d"
WORK_Q = "urn:uuid:7963675d-fd51-47aa-9c02-50a43b655f86"
WORK_Z = "urn:uuid:57c8263b-a39f-47cf-b3fd-c63f48993143"
COPY_WORK_P = "urn:uuid:65e70921-e836-46bd-8fc3-005026a445cb"
COPY_WORK_Q = "urn:uuid:206fffc0-a454-43b5-9086-4307ed834e74"
WORK_ID_TOKEN = re.compile(rb"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
SAFE_JSON_INTEGER_MAX = (1 << 53) - 1


def canonical_json_value(value: object) -> bool:
    """The signed-object profile permits only finite, integer JSON values."""
    if value is None or isinstance(value, bool) or isinstance(value, str):
        return True
    if isinstance(value, int):
        return -SAFE_JSON_INTEGER_MAX <= value <= SAFE_JSON_INTEGER_MAX
    if isinstance(value, list):
        return all(canonical_json_value(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and key.isascii() and canonical_json_value(item)
                   for key, item in value.items())
    return False


def canonical_json(value: object) -> bytes:
    if not canonical_json_value(value):
        raise ValueError("signed JSON must contain ASCII object keys and finite integer values only")
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def parse_canonical_json(data: bytes) -> object | None:
    """Reject duplicate fields, whitespace, non-integer numbers, and noncanonical key order."""
    try:
        value = json.loads(data.decode("utf-8"))
        return value if canonical_json(value) == data else None
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return None


def canonical_json_corpus_results() -> list[dict]:
    corpus = json.loads((PROJECT / "canonical-json-corpus.json").read_text(encoding="utf-8"))
    if corpus.get("schema") != "acsd-v1.6.0-canonical-json-corpus/v1" or not isinstance(corpus.get("cases"), list):
        raise ValueError("invalid canonical JSON corpus")
    results = []
    for case in corpus["cases"]:
        accepted = isinstance(case, dict) and isinstance(case.get("body"), str) \
            and parse_canonical_json(case["body"].encode("utf-8")) is not None
        results.append({"id": case.get("id"), "expected_canonical": case.get("expected_canonical"),
                        "accepted": accepted, "passed": accepted == case.get("expected_canonical")})
    return results


def write_json(path: Path, value: object, *, canonical: bool = False) -> None:
    body = canonical_json(value) if canonical else json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")
    path.write_bytes(body + b"\n")


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256(data: bytes) -> str:
    return sha256_bytes(data).hex()


def extract_explicit_work_ids(content: bytes) -> list[str]:
    """The fixture's citation syntax is an exact ASCII WorkID token, not NLP."""
    return sorted({match.group(0).decode("ascii") for match in WORK_ID_TOKEN.finditer(content)})


def explicit_work_id_witnesses(content: bytes) -> list[dict]:
    """Byte-range witnesses are stable because the release commits to content SHA-256."""
    return [
        {"work_id": match.group(0).decode("ascii"), "byte_offset": match.start(), "byte_length": len(match.group(0))}
        for match in WORK_ID_TOKEN.finditer(content)
    ]


def reference_work_ids_match_content(payload: dict, content: bytes) -> bool:
    references = payload.get("reference_work_ids")
    return isinstance(references, list) and all(isinstance(item, str) for item in references) \
        and references == extract_explicit_work_ids(content) \
        and payload.get("citation_witnesses") == explicit_work_id_witnesses(content)


def fixture_key(key_id: str) -> ed25519.Ed25519PrivateKey:
    seed = sha256_bytes(f"ACSD v1.6.0 deterministic test-only key::{key_id}".encode("ascii"))
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)


def private_pem(key: ed25519.Ed25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def public_pem(key: ed25519.Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def kid(pem: bytes) -> bytes:
    key = serialization.load_pem_public_key(pem)
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return sha256_bytes(der)[:16]


def plain(value):
    if isinstance(value, (bytes, bytearray, str, int, bool)) or value is None:
        return value
    if hasattr(value, "items"):
        return {key: plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain(item) for item in value]
    return value


def protected_headers(message: bytes) -> dict:
    outer = cbor2.loads(message)
    if not isinstance(outer, cbor2.CBORTag) or outer.tag != 18 or len(outer.value) != 4:
        raise ValueError("not a COSE_Sign1")
    return plain(cbor2.loads(outer.value[0]))


def has_cycle(nodes: set[str], edges: list[tuple[str, str]]) -> bool:
    outgoing = {node: [] for node in nodes}
    indegree = {node: 0 for node in nodes}
    for source, target in edges:
        outgoing[source].append(target)
        indegree[target] += 1
    queue = [node for node in nodes if indegree[node] == 0]
    visited = 0
    while queue:
        node = queue.pop()
        visited += 1
        for target in outgoing[node]:
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)
    return visited != len(nodes)


def bundle_rank_is_valid(payload: dict) -> bool:
    """Check the structural rank certificate mirrored by the Lean model.

    This is deliberately not a clock, sequence, or priority test.  It only
    states that this bundle anchor is above every release version it resolves.
    """
    rank = payload.get("commitment_anchor_rank")
    if type(rank) is not int or rank < 0:
        return False
    releases = payload.get("releases")
    if not isinstance(releases, list):
        return False
    for entry in releases:
        slot = entry.get("slot") if isinstance(entry, dict) else None
        version = slot.get("version") if isinstance(slot, dict) else None
        if type(version) is not int or version < 0 or version >= rank:
            return False
    return True


def bundle_semantic_edges_are_supported(payload: dict, releases: dict) -> bool:
    """Require each work-level citation edge to have a listed paper witness."""
    entries = payload.get("releases")
    edges = payload.get("semantic_edges")
    if not isinstance(entries, list) or not isinstance(edges, list):
        return False
    declared_work_ids = set()
    for entry in entries:
        slot = entry.get("slot") if isinstance(entry, dict) else None
        work_id = slot.get("work_id") if isinstance(slot, dict) else None
        if not isinstance(work_id, str):
            return False
        declared_work_ids.add(work_id)
    for edge in edges:
        if not isinstance(edge, dict) or edge.get("relation") != "cites":
            return False
        source = edge.get("from_work_id")
        target = edge.get("to_work_id")
        if not isinstance(source, str) or not isinstance(target, str) or source not in declared_work_ids or target not in declared_work_ids:
            return False
        supported = any(
            entry["slot"]["work_id"] == source
            and reference_work_ids_match_content(releases[entry["release_key"]]["payload"], releases[entry["release_key"]]["content"])
            and target in releases[entry["release_key"]]["payload"]["reference_work_ids"]
            for entry in entries
        )
        if not supported:
            return False
    return True


def main() -> None:
    key_ids = [
        "p-slot-1", "p-slot-2", "q-slot-1", "q-slot-2", "q-slot-3",
        "copy-p-slot-1", "copy-p-slot-2", "copy-q-slot-1", "copy-q-slot-2",
        "series-epoch-0", "series-epoch-1", "copy-series-epoch-0", "local-observer",
    ]
    keys = {}
    for key_id in key_ids:
        key = fixture_key(key_id)
        private = private_pem(key)
        public = public_pem(key)
        issuer = f"urn:acsd:pseudonym:{key_id}"
        (PRIVATE / f"{key_id}.pem").write_bytes(private)
        (PUBLIC_KEYS / f"{key_id}-public.pem").write_bytes(public)
        keys[key_id] = {
            "key": key, "private": private, "public": public, "issuer": issuer,
            "kid": kid(public), "kid_hex": kid(public).hex(),
            "public_key_path": f"artifacts/public-keys/{key_id}-public.pem",
        }

    contents = {
        "p-v1": f"Paper P version 1. Companion work: {WORK_Q}. Core result alpha.\n".encode(),
        "q-v1": f"Paper Q version 1. Companion work: {WORK_P}. Core result beta.\n".encode(),
        "p-v2-main": f"Paper P version 2 main line. Companion work: {WORK_Q}. Strengthened result alpha-plus.\n".encode(),
        "p-v2-companion": f"Paper P version 2 computational line. Companion work: {WORK_Q}. Independent experiments.\n".encode(),
        "p-v2-conflict": f"Paper P version 2 main line. Companion work: {WORK_Q}. Conflicting replacement result.\n".encode(),
        "q-v2-amendment": f"Paper Q version 2 amendment. References: {WORK_P} and later work {WORK_Z}.\n".encode(),
    }
    content_meta = {}
    for content_id, body in contents.items():
        path_value = CONTENTS / f"{content_id}.txt"
        path_value.write_bytes(body)
        content_meta[content_id] = {"path": f"artifacts/contents/{content_id}.txt", "sha256": sha256(body)}

    author_profiles = {
        "p": [
            {"slot": 1, "key_id": "p-slot-1", "role": "co-first", "corresponding": False, "contributions": ["conceptualization", "formal-analysis"]},
            {"slot": 2, "key_id": "p-slot-2", "role": "co-first", "corresponding": True, "contributions": ["methodology", "writing-review"]},
        ],
        "q": [
            {"slot": 1, "key_id": "q-slot-1", "role": "first", "corresponding": False, "contributions": ["conceptualization", "software"]},
            {"slot": 2, "key_id": "q-slot-2", "role": "middle", "corresponding": False, "contributions": ["validation"]},
            {"slot": 3, "key_id": "q-slot-3", "role": "senior", "corresponding": True, "contributions": ["supervision", "writing-review"]},
        ],
        "copy-p": [
            {"slot": 1, "key_id": "copy-p-slot-1", "role": "first", "corresponding": False, "contributions": ["claimed-conceptualization"]},
            {"slot": 2, "key_id": "copy-p-slot-2", "role": "corresponding", "corresponding": True, "contributions": ["claimed-writing"]},
        ],
        "copy-q": [
            {"slot": 1, "key_id": "copy-q-slot-1", "role": "first", "corresponding": False, "contributions": ["claimed-conceptualization"]},
            {"slot": 2, "key_id": "copy-q-slot-2", "role": "corresponding", "corresponding": True, "contributions": ["claimed-writing"]},
        ],
    }

    releases = {}
    release_meta = {}
    endorsement_meta = []

    def make_release(*, release_key: str, work_id: str, version: int, line: str, content_id: str,
                     parent_release_id: str | None, references: list[str], profile: str, issued_at: int,
                     ai_use: dict) -> None:
        content_bytes = (PROJECT / content_meta[content_id]["path"]).read_bytes()
        explicit_references = extract_explicit_work_ids(content_bytes)
        if sorted(references) != explicit_references:
            raise ValueError(f"{release_key}: reference_work_ids must equal explicit WorkID tokens in exact content")
        authors = []
        for item in author_profiles[profile]:
            key_info = keys[item["key_id"]]
            authors.append({
                **item,
                "issuer": key_info["issuer"],
                "kid_hex": key_info["kid_hex"],
                "public_key_path": key_info["public_key_path"],
            })
        payload = {
            "schema": "acsd-v1.6.0-paper-release/v1",
            "work_id": work_id,
            "slot": {"work_id": work_id, "version": version, "line": line},
            "content": content_meta[content_id],
            "parent_release_id": parent_release_id,
            "reference_work_ids": sorted(references),
            "citation_witnesses": explicit_work_id_witnesses(content_bytes),
            "authors": authors,
            "ai_use": ai_use,
            "issued_at": issued_at,
            "standalone_semantics": "Every listed author key endorses this exact release payload; series membership is optional additional evidence.",
        }
        body = canonical_json(payload)
        release_id = f"urn:sha256:{sha256(body)}"
        (RELEASES / f"{release_key}.json").write_bytes(body + b"\n")
        endorsements = []
        package_endorsements = []
        for author in authors:
            key_info = keys[author["key_id"]]
            statement = build_signed_statement(
                body,
                alg="EdDSA",
                private_key_pem=key_info["private"],
                issuer=key_info["issuer"],
                subject=release_id,
                content_type=PAPER_CONTENT_TYPE,
                extra_cwt_claims={6: issued_at},
                kid=key_info["kid"],
            )
            endorsement_id = f"{release_key}--{author['key_id']}"
            (ENDORSEMENTS / f"{endorsement_id}.scitt").write_bytes(statement)
            endorsements.append(endorsement_id)
            endorsement_record = {
                "id": endorsement_id, "release_key": release_key, "author_key_id": author["key_id"],
                "path": f"artifacts/endorsements/{endorsement_id}.scitt", "sha256": sha256(statement),
            }
            endorsement_meta.append(endorsement_record)
            package_endorsements.append(endorsement_record)
        package = {
            "schema": "acsd-v1.6.0-standalone-paper-package/v1",
            "release_key": release_key,
            "release_id": release_id,
            "release_path": f"artifacts/releases/{release_key}.json",
            "content_path": content_meta[content_id]["path"],
            "endorsement_ids": endorsements,
            "endorsements": package_endorsements,
            "content_type": PAPER_CONTENT_TYPE,
            "series_required_for_verification": False,
        }
        write_json(PACKAGES / f"{release_key}.json", package)
        releases[release_key] = {"payload": payload, "body": body, "content": content_bytes, "release_id": release_id, "endorsements": endorsements}
        release_meta[release_key] = {
            "release_id": release_id, "release_path": package["release_path"], "package_path": f"artifacts/standalone-packages/{release_key}.json",
            "content_path": package["content_path"], "endorsement_ids": endorsements,
        }

    no_ai = {"used": False, "tools": [], "human_review_key_ids": []}
    language_ai = {"used": True, "tools": ["local-language-model"], "purposes": ["language-editing"], "human_review_key_ids": ["p-slot-1", "p-slot-2"]}
    make_release(release_key="p-v1", work_id=WORK_P, version=1, line="main", content_id="p-v1", parent_release_id=None,
                 references=[WORK_Q], profile="p", issued_at=1788998400, ai_use=language_ai)
    make_release(release_key="q-v1", work_id=WORK_Q, version=1, line="main", content_id="q-v1", parent_release_id=None,
                 references=[WORK_P], profile="q", issued_at=1788998410, ai_use=no_ai)
    make_release(release_key="p-v2-main", work_id=WORK_P, version=2, line="main", content_id="p-v2-main", parent_release_id=releases["p-v1"]["release_id"],
                 references=[WORK_Q], profile="p", issued_at=1788999000, ai_use=language_ai)
    make_release(release_key="p-v2-companion", work_id=WORK_P, version=2, line="computational", content_id="p-v2-companion", parent_release_id=releases["p-v1"]["release_id"],
                 references=[WORK_Q], profile="p", issued_at=1788999010, ai_use=no_ai)
    make_release(release_key="p-v2-conflict", work_id=WORK_P, version=2, line="main", content_id="p-v2-conflict", parent_release_id=releases["p-v1"]["release_id"],
                 references=[WORK_Q], profile="p", issued_at=1788999020, ai_use=no_ai)
    make_release(release_key="q-v2-amendment", work_id=WORK_Q, version=2, line="amendment", content_id="q-v2-amendment", parent_release_id=releases["q-v1"]["release_id"],
                 references=[WORK_P, WORK_Z], profile="q", issued_at=1788999100, ai_use=no_ai)
    # Copycat packages reuse exact content bytes but have new WorkIDs and new author keys.
    content_meta["copy-p-v1"] = content_meta["p-v1"]
    content_meta["copy-q-v1"] = content_meta["q-v1"]
    make_release(release_key="copy-p-v1", work_id=COPY_WORK_P, version=1, line="main", content_id="copy-p-v1", parent_release_id=None,
                 references=[WORK_Q], profile="copy-p", issued_at=1789002000, ai_use=no_ai)
    make_release(release_key="copy-q-v1", work_id=COPY_WORK_Q, version=1, line="main", content_id="copy-q-v1", parent_release_id=None,
                 references=[WORK_P], profile="copy-q", issued_at=1789002010, ai_use=no_ai)

    # Negative releases stay outside the ordinary index.  They demonstrate
    # that a signature over a release payload is insufficient if the signed
    # reference manifest or its exact byte witnesses disagree with the content
    # whose hash the payload also commits to.
    def make_signed_negative_fixture(*, release_key: str, payload: dict,
                                     body_override: bytes | None = None) -> dict:
        body = canonical_json(payload) if body_override is None else body_override
        release_id = f"urn:sha256:{sha256(body)}"
        payload_path = NEGATIVE_FIXTURES / f"{release_key}.json"
        payload_path.write_bytes(body + b"\n")
        endorsements = []
        for author in payload["authors"]:
            key_info = keys[author["key_id"]]
            statement = build_signed_statement(
                body, alg="EdDSA", private_key_pem=key_info["private"], issuer=key_info["issuer"],
                subject=release_id, content_type=PAPER_CONTENT_TYPE,
                extra_cwt_claims={6: payload["issued_at"]}, kid=key_info["kid"],
            )
            endorsement_path = NEGATIVE_FIXTURES / f"{release_key}--{author['key_id']}.scitt"
            endorsement_path.write_bytes(statement)
            endorsements.append({
                "author_key_id": author["key_id"], "path": f"artifacts/negative-fixtures/{endorsement_path.name}",
                "sha256": sha256(statement),
            })
        return {
            "payload": payload, "body": body, "release_id": release_id,
            "meta": {
                "release_key": release_key, "release_id": release_id,
                "payload_path": f"artifacts/negative-fixtures/{payload_path.name}",
                "content_path": content_meta["p-v1"]["path"], "endorsements": endorsements,
            },
        }

    reference_mismatch_payload = json.loads(canonical_json(releases["p-v1"]["payload"]))
    reference_mismatch_payload["reference_work_ids"] = [WORK_P]
    reference_mismatch = make_signed_negative_fixture(
        release_key="p-v1-reference-work-id-mismatch", payload=reference_mismatch_payload)
    reference_mismatch_meta = reference_mismatch["meta"]

    witness_mismatch_payload = json.loads(canonical_json(releases["p-v1"]["payload"]))
    witness_mismatch_payload["citation_witnesses"][0]["byte_offset"] += 1
    witness_mismatch = make_signed_negative_fixture(
        release_key="p-v1-citation-witness-offset-mismatch", payload=witness_mismatch_payload)
    witness_mismatch_meta = witness_mismatch["meta"]

    noncanonical_payload = json.loads(canonical_json(releases["p-v1"]["payload"]))
    noncanonical = make_signed_negative_fixture(
        release_key="p-v1-noncanonical-json", payload=noncanonical_payload,
        body_override=b" " + canonical_json(noncanonical_payload))
    noncanonical_meta = noncanonical["meta"]

    bundle_meta = {}

    def sign_series_payload(*, object_id: str, payload: dict, key_id: str, content_type: str, subject: str) -> bytes:
        body = canonical_json(payload)
        key_info = keys[key_id]
        statement = build_signed_statement(
            body, alg="EdDSA", private_key_pem=key_info["private"], issuer=key_info["issuer"], subject=subject,
            content_type=content_type, extra_cwt_claims={6: payload["issued_at"]}, kid=key_info["kid"],
        )
        (SERIES / f"{object_id}.json").write_bytes(body + b"\n")
        (SERIES / f"{object_id}.scitt").write_bytes(statement)
        return statement

    def release_entry(release_key: str) -> dict:
        item = releases[release_key]
        return {"release_key": release_key, "release_id": item["release_id"], "slot": item["payload"]["slot"]}

    bundle1_payload = {
        "schema": "acsd-v1.6.0-series-bundle/v1", "series_id": SERIES_ID, "epoch": 0, "sequence": 1,
        "exclusive_sequence": True, "previous_bundle_sha256": None, "rotation_sha256": None,
        "commitment_anchor_rank": 2,
        "releases": [release_entry("p-v1"), release_entry("q-v1")],
        "heads": {WORK_P: [releases["p-v1"]["release_id"]], WORK_Q: [releases["q-v1"]["release_id"]]},
        "semantic_edges": [
            {"from_work_id": WORK_P, "relation": "cites", "to_work_id": WORK_Q},
            {"from_work_id": WORK_Q, "relation": "cites", "to_work_id": WORK_P},
        ],
        "issued_at": 1788998460,
    }
    bundle1 = sign_series_payload(object_id="bundle-epoch0-seq1", payload=bundle1_payload, key_id="series-epoch-0", content_type=SERIES_CONTENT_TYPE, subject=SERIES_ID)
    bundle1_hash = sha256(bundle1)
    bundle_meta["bundle1"] = {"path": "artifacts/series/bundle-epoch0-seq1.scitt", "payload_path": "artifacts/series/bundle-epoch0-seq1.json", "sha256": bundle1_hash, "key_id": "series-epoch-0"}

    rotation_payload = {
        "schema": "acsd-v1.6.0-series-key-rotation/v1", "series_id": SERIES_ID,
        "from_epoch": 0, "from_kid_hex": keys["series-epoch-0"]["kid_hex"],
        "to_epoch": 1, "to_kid_hex": keys["series-epoch-1"]["kid_hex"],
        "to_public_key_sha256": sha256(keys["series-epoch-1"]["public"]),
        "previous_bundle_sha256": bundle1_hash, "effective_sequence": 2, "issued_at": 1788998500,
    }
    rotation = sign_series_payload(object_id="rotation-epoch0-to-1", payload=rotation_payload, key_id="series-epoch-0", content_type=ROTATION_CONTENT_TYPE, subject=SERIES_ID)
    rotation_hash = sha256(rotation)

    def make_bundle2(*, object_id: str, main_release: str) -> None:
        payload = {
            "schema": "acsd-v1.6.0-series-bundle/v1", "series_id": SERIES_ID, "epoch": 1, "sequence": 2,
            "exclusive_sequence": True, "previous_bundle_sha256": bundle1_hash, "rotation_sha256": rotation_hash,
            "commitment_anchor_rank": 3,
            "releases": [release_entry("p-v1"), release_entry("q-v1"), release_entry(main_release), release_entry("p-v2-companion")],
            "heads": {WORK_P: [releases[main_release]["release_id"], releases["p-v2-companion"]["release_id"]], WORK_Q: [releases["q-v1"]["release_id"]]},
            "semantic_edges": bundle1_payload["semantic_edges"], "issued_at": 1788999060,
        }
        statement = sign_series_payload(object_id=object_id, payload=payload, key_id="series-epoch-1", content_type=SERIES_CONTENT_TYPE, subject=SERIES_ID)
        bundle_meta[object_id] = {"path": f"artifacts/series/{object_id}.scitt", "payload_path": f"artifacts/series/{object_id}.json", "sha256": sha256(statement), "key_id": "series-epoch-1"}

    make_bundle2(object_id="bundle-epoch1-seq2", main_release="p-v2-main")
    make_bundle2(object_id="bundle-epoch1-seq2-conflict", main_release="p-v2-conflict")

    rank_too_low_payload = dict(bundle1_payload)
    rank_too_low_payload["commitment_anchor_rank"] = 1
    rank_too_low = sign_series_payload(object_id="bundle-epoch0-seq1-rank-too-low", payload=rank_too_low_payload,
                                       key_id="series-epoch-0", content_type=SERIES_CONTENT_TYPE, subject=SERIES_ID)
    bundle_meta["bundle-rank-too-low"] = {
        "path": "artifacts/series/bundle-epoch0-seq1-rank-too-low.scitt",
        "payload_path": "artifacts/series/bundle-epoch0-seq1-rank-too-low.json",
        "sha256": sha256(rank_too_low), "key_id": "series-epoch-0",
    }

    unsupported_edge_payload = dict(bundle1_payload)
    unsupported_edge_payload["semantic_edges"] = [
        {"from_work_id": WORK_P, "relation": "cites", "to_work_id": WORK_P},
    ]
    unsupported_edge = sign_series_payload(object_id="bundle-epoch0-seq1-unsupported-semantic-edge",
                                            payload=unsupported_edge_payload, key_id="series-epoch-0",
                                            content_type=SERIES_CONTENT_TYPE, subject=SERIES_ID)
    bundle_meta["bundle-unsupported-semantic-edge"] = {
        "path": "artifacts/series/bundle-epoch0-seq1-unsupported-semantic-edge.scitt",
        "payload_path": "artifacts/series/bundle-epoch0-seq1-unsupported-semantic-edge.json",
        "sha256": sha256(unsupported_edge), "key_id": "series-epoch-0",
    }

    copy_payload = {
        "schema": "acsd-v1.6.0-series-bundle/v1", "series_id": COPY_SERIES_ID, "epoch": 0, "sequence": 1,
        "exclusive_sequence": True, "previous_bundle_sha256": None, "rotation_sha256": None,
        "commitment_anchor_rank": 2,
        "releases": [release_entry("copy-p-v1"), release_entry("copy-q-v1")],
        "heads": {COPY_WORK_P: [releases["copy-p-v1"]["release_id"]], COPY_WORK_Q: [releases["copy-q-v1"]["release_id"]]},
        # Exact copied bytes still cite the original WorkIDs.  A fresh series
        # may not relabel those textual citations as internal copy WorkIDs.
        "semantic_edges": [],
        "issued_at": 1789002060,
    }
    copy_bundle = sign_series_payload(object_id="copy-bundle-epoch0-seq1", payload=copy_payload, key_id="copy-series-epoch-0", content_type=SERIES_CONTENT_TYPE, subject=COPY_SERIES_ID)
    copy_bundle_hash = sha256(copy_bundle)
    bundle_meta["copy-bundle"] = {"path": "artifacts/series/copy-bundle-epoch0-seq1.scitt", "payload_path": "artifacts/series/copy-bundle-epoch0-seq1.json", "sha256": copy_bundle_hash, "key_id": "copy-series-epoch-0"}

    def observe(object_id: str, bundle_id: str, series_id: str, bundle_hash: str, observed_at: int) -> dict:
        payload = {
            "schema": "acsd-v1.6.0-local-observation/v1", "observer_scope": "local fixture only",
            "bundle_id": bundle_id, "bundle_sha256": bundle_hash, "series_id": series_id,
            "observed_at": observed_at, "independent_time": False,
        }
        body = canonical_json(payload)
        key_info = keys["local-observer"]
        statement = build_signed_statement(
            body, alg="EdDSA", private_key_pem=key_info["private"], issuer=key_info["issuer"],
            subject=f"urn:sha256:{bundle_hash}", content_type=OBSERVATION_CONTENT_TYPE,
            extra_cwt_claims={6: observed_at}, kid=key_info["kid"],
        )
        (OBSERVATIONS / f"{object_id}.json").write_bytes(body + b"\n")
        (OBSERVATIONS / f"{object_id}.scitt").write_bytes(statement)
        return {"path": f"artifacts/observations/{object_id}.scitt", "payload_path": f"artifacts/observations/{object_id}.json", "sha256": sha256(statement)}

    observations = {
        "original": observe("observe-original-bundle1", "bundle1", SERIES_ID, bundle1_hash, 1788998520),
        "copy": observe("observe-copy-bundle1", "copy-bundle", COPY_SERIES_ID, copy_bundle_hash, 1789002120),
    }

    # Cryptographic dependencies point from newer objects to already fixed objects; semantic WorkID references are excluded.
    crypto_nodes = {"p-v1", "q-v1", "p-v2-main", "p-v2-companion", "p-v2-conflict", "q-v2-amendment", "bundle1", "rotation", "bundle2", "bundle2-conflict"}
    crypto_edges = [
        ("p-v2-main", "p-v1"), ("p-v2-companion", "p-v1"), ("p-v2-conflict", "p-v1"), ("q-v2-amendment", "q-v1"),
        ("bundle1", "p-v1"), ("bundle1", "q-v1"), ("rotation", "bundle1"),
        ("bundle2", "bundle1"), ("bundle2", "rotation"), ("bundle2", "p-v2-main"), ("bundle2", "p-v2-companion"),
        ("bundle2-conflict", "bundle1"), ("bundle2-conflict", "rotation"), ("bundle2-conflict", "p-v2-conflict"), ("bundle2-conflict", "p-v2-companion"),
    ]
    semantic_nodes = {WORK_P, WORK_Q}
    semantic_edges = [(WORK_P, WORK_Q), (WORK_Q, WORK_P)]
    model_results = {
        "schema": "acsd-v1.6.0-series-graph-model-results/v1",
        "cryptographic_dependency_graph": {"node_count": len(crypto_nodes), "edge_count": len(crypto_edges), "has_cycle": has_cycle(crypto_nodes, crypto_edges)},
        "semantic_reference_graph": {"node_count": len(semantic_nodes), "edge_count": len(semantic_edges), "has_cycle": has_cycle(semantic_nodes, semantic_edges)},
        "two_phase_rule": "Paper releases cite stable WorkIDs; a later signed bundle maps WorkIDs to exact release hashes.",
        "single_paper_requires_series": False,
    }
    write_json(ARTIFACTS / "model-results.json", model_results)

    scenarios = [
        {"id": "standalone-p-v1-without-series", "type": "standalone", "release_keys": ["p-v1"], "expected": "ACCEPTED", "expected_code": "STANDALONE_VALID"},
        {"id": "mutual-citation-bundle1", "type": "bundle", "bundle_ids": ["bundle1"], "expected": "ACCEPTED", "expected_code": "SERIES_VALID"},
        {"id": "semantic-cycle-crypto-dag", "type": "graph", "expected": "ACCEPTED", "expected_code": "SEMANTIC_CYCLE_DAG_VALID"},
        {"id": "signed-bundle-with-low-commitment-rank", "type": "commitment_rank", "bundle_ids": ["bundle-rank-too-low"], "expected": "INVALID", "expected_code": "COMMITMENT_RANK_INVALID"},
        {"id": "signed-bundle-with-unsupported-semantic-edge", "type": "semantic_edge", "bundle_ids": ["bundle-unsupported-semantic-edge"], "expected": "INVALID", "expected_code": "SEMANTIC_EDGE_UNSUPPORTED"},
        {"id": "late-amendment-not-backdated", "type": "late_amendment", "release_keys": ["q-v1", "q-v2-amendment"], "bundle_ids": ["bundle1"], "expected": "ACCEPTED", "expected_code": "LATE_AMENDMENT"},
        {"id": "substitute-amendment-into-old-bundle", "type": "substitution", "release_keys": ["q-v2-amendment"], "bundle_ids": ["bundle1"], "expected": "INVALID", "expected_code": "BUNDLE_RELEASE_MISMATCH"},
        {"id": "copy-and-resign-later-lineage", "type": "copy", "bundle_ids": ["bundle1", "copy-bundle"], "expected": "INDETERMINATE", "expected_code": "CONTENT_REUSE_DIFFERENT_LINEAGE"},
        {"id": "legitimate-parallel-branches", "type": "paper_pair", "release_keys": ["p-v2-main", "p-v2-companion"], "expected": "ACCEPTED", "expected_code": "LEGITIMATE_BRANCH"},
        {"id": "same-slot-paper-double-release", "type": "paper_pair", "release_keys": ["p-v2-main", "p-v2-conflict"], "expected": "EQUIVOCATION", "expected_code": "PAPER_SLOT_CONFLICT"},
        {"id": "same-sequence-series-double-bundle", "type": "bundle_pair", "bundle_ids": ["bundle-epoch1-seq2", "bundle-epoch1-seq2-conflict"], "expected": "EQUIVOCATION", "expected_code": "SERIES_SEQUENCE_CONFLICT"},
        {"id": "epoch1-without-rotation", "type": "missing_rotation", "bundle_ids": ["bundle-epoch1-seq2"], "expected": "INVALID", "expected_code": "UNAUTHORIZED_SERIES_KEY"},
        {"id": "cross-paper-author-link-not-proven", "type": "author_link", "release_keys": ["p-v1", "q-v1"], "expected": "INDETERMINATE", "expected_code": "AUTHOR_LINK_UNPROVEN"},
    ]
    write_json(ARTIFACTS / "scenarios.json", {"schema": "acsd-v1.6.0-series-scenarios/v1", "scenarios": scenarios})

    # Python reference verification of all signed objects.
    release_checks = []
    endorsement_by_id = {item["id"]: item for item in endorsement_meta}
    for release_key, item in releases.items():
        body = item["body"]
        content = (PROJECT / item["payload"]["content"]["path"]).read_bytes()
        valid = parse_canonical_json(body) == item["payload"] \
            and item["release_id"] == f"urn:sha256:{sha256(body)}" and sha256(content) == item["payload"]["content"]["sha256"] \
            and reference_work_ids_match_content(item["payload"], content)
        for endorsement_id in item["endorsements"]:
            meta = endorsement_by_id[endorsement_id]
            author = keys[meta["author_key_id"]]
            statement = (PROJECT / meta["path"]).read_bytes()
            parsed = parse_signed_statement(statement, public_key_pem=author["public"])
            valid = valid and parsed["signature_verified"] and parsed["payload"] == body and parsed["subject"] == item["release_id"] and protected_headers(statement).get(4) == author["kid"]
        release_checks.append({"release_key": release_key, "valid": valid})

    def signed_negative_fixture_is_rejected(fixture: dict) -> bool:
        meta = fixture["meta"]
        signatures_valid = True
        for endorsement in meta["endorsements"]:
            author = keys[endorsement["author_key_id"]]
            statement = (PROJECT / endorsement["path"]).read_bytes()
            parsed = parse_signed_statement(statement, public_key_pem=author["public"])
            signatures_valid = signatures_valid and parsed["signature_verified"] \
                and parsed["payload"] == fixture["body"] and parsed["subject"] == fixture["release_id"] \
                and protected_headers(statement).get(4) == author["kid"]
        content = (PROJECT / meta["content_path"]).read_bytes()
        parsed_payload = parse_canonical_json(fixture["body"])
        return signatures_valid and (not isinstance(parsed_payload, dict)
                                    or not reference_work_ids_match_content(parsed_payload, content))

    reference_mismatch_rejected = signed_negative_fixture_is_rejected(reference_mismatch)
    witness_mismatch_rejected = signed_negative_fixture_is_rejected(witness_mismatch)
    noncanonical_rejected = signed_negative_fixture_is_rejected(noncanonical)

    signed_object_checks = []
    signed_specs = [
        ("bundle1", bundle1, bundle1_payload, "series-epoch-0", SERIES_CONTENT_TYPE),
        ("rotation", rotation, rotation_payload, "series-epoch-0", ROTATION_CONTENT_TYPE),
        ("bundle2", (SERIES / "bundle-epoch1-seq2.scitt").read_bytes(), json.loads((SERIES / "bundle-epoch1-seq2.json").read_bytes()), "series-epoch-1", SERIES_CONTENT_TYPE),
        ("bundle2-conflict", (SERIES / "bundle-epoch1-seq2-conflict.scitt").read_bytes(), json.loads((SERIES / "bundle-epoch1-seq2-conflict.json").read_bytes()), "series-epoch-1", SERIES_CONTENT_TYPE),
        ("bundle-rank-too-low", rank_too_low, rank_too_low_payload, "series-epoch-0", SERIES_CONTENT_TYPE),
        ("bundle-unsupported-semantic-edge", unsupported_edge, unsupported_edge_payload, "series-epoch-0", SERIES_CONTENT_TYPE),
        ("copy-bundle", copy_bundle, copy_payload, "copy-series-epoch-0", SERIES_CONTENT_TYPE),
    ]
    for object_id, message, payload, key_id, content_type in signed_specs:
        parsed = parse_signed_statement(message, public_key_pem=keys[key_id]["public"])
        signed_object_checks.append({"id": object_id, "valid": parsed["signature_verified"] and parsed["payload"] == canonical_json(payload) and parsed["content_type"] == content_type})

    valid_bundle_payloads = [bundle1_payload, json.loads((SERIES / "bundle-epoch1-seq2.json").read_bytes()),
                             json.loads((SERIES / "bundle-epoch1-seq2-conflict.json").read_bytes()), copy_payload]
    rank_too_low_parsed = parse_signed_statement(rank_too_low, public_key_pem=keys["series-epoch-0"]["public"])
    unsupported_edge_parsed = parse_signed_statement(unsupported_edge, public_key_pem=keys["series-epoch-0"]["public"])

    observation_checks = []
    for object_id, meta in observations.items():
        message = (PROJECT / meta["path"]).read_bytes()
        parsed = parse_signed_statement(message, public_key_pem=keys["local-observer"]["public"])
        parsed_payload = parse_canonical_json(parsed["payload"])
        observation_checks.append({"id": object_id, "valid": parsed["signature_verified"]
                                   and isinstance(parsed_payload, dict)
                                   and parsed["content_type"] == OBSERVATION_CONTENT_TYPE})

    canonical_corpus_checks = canonical_json_corpus_results()

    reference = {
        "schema": "acsd-v1.6.0-python-reference-results/v1",
        "release_checks": release_checks,
        "signed_object_checks": signed_object_checks,
        "observation_checks": observation_checks,
        "all_standalone_releases_valid": all(item["valid"] for item in release_checks),
        "all_release_reference_manifests_match_content": all(
            reference_work_ids_match_content(item["payload"], (PROJECT / item["payload"]["content"]["path"]).read_bytes())
            for item in releases.values()),
        "signed_reference_work_id_mismatch_rejected": reference_mismatch_rejected,
        "signed_citation_witness_offset_mismatch_rejected": witness_mismatch_rejected,
        "signed_noncanonical_json_rejected": noncanonical_rejected,
        "canonical_json_corpus": canonical_corpus_checks,
        "canonical_json_corpus_all_match_expected": all(item["passed"] for item in canonical_corpus_checks),
        "all_series_objects_valid": all(item["valid"] for item in signed_object_checks),
        "all_valid_bundle_commitment_ranks_valid": all(bundle_rank_is_valid(payload) for payload in valid_bundle_payloads),
        "signed_rank_too_low_bundle_rejected": rank_too_low_parsed["signature_verified"] and not bundle_rank_is_valid(rank_too_low_payload),
        "all_valid_bundle_semantic_edges_supported": all(bundle_semantic_edges_are_supported(payload, releases) for payload in valid_bundle_payloads),
        "signed_unsupported_semantic_edge_rejected": unsupported_edge_parsed["signature_verified"] and not bundle_semantic_edges_are_supported(unsupported_edge_payload, releases),
        "all_observations_valid": all(item["valid"] for item in observation_checks),
        "semantic_graph_cyclic": model_results["semantic_reference_graph"]["has_cycle"],
        "cryptographic_graph_acyclic": not model_results["cryptographic_dependency_graph"]["has_cycle"],
    }
    write_json(EVIDENCE / "python-reference-results.json", reference)

    public_key_meta = {
        key_id: {"issuer": item["issuer"], "kid_hex": item["kid_hex"], "public_key_path": item["public_key_path"]}
        for key_id, item in keys.items()
    }
    index = {
        "schema": "acsd-v1.6.0-anonymous-series-index/v1", "checked_at": "2026-09-09",
        "content_types": {"paper": PAPER_CONTENT_TYPE, "series": SERIES_CONTENT_TYPE, "rotation": ROTATION_CONTENT_TYPE, "observation": OBSERVATION_CONTENT_TYPE},
        "series_ids": {"original": SERIES_ID, "copy": COPY_SERIES_ID}, "work_ids": {"p": WORK_P, "q": WORK_Q, "z": WORK_Z, "copy_p": COPY_WORK_P, "copy_q": COPY_WORK_Q},
        "public_keys": public_key_meta, "releases": release_meta, "endorsements": endorsement_meta,
        "bundles": bundle_meta,
        "negative_fixtures": {
            "reference_work_id_mismatch": reference_mismatch_meta,
            "citation_witness_offset_mismatch": witness_mismatch_meta,
            "noncanonical_json": noncanonical_meta,
        },
        "rotation": {"path": "artifacts/series/rotation-epoch0-to-1.scitt", "payload_path": "artifacts/series/rotation-epoch0-to-1.json", "sha256": rotation_hash, "from_key_id": "series-epoch-0", "to_key_id": "series-epoch-1"},
        "observations": observations, "model_results_path": "artifacts/model-results.json", "scenarios_path": "artifacts/scenarios.json",
        "external_time_used": False, "external_transparency_service_used": False, "author_natural_identity_established": False,
        "cross_paper_author_identity_link_established": False, "originality_truth_established": False, "legal_non_repudiation_established": False,
    }
    write_json(ARTIFACTS / "profile-index.json", index)

    print(json.dumps({
        "standalone_releases": len(releases), "author_endorsements": len(endorsement_meta), "series_signed_objects": len(signed_specs),
        "scenarios": len(scenarios), "python_reference_valid": reference["all_standalone_releases_valid"] and reference["all_series_objects_valid"] and reference["all_observations_valid"],
        "semantic_cycle": reference["semantic_graph_cyclic"], "cryptographic_dag": reference["cryptographic_graph_acyclic"],
    }, indent=2))


if __name__ == "__main__":
    main()
