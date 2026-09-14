"""I/O-free audit of observable public-key reuse across ACSD releases."""

from canonical_json import require
from release_adapter import adapt_release


NON_CLAIMS = [
    "natural_person_identity_verified",
    "universal_unlinkability_verified",
    "common_human_controller_verified",
]


def audit_releases(releases):
    """Classify repeated public keys within and across WorkID lineages.

    Inputs are assumed to have passed the caller's release-verification policy.
    The function remains defensive about the fields it projects and performs no
    filesystem, signature, or network operations.
    """
    require(isinstance(releases, list) and len(releases) >= 2,
            "AT_LEAST_TWO_RELEASES_REQUIRED")
    seen_release_digests = set()
    occurrences = []
    for release_index, release in enumerate(releases, 1):
        require(isinstance(release, dict), "RELEASE_INVALID")
        adapted = adapt_release(release)
        require(adapted["digest"] not in seen_release_digests,
                "DUPLICATE_RELEASE_INPUT")
        seen_release_digests.add(adapted["digest"])
        authors = release.get("authors")
        require(isinstance(authors, list) and authors, "RELEASE_AUTHORS_INVALID")
        for author in authors:
            require(isinstance(author, dict), "RELEASE_AUTHORS_INVALID")
            slot = author.get("slot")
            key_id = author.get("key_id")
            require(isinstance(slot, int) and not isinstance(slot, bool) and slot > 0,
                    "RELEASE_AUTHOR_SLOT_INVALID")
            require(isinstance(key_id, str) and bool(key_id), "KEY_ID_INVALID")
            occurrences.append({
                "release_index": release_index,
                "release_digest": adapted["digest"],
                "work_id": adapted["work_id"],
                "line": adapted["line"],
                "version": adapted["version"],
                "author_slot": slot,
                "key_id": key_id,
            })

    by_key = {}
    for occurrence in occurrences:
        by_key.setdefault(occurrence["key_id"], []).append(occurrence)

    cross_work_groups = []
    same_work_groups = []
    for key_id in sorted(by_key):
        items = sorted(
            by_key[key_id],
            key=lambda item: (
                item["release_index"], item["author_slot"], item["line"],
                item["version"], item["release_digest"],
            ),
        )
        if len(items) < 2:
            continue
        work_ids = sorted({item["work_id"] for item in items})
        group = {
            "key_id": key_id,
            "work_ids": work_ids,
            "occurrences": items,
        }
        if len(work_ids) > 1:
            cross_work_groups.append(group)
        else:
            same_work_groups.append(group)

    status = (
        "CROSS_WORK_KEY_REUSE_DETECTED"
        if cross_work_groups else "NO_CROSS_WORK_KEY_REUSE"
    )
    return {
        "status": status,
        "release_count": len(releases),
        "author_slot_occurrence_count": len(occurrences),
        "cross_work_reuse_groups": cross_work_groups,
        "same_work_reuse_groups": same_work_groups,
        "non_claims": list(NON_CLAIMS),
    }
