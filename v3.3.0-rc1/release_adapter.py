"""Pure projections from supported ACSD release wire formats.

The adapter does not establish authorship or verify signatures.  It only
normalizes fields already present in an accepted release object into the
binding view consumed by PEC validation.
"""

from canonical_json import digest, require


SUPPORTED_RELEASE_SCHEMAS = frozenset({
    "acsd-v1.6.0-paper-release/v1",
    "acsd-v3-paper-release/v1",
})


def adapt_release(release):
    """Project a supported release object into its PEC binding view."""
    require(release.get("schema") in SUPPORTED_RELEASE_SCHEMAS, "RELEASE_SCHEMA")
    return {
        "digest": digest(release),
        "content_sha256": release["content"]["sha256"],
        "author_key_ids": [author["key_id"] for author in release["authors"]],
        "work_id": release["work_id"],
        "version": release["slot"]["version"],
        "line": release["slot"]["line"],
    }
