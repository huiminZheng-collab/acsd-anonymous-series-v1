# Multi-author partial and full unblinding

Checked 2026-09-14 against the post-v3.2 source tree. ACSD treats author-slot
identity assent, full-byline coverage, contribution claims, and venue status as
different statements.

## Rule

Each author slot signs its own exact identity sidecar. A valid subset is useful
and is labeled `PARTIAL_BYLINE_KEY_ASSENT`; it does not speak for missing
slots. `FULL_BYLINE_KEY_ASSENT` requires exactly one valid sidecar for every
slot in the verified release. Duplicate or conflicting sidecars for one slot
are rejected without choosing a winner.

The aggregate result preserves the release's slot ordering and may report a
shared publication reference when all supplied sidecars sign the same string.
It does not verify natural-person identity, contribution truth, a joint team
statement, or venue acceptance. Contribution disclosure needs its own typed
object and authorization rule; adding a contribution field to an identity
sidecar is rejected rather than silently interpreted.

This narrow result matters under key compromise: a thief holding a slot key can
create a valid sidecar naming an uninvolved person. Such an object remains only
slot-key assent to an identity string; it is not authenticated consent by, or
verification of, the named natural person. A deployment that wants that stronger
claim needs an additional independently authenticated countersignature or
credential and its own issuer/revocation assumptions.

Partial disclosure also does not guarantee that undisclosed teammates remain
anonymous. Collaboration graphs and public context may reveal them by inference.
All identity disclosures are practically irreversible once published, and a
valid signature does not establish absence of error or coercion. Authors should
therefore perform a team-level privacy review before publishing even one slot.

## CLI

```text
acsd verify-identity-set release-dir \
  --disclosure identity-slot-1.json --signature identity-slot-1.cose \
  --disclosure identity-slot-2.json --signature identity-slot-2.cose \
  --require-full-byline
```

Omit `--require-full-byline` when an intentionally partial disclosure should
be accepted as partial. With the flag, valid but incomplete coverage returns
exit code 5. Invalid signatures, wrong releases or keys, duplicate slots, and
malformed bodies return verification failure instead.

## Executable experiment

`design/multi_author_unblinding_runner.py` constructs a temporary three-author
release and checks 1/3, 2/3, and 3/3 coverage through the installed-style public
CLI. It also rejects a repeated slot, a signed-name mutation, and an attempted
contribution-field injection. The checked report contains no private keys or
real identities.
