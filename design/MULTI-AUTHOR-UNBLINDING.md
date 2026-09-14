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
