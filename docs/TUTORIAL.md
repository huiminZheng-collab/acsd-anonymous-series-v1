# ACSD hands-on tutorial

This tutorial takes an author from a clean checkout to a locally verified ACSD
release. It then shows the corresponding-author workflow for remote coauthors
and the commands an independent reader uses to verify a received package.

The bundled `examples/tutorial-paper.txt` is deliberately fictional and
contains no author identity. Replace it with your final PDF when using ACSD for
real work.

## Choose a path

| Goal | Start here | Typical operator |
|---|---|---|
| Freeze and approve one manuscript locally | [A. Single author](#a-single-author-five-minute-path) | One author |
| Collect approvals without collecting private keys | [B. Remote coauthors](#b-corresponding-author-and-remote-coauthors) | Corresponding author and coauthors |
| Check a package received from someone else | [C. Independent verification](#c-independent-third-party-verification) | Reader, reviewer, or archivist |

ACSD creates and verifies local evidence packages. None of these commands
uploads to GitHub, submits to a venue, or publishes to an archive.

## Before you start

You need Python 3.9 or newer. From the repository root, install the CLI and
confirm the version:

```console
python -m pip install .
acsd --version
```

Keep these boundaries in mind:

- A private key stays with its author. Never put it inside a release directory,
  repository, archive, chat, or shared drive.
- A Git commit date is not independent time evidence. Use an external RFC 3161
  timestamp authority when independently witnessed time matters.
- A valid ACSD package proves statements about exact bytes and pseudonymous
  keys. It does not prove a person's civil identity, originality, correctness,
  peer review, or global priority.
- The public repository may still identify its account owner. A manuscript
  without names is content-anonymous, not necessarily author-unlinkable.

All commands below use forward slashes and work in PowerShell, Bash, and zsh.
If your Python installation exposes the command as `py` or `python3`, use that
name for the installation command.

## A. Single author: five-minute path

### A1. Generate and protect the author key

Create the key outside the directory that will become public:

```console
acsd keygen --name author --out-dir private-keys --encrypt
```

Enter a passphrase twice when prompted. The command creates:

```text
private-keys/
  author.key    private, encrypted; do not publish
  author.pub    public; safe to include in protocol objects
```

Back up the private key and passphrase separately. ACSD has no identity-based
account recovery. Losing the only authorized key can permanently stop that
WorkID lineage unless a recovery authority was committed in advance.

### A2. Build and approve the release

To run the bundled example:

```console
acsd release examples/tutorial-paper.txt --key private-keys/author.key --out tutorial-release --allow-untimestamped
```

For a real manuscript, replace `examples/tutorial-paper.txt` with the path to
the final PDF. ACSD prompts once for the encrypted key and produces a finalized
directory package at `tutorial-release/`.

The `--allow-untimestamped` flag is an explicit downgrade used here so the
tutorial works without contacting an external service. It does not create
independent time evidence. For a real timestamped release, replace it with a
TSA selected under your own trust policy:

```console
acsd release paper.pdf --key private-keys/author.key --out release-dir --tsa https://tsa.example/tsr
```

The TSA URL is a network destination: check its privacy policy, retention
policy, certificate chain, and availability before sending a request. ACSD
sends a SHA-256 message imprint in an RFC 3161 request, not the manuscript.

### A3. Verify locally

```console
acsd verify tutorial-release
```

A successful untimestamped example reports a valid package and pseudonymous
key assent, but it does not grant `APPROVAL_SET_EXISTED_NOT_AFTER`.

For an externally timestamped package, obtain the TSA signer certificate or
its SHA-256 fingerprint independently and pin it during verification:

```console
acsd verify release-dir --tsa-trust-cert independently-obtained-tsa.crt --require-external-time
```

Merely accepting a certificate embedded in the package would let the package
choose its own time authority. `--require-external-time` fails unless the
independently pinned RFC 3161 evidence verifies.

### A4. Know what can be shared

Share or publish the finalized release directory only after inspecting it.
Keep `private-keys/` private. A minimal layout is:

```text
private-keys/       KEEP PRIVATE
tutorial-release/   SHAREABLE AFTER REVIEW
```

Preparing this directory is not authorization to push it, create a public
repository, publish a DOI, or submit it to a venue. Those are separate actions.

## B. Corresponding author and remote coauthors

This path lets the corresponding author assemble and timestamp the package
without receiving anyone else's private key. The example has Alice in author
slot 1 and Bob in slot 2. Names here label local folders only; the protocol
records pseudonymous public keys.

### B1. Each author generates a key locally

On Alice's machine:

```console
acsd keygen --name alice --out-dir alice-private --encrypt
```

On Bob's machine:

```console
acsd keygen --name bob --out-dir bob-private --encrypt
```

Each author sends only the `.pub` file to the corresponding author. Private
`.key` files never move between authors.

### B2. The corresponding author initializes the candidate

With the public keys placed in byline order:

```console
acsd init paper.pdf --public-key alice.pub --public-key bob.pub --role first-author --role senior-author --corresponding 1 --contribution 1:conceptualization --contribution 2:supervision --ai-tool ChatGPT --ai-purpose brainstorming --ai-reviewed-by 1 --out release-dir
```

Omit the AI options when no AI tool was used. Supplying both tool and purpose
makes the declaration part of the exact object every author reviews and signs.

The corresponding author can inspect progress without changing the package:

```console
acsd inspect release-dir
acsd review release-dir
```

### B3. Export one self-contained request per remote author

First list the missing approvals and key identifiers:

```console
acsd inspect release-dir
```

Then export Bob's request using the displayed key identifier:

```console
acsd export-approval-request release-dir --for-author <bob-key-id> --out bob-request
```

Send the complete `bob-request/` directory to Bob. It contains no private key.
Do not edit or cherry-pick files inside the request; its strict manifest covers
the transported snapshot.

For a larger team, export all outstanding requests at once:

```console
acsd export-approval-requests release-dir --out requests
```

Send each `requests/slot-*` child directory only to its intended author.

### B4. Each remote author reviews and responds

On Bob's machine:

```console
acsd respond-approval-request bob-request --key bob-private/bob.key --out bob-response
```

Before signing, ACSD validates and displays the manuscript digest and size,
ordered byline roles, corresponding-author choice, contribution and AI-use
declarations, claim policy, lineage edge, and approval-target digest. Bob must
type `APPROVE`. The resulting response contains the exact COSE approval and a
routing record, not Bob's private key.

Bob sends the complete `bob-response/` directory back to the corresponding
author.

### B5. Import responses and finalize atomically

For one response:

```console
acsd import-approval-response release-dir bob-response
```

The corresponding author approves their own slot locally:

```console
acsd author-approve release-dir --key alice-private/alice.key
```

Then finalize with an external TSA:

```console
acsd coordinator-finalize release-dir --tsa https://tsa.example/tsr
```

If independent time evidence is deliberately not required, the coordinator
must state that downgrade explicitly:

```console
acsd coordinator-finalize release-dir --allow-untimestamped
```

For a batch, place each returned response directory immediately below
`responses/` and combine verified import with finalization:

```console
acsd coordinator-finalize release-dir --responses-dir responses --tsa https://tsa.example/tsr
```

Import and finalization are transactional. A forged signature, altered request,
wrong target, duplicate author, or malformed response leaves the live candidate
unchanged.

### B6. Final check before sharing

```console
acsd verify release-dir
```

When external time is required, use the independently obtained TSA trust input:

```console
acsd verify release-dir --tsa-trust-cert independently-obtained-tsa.crt --require-external-time
```

The corresponding author may now distribute the finalized directory. GitHub,
Zenodo, and venue submission remain separate publication decisions.

## C. Independent third-party verification

Start from the exact directory you received or downloaded, not the author's
working copy. Install ACSD, then run:

```console
acsd verify received-release
```

Read the result in layers:

1. **Package integrity:** the manifest and manuscript bytes agree.
2. **Approval:** the declared pseudonymous author keys approved the same closed
   target.
3. **Lineage:** for a successor, predecessor authority approved that exact
   parent-to-child edge.
4. **Time:** an external-time outcome appears only when independently pinned
   RFC 3161 evidence verifies.

If a release claims independent time, require it explicitly:

```console
acsd verify received-release --tsa-trust-cert tsa-signer.crt --require-external-time
```

For a revision, pin the exact parent that you previously accepted:

```console
acsd verify received-v2 --expected-parent-release-id urn:sha256:<known-parent-release-id>
```

Without parent pinning, a verifier cannot distinguish the known lineage from a
parallel genesis that merely copied a visible WorkID.

For machine-readable output:

```console
acsd verify received-release --json
```

Treat a zero exit status as acceptance under ACSD's stated profile, not as a
judgment of scientific correctness, originality, natural-person authorship,
venue acceptance, or peer review.

## What to learn next

- Authorized revisions, recovery quorums, fork detection, and key-reuse audits:
  [README: Authorized revisions](../README.md#authorized-revisions)
- RFC 3161 trust and local-test behavior:
  [README: Independent time evidence](../README.md#independent-time-evidence)
- Selective author unblinding:
  [README: Selective author unblinding](../README.md#selective-author-unblinding)
- Full command and exit-code reference:
  [CLI specification](../design/CLI-SPEC.md)
- Security boundaries and protocol objects:
  [Protocol specification](../SPEC.md)

## Common failures

| Symptom | Meaning and next action |
|---|---|
| `PRIVATE_KEY_PASSPHRASE_REQUIRED` | The encrypted key needs an interactive terminal. Do not put its passphrase in a command-line argument or environment variable. |
| Finalization refuses to continue without time options | Choose `--tsa URL` or deliberately acknowledge the downgrade with `--allow-untimestamped`. |
| A remote response is rejected | Re-export from the current candidate. Do not copy individual signature files or rewrite the request/response manifest. |
| `VALID_OBJECT_BUT_UNAUTHORIZED_SUCCESSOR` | The child is internally valid but lacks the predecessor threshold's authorization for the exact lineage edge. |
| `UNPINNED_EXACT_PARENT` | Supply the exact parent ReleaseID you previously accepted when lineage continuity matters. |
| External time is present but unverified | Supply an independently obtained TSA signer certificate or fingerprint; do not trust a package solely because it contains a receipt. |
