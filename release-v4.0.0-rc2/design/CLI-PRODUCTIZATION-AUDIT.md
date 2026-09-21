# CLI productization audit

Status: **bounded installed-CLI route**. Checked 2026-09-15.

## Question

Can sole and distributed coauthors use ACSD without understanding internal PEC
files or exchanging private keys, while retaining the deliberate boundary that
key generation, encryption, and backup remain a local security choice?

## Verified current surface

The installed `acsd` command has one-command `release` and `revise` paths.
`release` creates, approves, and finalizes a genesis release from locally held
author keys. `revise` creates the exact successor, supplies predecessor
authorization only if the authority changes, approves the child, and finalizes
it. Identity disclosure is an external sidecar command and does not mutate a
finalized release.

For a distributed team, the coordinator exports one review request per author,
collects minimal response directories, and can import, automatically exercise
exact delegations addressed to local agent keys, and finalize in one staged
transaction. The workflow requires no JSON editing and no copying of key IDs.

This audit intentionally treats key creation as a separate first-time action:
an author chooses where a private key lives and whether it is encrypted before
a release command ever sees it. Combining key creation with release output
would make a short demo but would blur the public/private plane and create an
unsafe default for backups and passphrase handling.

## Route ledger

| Approach | Target or obstruction | Evidence | Missing check | Cost | Status |
|---|---|---|---|---|---|
| One command for genesis after pre-existing key setup | Avoid internal-object manipulation for the common single-author case | `acsd release`, README quickstart, and fresh-wheel gate | A future usability study rather than another protocol test | low | bounded validation complete |
| One command for same-author revision | Preserve lineage while avoiding manual transition files | `acsd revise`, fresh-wheel pinned-parent verification, same-line audit, and successor disclosure | A future usability study rather than another protocol test | low | bounded validation complete |
| Distributed coauthor collection | Keep author keys local while removing per-slot digest and key-ID handling | batch request/response exchange, `coordinator-finalize --delegate-key`, scripted three-author evaluation, and fresh-wheel gate | Human-participant usability evidence | medium | scripted validation complete |
| Automatically create/store a private key during release | Fails separation of public release output from local key custody and passphrase choice | CLI key-protection profile and encrypted-key behavior | A secure keystore/recovery design, not a convenience wrapper | high | ruled out |
| Hide authority-changing revision choices behind an automatic default | Would conceal threshold, predecessor, and recovery authorization choices | Exact-transition threat model | Explicit UX research and a safe policy language | high | ruled out |
| Add a graphical or hosted workflow | Could reduce friction but adds key-custody/service trust scope | No such trust/deployment model is specified | Product and threat-model decision | high | unexplored |

## Smallest informative installed-path test

The engineering gate's fresh-wheel flow now exercises exactly this sequence in
a new virtual environment and temporary directory:

1. generate a local author key outside all release directories;
2. run one-command genesis `release` and offline `verify`;
3. run one-command same-author `revise`;
4. verify the successor with its exact `parent_release_id` pinned;
5. audit same-line key reuse as continuity rather than cross-WorkID linkage;
6. publish and verify a full-byline identity sidecar for the successor;
7. create a separate release with a different key and run the cross-work audit;
8. exchange an author response that delegates one exact target; and
9. import the response, discover its slot from the agent key, finalize, and
   verify without manually supplying an author key ID.

The test is **exact computation/integration validation**, not a usability
study. It demonstrates that these commands need neither PEC-file editing nor
manual digest construction. It does not show that a first-time researcher
understands key backup, chooses a trustworthy TSA, or has achieved authorship,
priority, venue acceptance, or strict double-blind unlinkability.

## Pre-mortem and stop conditions

| Failure | Early warning | Stop condition or mitigation |
|---|---|---|
| The wheel CLI differs from the source CLI | A source-only test passes while installed command fails | Gate must execute only the installed console script for this route |
| `revise` silently accepts an unpinned parent | A verification succeeds without exercising `--expected-parent-release-id` | Read the child-recorded parent ID and pass it explicitly in the gate |
| Disclosure mutates the release | Tree/manifest changes after disclosure | Keep sidecars in a distinct directory and verify them separately |
| Convenience erodes key protection | A new option accepts passphrases or writes keys under a release | Reject the route; retain interactive local key handling |
| Test becomes a real-publication proxy | Test fixture starts claiming time, authorship, acceptance, or priority | Keep the scenario local and state its non-claims |

## Acceptance condition

The route has passed the installed-wheel scenarios and the final read-only
gate, including source-tree byte identity. A separate scripted three-author
evaluation records seven post-key-setup commands, zero JSON edits, zero private
key transfers, zero copied protocol identifiers, and atomic rejection of a
tampered response collection. Until a
separate key-custody or UX study exists, ACSD should describe this as a tested
command-line workflow, not as universally easy author software.

The public GitHub repository is currently hosted under a personally identifying
account. That is compatible with a named-hosted research prototype, but not
with a claim of unlinkable double-blind publication. No promotion or discovery
campaign is part of this pre-submission engineering work.
