# Manuscript scope and split audit

Checked 2026-09-16. This is a planning record, not a venue-submission decision
or publication authorization.

## Verified constraints

- The maintained manuscript remains a full single-column technical report; a
  one-line wrapper now compiles the same source in the conference template, so
  there is no second scientific manuscript to drift out of sync.
- The ACSAC 2026 call requires IEEEtran `conference,compsoc`, at most 11
  double-column body pages, and at most 5 pages of references and appendices;
  reviewers need not read appendices.
- The same call evaluates novelty, technical correctness, evaluation quality,
  and presentation clarity, and expects artifact availability after acceptance.
- `paper/architecture.tikz` exists, is compiled into the PDF, and is explicitly
  included by `build_release.py`.

Primary venue source:
<https://www.acsac.org/2026/submissions/papers/>.

## Route ledger

| Approach | Target or obstruction | Evidence | Missing check | Cost | Status |
|---|---|---|---|---|---|
| Submit the current full manuscript unchanged | Preserve every subsystem in the main narrative | Complete 19-page technical manuscript and artifact | IEEE-template page count and first-pass reader load | low | ruled out for ACSAC formatting, not for technical-report use |
| Immediately split into lineage and disclosure/citation papers | Reduce terminology per paper | The subsystems have distinguishable objects and tests | A second independent research question, threat model, evaluation, and non-overlap argument | high | unexplored |
| Core-first conference paper with full implementation artifact | Foreground approval closure, authorized succession, recovery, exact delegation, and controlled baselines; summarize series and disclosures as scoped extensions | Current architecture, formal properties, attack corpus, GnuPG/Ed25519 comparison, and scripted roles | Recheck the future venue's final call and conduct external review | medium | locally demonstrated; preferred route |
| Full local technical report plus a shorter anonymous submission | Retain complete specification while reducing reviewer load | Existing full manuscript and reproducible evidence package | Venue self-citation/anonymity treatment and overlap check before any public report | medium | unexplored; no publication authorized |
| Later companion paper | Develop series/citation or selective disclosure into a separate contribution | Existing implementation and early experiments | New central claim and evaluation not already consumed by the core paper | high | unexplored |

## Smallest informative next experiment

Compile the single source through `paper/acsd-acsac.tex`, then enforce a
`\clearpage` boundary immediately before the excluded LLM statement and
references. Allocate the 11-page body first to: problem and
GPG-plus-timestamp boundary; architecture/threat model; approval closure and
authorized lineage; recovery and exact delegation; implementation/evaluation;
formal properties; related work and limitations. Keep the grouped evaluation
summary in the paper and the complete case-level matrix in the artifact.

The experiment succeeds if the LLM statement starts on page 12 after all body
floats have been flushed, without shrinking fonts, hiding limitations, or
depending on appendix-only definitions. The current local build meets that
test under the verified ACSAC 2026 rules. Future calls must be checked again;
this result is not a claim about unpublished ACSAC 2027 requirements.

## Decision

Do not split now. Preserve one complete engineering and formal model, but make
the conference narrative core-first. The template experiment no longer shows
a page obstruction: the grouped evidence table retains the claims needed by a
reviewer, while the artifact retains the full matrix. A split becomes justified
only if later external review identifies two independent questions and
evaluations; terminology count alone is not sufficient evidence.

## Mock-review pass (2026-09-16)

The smallest informative review object was the compiled 11-page body, not the
long technical-report source. The pass treated novelty, correctness,
evaluation, presentation, and double-blind compliance as separate decisions.

| Route | Target or obstruction | Evidence | Missing check | Cost | Status |
|---|---|---|---|---|---|
| Add more protocol mechanisms | Increase apparent contribution count | The current profile already spans lineage, recovery, series and disclosure | No reviewer request identifies a missing security decision | high | ruled out for this pass |
| Split immediately | Reduce terminology per paper | The body already fits 11 pages and one end-to-end claim connects the subsystems | Independent second question and evaluation | high | unexplored |
| Language-only convergence | Reduce defensive phrasing and first-pass load | Repetitive negative constructions in threat model and related work | Recompile and recheck page boundary | low | attempted; preferred |
| Double-blind repair | Remove identity-linked repository evidence from the submission text | A named GitHub account appeared in the v1 proof-surface footnote | Submission-package-wide anonymity scan | low | attempted; required |

The pass removed the identity-linked URL from the manuscript, split the dense
adversary sentence, and rewrote selected related-work and limitation sentences
affirmatively. It deliberately retained the Introduction's simple-baseline
challenge, protocol definitions, attack model, measured comparisons, formal
boundary, and limitations. The remaining external-validity gap is unchanged:
there are no human participants or production deployments.
