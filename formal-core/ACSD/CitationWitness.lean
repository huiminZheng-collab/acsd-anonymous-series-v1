import ACSD.SeriesGraph

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

/-!
This small layer specifies the byte-witness contract used by the executable
series profile.  A witness names a stable WorkId and an exact UTF-8 byte range
inside one exact revision.  `exactToken` deliberately remains an abstract
scanner relation: this module proves the consequences of a scanner result, not
the correctness of a particular parser, JSON decoder, or hash implementation.
-/

structure CitationByteWitness where
  work : WorkId
  byteOffset : Nat
  byteLength : Nat

structure CitationWitnessManifest where
  digest : Digest
  revision : RevisionRef
  listedReference : WorkId → Prop
  signedWitness : CitationByteWitness → Prop

structure CitationWitnessScanner where
  exactToken : RevisionRef → CitationByteWitness → Prop

def WitnessTargets (manifest : CitationWitnessManifest) (work : WorkId) : Prop :=
  ∃ witness, manifest.signedWitness witness ∧ witness.work = work

def ScannerTargets (scanner : CitationWitnessScanner) (revision : RevisionRef)
    (work : WorkId) : Prop :=
  ∃ witness, scanner.exactToken revision witness ∧ witness.work = work

/-! Acceptance requires equality of the signed witness collection and the
scanner result, plus an exact correspondence between the published WorkId list
and the targets of those witnesses. -/
structure CitationWitnessAcceptance (scanner : CitationWitnessScanner)
    (manifest : CitationWitnessManifest) : Prop where
  signed_witness_is_exact_token :
    ∀ witness, manifest.signedWitness witness → scanner.exactToken manifest.revision witness
  exact_token_is_signed_witness :
    ∀ witness, scanner.exactToken manifest.revision witness → manifest.signedWitness witness
  listed_reference_iff_witness_target :
    ∀ work, manifest.listedReference work ↔ WitnessTargets manifest work

/-! This is the explicit refinement seam to the general SeriesGraph model.
It must be discharged by a real implementation before treating its idealized
`releaseTextCites` predicate as a statement about bytes. -/
structure CitationWitnessSeriesRefinement (scanner : CitationWitnessScanner)
    (manifest : CitationWitnessManifest) (graph : SeriesGraph) : Prop where
  text_cites_iff_scanner_target :
    ∀ work, graph.releaseTextCites manifest.revision work ↔
      ScannerTargets scanner manifest.revision work

theorem accepted_listed_reference_has_exact_signed_byte_witness
    {scanner : CitationWitnessScanner} {manifest : CitationWitnessManifest}
    {work : WorkId}
    (accepted : CitationWitnessAcceptance scanner manifest)
    (listed : manifest.listedReference work) :
    ∃ witness, manifest.signedWitness witness ∧
      scanner.exactToken manifest.revision witness ∧ witness.work = work := by
  obtain ⟨witness, signed, target⟩ :=
    (accepted.listed_reference_iff_witness_target work).mp listed
  exact ⟨witness, signed, accepted.signed_witness_is_exact_token witness signed, target⟩

theorem accepted_exact_byte_token_is_listed_reference
    {scanner : CitationWitnessScanner} {manifest : CitationWitnessManifest}
    {work : WorkId}
    (accepted : CitationWitnessAcceptance scanner manifest)
    (token : ScannerTargets scanner manifest.revision work) :
    manifest.listedReference work := by
  obtain ⟨witness, exact, target⟩ := token
  exact (accepted.listed_reference_iff_witness_target work).mpr
    ⟨witness, accepted.exact_token_is_signed_witness witness exact, target⟩

/-! A signed witness at a byte range which the scanner rejects makes the
manifest unacceptable, even if signatures over the manifest itself verify. -/
theorem witness_offset_mismatch_prevents_acceptance
    {scanner : CitationWitnessScanner} {manifest : CitationWitnessManifest}
    {witness : CitationByteWitness}
    (signed : manifest.signedWitness witness)
    (notExact : ¬ scanner.exactToken manifest.revision witness) :
    ¬ CitationWitnessAcceptance scanner manifest := by
  intro accepted
  exact notExact (accepted.signed_witness_is_exact_token witness signed)

/-! Conversely, an exact token silently omitted from the signed witness
collection also makes the manifest unacceptable. -/
theorem omitted_exact_byte_token_prevents_acceptance
    {scanner : CitationWitnessScanner} {manifest : CitationWitnessManifest}
    {witness : CitationByteWitness}
    (exact : scanner.exactToken manifest.revision witness)
    (notSigned : ¬ manifest.signedWitness witness) :
    ¬ CitationWitnessAcceptance scanner manifest := by
  intro accepted
  exact notSigned (accepted.exact_token_is_signed_witness witness exact)

theorem accepted_listed_reference_refines_to_series_text_citation
    {scanner : CitationWitnessScanner} {manifest : CitationWitnessManifest}
    {graph : SeriesGraph} {work : WorkId}
    (accepted : CitationWitnessAcceptance scanner manifest)
    (refinement : CitationWitnessSeriesRefinement scanner manifest graph)
    (listed : manifest.listedReference work) :
    graph.releaseTextCites manifest.revision work := by
  apply (refinement.text_cites_iff_scanner_target work).mpr
  obtain ⟨witness, _signed, exact, target⟩ :=
    accepted_listed_reference_has_exact_signed_byte_witness accepted listed
  exact ⟨witness, exact, target⟩

end ACSD
