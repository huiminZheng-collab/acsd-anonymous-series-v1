import ACSD.Appraisal

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

/-! A small formal counterpart of `acsd-verification-certificate/v1`.
The raw JSON/COSE/Merkle adapters are outside Lean; this module independently
checks closure of the exact typed facts they report before appraisal. -/

inductive SignaturePurpose where
  | authorApproval
  | eventDisclosure
  | identityDisclosure
  deriving DecidableEq, Repr

structure TranscriptSignature where
  purpose : SignaturePurpose
  key : KeyId
  payloadDigest : Digest
  coseDigest : Digest
  deriving DecidableEq, Repr

structure TranscriptMerkle where
  bodyDigest : Digest
  commitmentDigest : Digest
  firstIndex : Nat
  lastIndex : Nat
  openedLeafCount : Nat
  deriving DecidableEq, Repr

structure TranscriptIdentity where
  bodyDigest : Digest
  releaseDigest : Digest
  authorSlot : Nat
  authorKey : KeyId
  assertionDigest : Digest
  coseDigest : Digest
  deriving DecidableEq, Repr

structure TranscriptTime where
  approvalSetDigest : Digest
  approvalTargetDigest : Digest
  authorApprovals : List (KeyId × Digest)
  lineageAuthorizations : List (KeyId × Digest)
  notAfterUtc : String
  policyOid : String
  serialHex : String
  requestDigest : Digest
  responseDigest : Digest
  certificateDigest : Digest
  reportDigest : Digest
  approvalSetInputDigest : Digest
  signerFingerprint : Digest
  trustedSignerFingerprint : Digest
  trustedCertificateDigest : Digest
  authorityExternal : Bool
  trustedAuthorityExternal : Bool
  deriving DecidableEq, Repr

structure VerificationTranscript where
  targetDigest : Digest
  approvalPecDigest : Digest
  eventPecDigest : Digest
  policyPecDigest : Digest
  policyClaims : List ScopedClaim
  approvalKeys : List KeyId
  approvalCoseDigests : List Digest
  eventBodyDigest : Digest
  eventId : String
  eventSequence : Nat
  eventCommitmentDigest : Digest
  eventFirstIndex : Nat
  eventLastIndex : Nat
  eventKeys : List KeyId
  eventCoseDigests : List Digest
  releaseDigest : Option Digest
  releaseSlots : List (Nat × KeyId)
  identityFacts : List TranscriptIdentity
  identityCoseDigests : List Digest
  timeFacts : List TranscriptTime
  approvalSetInputDigests : List Digest
  timeRequestDigests : List Digest
  timeResponseDigests : List Digest
  tsaCertificateDigests : List Digest
  timeReportDigests : List Digest
  signatures : List TranscriptSignature
  merkleFacts : List TranscriptMerkle
  deriving DecidableEq, Repr

def signatureProjection
    (purpose : SignaturePurpose) (facts : List TranscriptSignature) :
    List (KeyId × Digest) :=
  (facts.filter fun item => decide (item.purpose = purpose)).map
    fun item => (item.key, item.payloadDigest)

def expectedSignatures (keys : List KeyId) (payload : Digest) :
    List (KeyId × Digest) := keys.map fun key => (key, payload)

def ApprovalGroupClosed (transcript : VerificationTranscript) : Prop :=
  transcript.approvalKeys ≠ [] ∧
  transcript.approvalKeys.Nodup ∧
  signatureProjection .authorApproval transcript.signatures =
    expectedSignatures transcript.approvalKeys transcript.targetDigest ∧
  transcript.approvalCoseDigests.Nodup ∧
  (transcript.signatures.filter fun item =>
      decide (item.purpose = .authorApproval)).map (·.coseDigest) =
    transcript.approvalCoseDigests

def approvalGroupClosedB (transcript : VerificationTranscript) : Bool :=
  decide (transcript.approvalKeys ≠ []) &&
  decide (transcript.approvalKeys.Nodup) &&
  decide (
    signatureProjection .authorApproval transcript.signatures =
      expectedSignatures transcript.approvalKeys transcript.targetDigest) &&
  decide (transcript.approvalCoseDigests.Nodup) &&
  decide (
    (transcript.signatures.filter fun item =>
        decide (item.purpose = .authorApproval)).map (·.coseDigest) =
      transcript.approvalCoseDigests)

def expectedMerkle (transcript : VerificationTranscript) : TranscriptMerkle := {
  bodyDigest := transcript.eventBodyDigest
  commitmentDigest := transcript.eventCommitmentDigest
  firstIndex := transcript.eventFirstIndex
  lastIndex := transcript.eventLastIndex
  openedLeafCount := transcript.eventLastIndex - transcript.eventFirstIndex + 1
}

def EventGroupClosed (transcript : VerificationTranscript) : Prop :=
  transcript.eventPecDigest = transcript.approvalPecDigest ∧
  transcript.eventKeys ≠ [] ∧
  transcript.eventKeys.Nodup ∧
  transcript.eventFirstIndex ≤ transcript.eventLastIndex ∧
  signatureProjection .eventDisclosure transcript.signatures =
    expectedSignatures transcript.eventKeys transcript.eventBodyDigest ∧
  transcript.eventCoseDigests.Nodup ∧
  (transcript.signatures.filter fun item =>
      decide (item.purpose = .eventDisclosure)).map (·.coseDigest) =
    transcript.eventCoseDigests ∧
  transcript.merkleFacts = [expectedMerkle transcript]

def eventGroupClosedB (transcript : VerificationTranscript) : Bool :=
  decide (transcript.eventPecDigest = transcript.approvalPecDigest) &&
  decide (transcript.eventKeys ≠ []) &&
  decide (transcript.eventKeys.Nodup) &&
  decide (transcript.eventFirstIndex ≤ transcript.eventLastIndex) &&
  decide (
    signatureProjection .eventDisclosure transcript.signatures =
      expectedSignatures transcript.eventKeys transcript.eventBodyDigest) &&
  decide (transcript.eventCoseDigests.Nodup) &&
  decide (
    (transcript.signatures.filter fun item =>
        decide (item.purpose = .eventDisclosure)).map (·.coseDigest) =
      transcript.eventCoseDigests) &&
  decide (transcript.merkleFacts = [expectedMerkle transcript])

def identitySignatureProjection (facts : List TranscriptSignature) :
    List (KeyId × Digest × Digest) :=
  (facts.filter fun item => decide (item.purpose = .identityDisclosure)).map
    fun item => (item.key, item.payloadDigest, item.coseDigest)

def expectedIdentitySignatures (facts : List TranscriptIdentity) :
    List (KeyId × Digest × Digest) :=
  facts.map fun item => (item.authorKey, item.bodyDigest, item.coseDigest)

def IdentityGroupClosed (transcript : VerificationTranscript) : Prop :=
  (transcript.releaseSlots.map Prod.fst).Nodup ∧
  (transcript.releaseSlots.map Prod.snd).Nodup ∧
  (transcript.identityFacts.map (·.authorSlot)).Nodup ∧
  identitySignatureProjection transcript.signatures =
    expectedIdentitySignatures transcript.identityFacts ∧
  (transcript.identityFacts.map (·.coseDigest)).Nodup ∧
  transcript.identityCoseDigests =
    transcript.identityFacts.map (·.coseDigest) ∧
  ∀ fact, fact ∈ transcript.identityFacts →
    transcript.releaseDigest = some fact.releaseDigest ∧
    (fact.authorSlot, fact.authorKey) ∈ transcript.releaseSlots

def identityGroupClosedB (transcript : VerificationTranscript) : Bool :=
  decide ((transcript.releaseSlots.map Prod.fst).Nodup) &&
  decide ((transcript.releaseSlots.map Prod.snd).Nodup) &&
  decide ((transcript.identityFacts.map (·.authorSlot)).Nodup) &&
  decide (identitySignatureProjection transcript.signatures =
    expectedIdentitySignatures transcript.identityFacts) &&
  decide ((transcript.identityFacts.map (·.coseDigest)).Nodup) &&
  decide (transcript.identityCoseDigests =
    transcript.identityFacts.map (·.coseDigest)) &&
  transcript.identityFacts.all fun fact =>
    decide (transcript.releaseDigest = some fact.releaseDigest) &&
    transcript.releaseSlots.contains (fact.authorSlot, fact.authorKey)

theorem approvalGroupClosedB_iff (transcript : VerificationTranscript) :
    approvalGroupClosedB transcript = true ↔ ApprovalGroupClosed transcript := by
  simp [approvalGroupClosedB, ApprovalGroupClosed, and_assoc]

theorem eventGroupClosedB_iff (transcript : VerificationTranscript) :
    eventGroupClosedB transcript = true ↔ EventGroupClosed transcript := by
  simp [eventGroupClosedB, EventGroupClosed, and_assoc]

theorem identityGroupClosedB_iff (transcript : VerificationTranscript) :
    identityGroupClosedB transcript = true ↔ IdentityGroupClosed transcript := by
  simp [identityGroupClosedB, IdentityGroupClosed, and_assoc]

def expectedApprovalSetEntries (transcript : VerificationTranscript) :
    List (KeyId × Digest) :=
  (transcript.signatures.filter fun item =>
    decide (item.purpose = .authorApproval)).map fun item =>
      (item.key, item.coseDigest)

def TimeGroupClosed (transcript : VerificationTranscript) : Prop :=
  match transcript.timeFacts with
  | [fact] =>
      fact.approvalTargetDigest = transcript.targetDigest ∧
      fact.authorApprovals = expectedApprovalSetEntries transcript ∧
      fact.authorApprovals.map Prod.fst = transcript.approvalKeys ∧
      fact.lineageAuthorizations = [] ∧
      fact.notAfterUtc ≠ "" ∧
      fact.authorityExternal = true ∧
      fact.trustedAuthorityExternal = true ∧
      fact.signerFingerprint = fact.trustedSignerFingerprint ∧
      fact.certificateDigest = fact.trustedCertificateDigest ∧
      transcript.approvalSetInputDigests = [fact.approvalSetInputDigest] ∧
      transcript.timeRequestDigests = [fact.requestDigest] ∧
      transcript.timeResponseDigests = [fact.responseDigest] ∧
      transcript.tsaCertificateDigests = [fact.certificateDigest] ∧
      transcript.timeReportDigests = [fact.reportDigest]
  | _ => False

def timeGroupClosedB (transcript : VerificationTranscript) : Bool :=
  match transcript.timeFacts with
  | [fact] =>
      decide (fact.approvalTargetDigest = transcript.targetDigest) &&
      decide (fact.authorApprovals = expectedApprovalSetEntries transcript) &&
      decide (fact.authorApprovals.map Prod.fst = transcript.approvalKeys) &&
      decide (fact.lineageAuthorizations = []) &&
      decide (fact.notAfterUtc ≠ "") &&
      fact.authorityExternal && fact.trustedAuthorityExternal &&
      decide (fact.signerFingerprint = fact.trustedSignerFingerprint) &&
      decide (fact.certificateDigest = fact.trustedCertificateDigest) &&
      decide (transcript.approvalSetInputDigests = [fact.approvalSetInputDigest]) &&
      decide (transcript.timeRequestDigests = [fact.requestDigest]) &&
      decide (transcript.timeResponseDigests = [fact.responseDigest]) &&
      decide (transcript.tsaCertificateDigests = [fact.certificateDigest]) &&
      decide (transcript.timeReportDigests = [fact.reportDigest])
  | _ => false

theorem timeGroupClosedB_iff (transcript : VerificationTranscript) :
    timeGroupClosedB transcript = true ↔ TimeGroupClosed transcript := by
  cases h : transcript.timeFacts with
  | nil => simp [timeGroupClosedB, TimeGroupClosed, h]
  | cons head tail =>
      cases tail with
      | nil => simp [timeGroupClosedB, TimeGroupClosed, h, and_assoc]
      | cons next rest => simp [timeGroupClosedB, TimeGroupClosed, h]

def approvalTranscriptAtom
    (transcript : VerificationTranscript) (certificate : Digest) :
    AppraisedAtom := {
  kind := .unanimousApproval
  subject := .approvalTarget transcript.targetDigest
  certificateDigest := certificate
}

def eventTranscriptAtom
    (transcript : VerificationTranscript) (certificate : Digest) :
    AppraisedAtom := {
  kind := .eventDisclosure
  subject := .eventWindow
    transcript.eventPecDigest transcript.eventId transcript.eventSequence
    transcript.eventCommitmentDigest transcript.eventFirstIndex
    transcript.eventLastIndex
  certificateDigest := certificate
}

def identityTranscriptAtom
    (fact : TranscriptIdentity) (certificate : Digest) : AppraisedAtom := {
  kind := .identityDisclosure
  subject := .identityAssertion fact.releaseDigest fact.authorSlot
    fact.authorKey fact.assertionDigest
  certificateDigest := certificate
}

def timeTranscriptAtom
    (fact : TranscriptTime) (certificate : Digest) : AppraisedAtom := {
  kind := .approvalSetTimestamp
  subject := .approvalSetTime fact.approvalSetDigest fact.notAfterUtc
  certificateDigest := certificate
}

def checkApprovalGroup
    (transcript : VerificationTranscript) (certificate : Digest) :
    Option AppraisedAtom :=
  if approvalGroupClosedB transcript = true then
    some (approvalTranscriptAtom transcript certificate)
  else none

def checkEventGroup
    (transcript : VerificationTranscript) (certificate : Digest) :
    Option AppraisedAtom :=
  if eventGroupClosedB transcript = true then
    some (eventTranscriptAtom transcript certificate)
  else none

def checkIdentityGroup
    (transcript : VerificationTranscript) (certificate : Digest) :
    List AppraisedAtom :=
  if identityGroupClosedB transcript = true then
    transcript.identityFacts.map fun fact => identityTranscriptAtom fact certificate
  else []

def checkTimeGroup
    (transcript : VerificationTranscript) (certificate : Digest) :
    Option AppraisedAtom :=
  if timeGroupClosedB transcript = true then
    match transcript.timeFacts with
    | [fact] => some (timeTranscriptAtom fact certificate)
    | _ => none
  else none

def transcriptAtoms
    (transcript : VerificationTranscript) (certificate : Digest) :
    List AppraisedAtom :=
  (checkApprovalGroup transcript certificate).toList ++
  (checkEventGroup transcript certificate).toList ++
  checkIdentityGroup transcript certificate ++
  (checkTimeGroup transcript certificate).toList

def TranscriptPolicyBound (transcript : VerificationTranscript) : Prop :=
  transcript.policyPecDigest = transcript.approvalPecDigest ∧
  transcript.eventPecDigest = transcript.approvalPecDigest

def transcriptPolicyBoundB (transcript : VerificationTranscript) : Bool :=
  decide (transcript.policyPecDigest = transcript.approvalPecDigest) &&
  decide (transcript.eventPecDigest = transcript.approvalPecDigest)

def transcriptPolicy (transcript : VerificationTranscript) : AppraisalPolicy := {
  permittedClaims := transcript.policyClaims
}

def transcriptCheckClaim
    (transcript : VerificationTranscript) (certificate : Digest)
    (request : AppraisalRequest) : Bool :=
  transcriptPolicyBoundB transcript &&
  checkClaim (transcriptPolicy transcript)
    (transcriptAtoms transcript certificate) request

theorem transcriptPolicyBoundB_iff (transcript : VerificationTranscript) :
    transcriptPolicyBoundB transcript = true ↔
      TranscriptPolicyBound transcript := by
  simp [transcriptPolicyBoundB, TranscriptPolicyBound]

def transcriptRequests (transcript : VerificationTranscript) :
    List AppraisalRequest := [{
      kind := .keyAssent
      subject := .approvalTarget transcript.targetDigest
    }, {
      kind := .governanceAssent
      subject := .approvalTarget transcript.targetDigest
    }, {
      kind := .committedEvidenceMatch
      subject := .eventWindow
        transcript.eventPecDigest transcript.eventId transcript.eventSequence
        transcript.eventCommitmentDigest transcript.eventFirstIndex
        transcript.eventLastIndex
    }]
  ++ (transcript.identityFacts.map fun fact => {
    kind := .slotKeyIdentityAssent
    subject := .identityAssertion fact.releaseDigest fact.authorSlot
      fact.authorKey fact.assertionDigest
  })
  ++ (transcript.timeFacts.map fun fact => {
    kind := .approvalSetExistedNotAfter
    subject := .approvalSetTime fact.approvalSetDigest fact.notAfterUtc
  })

def transcriptClaims
    (transcript : VerificationTranscript) (certificate : Digest) :
    List AppraisalRequest :=
  (transcriptRequests transcript).filter fun request =>
    transcriptCheckClaim transcript certificate request

inductive TranscriptSupports
    (transcript : VerificationTranscript) (certificate : Digest) :
    AppraisedAtom → Prop where
  | approval (closed : ApprovalGroupClosed transcript) :
      TranscriptSupports transcript certificate
        (approvalTranscriptAtom transcript certificate)
  | event (closed : EventGroupClosed transcript) :
      TranscriptSupports transcript certificate
        (eventTranscriptAtom transcript certificate)
  | identity (closed : IdentityGroupClosed transcript)
      (fact : TranscriptIdentity) (member : fact ∈ transcript.identityFacts) :
      TranscriptSupports transcript certificate
        (identityTranscriptAtom fact certificate)
  | time (closed : TimeGroupClosed transcript) (fact : TranscriptTime)
      (exactFacts : transcript.timeFacts = [fact]) :
      TranscriptSupports transcript certificate
        (timeTranscriptAtom fact certificate)

theorem checkApprovalGroup_sound
    {transcript : VerificationTranscript} {certificate : Digest}
    {atom : AppraisedAtom}
    (checked : checkApprovalGroup transcript certificate = some atom) :
    ApprovalGroupClosed transcript ∧
      atom = approvalTranscriptAtom transcript certificate := by
  unfold checkApprovalGroup at checked
  split at checked
  · simp only [Option.some.injEq] at checked
    exact ⟨approvalGroupClosedB_iff transcript |>.mp ‹_›, checked.symm⟩
  · contradiction

theorem checkEventGroup_sound
    {transcript : VerificationTranscript} {certificate : Digest}
    {atom : AppraisedAtom}
    (checked : checkEventGroup transcript certificate = some atom) :
    EventGroupClosed transcript ∧
      atom = eventTranscriptAtom transcript certificate := by
  unfold checkEventGroup at checked
  split at checked
  · simp only [Option.some.injEq] at checked
    exact ⟨eventGroupClosedB_iff transcript |>.mp ‹_›, checked.symm⟩
  · contradiction

theorem checkIdentityGroup_sound
    {transcript : VerificationTranscript} {certificate : Digest}
    {atom : AppraisedAtom}
    (member : atom ∈ checkIdentityGroup transcript certificate) :
    ∃ fact,
      IdentityGroupClosed transcript ∧
      fact ∈ transcript.identityFacts ∧
      atom = identityTranscriptAtom fact certificate := by
  unfold checkIdentityGroup at member
  split at member
  · have closed := identityGroupClosedB_iff transcript |>.mp ‹_›
    obtain ⟨fact, factMember, exactAtom⟩ := List.mem_map.mp member
    exact ⟨fact, closed, factMember, exactAtom.symm⟩
  · simp at member

theorem checkTimeGroup_sound
    {transcript : VerificationTranscript} {certificate : Digest}
    {atom : AppraisedAtom}
    (checked : checkTimeGroup transcript certificate = some atom) :
    ∃ fact,
      TimeGroupClosed transcript ∧
      transcript.timeFacts = [fact] ∧
      atom = timeTranscriptAtom fact certificate := by
  unfold checkTimeGroup at checked
  split at checked
  · have closed := timeGroupClosedB_iff transcript |>.mp ‹_›
    cases h : transcript.timeFacts with
    | nil => simp [TimeGroupClosed, h] at closed
    | cons head tail =>
        cases tail with
        | nil =>
            simp [h] at checked
            exact ⟨head, closed, rfl, checked.symm⟩
        | cons next rest => simp [TimeGroupClosed, h] at closed
  · contradiction

theorem transcriptAtoms_sound
    {transcript : VerificationTranscript} {certificate : Digest}
    {atom : AppraisedAtom}
    (member : atom ∈ transcriptAtoms transcript certificate) :
    TranscriptSupports transcript certificate atom := by
  rw [transcriptAtoms, List.mem_append] at member
  rcases member with baseMember | timeMember
  · rw [List.mem_append] at baseMember
    rcases baseMember with baseMember | identityMember
    · rw [List.mem_append] at baseMember
      rcases baseMember with approvalMember | eventMember
      · have checked : checkApprovalGroup transcript certificate = some atom := by
          simpa using approvalMember
        obtain ⟨closed, exactAtom⟩ := checkApprovalGroup_sound checked
        rw [exactAtom]
        exact .approval closed
      · have checked : checkEventGroup transcript certificate = some atom := by
          simpa using eventMember
        obtain ⟨closed, exactAtom⟩ := checkEventGroup_sound checked
        rw [exactAtom]
        exact .event closed
    · obtain ⟨fact, closed, factMember, exactAtom⟩ :=
        checkIdentityGroup_sound identityMember
      rw [exactAtom]
      exact .identity closed fact factMember
  · have checked : checkTimeGroup transcript certificate = some atom := by
      simpa using timeMember
    obtain ⟨fact, closed, exactFacts, exactAtom⟩ := checkTimeGroup_sound checked
    rw [exactAtom]
    exact .time closed fact exactFacts

/-! Composition theorem: an accepted claim from a transcript has both a
declarative appraisal rule and a transcript support derivation. -/
theorem transcript_atoms_checkClaim_sound
    {policy : AppraisalPolicy} {transcript : VerificationTranscript}
    {certificate : Digest} {request : AppraisalRequest}
    (accepted :
      checkClaim policy (transcriptAtoms transcript certificate) request = true) :
    ∃ atom,
      TranscriptSupports transcript certificate atom ∧
      atom.subject = request.subject ∧ AppraisalRule atom.kind request.kind := by
  have derived := checkClaim_sound accepted
  obtain ⟨atom, member, exactSubject, rule⟩ := derives_has_exact_support derived
  exact ⟨atom, transcriptAtoms_sound member, exactSubject, rule⟩

theorem transcript_checkClaim_sound
    {transcript : VerificationTranscript} {certificate : Digest}
    {request : AppraisalRequest}
    (accepted : transcriptCheckClaim transcript certificate request = true) :
    TranscriptPolicyBound transcript ∧
    ∃ atom,
      TranscriptSupports transcript certificate atom ∧
      atom.subject = request.subject ∧ AppraisalRule atom.kind request.kind := by
  have parts :
      transcriptPolicyBoundB transcript = true ∧
      checkClaim (transcriptPolicy transcript)
        (transcriptAtoms transcript certificate) request = true := by
    simpa [transcriptCheckClaim] using accepted
  exact ⟨transcriptPolicyBoundB_iff transcript |>.mp parts.1,
    transcript_atoms_checkClaim_sound parts.2⟩

theorem transcriptClaims_sound
    {transcript : VerificationTranscript} {certificate : Digest}
    {request : AppraisalRequest}
    (member : request ∈ transcriptClaims transcript certificate) :
    TranscriptPolicyBound transcript ∧
    ∃ atom,
      TranscriptSupports transcript certificate atom ∧
      atom.subject = request.subject ∧ AppraisalRule atom.kind request.kind := by
  have accepted :
      transcriptCheckClaim transcript certificate request = true :=
    (List.mem_filter.mp member).2
  exact transcript_checkClaim_sound accepted

/-! In addition to identifying the closed transcript group that supports a
claim, membership in the executable result has a derivation in the independent
exact-subject semantics.  This is the bridge used by the strict JSON decoder. -/
theorem transcriptClaims_derivable
    {transcript : VerificationTranscript} {certificate : Digest}
    {request : AppraisalRequest}
    (member : request ∈ transcriptClaims transcript certificate) :
    TranscriptPolicyBound transcript ∧
    AppraisalDerives (transcriptPolicy transcript)
      (transcriptAtoms transcript certificate) request := by
  have accepted :
      transcriptCheckClaim transcript certificate request = true :=
    (List.mem_filter.mp member).2
  have parts :
      transcriptPolicyBoundB transcript = true ∧
      checkClaim (transcriptPolicy transcript)
        (transcriptAtoms transcript certificate) request = true := by
    simpa [transcriptCheckClaim] using accepted
  exact ⟨transcriptPolicyBoundB_iff transcript |>.mp parts.1,
    checkClaim_sound parts.2⟩

/-! A concrete countermodel for the tempting weak rule “one approval signature
is enough”. The predecessor-selected two-key set is not closed. -/
def weakKeyOne : KeyId := { value := 1 }
def weakKeyTwo : KeyId := { value := 2 }
def weakDigestOne : Digest := { value := 1 }
def weakDigestTwo : Digest := { value := 2 }

def weakTranscript : VerificationTranscript := {
  targetDigest := weakDigestOne
  approvalPecDigest := weakDigestTwo
  eventPecDigest := weakDigestTwo
  policyPecDigest := weakDigestTwo
  policyClaims := [.keyAssent]
  approvalKeys := [weakKeyOne, weakKeyTwo]
  approvalCoseDigests := [weakDigestTwo]
  eventBodyDigest := weakDigestOne
  eventId := "weak-event"
  eventSequence := 0
  eventCommitmentDigest := weakDigestTwo
  eventFirstIndex := 0
  eventLastIndex := 0
  eventKeys := []
  eventCoseDigests := []
  releaseDigest := none
  releaseSlots := []
  identityFacts := []
  identityCoseDigests := []
  timeFacts := []
  approvalSetInputDigests := []
  timeRequestDigests := []
  timeResponseDigests := []
  tsaCertificateDigests := []
  timeReportDigests := []
  signatures := [{
    purpose := .authorApproval
    key := weakKeyOne
    payloadDigest := weakDigestOne
    coseDigest := weakDigestTwo
  }]
  merkleFacts := []
}

def weakAnyApprovalB (transcript : VerificationTranscript) : Bool :=
  transcript.signatures.any fun item =>
    decide (item.purpose = .authorApproval) &&
    decide (item.payloadDigest = transcript.targetDigest)

theorem weak_any_approval_accepts_missing_required_signer :
    weakAnyApprovalB weakTranscript = true ∧
      approvalGroupClosedB weakTranscript = false := by
  decide

end ACSD
