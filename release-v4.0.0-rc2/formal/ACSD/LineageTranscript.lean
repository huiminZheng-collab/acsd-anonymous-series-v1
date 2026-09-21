import ACSD.Appraisal
import ACSD.Lineage

set_option autoImplicit false
set_option warningAsError true

namespace ACSD

inductive LineageSignaturePurpose where
  | childApproval
  | predecessorAuthorization
  deriving DecidableEq, Repr

inductive LineageAuthorizationMode where
  | continuity
  | transition
  deriving DecidableEq, Repr

structure LineageSignatureFact where
  purpose : LineageSignaturePurpose
  key : KeyId
  payloadDigest : Digest
  coseDigest : Digest
  publicKeyDigest : Digest
  deriving DecidableEq, Repr

structure LineageVerificationTranscript where
  work : Digest
  transitionDigest : Digest
  transitionInputDigest : Digest
  transitionKind : String
  mode : LineageAuthorizationMode
  parent : VersionedRelease
  child : VersionedRelease
  childTargetDigest : Digest
  boundTransitionDigest : Digest
  policyPecDigest : Digest
  policyClaims : List ScopedClaim
  approvalSetTargetDigest : Digest
  approvalSetAuthorEntries : List (KeyId × Digest)
  approvalSetLineageEntries : List (KeyId × Digest)
  approvalSetInputDigest : Digest
  parentReleaseInputDigests : List Digest
  parentPecInputDigests : List Digest
  childReleaseInputDigests : List Digest
  childGovernanceInputDigests : List Digest
  childPecInputDigests : List Digest
  childTargetInputDigests : List Digest
  transitionInputDigests : List Digest
  approvalSetInputDigests : List Digest
  childApprovalCoseDigests : List Digest
  childPublicKeyDigests : List Digest
  predecessorCoseDigests : List Digest
  predecessorPublicKeyDigests : List Digest
  parentReleaseInputDigest : Digest
  parentPecInputDigest : Digest
  childReleaseInputDigest : Digest
  childGovernanceInputDigest : Digest
  childPecInputDigest : Digest
  childTargetInputDigest : Digest
  signatures : List LineageSignatureFact
  deriving DecidableEq, Repr

def lineageSignatureFacts
    (purpose : LineageSignaturePurpose)
    (transcript : LineageVerificationTranscript) : List LineageSignatureFact :=
  transcript.signatures.filter fun item => decide (item.purpose = purpose)

def lineageSignerKeys
    (purpose : LineageSignaturePurpose)
    (transcript : LineageVerificationTranscript) : List KeyId :=
  (lineageSignatureFacts purpose transcript).map (·.key)

def lineageCoseDigests
    (purpose : LineageSignaturePurpose)
    (transcript : LineageVerificationTranscript) : List Digest :=
  (lineageSignatureFacts purpose transcript).map (·.coseDigest)

def lineagePublicKeyDigests
    (purpose : LineageSignaturePurpose)
    (transcript : LineageVerificationTranscript) : List Digest :=
  (lineageSignatureFacts purpose transcript).map (·.publicKeyDigest)

def lineageApprovalEntries
    (purpose : LineageSignaturePurpose)
    (transcript : LineageVerificationTranscript) : List (KeyId × Digest) :=
  (lineageSignatureFacts purpose transcript).map fun item =>
    (item.key, item.coseDigest)

def authorityWellFormed (authority : LineageAuthority) : Prop :=
  authority.keys ≠ [] ∧ authority.keys.Nodup ∧
  0 < authority.threshold ∧ authority.threshold ≤ authority.keys.length

instance (authority : LineageAuthority) : Decidable (authorityWellFormed authority) := by
  unfold authorityWellFormed
  infer_instance

instance (parent child : VersionedRelease) :
    Decidable (StructuralSuccessor parent child) := by
  unfold StructuralSuccessor
  infer_instance

instance (transition : LineageTransition) (parent child : VersionedRelease) :
    Decidable (ExactTransition transition parent child) := by
  unfold ExactTransition
  infer_instance

def transcriptQuorumB
    (authority : LineageAuthority) (evidence : LineageApprovalEvidence) : Bool :=
  decide evidence.signerKeys.Nodup &&
  (evidence.signerKeys.all fun key => authority.keys.contains key) &&
  decide (authority.threshold ≤ evidence.signerKeys.length)

def transcriptQuorum
    (authority : LineageAuthority) (evidence : LineageApprovalEvidence) : Prop :=
  transcriptQuorumB authority evidence = true

def transcriptLineageModel : LineageAuthModel := {
  quorum := transcriptQuorum
}

def transcriptTransition (transcript : LineageVerificationTranscript) :
    LineageTransition := {
  work := transcript.child.work
  parentReleaseDigest := transcript.parent.releaseDigest
  parentPecDigest := transcript.parent.pecDigest
  childReleaseDigest := transcript.child.releaseDigest
  childPecDigest := transcript.child.pecDigest
  oldAuthority := transcript.parent.authority
  newAuthority := transcript.child.authority
}

def transcriptSuccessionProof (transcript : LineageVerificationTranscript) :
    SuccessionProof :=
  match transcript.mode with
  | .continuity => .continuity {
      signerKeys := lineageSignerKeys .childApproval transcript
    }
  | .transition => .transition (transcriptTransition transcript) {
      signerKeys := lineageSignerKeys .predecessorAuthorization transcript
    }

def expectedTransitionKind (transcript : LineageVerificationTranscript) : String :=
  if transcript.parent.line ≠ transcript.child.line then "branch"
  else if transcript.parent.authority.keys ≠ transcript.child.authority.keys then
    "team-change"
  else if transcript.parent.authority.threshold ≠ transcript.child.authority.threshold then
    "threshold-change"
  else "continuation"

def childSignaturePayloadsClosed (transcript : LineageVerificationTranscript) : Prop :=
  lineageSignerKeys .childApproval transcript = transcript.child.authority.keys ∧
  (lineageSignatureFacts .childApproval transcript).all
    (fun fact => decide (fact.payloadDigest = transcript.childTargetDigest)) = true

instance (transcript : LineageVerificationTranscript) :
    Decidable (childSignaturePayloadsClosed transcript) := by
  unfold childSignaturePayloadsClosed
  infer_instance

def predecessorSignaturePayloadsClosed
    (transcript : LineageVerificationTranscript) : Prop :=
  (lineageSignatureFacts .predecessorAuthorization transcript).all
    (fun fact => decide (fact.payloadDigest = transcript.transitionDigest)) = true

instance (transcript : LineageVerificationTranscript) :
    Decidable (predecessorSignaturePayloadsClosed transcript) := by
  unfold predecessorSignaturePayloadsClosed
  infer_instance

def signatureInputsClosed (transcript : LineageVerificationTranscript) : Prop :=
  transcript.childApprovalCoseDigests =
      lineageCoseDigests .childApproval transcript ∧
  transcript.childPublicKeyDigests =
      lineagePublicKeyDigests .childApproval transcript ∧
  transcript.predecessorCoseDigests =
      lineageCoseDigests .predecessorAuthorization transcript ∧
  transcript.predecessorPublicKeyDigests =
      lineagePublicKeyDigests .predecessorAuthorization transcript

instance (transcript : LineageVerificationTranscript) :
    Decidable (signatureInputsClosed transcript) := by
  unfold signatureInputsClosed
  infer_instance

def exactObjectInputsClosed (transcript : LineageVerificationTranscript) : Prop :=
  transcript.parentReleaseInputDigests = [transcript.parentReleaseInputDigest] ∧
  transcript.parentPecInputDigests = [transcript.parentPecInputDigest] ∧
  transcript.childReleaseInputDigests = [transcript.childReleaseInputDigest] ∧
  transcript.childGovernanceInputDigests = [transcript.childGovernanceInputDigest] ∧
  transcript.childPecInputDigests = [transcript.childPecInputDigest] ∧
  transcript.childTargetInputDigests = [transcript.childTargetInputDigest] ∧
  transcript.transitionInputDigests = [transcript.transitionInputDigest] ∧
  transcript.approvalSetInputDigests = [transcript.approvalSetInputDigest]

instance (transcript : LineageVerificationTranscript) :
    Decidable (exactObjectInputsClosed transcript) := by
  unfold exactObjectInputsClosed
  infer_instance

def approvalSetLineageClosed (transcript : LineageVerificationTranscript) : Prop :=
  transcript.approvalSetTargetDigest = transcript.childTargetDigest ∧
  transcript.approvalSetAuthorEntries =
    lineageApprovalEntries .childApproval transcript ∧
  transcript.approvalSetLineageEntries =
    lineageApprovalEntries .predecessorAuthorization transcript

instance (transcript : LineageVerificationTranscript) :
    Decidable (approvalSetLineageClosed transcript) := by
  unfold approvalSetLineageClosed
  infer_instance

def modeClosed (transcript : LineageVerificationTranscript) : Prop :=
  match transcript.mode with
  | .continuity =>
      transcript.parent.authority = transcript.child.authority ∧
      lineageSignatureFacts .predecessorAuthorization transcript = [] ∧
      transcript.predecessorCoseDigests = [] ∧
      transcript.predecessorPublicKeyDigests = []
  | .transition => transcript.parent.authority ≠ transcript.child.authority

instance (transcript : LineageVerificationTranscript) :
    Decidable (modeClosed transcript) := by
  unfold modeClosed
  cases transcript.mode <;> infer_instance

def LineageGroupPrerequisites (transcript : LineageVerificationTranscript) : Prop :=
  authorityWellFormed transcript.parent.authority ∧
  authorityWellFormed transcript.child.authority ∧
  transcript.policyPecDigest = transcript.child.pecDigest ∧
  ScopedClaim.authorizedSuccessor ∈ transcript.policyClaims ∧
  transcript.transitionKind = expectedTransitionKind transcript ∧
  transcript.boundTransitionDigest = transcript.transitionDigest ∧
  childSignaturePayloadsClosed transcript ∧
  predecessorSignaturePayloadsClosed transcript ∧
  signatureInputsClosed transcript ∧
  exactObjectInputsClosed transcript ∧
  approvalSetLineageClosed transcript ∧
  modeClosed transcript

instance (transcript : LineageVerificationTranscript) :
    Decidable (LineageGroupPrerequisites transcript) := by
  unfold LineageGroupPrerequisites
  infer_instance

def LineageGroupClosed (transcript : LineageVerificationTranscript) : Prop :=
  LineageGroupPrerequisites transcript ∧
  AuthorizedSuccessor transcriptLineageModel transcript.parent transcript.child
    (transcriptSuccessionProof transcript)

def authorizedSuccessorB (transcript : LineageVerificationTranscript) : Bool :=
  decide (StructuralSuccessor transcript.parent transcript.child) &&
  match transcript.mode with
  | .continuity =>
      decide (transcript.child.authority = transcript.parent.authority) &&
      transcriptQuorumB transcript.parent.authority {
        signerKeys := lineageSignerKeys .childApproval transcript
      }
  | .transition =>
      decide (ExactTransition (transcriptTransition transcript)
        transcript.parent transcript.child) &&
      transcriptQuorumB transcript.parent.authority {
        signerKeys := lineageSignerKeys .predecessorAuthorization transcript
      }

theorem authorizedSuccessorB_sound
    {transcript : LineageVerificationTranscript}
    (accepted : authorizedSuccessorB transcript = true) :
    AuthorizedSuccessor transcriptLineageModel transcript.parent transcript.child
      (transcriptSuccessionProof transcript) := by
  cases modeEq : transcript.mode with
  | continuity =>
      have parts :
          decide (StructuralSuccessor transcript.parent transcript.child) = true ∧
          decide (transcript.child.authority = transcript.parent.authority) = true ∧
          transcriptQuorumB transcript.parent.authority {
            signerKeys := lineageSignerKeys .childApproval transcript
          } = true := by
        simpa [authorizedSuccessorB, modeEq] using accepted
      have structural : StructuralSuccessor transcript.parent transcript.child :=
        of_decide_eq_true parts.1
      have sameAuthority :
          transcript.child.authority = transcript.parent.authority :=
        of_decide_eq_true parts.2.1
      have quorum : transcriptQuorum transcript.parent.authority {
          signerKeys := lineageSignerKeys .childApproval transcript
        } := parts.2.2
      have result : StructuralSuccessor transcript.parent transcript.child ∧
          transcript.child.authority = transcript.parent.authority ∧
          transcriptQuorum transcript.parent.authority {
          signerKeys := lineageSignerKeys .childApproval transcript
        } := ⟨structural, sameAuthority, quorum⟩
      simpa [AuthorizedSuccessor, transcriptSuccessionProof, modeEq,
        transcriptLineageModel] using result
  | transition =>
      have parts :
          decide (StructuralSuccessor transcript.parent transcript.child) = true ∧
          decide (ExactTransition (transcriptTransition transcript)
            transcript.parent transcript.child) = true ∧
          transcriptQuorumB transcript.parent.authority {
            signerKeys := lineageSignerKeys .predecessorAuthorization transcript
          } = true := by
        simpa [authorizedSuccessorB, modeEq] using accepted
      have structural : StructuralSuccessor transcript.parent transcript.child :=
        of_decide_eq_true parts.1
      have exactTransition : ExactTransition (transcriptTransition transcript)
          transcript.parent transcript.child :=
        of_decide_eq_true parts.2.1
      have quorum : transcriptQuorum transcript.parent.authority {
          signerKeys := lineageSignerKeys .predecessorAuthorization transcript
        } := parts.2.2
      have result : StructuralSuccessor transcript.parent transcript.child ∧
          ExactTransition (transcriptTransition transcript)
          transcript.parent transcript.child ∧
          transcriptQuorum transcript.parent.authority {
            signerKeys := lineageSignerKeys .predecessorAuthorization transcript
          } := ⟨structural, exactTransition, quorum⟩
      simpa [AuthorizedSuccessor, transcriptSuccessionProof, modeEq,
        transcriptLineageModel] using result

def lineageGroupClosedB (transcript : LineageVerificationTranscript) : Bool :=
  decide (LineageGroupPrerequisites transcript) && authorizedSuccessorB transcript

theorem lineageGroupClosedB_sound
    {transcript : LineageVerificationTranscript}
    (accepted : lineageGroupClosedB transcript = true) :
    LineageGroupClosed transcript := by
  have parts :
      decide (LineageGroupPrerequisites transcript) = true ∧
      authorizedSuccessorB transcript = true := by
    simpa [lineageGroupClosedB] using accepted
  have prerequisites : LineageGroupPrerequisites transcript := by
    simpa using parts.1
  exact ⟨prerequisites, authorizedSuccessorB_sound parts.2⟩

theorem closed_lineage_is_authorized_successor
    {transcript : LineageVerificationTranscript}
    (closed : LineageGroupClosed transcript) :
    AuthorizedSuccessor transcriptLineageModel transcript.parent transcript.child
      (transcriptSuccessionProof transcript) := by
  exact closed.2

def lineageTranscriptSubject (transcript : LineageVerificationTranscript) :
    ScopedSubject :=
  .lineageEdge transcript.work transcript.parent.releaseDigest
    transcript.parent.pecDigest { value := transcript.parent.line }
    transcript.parent.version transcript.child.releaseDigest
    transcript.child.pecDigest { value := transcript.child.line }
    transcript.child.version transcript.transitionDigest

def lineageTranscriptAtom
    (transcript : LineageVerificationTranscript) (certificate : Digest) :
    AppraisedAtom := {
  kind := .lineageAuthorization
  subject := lineageTranscriptSubject transcript
  certificateDigest := certificate
}

def checkLineageGroup
    (transcript : LineageVerificationTranscript) (certificate : Digest) :
    Option AppraisedAtom :=
  if lineageGroupClosedB transcript = true then
    some (lineageTranscriptAtom transcript certificate)
  else none

theorem checkLineageGroup_sound
    {transcript : LineageVerificationTranscript} {certificate : Digest}
    {atom : AppraisedAtom}
    (checked : checkLineageGroup transcript certificate = some atom) :
    LineageGroupClosed transcript ∧
      atom = lineageTranscriptAtom transcript certificate := by
  unfold checkLineageGroup at checked
  split at checked
  · simp only [Option.some.injEq] at checked
    exact ⟨lineageGroupClosedB_sound ‹_›, checked.symm⟩
  · contradiction

def lineageTranscriptPolicy (transcript : LineageVerificationTranscript) :
    AppraisalPolicy := { permittedClaims := transcript.policyClaims }

def lineageTranscriptRequest (transcript : LineageVerificationTranscript) :
    AppraisalRequest := {
  kind := .authorizedSuccessor
  subject := lineageTranscriptSubject transcript
}

def lineageTranscriptClaim
    (transcript : LineageVerificationTranscript) (certificate : Digest) : Bool :=
  match checkLineageGroup transcript certificate with
  | some atom => checkClaim (lineageTranscriptPolicy transcript) [atom]
      (lineageTranscriptRequest transcript)
  | none => false

theorem lineageTranscriptClaim_sound
    {transcript : LineageVerificationTranscript} {certificate : Digest}
    (accepted : lineageTranscriptClaim transcript certificate = true) :
    LineageGroupClosed transcript ∧
    AppraisalDerives (lineageTranscriptPolicy transcript)
      [lineageTranscriptAtom transcript certificate]
      (lineageTranscriptRequest transcript) := by
  unfold lineageTranscriptClaim at accepted
  cases checked : checkLineageGroup transcript certificate with
  | none => simp [checked] at accepted
  | some atom =>
      have closed := checkLineageGroup_sound checked
      have checkedClaim :
          checkClaim (lineageTranscriptPolicy transcript) [atom]
            (lineageTranscriptRequest transcript) = true := by
        simpa [checked] using accepted
      have derived := checkClaim_sound checkedClaim
      rw [closed.2] at derived
      exact ⟨closed.1, derived⟩

end ACSD
