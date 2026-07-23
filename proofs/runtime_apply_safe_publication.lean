/-
LLM contract: FIX_PROPOSED -> VERIFIED -> AUTHORIZED -> EXPLICITLY_REQUESTED ->
SOURCE_REVALIDATED -> TRANSACTION_STAGED -> PUBLISHED; any failed gate -> DENIED
with the original snapshot preserved.

Proof contract: this file proves the prospective pure publication decision,
original-snapshot transition, exact authorization binding, and single-use
authorization state that a future Rust `fix --apply-safe` path must implement.
The current `origin/main` has no such command path and publishes only private
scratch workspaces. `publish` below therefore denotes a future
original-repository transition, not current Rust behavior.

This model does not prove filesystem atomicity, Git behavior, SHA-256 collision
resistance, or its correspondence with future Rust code. Those executable
claims remain Rust integration-test obligations.

Sources:
- https://github.com/Anionix/diagnostic-triage/issues/83
- https://git-scm.com/docs/git-apply
- https://lean-lang.org/doc/reference/latest/Basic-Types/Booleans/
-/

inductive FixApplicability where
  | safe
  | unsafeFix
  | manual
  deriving DecidableEq

inductive RequiredProviderState where
  | complete
  | incomplete
  | unsupported
  deriving DecidableEq

inductive PatchApplicationState where
  | applied
  | conflict
  | failed
  deriving DecidableEq

inductive AuthorizationState where
  | absent
  | fresh
  | consumed
  deriving DecidableEq

inductive PublicationDecision where
  | denied
  | publish
  deriving DecidableEq

structure RepositorySnapshot where
  head : String
  index : String
  tracked : String
  untracked : String
  deriving DecidableEq

structure AuthorizationBinding where
  state : AuthorizationState
  workspaceNonce : String
  candidateId : String
  patchDigest : String
  base : RepositorySnapshot
  result : RepositorySnapshot

structure ApplySafeGate where
  explicitlyRequested : Bool
  applicability : FixApplicability
  toolNative : Bool
  verificationPassed : Bool
  requiredProviderState : RequiredProviderState
  noRegression : Bool
  patchApplication : PatchApplicationState
  workspaceNonce : String
  candidateId : String
  patchDigest : String
  currentSource : RepositorySnapshot
  observedResult : RepositorySnapshot
  authorization : AuthorizationBinding

def allPublicationGates (gate : ApplySafeGate) : Prop :=
  gate.explicitlyRequested = true ∧
  gate.applicability = .safe ∧
  gate.toolNative = true ∧
  gate.verificationPassed = true ∧
  gate.requiredProviderState = .complete ∧
  gate.noRegression = true ∧
  gate.patchApplication = .applied ∧
  gate.workspaceNonce = gate.authorization.workspaceNonce ∧
  gate.candidateId = gate.authorization.candidateId ∧
  gate.patchDigest = gate.authorization.patchDigest ∧
  gate.currentSource = gate.authorization.base ∧
  gate.observedResult = gate.authorization.result ∧
  gate.authorization.state = .fresh

def mayPublish (gate : ApplySafeGate) : Bool :=
  gate.explicitlyRequested &&
  decide (gate.applicability = .safe) &&
  gate.toolNative &&
  gate.verificationPassed &&
  decide (gate.requiredProviderState = .complete) &&
  gate.noRegression &&
  decide (gate.patchApplication = .applied) &&
  decide (gate.workspaceNonce = gate.authorization.workspaceNonce) &&
  decide (gate.candidateId = gate.authorization.candidateId) &&
  decide (gate.patchDigest = gate.authorization.patchDigest) &&
  decide (gate.currentSource = gate.authorization.base) &&
  decide (gate.observedResult = gate.authorization.result) &&
  decide (gate.authorization.state = .fresh)

def publicationDecision (gate : ApplySafeGate) : PublicationDecision :=
  if mayPublish gate then .publish else .denied

def prospectiveOriginalAfter (gate : ApplySafeGate) : RepositorySnapshot :=
  if mayPublish gate then gate.observedResult else gate.currentSource

def authorizationAfterAttempt (gate : ApplySafeGate) : AuthorizationState :=
  if gate.explicitlyRequested && decide (gate.authorization.state = .fresh) then
    .consumed
  else
    gate.authorization.state

theorem may_publish_iff_all_gates (gate : ApplySafeGate) :
    mayPublish gate = true ↔ allPublicationGates gate := by
  simp [mayPublish, allPublicationGates, and_assoc]

theorem publication_decision_iff_all_gates (gate : ApplySafeGate) :
    publicationDecision gate = .publish ↔ allPublicationGates gate := by
  simp [publicationDecision, may_publish_iff_all_gates]

theorem denied_preserves_current_snapshot (gate : ApplySafeGate)
    (denied : publicationDecision gate = .denied) :
    prospectiveOriginalAfter gate = gate.currentSource := by
  cases allowed : mayPublish gate <;>
    simp [publicationDecision, prospectiveOriginalAfter, allowed] at denied ⊢

theorem publication_yields_bound_result (gate : ApplySafeGate)
    (published : publicationDecision gate = .publish) :
    prospectiveOriginalAfter gate = gate.authorization.result := by
  have allGates := (publication_decision_iff_all_gates gate).mp published
  have allowed := (may_publish_iff_all_gates gate).mpr allGates
  rcases allGates with ⟨_, _, _, _, _, _, _, _, _, _, _, result, _⟩
  simp [prospectiveOriginalAfter, allowed, result]

theorem any_failed_gate_preserves_current_snapshot (gate : ApplySafeGate)
    (failed : ¬ allPublicationGates gate) :
    prospectiveOriginalAfter gate = gate.currentSource := by
  cases allowed : mayPublish gate with
  | false => simp [prospectiveOriginalAfter, allowed]
  | true => exact False.elim (failed ((may_publish_iff_all_gates gate).mp allowed))

theorem no_implicit_publication (gate : ApplySafeGate)
    (notRequested : gate.explicitlyRequested = false) :
    publicationDecision gate = .denied ∧
    prospectiveOriginalAfter gate = gate.currentSource := by
  simp [publicationDecision, prospectiveOriginalAfter, mayPublish, notRequested]

theorem non_safe_fix_never_publishes (gate : ApplySafeGate)
    (notSafe : gate.applicability ≠ .safe) :
    publicationDecision gate = .denied ∧
    prospectiveOriginalAfter gate = gate.currentSource := by
  simp [publicationDecision, prospectiveOriginalAfter, mayPublish, notSafe]

theorem non_tool_native_fix_never_publishes (gate : ApplySafeGate)
    (notToolNative : gate.toolNative = false) :
    publicationDecision gate = .denied ∧
    prospectiveOriginalAfter gate = gate.currentSource := by
  simp [publicationDecision, prospectiveOriginalAfter, mayPublish, notToolNative]

theorem rejected_verification_never_publishes (gate : ApplySafeGate)
    (rejected : gate.verificationPassed = false) :
    publicationDecision gate = .denied ∧
    prospectiveOriginalAfter gate = gate.currentSource := by
  simp [publicationDecision, prospectiveOriginalAfter, mayPublish, rejected]

theorem terminal_provider_never_publishes (gate : ApplySafeGate)
    (terminal : gate.requiredProviderState ≠ .complete) :
    publicationDecision gate = .denied ∧
    prospectiveOriginalAfter gate = gate.currentSource := by
  simp [publicationDecision, prospectiveOriginalAfter, mayPublish, terminal]

theorem unapplied_patch_never_publishes (gate : ApplySafeGate)
    (notApplied : gate.patchApplication ≠ .applied) :
    publicationDecision gate = .denied ∧
    prospectiveOriginalAfter gate = gate.currentSource := by
  simp [publicationDecision, prospectiveOriginalAfter, mayPublish, notApplied]

theorem regression_never_publishes (gate : ApplySafeGate)
    (regressed : gate.noRegression = false) :
    publicationDecision gate = .denied ∧
    prospectiveOriginalAfter gate = gate.currentSource := by
  simp [publicationDecision, prospectiveOriginalAfter, mayPublish, regressed]

theorem authorization_binding_required (gate : ApplySafeGate)
    (published : publicationDecision gate = .publish) :
    gate.workspaceNonce = gate.authorization.workspaceNonce ∧
    gate.candidateId = gate.authorization.candidateId ∧
    gate.patchDigest = gate.authorization.patchDigest ∧
    gate.currentSource = gate.authorization.base ∧
    gate.observedResult = gate.authorization.result := by
  rcases (publication_decision_iff_all_gates gate).mp published with
    ⟨_, _, _, _, _, _, _, nonce, candidate, patch, base, result, _⟩
  exact ⟨nonce, candidate, patch, base, result⟩

theorem non_fresh_authorization_never_publishes (gate : ApplySafeGate)
    (notFresh : gate.authorization.state ≠ .fresh) :
    publicationDecision gate = .denied ∧
    prospectiveOriginalAfter gate = gate.currentSource := by
  simp [publicationDecision, prospectiveOriginalAfter, mayPublish, notFresh]

theorem explicit_fresh_attempt_consumes_authorization (gate : ApplySafeGate)
    (requested : gate.explicitlyRequested = true)
    (fresh : gate.authorization.state = .fresh) :
    authorizationAfterAttempt gate = .consumed := by
  simp [authorizationAfterAttempt, requested, fresh]

theorem publication_consumes_authorization (gate : ApplySafeGate)
    (published : publicationDecision gate = .publish) :
    authorizationAfterAttempt gate = .consumed := by
  rcases (publication_decision_iff_all_gates gate).mp published with
    ⟨requested, _, _, _, _, _, _, _, _, _, _, _, fresh⟩
  exact explicit_fresh_attempt_consumes_authorization gate requested fresh
