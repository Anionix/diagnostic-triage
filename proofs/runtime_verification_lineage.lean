/-
LLM contract: PATCH_APPLIED -> VERIFY_PLANNED -> PROVIDER_TARGETS_VALIDATED ->
SOURCE_LINEAGE_VALIDATED -> PROVIDERS_PREFLIGHTED -> PROVIDERS_REAPED -> RESULT_RECAPTURED.

Proof contract: ordered base, patch, and result identity plus an exhaustive
original-read-only or scratch-mutable isolation partition.
Source: https://github.com/Anionix/diagnostic-triage/issues/82
-/
structure VerifyIdentity where
  base : String
  patch : String
  result : String

def verifyPreimage (value : VerifyIdentity) : List String :=
  [value.base, value.patch, value.result]

theorem ordered_verify_identity (left right : VerifyIdentity)
    (same : verifyPreimage left = verifyPreimage right) :
    left.base = right.base ∧ left.patch = right.patch ∧ left.result = right.result := by
  cases left
  cases right
  simpa [verifyPreimage] using same

inductive IsolationState where | original | scratch deriving DecidableEq

def mayMutate : IsolationState -> Bool
  | .original => false
  | .scratch => true

theorem isolation_state_partition (state : IsolationState) :
    (state = .original ∧ mayMutate state = false) ∨
    (state = .scratch ∧ mayMutate state = true) := by
  cases state <;> simp [mayMutate]
