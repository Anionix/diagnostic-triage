/-
LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED;
execution terminal: INCOMPLETE | UNSUPPORTED.
This models the pure budget choice; Rust tests cover compact JSON bytes and allocation order.
-/
def payloadBudget (jsonMax markdownMax overhead : Nat) : Option Nat :=
  if overhead ≤ markdownMax then
    some (min jsonMax (markdownMax - overhead))
  else
    none

theorem payload_budget_sound (jsonMax markdownMax overhead limit : Nat)
    (accepted : payloadBudget jsonMax markdownMax overhead = some limit) :
    limit ≤ jsonMax ∧ overhead + limit ≤ markdownMax := by
  unfold payloadBudget at accepted
  split at accepted
  next fits =>
    simp at accepted
    subst limit
    constructor
    · exact Nat.min_le_left _ _
    · calc
        overhead + min jsonMax (markdownMax - overhead) ≤
            overhead + (markdownMax - overhead) :=
          Nat.add_le_add_left (Nat.min_le_right _ _) _
        _ = markdownMax := Nat.add_sub_of_le fits
  next => simp at accepted
