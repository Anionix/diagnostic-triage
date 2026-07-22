/-
LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED;
execution terminal: INCOMPLETE | UNSUPPORTED.
This proves only the pure byte-charge rule; Rust tests cover representative serde_json behavior.
-/
def charge (limit used next : Nat) : Option Nat :=
  if used + next ≤ limit then some (used + next) else none

theorem charge_sound (limit used next total : Nat)
    (accepted : charge limit used next = some total) :
    total = used + next ∧ total ≤ limit := by
  unfold charge at accepted
  split at accepted <;> simp_all
