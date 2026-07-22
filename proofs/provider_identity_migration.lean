/-
LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED;
execution terminal: INCOMPLETE | UNSUPPORTED.
This proves the pure completeness rule; Rust tests establish Serde refinement.
-/
inductive IdentityField where
  | missing
  | present (value : String)

structure ProviderIdentity where
  adapterVersion : String
  toolName : String
  toolVersion : String

def completeIdentity (adapterVersion toolName toolVersion : IdentityField) :
    Option ProviderIdentity :=
  match adapterVersion, toolName, toolVersion with
  | .present adapter, .present tool, .present version => some ⟨adapter, tool, version⟩
  | _, _, _ => none

theorem complete_identity_iff (adapterVersion toolName toolVersion : IdentityField) :
    (∃ identity, completeIdentity adapterVersion toolName toolVersion = some identity) ↔
      ∃ adapter tool version, adapterVersion = .present adapter ∧
        toolName = .present tool ∧ toolVersion = .present version := by
  cases adapterVersion <;> cases toolName <;> cases toolVersion <;> simp [completeIdentity]

theorem complete_identity_preserves (adapter tool version : String) :
    completeIdentity (.present adapter) (.present tool) (.present version) =
      some ⟨adapter, tool, version⟩ := rfl
