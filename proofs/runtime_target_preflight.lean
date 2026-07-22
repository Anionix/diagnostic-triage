/-
LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED;
execution terminal: INCOMPLETE | UNSUPPORTED.

Proof contract: PLANNED_TARGETS -> PREFLIGHTED_TARGETS -> PROVIDER_LAUNCH_PLAN.
This model proves only the all-targets-before-any-launch decision. Rust tests
remain responsible for filesystem canonicalization, symlink, and process facts.
-/

def providerLaunchPlan (providerCount : Nat) (targetValidity : List Bool) :
    Option (List Unit) :=
  if targetValidity.all (fun valid => valid) then
    some (List.replicate providerCount ())
  else
    none

theorem one_escape_blocks_all_provider_launches
    (providerCount : Nat) (before after : List Bool) :
    providerLaunchPlan providerCount (before ++ false :: after) = none := by
  simp [providerLaunchPlan]

theorem launch_generated_iff_all_targets_valid
    (providerCount : Nat) (targetValidity : List Bool) :
    (providerLaunchPlan providerCount targetValidity).isSome =
      targetValidity.all (fun target => target) := by
  cases h : targetValidity.all (fun target => target) <;>
    simp [providerLaunchPlan, h]

theorem all_valid_targets_preserve_provider_count
    (providerCount : Nat) (targetValidity : List Bool)
    (valid : targetValidity.all (fun target => target) = true) :
    (providerLaunchPlan providerCount targetValidity).map List.length =
      some providerCount := by
  simp [providerLaunchPlan, valid]
