/-
LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED;
execution terminal: INCOMPLETE | UNSUPPORTED.

Proof contract: RAW_INPUT -> NORMALIZED_INPUT -> DOMAIN_SEPARATED_PREIMAGE -> DERIVED_ID.
This model proves equality and separation of pure derivation preimages. Lean does
not prove SHA-256/UUIDv8 collision resistance, Serde canonicalization, or Rust/kernel
behavior. Rust tests establish those executable facts; `NoCollisionOn` names the
collision assumption used below.
Provider permutation theorems begin after successful Rust input validation.
Source: https://www.rfc-editor.org/rfc/rfc9562.html#section-5.8
-/

inductive ReadOnlyMode where
  | check
  | ci
  deriving DecidableEq

structure NormalizedPlanInput where
  mode : ReadOnlyMode
  normalizedConfigJson : String
  repositoryDigest : String
  deriving DecidableEq

structure AdapterIdentity where
  adapterId : String
  deriving DecidableEq

structure PlanId where
  value : String
  deriving DecidableEq

structure IdPreimage where
  domain : String
  fields : List String
  deriving DecidableEq

def planIdDomain : String := "diagnostic-triage.runtime-plan/v1"
def requestIdDomain : String := "diagnostic-triage.runtime-request/v1"
def runtimeExecutionIdDomain : String := "diagnostic-triage.runtime-execution/v1"

def ReadOnlyMode.wire : ReadOnlyMode -> String
  | .check => "check"
  | .ci => "ci"

def planIdPreimage (input : NormalizedPlanInput) : IdPreimage :=
  ⟨planIdDomain,
    [input.mode.wire, input.normalizedConfigJson, input.repositoryDigest]⟩

def requestIdPreimage (planId : PlanId) (adapter : AdapterIdentity) : IdPreimage :=
  ⟨requestIdDomain, [planId.value, adapter.adapterId]⟩

def runtimeExecutionIdPreimage
    (planId : PlanId) (adapter : AdapterIdentity) : IdPreimage :=
  ⟨runtimeExecutionIdDomain, [planId.value, adapter.adapterId]⟩

def CanonicalizesProviderPermutations {ValidatedProviderInput : Type}
    (normalize : List ValidatedProviderInput -> NormalizedPlanInput) : Prop :=
  ∀ left right, left.Perm right -> normalize left = normalize right

theorem identical_normalized_inputs_same_plan_id_preimage
    (left right : NormalizedPlanInput) (same : left = right) :
    planIdPreimage left = planIdPreimage right := by
  exact congrArg planIdPreimage same

theorem provider_input_permutations_same_plan_id_preimage
    {ValidatedProviderInput : Type}
    (normalize : List ValidatedProviderInput -> NormalizedPlanInput)
    (canonical : CanonicalizesProviderPermutations normalize)
    (left right : List ValidatedProviderInput) (permuted : left.Perm right) :
    planIdPreimage (normalize left) = planIdPreimage (normalize right) := by
  exact congrArg planIdPreimage (canonical left right permuted)

theorem request_id_runtime_execution_id_preimages_distinct
    (planId : PlanId) (adapter : AdapterIdentity) :
    requestIdPreimage planId adapter ≠
      runtimeExecutionIdPreimage planId adapter := by
  intro same
  have separated : requestIdDomain ≠ runtimeExecutionIdDomain := by decide
  exact separated (congrArg IdPreimage.domain same)

def NoCollisionOn {ObjectId : Type}
    (derive : IdPreimage -> ObjectId) (left right : IdPreimage) : Prop :=
  derive left = derive right -> left = right

theorem request_id_runtime_execution_id_distinct_under_no_collision
    {ObjectId : Type} (derive : IdPreimage -> ObjectId)
    (planId : PlanId) (adapter : AdapterIdentity)
    (noCollision : NoCollisionOn derive
      (requestIdPreimage planId adapter)
      (runtimeExecutionIdPreimage planId adapter)) :
    derive (requestIdPreimage planId adapter) ≠
      derive (runtimeExecutionIdPreimage planId adapter) := by
  intro sameId
  exact request_id_runtime_execution_id_preimages_distinct planId adapter
    (noCollision sameId)
