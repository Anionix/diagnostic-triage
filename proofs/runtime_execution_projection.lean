/-
LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.
Proof contract: VALID_PROVIDER_OUTCOME -> EXECUTION_SYNTHESIZED -> REPORTED; invalid -> REJECTED.
Source: https://github.com/Anionix/diagnostic-triage/issues/228
-/
inductive ProviderState where | complete | incomplete | unsupported
inductive ExecutionStatus where | complete | incomplete | unsupported
structure Execution where status : ExecutionStatus
inductive InputValidity where | valid | invalid
inductive ProjectionError where | invalidInput
def executionStatus : ProviderState -> ExecutionStatus
  | .complete => .complete
  | .incomplete => .incomplete
  | .unsupported => .unsupported
def synthesizeExecution (validity : InputValidity) (state : ProviderState) :
    Except ProjectionError (List Execution) :=
  match validity with
  | .valid => .ok [⟨executionStatus state⟩]
  | .invalid => .error .invalidInput
theorem provider_state_mapping_exhaustive (state : ProviderState) :
    (executionStatus state = .complete ↔ state = .complete) ∧
    (executionStatus state = .incomplete ↔ state = .incomplete) ∧
    (executionStatus state = .unsupported ↔ state = .unsupported) := by
  cases state <;> simp [executionStatus]
theorem valid_provider_state_yields_exactly_one_execution (state : ProviderState) :
    ∃ execution, synthesizeExecution .valid state = .ok [execution] := by
  exact ⟨⟨executionStatus state⟩, rfl⟩
theorem invalid_provider_state_is_rejected (state : ProviderState) :
    synthesizeExecution .invalid state = .error .invalidInput := by
  rfl
def synthesizeAll : List ProviderState -> List Execution
  | [] => []
  | state :: states => ⟨executionStatus state⟩ :: synthesizeAll states
theorem valid_provider_list_yields_one_execution_per_provider (states : List ProviderState) :
    (synthesizeAll states).length = states.length := by
  induction states <;> simp [synthesizeAll, *]
