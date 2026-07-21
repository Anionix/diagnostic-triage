/-
LLM contract: SIGNALING -> REAPED -> GROUP_ABSENT -> COMPLETE | INCOMPLETE.

This model proves only the pure suppression decision. Rust integration tests
remain responsible for establishing the kernel facts represented by the two
Boolean inputs.
-/

inductive SignalOrigin where
  | native
  | injected
  deriving DecidableEq

def maySuppressPermissionError
    (origin : SignalOrigin)
    (isNativeEperm leaderReaped groupAbsent : Bool) : Bool :=
  origin == .native && isNativeEperm && leaderReaped && groupAbsent

theorem injected_never_suppressed
    (isNativeEperm leaderReaped groupAbsent : Bool) :
    maySuppressPermissionError .injected isNativeEperm leaderReaped groupAbsent = false := by
  simp [maySuppressPermissionError]

theorem suppression_requires_leader_reaped
    (origin : SignalOrigin) (isNativeEperm leaderReaped groupAbsent : Bool)
    (accepted : maySuppressPermissionError origin isNativeEperm leaderReaped groupAbsent = true) :
    leaderReaped = true := by
  simp [maySuppressPermissionError] at accepted
  exact accepted.1.2

theorem suppression_requires_group_absent
    (origin : SignalOrigin) (isNativeEperm leaderReaped groupAbsent : Bool)
    (accepted : maySuppressPermissionError origin isNativeEperm leaderReaped groupAbsent = true) :
    groupAbsent = true := by
  simp [maySuppressPermissionError] at accepted
  exact accepted.2
