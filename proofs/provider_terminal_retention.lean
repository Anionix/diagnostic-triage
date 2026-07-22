/-
LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED;
execution terminal: INCOMPLETE | UNSUPPORTED.

Proof contract: VALIDATED -> TERMINAL_MAPPED -> RETENTION_VERIFIED.
This pure model covers the exhaustive Provider terminal-origin mapping. A
validated protocol completion carries its session; transport, handshake,
malformed-stream, and capability-negotiation failures cannot fabricate one.
Source: https://github.com/Anionix/diagnostic-triage/issues/221
-/

inductive ProviderTerminal where
  | complete
  | incomplete
  | unsupported
  | transportFailure
  | handshakeFailure
  | malformedStream
  | capabilityNegotiationFailure

def retainedSession {Session : Type} (terminal : ProviderTerminal) (session : Session) :
    Option Session :=
  match terminal with
  | .complete | .incomplete | .unsupported => some session
  | .transportFailure | .handshakeFailure | .malformedStream |
      .capabilityNegotiationFailure => none

theorem retained_session_exhaustive {Session : Type}
    (terminal : ProviderTerminal) (session : Session) :
    (retainedSession terminal session = some session ↔
      terminal = .complete ∨ terminal = .incomplete ∨ terminal = .unsupported) ∧
    (retainedSession terminal session = none ↔
      terminal = .transportFailure ∨ terminal = .handshakeFailure ∨
        terminal = .malformedStream ∨ terminal = .capabilityNegotiationFailure) := by
  cases terminal <;> simp [retainedSession]
