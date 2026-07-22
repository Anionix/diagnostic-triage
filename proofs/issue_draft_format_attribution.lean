/-
LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED;
execution terminal: INCOMPLETE | UNSUPPORTED.
This pure model covers only ReporterError branches carrying ReportFormat; Contract is excluded.
-/
inductive DraftFormat where | json | markdown
inductive AttributedStage where
  | projectionLimit | intermediateEncoding | outputEncoding | writerIo

structure DraftFailure where
  stage : AttributedStage
  format : DraftFormat

def attributeFailure (requested : DraftFormat) (stage : AttributedStage) : DraftFailure :=
  ⟨stage, requested⟩

def pipeline (requested : DraftFormat) (stages : List AttributedStage) : List DraftFailure :=
  stages.map (attributeFailure requested)

theorem pipeline_preserves_format (requested : DraftFormat) (stages : List AttributedStage) :
    ∀ failure ∈ pipeline requested stages, failure.format = requested := by
  induction stages with
  | nil => simp [pipeline]
  | cons head tail _ => simp [pipeline, attributeFailure]
