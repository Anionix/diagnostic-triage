//! Evidence-backed mapping from native diagnostics to the canonical taxonomy.

use std::collections::BTreeSet;

use diagnostic_triage_contracts::{
    Language,
    model::{Observation, Origin, Taxonomy},
};

use crate::{EngineError, EngineInputError, normalize::collapse_whitespace};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// Maximum number of taxonomy mappings accepted by the v1 classifier.
pub const MAX_CLASSIFICATION_RULES: usize = 4096;
const MAX_AMBIGUOUS_RULE_IDS: usize = 8;

/// Match behavior for an optional native rule identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuleIdSelector {
    Any,
    Absent,
    Exact(String),
}

impl RuleIdSelector {
    fn matches(&self, candidate: Option<&str>) -> bool {
        match self {
            Self::Any => true,
            Self::Absent => candidate.is_none(),
            Self::Exact(expected) => candidate == Some(expected.as_str()),
        }
    }

    fn is_constrained(&self) -> bool {
        !matches!(self, Self::Any)
    }
}

/// A policy-independent mapping justified by structured Provider identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassificationRule {
    pub id: String,
    pub tool_name: String,
    pub tool_version: Option<String>,
    pub native_rule_id: RuleIdSelector,
    pub language: Option<Language>,
    pub origin: Option<Origin>,
    pub taxonomy: Taxonomy,
}

impl ClassificationRule {
    fn validate(&self) -> Result<(), EngineError> {
        let id_length = self.id.chars().count();
        if id_length == 0 || id_length > 128 {
            return Err(EngineInputError::InvalidClassificationRuleId { length: id_length }.into());
        }
        if self.tool_name.is_empty() || self.tool_name.chars().count() > 64 {
            return Err(EngineInputError::InvalidClassificationToolName {
                rule_id: self.id.clone(),
            }
            .into());
        }
        if collapse_whitespace(&self.tool_name) != self.tool_name {
            return Err(EngineInputError::NonCanonicalClassificationToolName {
                rule_id: self.id.clone(),
            }
            .into());
        }
        if matches!(&self.tool_version, Some(value) if value.is_empty() || value.chars().count() > 64)
        {
            return Err(EngineInputError::InvalidClassificationToolVersion {
                rule_id: self.id.clone(),
            }
            .into());
        }
        if matches!(&self.tool_version, Some(value) if collapse_whitespace(value) != value.as_str())
        {
            return Err(EngineInputError::NonCanonicalClassificationToolVersion {
                rule_id: self.id.clone(),
            }
            .into());
        }
        if matches!(&self.native_rule_id, RuleIdSelector::Exact(value) if value.is_empty() || value.chars().count() > 128)
        {
            return Err(EngineInputError::InvalidClassificationNativeRuleId {
                rule_id: self.id.clone(),
            }
            .into());
        }
        if matches!(&self.native_rule_id, RuleIdSelector::Exact(value) if collapse_whitespace(value) != value.as_str())
        {
            return Err(EngineInputError::NonCanonicalClassificationNativeRuleId {
                rule_id: self.id.clone(),
            }
            .into());
        }
        self.taxonomy.validate()?;
        Ok(())
    }

    fn matches(&self, observation: &Observation) -> bool {
        self.tool_name == observation.tool.name
            && self
                .tool_version
                .as_ref()
                .is_none_or(|version| version == &observation.tool.version)
            && self
                .native_rule_id
                .matches(observation.tool.rule_id.as_deref())
            && self
                .language
                .as_ref()
                .is_none_or(|language| language == &observation.language)
            && self
                .origin
                .as_ref()
                .is_none_or(|origin| origin == &observation.origin)
    }

    fn is_more_specific_than(&self, other: &Self) -> bool {
        let own = [
            self.tool_version.is_some(),
            self.native_rule_id.is_constrained(),
            self.language.is_some(),
            self.origin.is_some(),
        ];
        let candidate = [
            other.tool_version.is_some(),
            other.native_rule_id.is_constrained(),
            other.language.is_some(),
            other.origin.is_some(),
        ];

        own.iter()
            .zip(candidate)
            .all(|(own, candidate)| !candidate || *own)
            && own
                .iter()
                .zip(candidate)
                .any(|(own, candidate)| *own && !candidate)
    }
}

/// The selected taxonomy and its auditable catalog rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassificationMatch {
    pub rule_id: String,
    pub taxonomy: Taxonomy,
}

/// Select the most-specific matching taxonomy rule without parsing prose.
///
/// # Errors
///
/// Returns an error for invalid observations or catalog rules, no match, or an
/// multiple incomparable or identically constrained maximal matches.
pub fn classify_observation(
    observation: &Observation,
    rules: &[ClassificationRule],
) -> Result<ClassificationMatch, EngineError> {
    observation.validate()?;
    if collapse_whitespace(&observation.tool.name) != observation.tool.name
        || collapse_whitespace(&observation.tool.version) != observation.tool.version
        || observation
            .tool
            .rule_id
            .as_deref()
            .is_some_and(|rule_id| collapse_whitespace(rule_id) != rule_id)
    {
        return Err(EngineInputError::NonCanonicalObservationTool {
            observation_id: observation.observation_id.to_string(),
        }
        .into());
    }
    if rules.len() > MAX_CLASSIFICATION_RULES {
        return Err(EngineInputError::ClassificationCatalogTooLarge {
            actual: rules.len(),
            max: MAX_CLASSIFICATION_RULES,
        }
        .into());
    }
    let mut rule_ids = BTreeSet::new();
    for rule in rules {
        rule.validate()?;
        if !rule_ids.insert(rule.id.as_str()) {
            return Err(EngineInputError::DuplicateClassificationRuleId {
                rule_id: rule.id.clone(),
            }
            .into());
        }
    }

    let matches = rules
        .iter()
        .filter(|rule| rule.matches(observation))
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return Err(EngineError::Unclassified {
            observation_id: observation.observation_id.to_string(),
        });
    }
    let mut maximal = matches
        .iter()
        .copied()
        .filter(|candidate| {
            !matches
                .iter()
                .any(|other| other.is_more_specific_than(candidate))
        })
        .collect::<Vec<_>>();
    maximal.sort_by(|left, right| left.id.cmp(&right.id));

    if maximal.len() > 1 {
        let reported_rule_count = maximal.len().min(MAX_AMBIGUOUS_RULE_IDS);
        return Err(EngineError::AmbiguousClassification {
            observation_id: observation.observation_id.to_string(),
            rule_ids: maximal
                .iter()
                .take(reported_rule_count)
                .map(|rule| rule.id.clone())
                .collect(),
            omitted_rule_count: maximal.len() - reported_rule_count,
        });
    }

    let selected = maximal[0];
    Ok(ClassificationMatch {
        rule_id: selected.id.clone(),
        taxonomy: selected.taxonomy.clone(),
    })
}
