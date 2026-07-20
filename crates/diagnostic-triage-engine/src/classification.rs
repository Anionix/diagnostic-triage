//! Evidence-backed mapping from native diagnostics to the canonical taxonomy.

use std::collections::BTreeSet;

use diagnostic_triage_contracts::{
    Language,
    model::{Observation, Origin, Taxonomy},
};

use crate::{EngineError, EngineInputError, normalize::collapse_whitespace};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

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

    fn specificity(&self) -> u8 {
        match self {
            Self::Any => 0,
            Self::Absent | Self::Exact(_) => 1,
        }
    }
}

/// A policy-independent mapping justified by structured Provider identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassificationRule {
    pub id: String,
    pub tool_name: String,
    pub native_rule_id: RuleIdSelector,
    pub language: Option<Language>,
    pub origin: Option<Origin>,
    pub taxonomy: Taxonomy,
}

impl ClassificationRule {
    fn validate(&self) -> Result<(), EngineError> {
        if self.id.is_empty() || self.id.chars().count() > 128 {
            return Err(EngineInputError::InvalidClassificationRuleId {
                rule_id: self.id.clone(),
            }
            .into());
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
        let tool_name = collapse_whitespace(&observation.tool.name);
        let native_rule_id = observation.tool.rule_id.as_deref().map(collapse_whitespace);
        self.tool_name == tool_name
            && self.native_rule_id.matches(native_rule_id.as_deref())
            && self
                .language
                .as_ref()
                .is_none_or(|language| language == &observation.language)
            && self
                .origin
                .as_ref()
                .is_none_or(|origin| origin == &observation.origin)
    }

    fn specificity(&self) -> u8 {
        self.native_rule_id.specificity()
            + u8::from(self.language.is_some())
            + u8::from(self.origin.is_some())
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
/// equally specific match that maps to conflicting taxonomies.
pub fn classify_observation(
    observation: &Observation,
    rules: &[ClassificationRule],
) -> Result<ClassificationMatch, EngineError> {
    observation.validate()?;
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

    let mut matches = rules
        .iter()
        .filter(|rule| rule.matches(observation))
        .collect::<Vec<_>>();
    let max_specificity = matches
        .iter()
        .map(|rule| rule.specificity())
        .max()
        .ok_or_else(|| EngineError::Unclassified {
            observation_id: observation.observation_id.to_string(),
        })?;
    matches.retain(|rule| rule.specificity() == max_specificity);
    matches.sort_by(|left, right| left.id.cmp(&right.id));

    let selected = matches[0];
    if matches
        .iter()
        .skip(1)
        .any(|candidate| candidate.taxonomy != selected.taxonomy)
    {
        return Err(EngineError::AmbiguousClassification {
            observation_id: observation.observation_id.to_string(),
            rule_ids: matches
                .iter()
                .map(|rule| rule.id.as_str())
                .collect::<Vec<_>>()
                .join(","),
        });
    }

    Ok(ClassificationMatch {
        rule_id: selected.id.clone(),
        taxonomy: selected.taxonomy.clone(),
    })
}
