//! Evidence-backed mapping from native diagnostics to the canonical taxonomy.

use std::collections::BTreeSet;

use diagnostic_triage_contracts::{
    Language,
    model::{Category, MicroCategory, Observation, Origin, Taxonomy},
};

use crate::{EngineError, EngineInputError, normalize::collapse_whitespace};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// Maximum number of taxonomy mappings accepted by the v1 classifier.
pub const MAX_CLASSIFICATION_RULES: usize = 4096;
const MAX_AMBIGUOUS_RULE_IDS: usize = 8;
const CONSTRAINT_MASK_COUNT: usize = 1 << 4;

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
        if self.taxonomy.category == Category::Unknown {
            return Err(EngineInputError::ReservedClassificationTaxonomy {
                rule_id: self.id.clone(),
            }
            .into());
        }
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

    fn constraint_mask(&self) -> u8 {
        u8::from(self.tool_version.is_some())
            | (u8::from(self.native_rule_id.is_constrained()) << 1)
            | (u8::from(self.language.is_some()) << 2)
            | (u8::from(self.origin.is_some()) << 3)
    }
}

fn maximal_constraint_masks(populated: u16) -> u16 {
    // Co-matching rules agree on every constrained value, so strict bit-set
    // inclusion is exactly the v1 refinement relation over four dimensions.
    let mut maximal = 0_u16;
    for candidate in 0..CONSTRAINT_MASK_COUNT {
        let candidate_bit = 1_u16 << candidate;
        if populated & candidate_bit == 0 {
            continue;
        }
        let dominated = (0..CONSTRAINT_MASK_COUNT).any(|other| {
            other != candidate
                && populated & (1_u16 << other) != 0
                && (other & candidate) == candidate
        });
        if !dominated {
            maximal |= candidate_bit;
        }
    }
    maximal
}

/// Typed provenance for the selected taxonomy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClassificationAttribution {
    /// A validated repository catalog rule selected the taxonomy.
    CatalogRule { rule_id: String },
    /// No catalog rule matched, so the Engine selected `unknown.unknown`.
    BuiltinUnknown,
}

/// The selected taxonomy and its auditable attribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassificationMatch {
    pub attribution: ClassificationAttribution,
    pub taxonomy: Taxonomy,
}

impl ClassificationMatch {
    fn builtin_unknown() -> Self {
        Self {
            attribution: ClassificationAttribution::BuiltinUnknown,
            taxonomy: Taxonomy {
                category: Category::Unknown,
                micro_category: MicroCategory::Unknown,
            },
        }
    }
}

/// Select the most-specific matching taxonomy rule without parsing prose.
///
/// # Errors
///
/// Returns an error for invalid observations or catalog rules, or multiple
/// incomparable or identically constrained maximal matches. No match is the
/// typed built-in `unknown.unknown` result.
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

    let mut matching_by_mask: [Vec<&ClassificationRule>; CONSTRAINT_MASK_COUNT] =
        std::array::from_fn(|_| Vec::new());
    let mut populated_masks = 0_u16;
    for rule in rules.iter().filter(|rule| rule.matches(observation)) {
        let mask = usize::from(rule.constraint_mask());
        populated_masks |= 1_u16 << mask;
        matching_by_mask[mask].push(rule);
    }
    if populated_masks == 0 {
        return Ok(ClassificationMatch::builtin_unknown());
    }

    let maximal_masks = maximal_constraint_masks(populated_masks);
    let maximal_rule_count = matching_by_mask
        .iter()
        .enumerate()
        .filter(|(mask, _)| maximal_masks & (1_u16 << mask) != 0)
        .map(|(_, rules)| rules.len())
        .sum::<usize>();
    if maximal_rule_count > 1 {
        let mut reported_rule_ids = BTreeSet::new();
        for rule in matching_by_mask
            .iter()
            .enumerate()
            .filter(|(mask, _)| maximal_masks & (1_u16 << mask) != 0)
            .flat_map(|(_, rules)| rules)
        {
            if reported_rule_ids.len() < MAX_AMBIGUOUS_RULE_IDS {
                reported_rule_ids.insert(rule.id.as_str());
                continue;
            }
            let should_replace = reported_rule_ids
                .last()
                .is_some_and(|largest| rule.id.as_str() < *largest);
            if should_replace {
                reported_rule_ids.pop_last();
                reported_rule_ids.insert(rule.id.as_str());
            }
        }
        return Err(EngineError::AmbiguousClassification {
            observation_id: observation.observation_id.to_string(),
            rule_ids: reported_rule_ids.into_iter().map(str::to_owned).collect(),
            omitted_rule_count: maximal_rule_count - maximal_rule_count.min(MAX_AMBIGUOUS_RULE_IDS),
        });
    }

    let Some(selected) = matching_by_mask
        .iter()
        .enumerate()
        .filter(|(mask, _)| maximal_masks & (1_u16 << mask) != 0)
        .flat_map(|(_, rules)| rules)
        .next()
    else {
        return Ok(ClassificationMatch::builtin_unknown());
    };
    Ok(ClassificationMatch {
        attribution: ClassificationAttribution::CatalogRule {
            rule_id: selected.id.clone(),
        },
        taxonomy: selected.taxonomy.clone(),
    })
}
