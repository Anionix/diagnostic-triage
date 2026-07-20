// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.
//! Deterministic, consumer-owned policy evaluation for v1 findings.

use std::collections::BTreeSet;
use std::str::FromStr;

use diagnostic_triage_contracts::model::{
    Category, Decision, DecisionAction, DecisionSchemaVersion, Finding, MicroCategory, Severity,
    Taxonomy, WaivedAction, Waiver, is_valid_rfc3339_datetime,
};
use diagnostic_triage_contracts::{Fingerprint, Language, ObjectId, Sha256Digest};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::EngineError;
use crate::deterministic_object_id;
use crate::finding::validate_finding_integrity;
use crate::normalize::normalize_context;

const DEFAULT_RULE_ID: &str = "default-error-block";
const DEFAULT_OBSERVE_RULE_ID: &str = "default-observe";
const POLICY_VERSION: &str = "diagnostic-triage.policy/v1";

/// The enforcement ordering is OBSERVE < WARN < BLOCK.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PolicyAction {
    Observe,
    Warn,
    Block,
}

impl PolicyAction {
    const fn decision_action(self) -> DecisionAction {
        match self {
            Self::Observe => DecisionAction::Observe,
            Self::Warn => DecisionAction::Warn,
            Self::Block => DecisionAction::Block,
        }
    }

    const fn can_be_waived_as(self, waived_action: WaivedAction) -> bool {
        matches!(
            (self, waived_action),
            (Self::Warn, WaivedAction::Warn) | (Self::Block, WaivedAction::Block)
        )
    }
}

/// Optional finding properties used by a consumer-owned rule.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyMatcher {
    pub severity: Option<Severity>,
    pub category: Option<Category>,
    pub micro_category: Option<MicroCategory>,
    pub fingerprint: Option<Fingerprint>,
    pub language: Option<Language>,
    /// Matches the provider/tool name, not its version.
    pub tool_name: Option<String>,
    pub tool_rule_id: Option<String>,
}

impl PolicyMatcher {
    fn matches(&self, finding: &Finding) -> bool {
        self.severity
            .as_ref()
            .is_none_or(|severity| severity == &finding.severity)
            && self
                .category
                .as_ref()
                .is_none_or(|category| category == &finding.classification.category)
            && self.micro_category.as_ref().is_none_or(|micro_category| {
                micro_category == &finding.classification.micro_category
            })
            && self
                .fingerprint
                .as_ref()
                .is_none_or(|fingerprint| fingerprint == &finding.fingerprint)
            && self
                .language
                .as_ref()
                .is_none_or(|language| language == &finding.language)
            && self
                .tool_name
                .as_deref()
                .is_none_or(|tool_name| tool_name == finding.tool.name)
            && self
                .tool_rule_id
                .as_deref()
                .is_none_or(|rule_id| finding.tool.rule_id.as_deref() == Some(rule_id))
    }
}

/// A policy rule has no repository-specific data in the Finding contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub rule_id: String,
    pub matcher: PolicyMatcher,
    pub action: PolicyAction,
}

impl PolicyRule {
    #[must_use]
    pub fn new(rule_id: impl Into<String>, matcher: PolicyMatcher, action: PolicyAction) -> Self {
        Self {
            rule_id: rule_id.into(),
            matcher,
            action,
        }
    }
}

/// Errors in the consumer-owned policy configuration.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy rule ID must contain 1..=128 characters: {rule_id:?}")]
    InvalidRuleId { rule_id: String },
    #[error("policy matcher {field} must contain 1..={max} characters: {value:?}")]
    InvalidToolMatcher {
        field: &'static str,
        max: usize,
        value: String,
    },
    #[error("policy rule ID is duplicated: {rule_id}")]
    DuplicateRuleId { rule_id: String },
    #[error("policy rule ID is reserved by the v1 engine: {rule_id}")]
    ReservedRuleId { rule_id: String },
    #[error("policy rule {rule_id} contains an invalid taxonomy matcher")]
    InvalidTaxonomyMatcher { rule_id: String },
    #[error("policy waiver {index} is invalid: {reason}")]
    InvalidWaiver { index: usize, reason: String },
    #[error("policy evaluation time is not RFC 3339: {value:?}")]
    InvalidEvaluationTime { value: String },
    #[error("finding is invalid for policy evaluation")]
    InvalidFinding {
        #[source]
        source: EngineError,
    },
    #[error("policy canonicalization failed: {reason}")]
    Canonicalization { reason: String },
}

/// Validate every rule before evaluating any finding.
///
/// # Errors
///
/// Returns [`PolicyError`] when a rule ID or tool matcher is empty or exceeds
/// its contract length.
pub fn validate_policy(rules: &[PolicyRule]) -> Result<(), PolicyError> {
    let mut rule_ids = BTreeSet::new();
    for rule in rules {
        if !(1..=128).contains(&rule.rule_id.chars().count()) {
            return Err(PolicyError::InvalidRuleId {
                rule_id: rule.rule_id.clone(),
            });
        }
        if matches!(
            rule.rule_id.as_str(),
            DEFAULT_RULE_ID | DEFAULT_OBSERVE_RULE_ID
        ) {
            return Err(PolicyError::ReservedRuleId {
                rule_id: rule.rule_id.clone(),
            });
        }
        if !rule_ids.insert(rule.rule_id.as_str()) {
            return Err(PolicyError::DuplicateRuleId {
                rule_id: rule.rule_id.clone(),
            });
        }
        validate_tool_matcher("tool_name", 64, rule.matcher.tool_name.as_deref())?;
        validate_tool_matcher("tool_rule_id", 128, rule.matcher.tool_rule_id.as_deref())?;
        match (&rule.matcher.category, &rule.matcher.micro_category) {
            (Some(category), Some(micro_category)) => {
                Taxonomy {
                    category: category.clone(),
                    micro_category: micro_category.clone(),
                }
                .validate()
                .map_err(|_| PolicyError::InvalidTaxonomyMatcher {
                    rule_id: rule.rule_id.clone(),
                })?;
            }
            (None, Some(_)) => {
                return Err(PolicyError::InvalidTaxonomyMatcher {
                    rule_id: rule.rule_id.clone(),
                });
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_tool_matcher(
    field: &'static str,
    max: usize,
    value: Option<&str>,
) -> Result<(), PolicyError> {
    if let Some(value) = value {
        let length = value.chars().count();
        if !(1..=max).contains(&length) || normalize_context(value) != value {
            return Err(PolicyError::InvalidToolMatcher {
                field,
                max,
                value: value.to_owned(),
            });
        }
    }
    Ok(())
}

/// An input waiver. Any invalid configured waiver rejects policy evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyWaiver {
    pub fingerprint: Fingerprint,
    pub waived_action: WaivedAction,
    pub reason: String,
    pub owner: String,
    pub expires_at: String,
}

impl PolicyWaiver {
    fn as_contract_waiver(&self) -> Waiver {
        Waiver {
            fingerprint: self.fingerprint.clone(),
            waived_action: self.waived_action.clone(),
            reason: self.reason.clone(),
            owner: self.owner.clone(),
            expires_at: self.expires_at.clone(),
        }
    }
}

/// Validate every configured waiver before evaluating a finding.
///
/// # Errors
///
/// Returns an indexed error when a waiver violates the v1 contract.
pub fn validate_waivers(waivers: &[PolicyWaiver]) -> Result<(), PolicyError> {
    for (index, waiver) in waivers.iter().enumerate() {
        waiver
            .as_contract_waiver()
            .validate()
            .map_err(|error| PolicyError::InvalidWaiver {
                index,
                reason: error.to_string(),
            })?;
    }
    Ok(())
}

/// Hash a canonical, order-independent policy snapshot.
///
/// # Errors
///
/// Returns an error for invalid policy input or failed canonical serialization.
pub fn policy_digest(
    rules: &[PolicyRule],
    waivers: &[PolicyWaiver],
) -> Result<Sha256Digest, PolicyError> {
    validate_policy(rules)?;
    validate_waivers(waivers)?;

    let mut canonical_rules = rules
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| PolicyError::Canonicalization {
            reason: error.to_string(),
        })?;
    let mut canonical_waivers = waivers
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| PolicyError::Canonicalization {
            reason: error.to_string(),
        })?;
    canonical_rules.sort();
    canonical_waivers.sort();

    let mut digest = Sha256::new();
    update_digest(&mut digest, POLICY_VERSION);
    for rule in &canonical_rules {
        update_digest(&mut digest, rule);
    }
    for waiver in &canonical_waivers {
        update_digest(&mut digest, waiver);
    }
    Sha256Digest::from_str(&format!("{:x}", digest.finalize())).map_err(|reason| {
        PolicyError::Canonicalization {
            reason: reason.into(),
        }
    })
}

/// The result of evaluating one Finding against one policy snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDecision {
    pub action: DecisionAction,
    pub matched_rule_id: String,
    pub waiver: Option<PolicyWaiver>,
}

/// Evaluate a Finding without mutating it or consulting external state.
///
/// Matching rules are reduced by action strength. Ties are selected by the
/// lexicographically smallest rule ID, making the result independent of input
/// rule order. A valid waiver changes WARN/BLOCK into WAIVE only when its
/// fingerprint, action, and expiry all match the evaluated Finding.
///
/// # Errors
///
/// Returns [`PolicyError`] when the supplied policy contains an invalid rule
/// ID or tool matcher.
pub fn evaluate_policy(
    finding: &Finding,
    rules: &[PolicyRule],
    waivers: &[PolicyWaiver],
    evaluation_time: &str,
) -> Result<PolicyDecision, PolicyError> {
    validate_finding_integrity(finding).map_err(|source| PolicyError::InvalidFinding { source })?;
    validate_policy(rules)?;
    validate_waivers(waivers)?;
    if !is_valid_rfc3339_datetime(evaluation_time) {
        return Err(PolicyError::InvalidEvaluationTime {
            value: evaluation_time.into(),
        });
    }
    let evaluation_instant =
        evaluation_time
            .parse::<Timestamp>()
            .map_err(|_| PolicyError::InvalidEvaluationTime {
                value: evaluation_time.into(),
            })?;
    let default = default_action(finding);
    let mut selected =
        (default == PolicyAction::Block).then(|| (default, default_rule_id(finding)));

    for rule in rules.iter().filter(|rule| rule.matcher.matches(finding)) {
        let should_select = selected.as_ref().is_none_or(|selected| {
            rule.action > selected.0 || (rule.action == selected.0 && rule.rule_id < selected.1)
        });
        if should_select {
            selected = Some((rule.action, rule.rule_id.clone()));
        }
    }
    let (action, matched_rule_id) =
        selected.unwrap_or((PolicyAction::Observe, DEFAULT_OBSERVE_RULE_ID.to_owned()));

    let waiver = action.can_be_waived_as_matching(finding, waivers, evaluation_instant);
    Ok(PolicyDecision {
        action: waiver
            .as_ref()
            .map_or_else(|| action.decision_action(), |_| DecisionAction::Waive),
        matched_rule_id,
        waiver,
    })
}

impl PolicyAction {
    fn can_be_waived_as_matching(
        self,
        finding: &Finding,
        waivers: &[PolicyWaiver],
        evaluation_instant: Timestamp,
    ) -> Option<PolicyWaiver> {
        waivers
            .iter()
            .filter(|waiver| {
                waiver.fingerprint == finding.fingerprint
                    && !waiver.reason.is_empty()
                    && !waiver.owner.is_empty()
                    && self.can_be_waived_as(waiver.waived_action.clone())
            })
            .filter_map(|waiver| {
                let expiry = waiver.expires_at.parse::<Timestamp>().ok()?;
                (expiry > evaluation_instant).then_some((expiry, waiver))
            })
            .min_by(|(left_expiry, left), (right_expiry, right)| {
                left_expiry
                    .cmp(right_expiry)
                    .then_with(|| left.reason.cmp(&right.reason))
                    .then_with(|| left.owner.cmp(&right.owner))
                    .then_with(|| left.expires_at.cmp(&right.expires_at))
            })
            .map(|(_, waiver)| waiver.clone())
    }
}

/// Materialize a contract Decision with a deterministic v1 object ID.
///
/// # Errors
///
/// Returns an error when policy validation, evaluation, hashing, or Decision
/// construction violates a v1 invariant.
pub fn build_decision(
    finding: &Finding,
    rules: &[PolicyRule],
    waivers: &[PolicyWaiver],
    evaluation_time: &str,
) -> Result<Decision, PolicyError> {
    let policy_digest = policy_digest(rules, waivers)?;
    let evaluated = evaluate_policy(finding, rules, waivers, evaluation_time)?;
    let action = action_wire(&evaluated.action);
    let waiver = evaluated.waiver.map(|waiver| waiver.as_contract_waiver());
    let decision_id = decision_id_from_fields(
        &finding.finding_id,
        &policy_digest,
        &evaluated.matched_rule_id,
        action,
        waiver.as_ref(),
    )
    .map_err(|error| PolicyError::Canonicalization {
        reason: error.to_string(),
    })?;
    let decision = Decision {
        schema_version: DecisionSchemaVersion::V1,
        decision_id,
        finding_id: finding.finding_id.clone(),
        action: evaluated.action,
        policy_digest,
        matched_rule_id: evaluated.matched_rule_id,
        waiver,
    };
    decision
        .validate()
        .map_err(|error| PolicyError::Canonicalization {
            reason: error.to_string(),
        })?;
    Ok(decision)
}

/// Derive the Engine-owned Decision ID from its policy result.
///
/// # Errors
///
/// Returns an error when the Decision contract or deterministic ID derivation
/// fails.
pub fn decision_id_for_decision(decision: &Decision) -> Result<ObjectId, EngineError> {
    decision.validate()?;
    decision_id_from_fields(
        &decision.finding_id,
        &decision.policy_digest,
        &decision.matched_rule_id,
        action_wire(&decision.action),
        decision.waiver.as_ref(),
    )
}

/// Reject a Decision whose stored ID is not the Engine-owned derivation.
///
/// # Errors
///
/// Returns an error when the Decision contract is invalid or its ID differs
/// from the deterministic v1 value.
pub fn validate_decision_integrity(decision: &Decision) -> Result<(), EngineError> {
    let expected_id = decision_id_for_decision(decision)?;
    if decision.decision_id != expected_id {
        return Err(EngineError::DecisionIdMismatch {
            decision_id: decision.decision_id.to_string(),
            expected_id: expected_id.to_string(),
        });
    }
    Ok(())
}

fn decision_id_from_fields(
    finding_id: &ObjectId,
    policy_digest: &Sha256Digest,
    matched_rule_id: &str,
    action: &str,
    waiver: Option<&Waiver>,
) -> Result<ObjectId, EngineError> {
    let waiver_identity =
        serde_json::to_string(&waiver).map_err(|error| EngineError::IdentityEncoding {
            object: "decision waiver",
            reason: error.to_string(),
        })?;
    deterministic_object_id(
        "diagnostic-triage.decision-id/v1",
        [
            finding_id.as_str(),
            policy_digest.as_str(),
            matched_rule_id,
            action,
            waiver_identity.as_str(),
        ],
    )
}

fn update_digest(digest: &mut Sha256, value: &str) {
    let length = u64::try_from(value.len()).expect("a Rust string length fits in u64");
    digest.update(length.to_be_bytes());
    digest.update(value.as_bytes());
}

const fn action_wire(action: &DecisionAction) -> &'static str {
    match action {
        DecisionAction::Observe => "OBSERVE",
        DecisionAction::Warn => "WARN",
        DecisionAction::Block => "BLOCK",
        DecisionAction::Waive => "WAIVE",
    }
}

fn default_action(finding: &Finding) -> PolicyAction {
    if finding.severity == Severity::Error
        && matches!(
            finding.classification.category,
            Category::Syntax
                | Category::Type
                | Category::Correctness
                | Category::Build
                | Category::Test
        )
    {
        PolicyAction::Block
    } else {
        PolicyAction::Observe
    }
}

fn default_rule_id(finding: &Finding) -> String {
    if default_action(finding) == PolicyAction::Block {
        DEFAULT_RULE_ID.to_owned()
    } else {
        DEFAULT_OBSERVE_RULE_ID.to_owned()
    }
}
