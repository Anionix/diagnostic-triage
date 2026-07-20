//! Bounded, deterministic evaluation of consumer-owned policy.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use diagnostic_triage_contracts::model::{
    Category, Decision, DecisionAction, DecisionSchemaVersion, Finding, FindingState,
    MicroCategory, PreReportState, Severity, Taxonomy, WaivedAction, Waiver,
    is_valid_rfc3339_datetime,
};
use diagnostic_triage_contracts::{Fingerprint, Language, ObjectId, Sha256Digest};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::finding::validate_finding_integrity;
use crate::normalize::collapse_whitespace;
use crate::{EngineError, deterministic_object_id};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// Maximum number of consumer policy rules accepted by v1.
pub const MAX_POLICY_RULES: usize = 4096;
/// Maximum number of configured waivers accepted by v1.
pub const MAX_POLICY_WAIVERS: usize = 10_000;

const DEFAULT_OBSERVE_RULE_ID: &str = "default.observe";
const DEFAULT_ERROR_SYNTAX_RULE_ID: &str = "default.error.syntax";
const DEFAULT_ERROR_TYPE_RULE_ID: &str = "default.error.type";
const DEFAULT_ERROR_CORRECTNESS_RULE_ID: &str = "default.error.correctness";
const DEFAULT_ERROR_BUILD_RULE_ID: &str = "default.error.build";
const DEFAULT_ERROR_TEST_RULE_ID: &str = "default.error.test";
const POLICY_DIGEST_DOMAIN: &str = "diagnostic-triage.policy/v1";

/// The v1 enforcement ordering is `OBSERVE < WARN < BLOCK`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PolicyAction {
    Observe,
    Warn,
    Block,
}

impl PolicyAction {
    const fn as_decision_action(self) -> DecisionAction {
        match self {
            Self::Observe => DecisionAction::Observe,
            Self::Warn => DecisionAction::Warn,
            Self::Block => DecisionAction::Block,
        }
    }

    const fn can_be_waived_by(self, waived_action: &WaivedAction) -> bool {
        matches!(
            (self, waived_action),
            (Self::Warn, WaivedAction::Warn) | (Self::Block, WaivedAction::Block)
        )
    }
}

/// Optional structured selectors used by a consumer policy rule.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyMatcher {
    pub severity: Option<Severity>,
    pub category: Option<Category>,
    pub micro_category: Option<MicroCategory>,
    pub fingerprint: Option<Fingerprint>,
    pub language: Option<Language>,
    /// Matches the Provider tool name, excluding its version.
    pub tool_name: Option<String>,
    /// Matches the Provider tool version as an opaque, case-sensitive value.
    pub tool_version: Option<String>,
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
                .is_none_or(|tool_name| tool_name == finding.tool.name.as_str())
            && self
                .tool_version
                .as_deref()
                .is_none_or(|tool_version| tool_version == finding.tool.version.as_str())
            && self
                .tool_rule_id
                .as_deref()
                .is_none_or(|rule_id| finding.tool.rule_id.as_deref() == Some(rule_id))
    }
}

/// One consumer-owned policy rule.
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

/// A consumer-owned waiver. Invalid or expired waivers never suppress policy.
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

/// Typed failures at the policy boundary.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy contains {actual} rules, exceeding the v1 limit of {max}")]
    RuleLimit { actual: usize, max: usize },
    #[error("policy contains {actual} waivers, exceeding the v1 limit of {max}")]
    WaiverLimit { actual: usize, max: usize },
    #[error("policy rule ID must contain 1..=128 characters, got {length}")]
    InvalidRuleId { length: usize },
    #[error("policy rule ID is not in canonical whitespace form: {rule_id:?}")]
    NonCanonicalRuleId { rule_id: String },
    #[error("policy rule ID is duplicated: {rule_id}")]
    DuplicateRuleId { rule_id: String },
    #[error("policy rule ID is reserved by the v1 engine: {rule_id}")]
    ReservedRuleId { rule_id: String },
    #[error(
        "policy matcher {field} must be canonical and contain 1..={max} characters, got {length}"
    )]
    InvalidToolMatcher {
        field: &'static str,
        max: usize,
        length: usize,
    },
    #[error("policy rule {rule_id} contains an invalid taxonomy matcher")]
    InvalidTaxonomyMatcher { rule_id: String },
    #[error("policy waiver {index} is invalid: {reason}")]
    InvalidWaiver { index: usize, reason: String },
    #[error("policy waiver {index} duplicates waiver {first_index}")]
    DuplicateWaiver { first_index: usize, index: usize },
    #[error("policy evaluation time is not in the v1 RFC 3339 profile")]
    InvalidEvaluationTime,
    #[error("finding is invalid for policy evaluation")]
    InvalidFinding {
        #[source]
        source: EngineError,
    },
    #[error("finding lifecycle state {state:?} cannot be policy-evaluated")]
    InvalidFindingLifecycle { state: FindingState },
    #[error("policy canonicalization failed: {reason}")]
    Canonicalization { reason: String },
    #[error("decision construction failed")]
    DecisionConstruction {
        #[source]
        source: EngineError,
    },
}

/// A validated policy snapshot whose digest can be reused for many Findings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicySnapshot {
    rules: Vec<PolicyRule>,
    waivers: Vec<PolicyWaiver>,
    digest: Sha256Digest,
}

impl PolicySnapshot {
    /// Validate, bound, and canonicalize one policy snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] before retaining invalid or oversized policy.
    pub fn new(rules: &[PolicyRule], waivers: &[PolicyWaiver]) -> Result<Self, PolicyError> {
        validate_snapshot_limits(rules.len(), waivers.len())?;
        validate_policy(rules)?;
        validate_waivers(waivers)?;
        let digest = digest_validated_policy(rules, waivers)?;

        let mut canonical_rules = rules.to_vec();
        canonical_rules.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
        let mut canonical_waivers = waivers.to_vec();
        canonical_waivers.sort_by(waiver_canonical_cmp);

        Ok(Self {
            rules: canonical_rules,
            waivers: canonical_waivers,
            digest,
        })
    }

    /// Return the canonical digest bound to Decisions from this snapshot.
    #[must_use]
    pub const fn digest(&self) -> &Sha256Digest {
        &self.digest
    }

    /// Evaluate one valid Finding without filesystem or process access.
    ///
    /// # Errors
    ///
    /// Returns an error for forged Finding identity or an invalid evaluation time.
    pub fn evaluate(
        &self,
        finding: &Finding,
        evaluation_time: &str,
    ) -> Result<PolicyDecision, PolicyError> {
        validate_policy_finding(finding)?;
        self.evaluate_validated(finding, evaluation_time)
    }

    fn evaluate_validated(
        &self,
        finding: &Finding,
        evaluation_time: &str,
    ) -> Result<PolicyDecision, PolicyError> {
        let evaluation_instant = parse_evaluation_time(evaluation_time)?;

        let baseline = default_action(finding);
        let selected_rule = self
            .rules
            .iter()
            .filter(|rule| rule.matcher.matches(finding))
            .max_by(|left, right| {
                left.action
                    .cmp(&right.action)
                    .then_with(|| right.rule_id.cmp(&left.rule_id))
            });
        let (action, matched_rule_id) = selected_rule
            .filter(|rule| rule.action >= baseline)
            .map_or_else(
                || (baseline, default_rule_id(finding, baseline).to_owned()),
                |rule| (rule.action, rule.rule_id.clone()),
            );

        let waiver = matching_waiver(
            action,
            &finding.fingerprint,
            &self.waivers,
            evaluation_instant,
        );
        Ok(PolicyDecision {
            action: waiver
                .as_ref()
                .map_or_else(|| action.as_decision_action(), |_| DecisionAction::Waive),
            matched_rule_id,
            waiver,
        })
    }

    /// Build one deterministic contract Decision from this snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid policy input, Finding identity, time, or Decision identity.
    pub fn build_decision(
        &self,
        finding: &Finding,
        evaluation_time: &str,
    ) -> Result<Decision, PolicyError> {
        validate_policy_finding(finding)?;
        self.build_decision_validated(finding, evaluation_time)
    }

    fn build_decision_validated(
        &self,
        finding: &Finding,
        evaluation_time: &str,
    ) -> Result<Decision, PolicyError> {
        let evaluated = self.evaluate_validated(finding, evaluation_time)?;
        let waiver = evaluated
            .waiver
            .as_ref()
            .map(PolicyWaiver::as_contract_waiver);
        let decision_id = decision_id_from_fields(
            &finding.finding_id,
            &self.digest,
            &evaluated.matched_rule_id,
            action_wire(&evaluated.action),
            evaluation_time,
            waiver.as_ref(),
        )
        .map_err(|source| PolicyError::DecisionConstruction { source })?;
        let decision = Decision {
            schema_version: DecisionSchemaVersion::V1,
            decision_id,
            finding_id: finding.finding_id.clone(),
            action: evaluated.action,
            evaluated_at: evaluation_time.to_owned(),
            policy_digest: self.digest.clone(),
            matched_rule_id: evaluated.matched_rule_id,
            waiver,
        };
        decision
            .validate()
            .map_err(EngineError::from)
            .map_err(|source| PolicyError::DecisionConstruction { source })?;
        Ok(decision)
    }
}

/// The selected action, rule attribution, and optional active waiver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDecision {
    pub action: DecisionAction,
    pub matched_rule_id: String,
    pub waiver: Option<PolicyWaiver>,
}

/// Validate all policy rules, including rules that do not match a Finding.
///
/// # Errors
///
/// Returns a typed configuration error for any invalid or oversized catalog.
pub fn validate_policy(rules: &[PolicyRule]) -> Result<(), PolicyError> {
    validate_rule_limit(rules.len())?;

    let mut rule_ids = BTreeSet::new();
    for rule in rules {
        let id_length = rule.rule_id.chars().count();
        if !(1..=128).contains(&id_length) {
            return Err(PolicyError::InvalidRuleId { length: id_length });
        }
        if collapse_whitespace(&rule.rule_id) != rule.rule_id {
            return Err(PolicyError::NonCanonicalRuleId {
                rule_id: rule.rule_id.clone(),
            });
        }
        if is_reserved_rule_id(&rule.rule_id) {
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
        validate_tool_matcher("tool_version", 64, rule.matcher.tool_version.as_deref())?;
        validate_tool_matcher("tool_rule_id", 128, rule.matcher.tool_rule_id.as_deref())?;
        match (&rule.matcher.category, &rule.matcher.micro_category) {
            (Some(category), Some(micro_category)) => Taxonomy {
                category: category.clone(),
                micro_category: micro_category.clone(),
            }
            .validate()
            .map_err(|_| PolicyError::InvalidTaxonomyMatcher {
                rule_id: rule.rule_id.clone(),
            })?,
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

/// Validate all configured waivers, including waivers unrelated to a Finding.
///
/// # Errors
///
/// Returns a typed configuration error for any invalid or oversized waiver set.
pub fn validate_waivers(waivers: &[PolicyWaiver]) -> Result<(), PolicyError> {
    validate_waiver_limit(waivers.len())?;
    let mut identities = BTreeMap::new();
    for (index, waiver) in waivers.iter().enumerate() {
        validate_waiver_text(index, "reason", &waiver.reason, 2048)?;
        validate_waiver_text(index, "owner", &waiver.owner, 256)?;
        if !is_valid_rfc3339_datetime(&waiver.expires_at) {
            return Err(PolicyError::InvalidWaiver {
                index,
                reason: "expires_at is not in the v1 RFC 3339 profile".to_owned(),
            });
        }
        let identity = (
            waiver.fingerprint.as_str(),
            action_wire_waived(&waiver.waived_action),
            waiver.reason.as_str(),
            waiver.owner.as_str(),
            waiver.expires_at.as_str(),
        );
        if let Some(first_index) = identities.insert(identity, index) {
            return Err(PolicyError::DuplicateWaiver { first_index, index });
        }
    }
    Ok(())
}

/// Hash an order-independent, versioned policy snapshot.
///
/// # Errors
///
/// Returns an error for invalid input or failed canonical serialization.
pub fn policy_digest(
    rules: &[PolicyRule],
    waivers: &[PolicyWaiver],
) -> Result<Sha256Digest, PolicyError> {
    validate_snapshot_limits(rules.len(), waivers.len())?;
    validate_policy(rules)?;
    validate_waivers(waivers)?;
    digest_validated_policy(rules, waivers)
}

/// Evaluate one Finding with a one-shot policy snapshot.
///
/// Prefer [`PolicySnapshot`] when evaluating multiple Findings.
///
/// # Errors
///
/// Returns a typed policy, Finding, or timestamp error.
pub fn evaluate_policy(
    finding: &Finding,
    rules: &[PolicyRule],
    waivers: &[PolicyWaiver],
    evaluation_time: &str,
) -> Result<PolicyDecision, PolicyError> {
    validate_snapshot_limits(rules.len(), waivers.len())?;
    validate_policy_finding(finding)?;
    PolicySnapshot::new(rules, waivers)?.evaluate_validated(finding, evaluation_time)
}

/// Build one deterministic Decision with a one-shot policy snapshot.
///
/// Prefer [`PolicySnapshot`] when building multiple Decisions.
///
/// # Errors
///
/// Returns a typed policy, Finding, timestamp, or identity error.
pub fn build_decision(
    finding: &Finding,
    rules: &[PolicyRule],
    waivers: &[PolicyWaiver],
    evaluation_time: &str,
) -> Result<Decision, PolicyError> {
    validate_snapshot_limits(rules.len(), waivers.len())?;
    validate_policy_finding(finding)?;
    PolicySnapshot::new(rules, waivers)?.build_decision_validated(finding, evaluation_time)
}

fn validate_snapshot_limits(rule_count: usize, waiver_count: usize) -> Result<(), PolicyError> {
    validate_rule_limit(rule_count)?;
    validate_waiver_limit(waiver_count)
}

fn validate_rule_limit(actual: usize) -> Result<(), PolicyError> {
    if actual > MAX_POLICY_RULES {
        Err(PolicyError::RuleLimit {
            actual,
            max: MAX_POLICY_RULES,
        })
    } else {
        Ok(())
    }
}

fn validate_waiver_limit(actual: usize) -> Result<(), PolicyError> {
    if actual > MAX_POLICY_WAIVERS {
        Err(PolicyError::WaiverLimit {
            actual,
            max: MAX_POLICY_WAIVERS,
        })
    } else {
        Ok(())
    }
}

/// Derive the Engine-owned Decision ID from its policy result.
///
/// # Errors
///
/// Returns an error when the Decision contract or deterministic encoding is invalid.
pub fn decision_id_for_decision(decision: &Decision) -> Result<ObjectId, EngineError> {
    decision.validate()?;
    decision_id_from_fields(
        &decision.finding_id,
        &decision.policy_digest,
        &decision.matched_rule_id,
        action_wire(&decision.action),
        &decision.evaluated_at,
        decision.waiver.as_ref(),
    )
}

/// Reject a Decision whose stored ID is not the Engine-owned derivation.
///
/// # Errors
///
/// Returns an error for an invalid Decision contract or forged Decision ID.
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

fn validate_tool_matcher(
    field: &'static str,
    max: usize,
    value: Option<&str>,
) -> Result<(), PolicyError> {
    if let Some(value) = value {
        let length = value.chars().count();
        if !(1..=max).contains(&length) || collapse_whitespace(value) != value {
            return Err(PolicyError::InvalidToolMatcher { field, max, length });
        }
    }
    Ok(())
}

fn validate_waiver_text(
    index: usize,
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), PolicyError> {
    let length = value.chars().count();
    if !(1..=max).contains(&length) {
        return Err(PolicyError::InvalidWaiver {
            index,
            reason: format!("{field} must contain 1..={max} characters, got {length}"),
        });
    }
    if collapse_whitespace(value) != value {
        return Err(PolicyError::InvalidWaiver {
            index,
            reason: format!("{field} is not in canonical whitespace form"),
        });
    }
    Ok(())
}

fn validate_policy_finding(finding: &Finding) -> Result<(), PolicyError> {
    validate_finding_integrity(finding).map_err(|source| PolicyError::InvalidFinding { source })?;
    let effective_state = match finding.pre_report_state {
        Some(PreReportState::Classified) => FindingState::Classified,
        Some(PreReportState::FixProposed) => FindingState::FixProposed,
        Some(PreReportState::Verified) => FindingState::Verified,
        None => finding.state,
    };
    if matches!(
        effective_state,
        FindingState::Discovered | FindingState::Normalized
    ) {
        return Err(PolicyError::InvalidFindingLifecycle {
            state: effective_state,
        });
    }
    Ok(())
}

fn is_reserved_rule_id(rule_id: &str) -> bool {
    matches!(
        rule_id,
        DEFAULT_OBSERVE_RULE_ID
            | DEFAULT_ERROR_SYNTAX_RULE_ID
            | DEFAULT_ERROR_TYPE_RULE_ID
            | DEFAULT_ERROR_CORRECTNESS_RULE_ID
            | DEFAULT_ERROR_BUILD_RULE_ID
            | DEFAULT_ERROR_TEST_RULE_ID
    )
}

fn digest_validated_policy(
    rules: &[PolicyRule],
    waivers: &[PolicyWaiver],
) -> Result<Sha256Digest, PolicyError> {
    let mut canonical_rules = canonical_json_values(rules)?;
    let mut canonical_waivers = canonical_json_values(waivers)?;
    canonical_rules.sort_unstable();
    canonical_waivers.sort_unstable();

    let mut digest = Sha256::new();
    update_digest(&mut digest, POLICY_DIGEST_DOMAIN);
    update_digest(&mut digest, "rules");
    update_digest(&mut digest, &rules.len().to_string());
    for rule in &canonical_rules {
        update_digest(&mut digest, rule);
    }
    update_digest(&mut digest, "waivers");
    update_digest(&mut digest, &waivers.len().to_string());
    for waiver in &canonical_waivers {
        update_digest(&mut digest, waiver);
    }

    Sha256Digest::from_str(&format!("{:x}", digest.finalize())).map_err(|reason| {
        PolicyError::Canonicalization {
            reason: reason.to_owned(),
        }
    })
}

fn canonical_json_values<T: Serialize>(values: &[T]) -> Result<Vec<String>, PolicyError> {
    values
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| PolicyError::Canonicalization {
            reason: error.to_string(),
        })
}

fn update_digest(digest: &mut Sha256, value: &str) {
    let length = u64::try_from(value.len()).expect("a Rust string length fits in u64");
    digest.update(length.to_be_bytes());
    digest.update(value.as_bytes());
}

fn parse_evaluation_time(value: &str) -> Result<Timestamp, PolicyError> {
    if !is_valid_rfc3339_datetime(value) {
        return Err(PolicyError::InvalidEvaluationTime);
    }
    value
        .parse::<Timestamp>()
        .map_err(|_| PolicyError::InvalidEvaluationTime)
}

fn matching_waiver(
    action: PolicyAction,
    fingerprint: &Fingerprint,
    waivers: &[PolicyWaiver],
    evaluation_instant: Timestamp,
) -> Option<PolicyWaiver> {
    waivers
        .iter()
        .filter(|waiver| {
            waiver.fingerprint == *fingerprint && action.can_be_waived_by(&waiver.waived_action)
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

fn waiver_canonical_cmp(left: &PolicyWaiver, right: &PolicyWaiver) -> std::cmp::Ordering {
    left.fingerprint
        .cmp(&right.fingerprint)
        .then_with(|| {
            action_wire_waived(&left.waived_action).cmp(action_wire_waived(&right.waived_action))
        })
        .then_with(|| left.reason.cmp(&right.reason))
        .then_with(|| left.owner.cmp(&right.owner))
        .then_with(|| left.expires_at.cmp(&right.expires_at))
}

fn decision_id_from_fields(
    finding_id: &ObjectId,
    policy_digest: &Sha256Digest,
    matched_rule_id: &str,
    action: &str,
    evaluated_at: &str,
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
            evaluated_at,
            waiver_identity.as_str(),
        ],
    )
}

const fn action_wire(action: &DecisionAction) -> &'static str {
    match action {
        DecisionAction::Observe => "OBSERVE",
        DecisionAction::Warn => "WARN",
        DecisionAction::Block => "BLOCK",
        DecisionAction::Waive => "WAIVE",
    }
}

const fn action_wire_waived(action: &WaivedAction) -> &'static str {
    match action {
        WaivedAction::Warn => "WARN",
        WaivedAction::Block => "BLOCK",
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

const fn default_rule_id(finding: &Finding, action: PolicyAction) -> &'static str {
    match action {
        PolicyAction::Observe | PolicyAction::Warn => DEFAULT_OBSERVE_RULE_ID,
        PolicyAction::Block => match finding.classification.category {
            Category::Syntax => DEFAULT_ERROR_SYNTAX_RULE_ID,
            Category::Type => DEFAULT_ERROR_TYPE_RULE_ID,
            Category::Correctness => DEFAULT_ERROR_CORRECTNESS_RULE_ID,
            Category::Build => DEFAULT_ERROR_BUILD_RULE_ID,
            Category::Test => DEFAULT_ERROR_TEST_RULE_ID,
            _ => DEFAULT_OBSERVE_RULE_ID,
        },
    }
}
