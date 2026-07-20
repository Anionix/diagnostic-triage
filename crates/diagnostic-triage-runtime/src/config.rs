//! Strict TOML configuration for the Diagnostic Triage runtime.

use std::collections::BTreeSet;

use diagnostic_triage_contracts::model::{Origin, Taxonomy};
use diagnostic_triage_contracts::{
    AdapterId, Capability, ContractError, Language, RepoPath, SourceRevision,
};
use diagnostic_triage_engine::classification::{
    ClassificationRule, MAX_CLASSIFICATION_RULES, RuleIdSelector,
};
use diagnostic_triage_engine::policy::{PolicyError, PolicyRule, PolicySnapshot, PolicyWaiver};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::process::{ProcessError, ProcessLimits, ProcessSpec};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// The v1 runtime timeout ceiling and default, in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u64 = 600_000;
/// The v1 provider stdout ceiling and default, in bytes.
pub const DEFAULT_MAX_STDOUT_BYTES: u64 = 16 * 1024 * 1024;
/// The v1 provider stderr ceiling and default, in bytes.
pub const DEFAULT_MAX_STDERR_BYTES: u64 = 4 * 1024 * 1024;
/// The v1 Evidence ceiling and default, in bytes.
pub const DEFAULT_MAX_EVIDENCE_BYTES: u64 = 1024 * 1024;
/// The v1 provider event ceiling and default.
pub const DEFAULT_MAX_EVENTS: u64 = 10_000;

/// Errors raised while parsing or validating runtime configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration TOML could not be parsed")]
    Parse(#[from] toml::de::Error),
    #[error("invalid configuration field {field}: {reason}")]
    Invalid { field: String, reason: String },
    #[error("classification rule {rule_id} is invalid: {reason}")]
    InvalidClassificationRule { rule_id: String, reason: String },
    #[error("configuration taxonomy is invalid")]
    Taxonomy(#[from] ContractError),
    #[error("policy configuration is invalid")]
    Policy(#[from] PolicyError),
    #[error("process configuration is invalid")]
    Process(#[from] ProcessError),
}

/// Complete runtime configuration loaded from `diagnostic-triage.toml`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub engine: EngineConfig,
    pub repository: RepositoryConfig,
    pub providers: Vec<ProviderConfig>,
    #[serde(default)]
    pub limits: RuntimeLimits,
    #[serde(default)]
    pub classification: ClassificationConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub output: OutputConfig,
}

impl RuntimeConfig {
    /// Parse and validate one complete TOML configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when TOML is malformed or any configured value
    /// violates the runtime or Engine boundary.
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let mut config = toml::from_str::<Self>(input)?;
        config.normalize_and_validate()?;
        Ok(config)
    }

    /// Validate a configuration assembled by Rust code.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when any configured value violates the runtime
    /// or Engine boundary.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut normalized = self.clone();
        normalized.normalize_and_validate()
    }

    /// Build the Engine-owned, validated policy snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when runtime or policy validation fails.
    pub fn policy_snapshot(&self) -> Result<PolicySnapshot, ConfigError> {
        let mut normalized = self.clone();
        normalized.normalize_and_validate()?;
        Ok(PolicySnapshot::new(
            &normalized.policy.rules,
            &normalized.policy.waivers,
        )?)
    }

    /// Convert classification wire rules to the Engine's classification rules.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when runtime or classification validation fails.
    pub fn classification_rules(&self) -> Result<Vec<ClassificationRule>, ConfigError> {
        let mut normalized = self.clone();
        normalized.normalize_and_validate()?;
        normalized
            .classification
            .rules
            .iter()
            .map(ClassificationRuleConfig::to_engine)
            .collect()
    }

    /// Build the validated protocol limits used in adapter request envelopes.
    ///
    /// The returned value preserves all five configured limits. The complete
    /// runtime configuration is normalized and validated before conversion.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when runtime configuration or its limits are
    /// invalid.
    pub fn request_limits(
        &self,
    ) -> Result<diagnostic_triage_contracts::protocol::RequestLimits, ConfigError> {
        let mut normalized = self.clone();
        normalized.normalize_and_validate()?;
        (&normalized.limits).try_into()
    }

    /// Build the checked process limits for one direct child invocation.
    ///
    /// Protocol evidence and event ceilings are retained by
    /// [`Self::request_limits`]; the process executor consumes its checked
    /// timeout and stdout/stderr subset.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when runtime configuration or process limits
    /// are invalid.
    pub fn process_limits(&self) -> Result<ProcessLimits, ConfigError> {
        let request_limits = self.request_limits()?;
        Ok(ProcessLimits::try_from(&request_limits)?)
    }

    /// Build a direct, shell-free process specification for one configured
    /// adapter.
    ///
    /// The provider's program and argv are copied without parsing or joining.
    /// This method intentionally does not resolve `repository.workspace` or
    /// set `current_dir`: callers must resolve that validated [`RepoPath`]
    /// beneath a trusted repository root before applying
    /// [`ProcessSpec::current_dir`].
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when runtime configuration is invalid or the
    /// requested adapter is not configured.
    pub fn process_spec(&self, adapter_id: &AdapterId) -> Result<ProcessSpec, ConfigError> {
        let mut normalized = self.clone();
        normalized.normalize_and_validate()?;
        let provider = normalized
            .providers
            .iter()
            .find(|provider| provider.adapter_id == *adapter_id)
            .ok_or_else(|| {
                invalid(
                    "adapter_id",
                    &format!("unknown configured adapter {}", adapter_id.as_str()),
                )
            })?;
        Ok(ProcessSpec::new(provider.program.clone()).args(provider.argv.clone()))
    }

    fn normalize_and_validate(&mut self) -> Result<(), ConfigError> {
        validate_text("engine.version", &self.engine.version, 1, 64)?;
        if self.repository.targets.is_empty() {
            return Err(invalid(
                "repository.targets",
                "must contain at least one target",
            ));
        }
        if self.repository.targets.len() > 256 {
            return Err(invalid(
                "repository.targets",
                "must contain at most 256 targets",
            ));
        }
        let mut target_set = BTreeSet::new();
        for target in &self.repository.targets {
            if !target_set.insert(target.as_str()) {
                return Err(invalid(
                    "repository.targets",
                    "must not contain duplicate paths",
                ));
            }
        }
        self.repository.targets.sort();

        if self.providers.is_empty() {
            return Err(invalid("providers", "must contain at least one provider"));
        }
        if self.providers.len() > 64 {
            return Err(invalid("providers", "must contain at most 64 providers"));
        }
        let mut provider_ids = BTreeSet::new();
        for provider in &mut self.providers {
            provider.normalize_and_validate()?;
            if !provider_ids.insert(provider.adapter_id.as_str()) {
                return Err(invalid("providers", "adapter_id must be unique"));
            }
        }
        if !self.providers.iter().any(|provider| provider.required) {
            return Err(invalid(
                "providers",
                "must contain at least one required provider",
            ));
        }
        self.providers
            .sort_by(|left, right| left.adapter_id.cmp(&right.adapter_id));
        self.limits.validate()?;
        self.output.validate()?;
        self.classification.validate()?;
        let _ = PolicySnapshot::new(&self.policy.rules, &self.policy.waivers)?;
        self.policy
            .rules
            .sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
        self.policy.waivers.sort_by(policy_waiver_canonical_cmp);
        Ok(())
    }
}

/// Engine identity recorded in every report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineConfig {
    pub version: String,
    pub source_revision: SourceRevision,
}

/// Repository-relative runtime inputs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryConfig {
    pub workspace: RepoPath,
    pub targets: Vec<RepoPath>,
}

/// An executable invocation. `program` is passed directly to `Command`; it is
/// never parsed as a shell command and `argv` is never joined into a string.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub adapter_id: AdapterId,
    pub program: String,
    #[serde(default)]
    pub argv: Vec<String>,
    pub required: bool,
    #[serde(default)]
    pub required_capabilities: Vec<Capability>,
    #[serde(default)]
    pub optional_capabilities: Vec<Capability>,
}

impl ProviderConfig {
    fn normalize_and_validate(&mut self) -> Result<(), ConfigError> {
        if self.program.trim().is_empty() || self.program.trim() != self.program {
            return Err(invalid(
                "providers.program",
                "must not be empty or have surrounding whitespace",
            ));
        }
        if self.program.chars().count() > 4096 {
            return Err(invalid(
                "providers.program",
                "must contain at most 4096 characters",
            ));
        }
        validate_no_nul("providers.program", &self.program)?;
        if self.argv.len() > 256 {
            return Err(invalid(
                "providers.argv",
                "must contain at most 256 arguments",
            ));
        }
        let mut argv_bytes = 0_usize;
        for (index, argument) in self.argv.iter().enumerate() {
            validate_no_nul(&format!("providers.argv[{index}]"), argument)?;
            if argument.chars().count() > 4096 {
                return Err(invalid(
                    &format!("providers.argv[{index}]"),
                    "must contain at most 4096 characters",
                ));
            }
            argv_bytes = argv_bytes
                .checked_add(argument.len())
                .ok_or_else(|| invalid("providers.argv", "aggregate byte count overflowed"))?;
        }
        if argv_bytes > 64 * 1024 {
            return Err(invalid(
                "providers.argv",
                "aggregate byte count must not exceed 65536",
            ));
        }
        validate_capabilities(&self.required_capabilities, &self.optional_capabilities)?;
        self.required_capabilities.sort();
        self.optional_capabilities.sort();
        Ok(())
    }
}

/// Bounded process and event limits.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLimits {
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_stdout_bytes")]
    pub max_stdout_bytes: u64,
    #[serde(default = "default_max_stderr_bytes")]
    pub max_stderr_bytes: u64,
    #[serde(default = "default_max_evidence_bytes")]
    pub max_evidence_bytes: u64,
    #[serde(default = "default_max_events")]
    pub max_events: u64,
}

impl Default for RuntimeLimits {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_TIMEOUT_MS,
            max_stdout_bytes: DEFAULT_MAX_STDOUT_BYTES,
            max_stderr_bytes: DEFAULT_MAX_STDERR_BYTES,
            max_evidence_bytes: DEFAULT_MAX_EVIDENCE_BYTES,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }
}

impl RuntimeLimits {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_nonzero_limit("limits.timeout_ms", self.timeout_ms, DEFAULT_TIMEOUT_MS)?;
        validate_ceiling(
            "limits.max_stdout_bytes",
            self.max_stdout_bytes,
            DEFAULT_MAX_STDOUT_BYTES,
        )?;
        validate_ceiling(
            "limits.max_stderr_bytes",
            self.max_stderr_bytes,
            DEFAULT_MAX_STDERR_BYTES,
        )?;
        validate_ceiling(
            "limits.max_evidence_bytes",
            self.max_evidence_bytes,
            DEFAULT_MAX_EVIDENCE_BYTES,
        )?;
        validate_ceiling("limits.max_events", self.max_events, DEFAULT_MAX_EVENTS)
    }
}

impl TryFrom<&RuntimeLimits> for diagnostic_triage_contracts::protocol::RequestLimits {
    type Error = ConfigError;

    fn try_from(value: &RuntimeLimits) -> Result<Self, Self::Error> {
        value.validate()?;
        Ok(Self {
            timeout_ms: value.timeout_ms,
            max_stdout_bytes: value.max_stdout_bytes,
            max_stderr_bytes: value.max_stderr_bytes,
            max_evidence_bytes: value.max_evidence_bytes,
            max_events: value.max_events,
        })
    }
}

/// Policy-independent classification catalog supplied by the repository.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassificationConfig {
    #[serde(default)]
    pub rules: Vec<ClassificationRuleConfig>,
}

impl ClassificationConfig {
    fn validate(&mut self) -> Result<(), ConfigError> {
        if self.rules.len() > MAX_CLASSIFICATION_RULES {
            return Err(invalid(
                "classification.rules",
                "exceeds the Engine classification rule limit",
            ));
        }
        let mut rule_ids = BTreeSet::new();
        for rule in &self.rules {
            rule.validate()?;
            if !rule_ids.insert(rule.id.as_str()) {
                return Err(ConfigError::InvalidClassificationRule {
                    rule_id: rule.id.clone(),
                    reason: "rule ID is duplicated".to_owned(),
                });
            }
        }
        self.rules.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(())
    }
}

/// One TOML classification rule.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassificationRuleConfig {
    pub id: String,
    pub tool_name: String,
    #[serde(default)]
    pub tool_version: Option<String>,
    #[serde(default)]
    pub native_rule_id: NativeRuleId,
    #[serde(default)]
    pub language: Option<Language>,
    #[serde(default)]
    pub origin: Option<Origin>,
    pub taxonomy: Taxonomy,
}

impl ClassificationRuleConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_text("classification.rule.id", &self.id, 1, 128)?;
        validate_text("classification.rule.tool_name", &self.tool_name, 1, 64)?;
        if let Some(version) = &self.tool_version {
            validate_text("classification.rule.tool_version", version, 1, 64)?;
        }
        if let NativeRuleId::Exact(value) = &self.native_rule_id {
            validate_text("classification.rule.native_rule_id", value, 1, 128)?;
        }
        self.taxonomy.validate().map_err(ConfigError::Taxonomy)
    }

    fn to_engine(&self) -> Result<ClassificationRule, ConfigError> {
        self.validate()?;
        Ok(ClassificationRule {
            id: self.id.clone(),
            tool_name: self.tool_name.clone(),
            tool_version: self.tool_version.clone(),
            native_rule_id: self.native_rule_id.to_engine(),
            language: self.language.clone(),
            origin: self.origin.clone(),
            taxonomy: self.taxonomy.clone(),
        })
    }
}

/// Native rule ID matching mode in the classification wire format.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeRuleId {
    #[default]
    Any,
    Absent,
    Exact(String),
}

impl NativeRuleId {
    fn to_engine(&self) -> RuleIdSelector {
        match self {
            Self::Any => RuleIdSelector::Any,
            Self::Absent => RuleIdSelector::Absent,
            Self::Exact(value) => RuleIdSelector::Exact(value.clone()),
        }
    }
}

/// Repository policy wire values. Evaluation and digesting remain Engine-owned.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    #[serde(default)]
    pub waivers: Vec<PolicyWaiver>,
}

/// Output destination and encoding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputConfig {
    #[serde(default)]
    pub format: OutputFormat,
    #[serde(default)]
    pub path: Option<RepoPath>,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Json,
            path: None,
        }
    }
}

impl OutputConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if let Some(path) = &self.path {
            if path.as_str() == "." {
                return Err(invalid("output.path", "must name an output file"));
            }
        }
        Ok(())
    }
}

/// Supported report encodings.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Json,
    Tsv,
}

fn validate_capabilities(
    required: &[Capability],
    optional: &[Capability],
) -> Result<(), ConfigError> {
    if required.len() > 64 || optional.len() > 64 {
        return Err(invalid(
            "providers.capabilities",
            "each capability list must contain at most 64 values",
        ));
    }
    let mut values = BTreeSet::new();
    for capability in required.iter().chain(optional) {
        if !values.insert(capability.as_str()) {
            return Err(invalid(
                "providers.capabilities",
                "required and optional capabilities must be unique and disjoint",
            ));
        }
    }
    Ok(())
}

fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

fn default_max_stdout_bytes() -> u64 {
    DEFAULT_MAX_STDOUT_BYTES
}

fn default_max_stderr_bytes() -> u64 {
    DEFAULT_MAX_STDERR_BYTES
}

fn default_max_evidence_bytes() -> u64 {
    DEFAULT_MAX_EVIDENCE_BYTES
}

fn default_max_events() -> u64 {
    DEFAULT_MAX_EVENTS
}

fn validate_nonzero_limit(field: &str, value: u64, maximum: u64) -> Result<(), ConfigError> {
    if value == 0 || value > maximum {
        return Err(invalid(field, &format!("must be between 1 and {maximum}")));
    }
    Ok(())
}

fn validate_ceiling(field: &str, value: u64, maximum: u64) -> Result<(), ConfigError> {
    if value > maximum {
        return Err(invalid(field, &format!("must not exceed {maximum}")));
    }
    Ok(())
}

fn validate_text(
    field: &str,
    value: &str,
    minimum: usize,
    maximum: usize,
) -> Result<(), ConfigError> {
    let length = value.chars().count();
    let canonical = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if !(minimum..=maximum).contains(&length) || canonical != value || value.contains('\0') {
        return Err(invalid(
            field,
            &format!("must contain {minimum}..={maximum} canonical characters"),
        ));
    }
    Ok(())
}

fn validate_no_nul(field: &str, value: &str) -> Result<(), ConfigError> {
    if value.contains('\0') {
        return Err(invalid(field, "must not contain NUL"));
    }
    Ok(())
}

fn invalid(field: &str, reason: &str) -> ConfigError {
    ConfigError::Invalid {
        field: field.to_owned(),
        reason: reason.to_owned(),
    }
}

fn policy_waiver_canonical_cmp(left: &PolicyWaiver, right: &PolicyWaiver) -> std::cmp::Ordering {
    left.fingerprint
        .cmp(&right.fingerprint)
        .then_with(|| {
            waived_action_wire(&left.waived_action).cmp(waived_action_wire(&right.waived_action))
        })
        .then_with(|| left.reason.cmp(&right.reason))
        .then_with(|| left.owner.cmp(&right.owner))
        .then_with(|| left.expires_at.cmp(&right.expires_at))
}

const fn waived_action_wire(
    action: &diagnostic_triage_contracts::model::WaivedAction,
) -> &'static str {
    match action {
        diagnostic_triage_contracts::model::WaivedAction::Warn => "WARN",
        diagnostic_triage_contracts::model::WaivedAction::Block => "BLOCK",
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        DEFAULT_MAX_EVENTS, DEFAULT_MAX_EVIDENCE_BYTES, DEFAULT_MAX_STDERR_BYTES,
        DEFAULT_MAX_STDOUT_BYTES, DEFAULT_TIMEOUT_MS, OutputFormat, RuntimeConfig,
    };
    use crate::process::{ProcessState, run_bounded};
    use diagnostic_triage_contracts::AdapterId;

    const REVISION: &str = "a12b34c56d78e90f1234567890abcdef12345678";

    fn minimal_config(extra: &str) -> String {
        format!(
            r#"
[engine]
version = "0.1.0"
source_revision = "{REVISION}"

[repository]
workspace = "."
targets = ["src", "tests"]

[[providers]]
adapter_id = "rust"
program = "cargo"
argv = ["check"]
required = true
required_capabilities = ["diagnostic.check/v1"]

{extra}
"#
        )
    }

    #[test]
    fn parses_defaults_and_direct_command_arguments() {
        let config = RuntimeConfig::from_toml(&minimal_config("")).expect("valid config");

        assert_eq!(config.limits.timeout_ms, DEFAULT_TIMEOUT_MS);
        assert_eq!(config.limits.max_stdout_bytes, DEFAULT_MAX_STDOUT_BYTES);
        assert_eq!(config.limits.max_stderr_bytes, DEFAULT_MAX_STDERR_BYTES);
        assert_eq!(config.limits.max_evidence_bytes, DEFAULT_MAX_EVIDENCE_BYTES);
        assert_eq!(config.limits.max_events, DEFAULT_MAX_EVENTS);
        assert_eq!(config.providers[0].program, "cargo");
        assert_eq!(config.providers[0].argv, ["check"]);
        assert!(config.providers[0].required);
        assert_eq!(config.output.format, OutputFormat::Json);
    }

    #[test]
    fn rejects_unknown_fields_and_unsafe_paths() {
        let base = minimal_config("");
        for invalid in [
            format!("{base}\nunknown = true"),
            base.replacen("workspace = \".\"", "workspace = \"/tmp/repo\"", 1),
            base.replacen(
                "targets = [\"src\", \"tests\"]",
                "targets = [\"../outside\"]",
                1,
            ),
            base.replacen(
                "targets = [\"src\", \"tests\"]",
                "targets = [\"src\\\\lib.rs\"]",
                1,
            ),
            base.replacen("program = \"cargo\"", "program = \"\"", 1),
            format!("{base}\n[limits]\ntimeout_ms = 0"),
            base.replacen("program = \"cargo\"", "program = \"bad\\u0000program\"", 1),
            format!("{base}\n[output]\npath = \"../report.json\""),
            base.replacen("argv = [\"check\"]", "command = \"cargo check\"", 1),
        ] {
            assert!(
                RuntimeConfig::from_toml(&invalid).is_err(),
                "unexpected valid config:\n{invalid}"
            );
        }
    }

    #[test]
    fn validates_provider_identity_capabilities_and_bounds() {
        let base = minimal_config("");
        for invalid in [
            base.replacen("required = true", "required = false", 1),
            base.replacen("adapter_id = \"rust\"", "adapter_id = \"Rust\"", 1),
            base.replacen(
                "required_capabilities = [\"diagnostic.check/v1\"]",
                "required_capabilities = [\"diagnostic.check/v1\", \"diagnostic.check/v1\"]",
                1,
            ),
            base.replacen(
                "required_capabilities = [\"diagnostic.check/v1\"]",
                "required_capabilities = [\"diagnostic.check/v1\"]\noptional_capabilities = [\"diagnostic.check/v1\"]",
                1,
            ),
            format!(
                "{base}\n[[providers]]\nadapter_id = \"rust\"\nprogram = \"cargo\"\nrequired = false"
            ),
        ] {
            assert!(RuntimeConfig::from_toml(&invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn permits_zero_optional_capture_and_event_limits() {
        let config = RuntimeConfig::from_toml(&minimal_config(
            "[limits]\nmax_stdout_bytes = 0\nmax_stderr_bytes = 0\nmax_evidence_bytes = 0\nmax_events = 0",
        ))
        .expect("zero optional limits are valid protocol-v1 ceilings");

        assert_eq!(config.limits.max_stdout_bytes, 0);
        assert_eq!(config.limits.max_stderr_bytes, 0);
        assert_eq!(config.limits.max_evidence_bytes, 0);
        assert_eq!(config.limits.max_events, 0);
    }

    #[test]
    fn converts_custom_limits_to_protocol_and_process_types() {
        let config = RuntimeConfig::from_toml(&minimal_config(
            "[limits]\ntimeout_ms = 1234\nmax_stdout_bytes = 321\nmax_stderr_bytes = 654\nmax_evidence_bytes = 777\nmax_events = 888",
        ))
        .expect("valid config");

        let request_limits = config.request_limits().expect("request limits");
        assert_eq!(request_limits.timeout_ms, 1234);
        assert_eq!(request_limits.max_stdout_bytes, 321);
        assert_eq!(request_limits.max_stderr_bytes, 654);
        assert_eq!(request_limits.max_evidence_bytes, 777);
        assert_eq!(request_limits.max_events, 888);

        let process_limits = config.process_limits().expect("process limits");
        assert_eq!(process_limits.timeout, Duration::from_millis(1234));
        assert_eq!(process_limits.max_stdout_bytes, 321);
        assert_eq!(process_limits.max_stderr_bytes, 654);
    }

    #[cfg(unix)]
    #[test]
    fn runs_configured_direct_command_with_exact_argv() {
        let input = minimal_config("").replacen(
            "program = \"cargo\"\nargv = [\"check\"]",
            "program = \"printf\"\nargv = ['%s\\n', 'first argument', 'second argument']",
            1,
        );
        let config = RuntimeConfig::from_toml(&input).expect("valid config");
        let adapter_id = "rust".parse::<AdapterId>().expect("adapter ID");

        let outcome = run_bounded(
            &config.process_spec(&adapter_id).expect("process spec"),
            config.process_limits().expect("process limits"),
        )
        .expect("direct process completes");

        assert_eq!(outcome.state, ProcessState::Complete);
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(outcome.stdout.bytes, b"first argument\nsecond argument\n");
        assert!(outcome.stderr.bytes.is_empty());
    }

    #[test]
    fn normalizes_sets_without_reordering_argv() {
        let input = minimal_config("")
            .replacen(
                "targets = [\"src\", \"tests\"]",
                "targets = [\"tests\", \"src\"]",
                1,
            )
            .replacen(
                "required_capabilities = [\"diagnostic.check/v1\"]",
                "required_capabilities = [\"diagnostic.fix/v1\", \"diagnostic.check/v1\"]",
                1,
            );
        let input = format!(
            "{input}\n[[providers]]\nadapter_id = \"python\"\nprogram = \"python-provider\"\nargv = [\"--first\", \"--second\"]\nrequired = false"
        );

        let config = RuntimeConfig::from_toml(&input).expect("valid config");
        assert_eq!(
            config
                .repository
                .targets
                .iter()
                .map(diagnostic_triage_contracts::RepoPath::as_str)
                .collect::<Vec<_>>(),
            ["src", "tests"]
        );
        assert_eq!(
            config
                .providers
                .iter()
                .map(|provider| provider.adapter_id.as_str())
                .collect::<Vec<_>>(),
            ["python", "rust"]
        );
        assert_eq!(config.providers[0].argv, ["--first", "--second"]);
        assert_eq!(
            config.providers[1]
                .required_capabilities
                .iter()
                .map(diagnostic_triage_contracts::Capability::as_str)
                .collect::<Vec<_>>(),
            ["diagnostic.check/v1", "diagnostic.fix/v1"]
        );
    }

    #[test]
    fn policy_digest_is_independent_of_wire_rule_order() {
        let forward = RuntimeConfig::from_toml(&minimal_config(
            r#"
[policy]
[[policy.rules]]
rule_id = "z-rule"
action = "WARN"
[policy.rules.matcher]
tool_name = "cargo"

[[policy.rules]]
rule_id = "a-rule"
action = "BLOCK"
[policy.rules.matcher]
tool_name = "cargo"

[[policy.waivers]]
fingerprint = "dtfp1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
waived_action = "BLOCK"
reason = "legacy release"
owner = "release-team"
expires_at = "2030-01-01T00:00:00Z"

[[policy.waivers]]
fingerprint = "dtfp1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
waived_action = "WARN"
reason = "known migration"
owner = "platform-team"
expires_at = "2031-01-01T00:00:00Z"
"#,
        ))
        .expect("valid forward config");
        let reverse = RuntimeConfig::from_toml(&minimal_config(
            r#"
[policy]
[[policy.rules]]
rule_id = "a-rule"
action = "BLOCK"
[policy.rules.matcher]
tool_name = "cargo"

[[policy.rules]]
rule_id = "z-rule"
action = "WARN"
[policy.rules.matcher]
tool_name = "cargo"

[[policy.waivers]]
fingerprint = "dtfp1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
waived_action = "WARN"
reason = "known migration"
owner = "platform-team"
expires_at = "2031-01-01T00:00:00Z"

[[policy.waivers]]
fingerprint = "dtfp1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
waived_action = "BLOCK"
reason = "legacy release"
owner = "release-team"
expires_at = "2030-01-01T00:00:00Z"
"#,
        ))
        .expect("valid reverse config");

        assert_eq!(forward, reverse);
        assert_eq!(forward.policy, reverse.policy);
        assert_eq!(
            forward.policy_snapshot().unwrap().digest(),
            reverse.policy_snapshot().unwrap().digest()
        );
    }

    #[test]
    fn parses_classification_taxonomy_and_output() {
        let config = RuntimeConfig::from_toml(&minimal_config(
            r#"
[classification]
[[classification.rules]]
id = "cargo.invalid"
tool_name = "cargo"
native_rule_id = { exact = "invalid" }
taxonomy = { category = "type", micro_category = "incompatible-type" }

[output]
format = "tsv"
path = "artifacts/report.tsv"
"#,
        ))
        .expect("valid classification config");

        let rules = config.classification_rules().expect("engine rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(config.output.format, OutputFormat::Tsv);
    }
}
