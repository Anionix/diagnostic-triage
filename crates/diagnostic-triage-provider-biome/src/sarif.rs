//! Typed Biome SARIF 2.1.0 input boundary.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

use serde::Deserialize;
use thiserror::Error;

const MAX_RESULTS: usize = 10_000;
const MAX_RULE_CHARS: usize = 256;
const MAX_MESSAGE_CHARS: usize = 8_192;
const MAX_URI_CHARS: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub(crate) struct SarifLog {
    pub(crate) version: String,
    pub(crate) runs: Vec<SarifRun>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub(crate) struct SarifRun {
    pub(crate) tool: SarifTool,
    #[serde(default)]
    pub(crate) results: Vec<SarifResult>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub(crate) struct SarifTool {
    pub(crate) driver: SarifDriver,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub(crate) struct SarifDriver {
    pub(crate) name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub(crate) struct SarifResult {
    #[serde(rename = "ruleId")]
    pub(crate) rule_id: String,
    #[serde(default)]
    pub(crate) level: SarifLevel,
    pub(crate) message: SarifMessage,
    #[serde(default)]
    pub(crate) locations: Vec<SarifLocation>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SarifLevel {
    Error,
    None,
    Note,
    #[default]
    Warning,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub(crate) struct SarifMessage {
    pub(crate) text: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub(crate) struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub(crate) physical_location: SarifPhysicalLocation,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub(crate) struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub(crate) artifact_location: SarifArtifactLocation,
    #[serde(default)]
    pub(crate) region: Option<SarifRegion>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub(crate) struct SarifArtifactLocation {
    pub(crate) uri: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub(crate) struct SarifRegion {
    #[serde(rename = "startLine")]
    pub(crate) start_line: u64,
    #[serde(rename = "startColumn", default = "one")]
    pub(crate) start_column: u64,
    #[serde(rename = "endLine", default)]
    pub(crate) end_line: Option<u64>,
    #[serde(rename = "endColumn", default)]
    pub(crate) end_column: Option<u64>,
}

const fn one() -> u64 {
    1
}

#[derive(Debug, Error)]
pub enum SarifError {
    #[error("Biome SARIF is malformed: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("Biome SARIF violates the typed boundary: {0}")]
    Invalid(String),
}

pub(crate) fn parse_sarif(input: &[u8]) -> Result<SarifLog, SarifError> {
    let log = serde_json::from_slice::<SarifLog>(input)?;
    if log.version != "2.1.0" {
        return Err(SarifError::Invalid(
            "version must be SARIF 2.1.0".to_owned(),
        ));
    }
    if log.runs.len() != 1 {
        return Err(SarifError::Invalid(
            "Biome SARIF must contain exactly one run".to_owned(),
        ));
    }
    let run = &log.runs[0];
    if run.tool.driver.name != "Biome" {
        return Err(SarifError::Invalid(
            "tool.driver.name must identify Biome".to_owned(),
        ));
    }
    if run.results.len() > MAX_RESULTS {
        return Err(SarifError::Invalid(format!(
            "result count exceeds {MAX_RESULTS}"
        )));
    }
    for result in &run.results {
        validate_result(result)?;
    }
    Ok(log)
}

fn validate_result(result: &SarifResult) -> Result<(), SarifError> {
    validate_text("ruleId", &result.rule_id, MAX_RULE_CHARS)?;
    validate_text("message.text", &result.message.text, MAX_MESSAGE_CHARS)?;
    if result.locations.len() > 1 {
        return Err(SarifError::Invalid(
            "a Biome result must not contain multiple primary locations".to_owned(),
        ));
    }
    if let Some(location) = result.locations.first() {
        validate_text(
            "artifactLocation.uri",
            &location.physical_location.artifact_location.uri,
            MAX_URI_CHARS,
        )?;
        if let Some(region) = &location.physical_location.region {
            validate_region(region)?;
        }
    }
    Ok(())
}

fn validate_region(region: &SarifRegion) -> Result<(), SarifError> {
    let start = (region.start_line, region.start_column);
    if start.0 == 0
        || start.1 == 0
        || u32::try_from(start.0).is_err()
        || u32::try_from(start.1).is_err()
    {
        return Err(SarifError::Invalid(
            "region start is outside the v1 position range".to_owned(),
        ));
    }
    match (region.end_line, region.end_column) {
        (None, None) => Ok(()),
        (Some(line), Some(column))
            if line > 0
                && column > 0
                && u32::try_from(line).is_ok()
                && u32::try_from(column).is_ok()
                && (line, column) >= start =>
        {
            Ok(())
        }
        _ => Err(SarifError::Invalid(
            "region end must be a complete v1 position at or after start".to_owned(),
        )),
    }
}

fn validate_text(field: &str, value: &str, maximum: usize) -> Result<(), SarifError> {
    let count = value.chars().count();
    if count == 0 || count > maximum {
        Err(SarifError::Invalid(format!(
            "{field} must contain 1..={maximum} characters"
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{SarifError, parse_sarif};

    #[test]
    fn rejects_partial_wrong_tool_and_incomplete_end_positions() {
        assert!(matches!(parse_sarif(b"{"), Err(SarifError::Malformed(_))));
        for input in [
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Other"}},"results":[]}]}"#,
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Biome"}},"results":[{"ruleId":"rule","message":{"text":"message"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"x.js"},"region":{"startLine":1,"startColumn":1,"endLine":1}}}]}]}]}"#,
        ] {
            assert!(matches!(
                parse_sarif(input.as_bytes()),
                Err(SarifError::Invalid(_))
            ));
        }
    }
}
