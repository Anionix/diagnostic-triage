//! Typed Biome SARIF 2.1.0 input boundary.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

use serde::{Deserialize, Deserializer};
use thiserror::Error;

const MAX_RESULTS: usize = 10_000;
const MAX_RULE_CHARS: usize = 256;
const MAX_MESSAGE_CHARS: usize = 8_192;
const MAX_URI_CHARS: usize = 4_096;
const SOURCE_BACKED_OMITTED_COLUMN_KIND_VERSION: &str = "2.4.15";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub(crate) struct SarifLog {
    pub(crate) version: String,
    pub(crate) runs: Vec<SarifRun>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub(crate) struct SarifRun {
    pub(crate) tool: SarifTool,
    #[serde(
        rename = "columnKind",
        default,
        deserialize_with = "deserialize_column_kind"
    )]
    pub(crate) column_kind: Option<SarifColumnKind>,
    #[serde(default)]
    pub(crate) results: Vec<SarifResult>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum SarifColumnKind {
    Utf16CodeUnits,
    UnicodeCodePoints,
}

fn deserialize_column_kind<'de, D>(deserializer: D) -> Result<Option<SarifColumnKind>, D::Error>
where
    D: Deserializer<'de>,
{
    SarifColumnKind::deserialize(deserializer).map(Some)
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
    #[error("Biome SARIF columnKind is unsupported; Location v1 requires unicodeCodePoints")]
    UnsupportedColumnKind,
    #[error("Biome SARIF violates the typed boundary: {0}")]
    Invalid(String),
}

pub(crate) fn parse_sarif(input: &[u8], tool_version: &str) -> Result<SarifLog, SarifError> {
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
    // Biome 2.4.15 tag 9dd3271 derives SARIF columns through
    // SourceFile::location; its column_index counts UTF-8 character boundaries.
    // Keep the source-backed omission version-pinned instead of trusting a
    // mutable tool name or future version.
    let unsupported_omission = run.column_kind.is_none()
        && !run.results.is_empty()
        && tool_version != SOURCE_BACKED_OMITTED_COLUMN_KIND_VERSION;
    if run.column_kind == Some(SarifColumnKind::Utf16CodeUnits) || unsupported_omission {
        return Err(SarifError::UnsupportedColumnKind);
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

    const SOURCE_BACKED_VERSION: &str = "2.4.15";

    #[test]
    fn rejects_partial_wrong_tool_and_invalid_end_positions() {
        assert!(matches!(
            parse_sarif(b"{", SOURCE_BACKED_VERSION),
            Err(SarifError::Malformed(_))
        ));
        let wrong_tool =
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Other"}},"results":[]}]}"#;
        assert!(matches!(
            parse_sarif(wrong_tool.as_bytes(), SOURCE_BACKED_VERSION),
            Err(SarifError::Invalid(_))
        ));

        let implicit_end_column = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Biome"}},"columnKind":"unicodeCodePoints","results":[{"ruleId":"rule","message":{"text":"message"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"x.js"},"region":{"startLine":1,"startColumn":1,"endLine":1}}}]}]}]}"#;
        assert!(matches!(
            parse_sarif(implicit_end_column.as_bytes(), SOURCE_BACKED_VERSION),
            Err(SarifError::Invalid(_))
        ));
    }

    #[test]
    fn accepts_biome_native_omission_and_rejects_explicit_unsupported_units() {
        let unicode = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Biome"}},"columnKind":"unicodeCodePoints","results":[{"ruleId":"rule","message":{"text":"message"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"x.js"},"region":{"startLine":1,"startColumn":1,"endLine":1,"endColumn":2}}}]}]}]}"#;
        parse_sarif(unicode.as_bytes(), "future-version")
            .expect("an explicit Location v1 column unit is accepted");

        let omitted_empty =
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Biome"}},"results":[]}] }"#;
        parse_sarif(omitted_empty.as_bytes(), "future-version")
            .expect("an empty run carries no coordinates");

        for omitted_nonempty in [
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Biome"}},"results":[{"ruleId":"rule","message":{"text":"message"},"locations":[]}]}]}"#,
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Biome"}},"results":[{"ruleId":"rule","message":{"text":"message"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"x.js"},"region":{"startLine":1,"startColumn":1,"endLine":1,"endColumn":2}}}]}]}]}"#,
        ] {
            parse_sarif(omitted_nonempty.as_bytes(), SOURCE_BACKED_VERSION)
                .expect("Biome native columns have source-backed code-point semantics");
            assert!(matches!(
                parse_sarif(omitted_nonempty.as_bytes(), "2.4.14"),
                Err(SarifError::UnsupportedColumnKind)
            ));
        }

        let utf16 = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Biome"}},"columnKind":"utf16CodeUnits","results":[]}] }"#;
        assert!(matches!(
            parse_sarif(utf16.as_bytes(), SOURCE_BACKED_VERSION),
            Err(SarifError::UnsupportedColumnKind)
        ));

        for invalid in [
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Biome"}},"columnKind":"bytes","results":[]}] }"#,
            r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Biome"}},"columnKind":null,"results":[]}] }"#,
        ] {
            assert!(matches!(
                parse_sarif(invalid.as_bytes(), SOURCE_BACKED_VERSION),
                Err(SarifError::Malformed(_))
            ));
        }
    }
}
