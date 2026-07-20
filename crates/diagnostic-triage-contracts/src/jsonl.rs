//! Strict, I/O-free decoding for bounded JSON Lines input.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use crate::ContractError;

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// A decoded JSON object and the number of bytes occupied by its original line.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DecodedLine {
    pub(crate) value: Value,
    pub(crate) raw_len: usize,
}

/// Decode one duplicate-free UTF-8 JSON object without performing I/O.
pub(crate) fn decode_json_object(input: &[u8]) -> Result<Value, ContractError> {
    if input.is_empty() {
        return Err(ContractError::JsonLines("document is empty".to_owned()));
    }
    std::str::from_utf8(input)
        .map_err(|error| ContractError::JsonLines(format!("document is not UTF-8: {error}")))?;
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = StrictValue::deserialize(&mut deserializer)
        .and_then(|value| deserializer.end().map(|()| value.0))
        .map_err(|error| ContractError::JsonLines(error.to_string()))?;
    if !value.is_object() {
        return Err(ContractError::JsonLines(
            "top-level JSON value must be an object".to_owned(),
        ));
    }
    Ok(value)
}

/// Deserialize one value while rejecting duplicate object keys recursively.
pub(crate) fn deserialize_strict_value<'de, D>(deserializer: D) -> Result<Value, D::Error>
where
    D: Deserializer<'de>,
{
    StrictValue::deserialize(deserializer).map(|value| value.0)
}

/// Decode UTF-8 JSON objects separated by lines without performing I/O.
///
/// Every line is parsed as exactly one JSON value. Objects are required at the
/// top level, and duplicate object keys are rejected recursively.
pub(crate) fn decode_jsonl(input: &[u8]) -> Result<Vec<DecodedLine>, ContractError> {
    if input.is_empty() {
        return Err(json_lines_error(1, "input is empty"));
    }

    input
        .split_inclusive(|byte| *byte == b'\n')
        .enumerate()
        .map(|(index, raw_line)| decode_line(index + 1, raw_line))
        .collect()
}

pub(crate) fn decode_line(
    line_number: usize,
    raw_line: &[u8],
) -> Result<DecodedLine, ContractError> {
    let line = std::str::from_utf8(raw_line).map_err(|error| {
        json_lines_error(line_number, format_args!("input is not UTF-8: {error}"))
    })?;

    if line.trim().is_empty() {
        return Err(json_lines_error(line_number, "blank lines are not allowed"));
    }

    let mut deserializer = serde_json::Deserializer::from_slice(raw_line);
    let value = StrictValue::deserialize(&mut deserializer)
        .and_then(|value| deserializer.end().map(|()| value.0))
        .map_err(|error| json_lines_error(line_number, format_args!("{error}")))?;

    if !value.is_object() {
        return Err(json_lines_error(
            line_number,
            "top-level JSON value must be an object",
        ));
    }

    Ok(DecodedLine {
        value,
        raw_len: raw_line.len(),
    })
}

fn json_lines_error(line_number: usize, message: impl fmt::Display) -> ContractError {
    ContractError::JsonLines(format!("line {line_number}: {message}"))
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(|number| StrictValue(Value::Number(number)))
            .ok_or_else(|| E::custom("JSON number must be finite"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = access.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate object key: {key}")));
            }
            let value = access.next_value::<StrictValue>()?;
            object.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(object)))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{decode_json_object, decode_jsonl};
    use crate::ContractError;

    fn error_text(input: &[u8]) -> String {
        match decode_jsonl(input) {
            Ok(_) => panic!("expected JSON Lines decoding to fail"),
            Err(ContractError::JsonLines(message)) => message,
            Err(error) => panic!("unexpected contract error: {error}"),
        }
    }

    #[test]
    fn decodes_objects_and_preserves_raw_line_lengths() {
        let decoded = decode_jsonl(
            br#"{"a":1}
{"b":[true,null]}"#,
        )
        .expect("valid JSON Lines should decode");

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].value, json!({"a": 1}));
        assert_eq!(decoded[1].value, json!({"b": [true, null]}));
        assert_eq!(decoded[0].raw_len, 8);
        assert_eq!(decoded[1].raw_len, 17);
    }

    #[test]
    fn rejects_empty_and_blank_input_with_line_context() {
        assert_eq!(error_text(b""), "line 1: input is empty");
        assert!(error_text(b"{}\n\n{}").starts_with("line 2:"));
        assert!(error_text(b"   \n{}").starts_with("line 1:"));
    }

    #[test]
    fn rejects_non_utf8_input_with_line_context() {
        let message = error_text(b"{\"text\":\xFF}\n");
        assert!(message.starts_with("line 1: input is not UTF-8:"));
    }

    #[test]
    fn rejects_malformed_and_trailing_json() {
        assert!(error_text(br#"{"a":}"#).starts_with("line 1:"));
        assert!(error_text(br"{} {}").starts_with("line 1:"));
        assert!(error_text(br"{} trailing").starts_with("line 1:"));
    }

    #[test]
    fn rejects_non_object_top_level_values() {
        for input in [br"[]".as_slice(), br"null", br"true", br"1"] {
            let message = error_text(input);
            assert!(message.contains("line 1:"));
            assert!(message.contains("top-level JSON value must be an object"));
        }
    }

    #[test]
    fn rejects_duplicate_keys_at_any_nesting_depth() {
        for input in [
            br#"{"a":1,"a":2}"#.as_slice(),
            br#"{"outer":{"a":1,"a":2}}"#.as_slice(),
            br#"{"items":[{"a":1,"a":2}]}"#.as_slice(),
            br#"{"a":1,"\u0061":2}"#.as_slice(),
        ] {
            let message = error_text(input);
            assert!(message.contains("line 1:"));
            assert!(message.contains("duplicate object key"));
        }
    }

    #[test]
    fn strict_document_decoder_accepts_pretty_json_and_rejects_duplicates() {
        let document = b"{\n  \"a\": 1\n}\n";
        assert_eq!(decode_json_object(document).unwrap(), json!({"a": 1}));
        assert!(decode_json_object(br#"{"a":1,"a":2}"#).is_err());
    }
}
