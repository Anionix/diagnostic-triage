//! Serde helpers that preserve JSON Schema required/null distinctions.

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// A required field whose JSON value may be `null`.
///
/// Unlike `Option<T>`, absence is rejected because the containing field has no
/// `default` annotation. This models required `integer | null` wire fields.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Nullable<T>(pub Option<T>);

impl<'de, T> Deserialize<'de> for Nullable<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(Self)
    }
}

/// Deserialize an optional field while rejecting an explicitly supplied null.
pub(crate) fn deserialize_optional<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}
