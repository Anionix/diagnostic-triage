//! Deterministic internal object identifiers for order-independent reports.

use std::str::FromStr;

use diagnostic_triage_contracts::ObjectId;
use sha2::{Digest, Sha256};

use crate::{EngineError, EngineInputError};

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// Derive a version-8 UUID from domain-separated, length-prefixed fields.
///
/// # Errors
///
/// Returns an error for an empty domain, a field whose byte length cannot be
/// represented by v1, or an internally invalid UUID scalar.
pub fn deterministic_object_id<'a>(
    domain: &str,
    fields: impl IntoIterator<Item = &'a str>,
) -> Result<ObjectId, EngineError> {
    if domain.is_empty() {
        return Err(EngineInputError::EmptyDeterministicIdDomain.into());
    }

    let mut digest = Sha256::new();
    update_field(&mut digest, domain)?;
    for field in fields {
        update_field(&mut digest, field)?;
    }
    let output = digest.finalize();
    let mut bytes = [0_u8; 16];
    for (target, source) in bytes.iter_mut().zip(output.iter()) {
        *target = *source;
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    let wire = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    );
    ObjectId::from_str(&wire).map_err(|reason| {
        EngineInputError::InvalidDerivedObjectId {
            reason: reason.into(),
        }
        .into()
    })
}

fn update_field(digest: &mut Sha256, field: &str) -> Result<(), EngineError> {
    let length =
        u64::try_from(field.len()).map_err(|_| EngineInputError::DeterministicIdFieldTooLarge)?;
    digest.update(length.to_be_bytes());
    digest.update(field.as_bytes());
    Ok(())
}
