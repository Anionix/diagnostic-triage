//! Validated scalar types shared by model and protocol objects.

use std::{fmt, str::FromStr};

use camino::Utf8PathBuf;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest, Sha256};
use uuid::Uuid;

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

macro_rules! validated_string {
    ($(#[$meta:meta])* $name:ident, $validator:ident, $expected:literal) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd)]
        #[schemars(transparent)]
        pub struct $name(String);

        impl $name {
            /// Return the canonical wire representation.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = &'static str;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                $validator(value).then(|| Self(value.to_owned())).ok_or($expected)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(D::Error::custom)
            }
        }
    };
}

validated_string!(
    /// Canonical lowercase RFC 9562 UUID accepted by the v1 schemas.
    ObjectId,
    valid_object_id,
    "expected a canonical lowercase UUID with version 1 through 8"
);
validated_string!(
    /// Lowercase SHA-256 digest without a prefix.
    Sha256Digest,
    valid_sha256,
    "expected 64 lowercase hexadecimal characters"
);

impl Sha256Digest {
    /// Compute the canonical lowercase SHA-256 digest for `bytes`.
    #[must_use]
    pub fn compute(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }
}

validated_string!(
    /// Full lowercase SHA-1 or SHA-256 Git object identifier.
    SourceRevision,
    valid_source_revision,
    "expected exactly 40 or 64 lowercase hexadecimal characters"
);
validated_string!(
    /// Versioned stable Finding fingerprint.
    Fingerprint,
    valid_fingerprint,
    "expected dtfp1 followed by a lowercase SHA-256 digest"
);
validated_string!(
    /// Stable lowercase language identifier.
    Language,
    valid_language,
    "expected a canonical language identifier"
);
validated_string!(
    /// Namespaced protocol capability ending in a positive `/vN` version.
    Capability,
    valid_capability,
    "expected a namespaced capability ending in /vN"
);
validated_string!(
    /// Stable Provider or Observer identifier.
    AdapterId,
    valid_adapter_id,
    "expected a lowercase adapter identifier"
);

/// Canonical repository-relative POSIX path, or `.` for the repository root.
#[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd)]
#[schemars(transparent)]
pub struct RepoPath(#[schemars(with = "String")] Utf8PathBuf);

impl RepoPath {
    /// Return the canonical wire representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl AsRef<str> for RepoPath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for RepoPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RepoPath {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if valid_repo_path(value) {
            Ok(Self(Utf8PathBuf::from(value)))
        } else {
            Err("expected a canonical repository-relative POSIX path")
        }
    }
}

impl Serialize for RepoPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RepoPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(D::Error::custom)
    }
}

fn lowercase_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_object_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        && bytes.iter().enumerate().all(|(index, byte)| {
            [8, 13, 18, 23].contains(&index)
                || byte.is_ascii_digit()
                || (b'a'..=b'f').contains(byte)
        })
        && (b'1'..=b'8').contains(&bytes[14])
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        && Uuid::parse_str(value).is_ok()
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && lowercase_hex(value)
}

fn valid_source_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && lowercase_hex(value)
}

fn valid_fingerprint(value: &str) -> bool {
    value.strip_prefix("dtfp1:").is_some_and(valid_sha256)
}

fn valid_language(value: &str) -> bool {
    let mut bytes = value.bytes();
    (1..=64).contains(&value.len())
        && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'+' | b'.' | b'#' | b'-')
        })
}

fn valid_capability(value: &str) -> bool {
    if !(4..=128).contains(&value.len()) {
        return false;
    }
    let Some((namespace, version)) = value.rsplit_once("/v") else {
        return false;
    };
    valid_adapter_id(namespace)
        && version
            .bytes()
            .enumerate()
            .all(|(index, byte)| byte.is_ascii_digit() && (index != 0 || byte != b'0'))
        && !version.is_empty()
}

fn valid_adapter_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    (1..=128).contains(&value.len())
        && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

fn valid_repo_path(value: &str) -> bool {
    if value == "." {
        return true;
    }
    if value.is_empty()
        || value.chars().count() > 4096
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains(['\\', '\0'])
        || value.contains("//")
    {
        return false;
    }
    let bytes = value.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return false;
    }
    value
        .split('/')
        .all(|component| component != "." && component != "..")
}

#[cfg(test)]
mod tests {
    use super::{AdapterId, Capability, ObjectId, RepoPath, Sha256Digest, SourceRevision};

    #[test]
    fn sha256_digest_compute_matches_known_vectors() {
        assert_eq!(
            Sha256Digest::compute(b"").as_str(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            Sha256Digest::compute(b"hello").as_str(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn rejects_noncanonical_paths() {
        for value in [
            "",
            "/absolute",
            "../escape",
            "nested/../escape",
            "C:drive-relative",
            "C:/absolute",
            "windows\\path",
            "nul\0path",
            "double//separator",
            "dot/./segment",
            "trailing/",
        ] {
            assert!(value.parse::<RepoPath>().is_err(), "accepted {value:?}");
        }
        assert!(".".parse::<RepoPath>().is_ok());
        assert!("src/lib.rs".parse::<RepoPath>().is_ok());
    }

    #[test]
    fn validates_uuid_and_capability_canonical_forms() {
        assert!(
            "019f7e95-0000-7000-8000-000000000001"
                .parse::<ObjectId>()
                .is_ok()
        );
        assert!(
            "019F7E95-0000-7000-8000-000000000001"
                .parse::<ObjectId>()
                .is_err()
        );
        assert!("diagnostic.check/v1".parse::<Capability>().is_ok());
        assert!("diagnostic.check/v2".parse::<Capability>().is_ok());
        assert!("diagnostic.check/v0".parse::<Capability>().is_err());
    }

    #[test]
    fn source_revision_accepts_only_full_git_object_ids() {
        for length in [40, 64] {
            assert!("a".repeat(length).parse::<SourceRevision>().is_ok());
        }
        for length in [39, 41, 63, 65] {
            assert!("a".repeat(length).parse::<SourceRevision>().is_err());
        }
    }

    #[test]
    fn adapter_id_enforces_exact_wire_boundaries() {
        for value in ["a".to_owned(), "github-actions".to_owned(), "a".repeat(128)] {
            assert!(value.parse::<AdapterId>().is_ok(), "rejected {value:?}");
        }
        for value in [
            String::new(),
            "GitHub Actions".to_owned(),
            "abc\n".to_owned(),
            "abc\r".to_owned(),
            "abc\r\n".to_owned(),
            "abc\u{2028}".to_owned(),
            "a".repeat(129),
        ] {
            assert!(value.parse::<AdapterId>().is_err(), "accepted {value:?}");
        }
    }
}
