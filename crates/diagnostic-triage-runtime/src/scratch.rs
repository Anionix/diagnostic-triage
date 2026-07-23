//! Bounded, repository-safe scratch workspaces for fix verification.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use diagnostic_triage_contracts::model::{
    Applicability, Evidence, EvidenceSchemaVersion, EvidenceSource, FixCandidate,
};
use diagnostic_triage_contracts::{ContractError, ObjectId, RepoPath, Sha256Digest};
use diagnostic_triage_engine::verification::{
    PatchApplication, SafeFixComparisonInput, SafeFixVerification, VerificationError, VerifiedFix,
    compare_safe_fix,
};
#[cfg(unix)]
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat, fstat, open, openat, statat};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use tempfile::{Builder, NamedTempFile, TempDir};
use thiserror::Error;
use uuid::Uuid;

#[cfg(all(test, unix))]
use std::cell::{Cell, RefCell};
#[cfg(unix)]
use std::ffi::OsStr;

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

/// The media type required by the engine for an inline base snapshot.
pub const SNAPSHOT_MEDIA_TYPE: &str = "application/vnd.diagnostic-triage.snapshot+json";
/// The media type used for an inline deterministic scratch result.
pub const RESULT_MEDIA_TYPE: &str = "application/vnd.diagnostic-triage.result+json";
/// The media type used for a deterministic scratch patch.
pub const PATCH_MEDIA_TYPE: &str = "application/vnd.diagnostic-triage.patch+json";

const SNAPSHOT_SCHEMA_VERSION: &str = "diagnostic-triage.scratch-snapshot/v1";

const DEFAULT_MAX_FILES: usize = 4_096;
const DEFAULT_MAX_ENTRIES: usize = 100_000;
const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_MAX_EVIDENCE_BYTES: u32 = 1_048_576;
const MAX_REPO_PATH_CHARS: usize = 4_096;
const MAX_REPO_PATH_BYTES: usize = MAX_REPO_PATH_CHARS * 4;
const MAX_TRAVERSAL_DEPTH: usize = 256;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
#[cfg(unix)]
const SAFE_CREATE_MODE: u32 = 0o600;
#[cfg(unix)]
const PERMISSION_MODE_MASK: u32 = 0o777;

#[cfg(all(test, unix))]
thread_local! {
    static APPLY_CHANGE_FAILURE_ON_CALL: Cell<Option<usize>> = const { Cell::new(None) };
    static LAST_TRANSACTION_CANDIDATE_PATH: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    static OPEN_ENTRY_RACE_HOOK: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    static IMMUTABLE_BASE_READ_FAILURE: Cell<bool> = const { Cell::new(false) };
    static PATCH_ENCODE_CALLED: Cell<bool> = const { Cell::new(false) };
    static SNAPSHOT_ENCODE_CALLED: Cell<bool> = const { Cell::new(false) };
    static REPLACED_WORKSPACE_CLEANUP_FAILURE: Cell<bool> = const { Cell::new(false) };
}

/// Bounds applied to source copies, scratch snapshots, and patch application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScratchLimits {
    /// Maximum number of regular files in the staged or resulting workspace.
    pub max_files: usize,
    /// Maximum number of filesystem entries visited without buffering a whole directory.
    pub max_entries: usize,
    /// Maximum aggregate bytes in staged or resulting regular files.
    pub max_bytes: u64,
    /// Maximum retained bytes for each inline Evidence record.
    pub max_evidence_bytes: u32,
}

impl Default for ScratchLimits {
    fn default() -> Self {
        Self {
            max_files: DEFAULT_MAX_FILES,
            max_entries: DEFAULT_MAX_ENTRIES,
            max_bytes: DEFAULT_MAX_BYTES,
            max_evidence_bytes: DEFAULT_MAX_EVIDENCE_BYTES,
        }
    }
}

/// A deterministic write or deletion to be applied only inside a scratch workspace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScratchChange {
    /// Replace or create one validated repository-relative regular file.
    Write { path: String, contents: Vec<u8> },
    /// Delete one validated repository-relative regular file.
    Delete { path: String },
}

/// A validated, deterministically encoded set of scratch changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScratchPatch {
    changes: Vec<ScratchChange>,
}

impl ScratchPatch {
    /// Validate and canonicalize a patch. Paths are sorted and duplicate targets are rejected.
    ///
    /// # Errors
    ///
    /// Returns an error when a path is invalid or a target appears more than once.
    pub fn new(changes: Vec<ScratchChange>) -> Result<Self, ScratchError> {
        let change_count = u64::try_from(changes.len()).unwrap_or(u64::MAX);
        if changes.len() > DEFAULT_MAX_FILES {
            return Err(ScratchError::BoundExceeded {
                resource: "patch files",
                actual: change_count,
                max: u64::try_from(DEFAULT_MAX_FILES).unwrap_or(u64::MAX),
            });
        }
        let raw_bytes = changes.iter().try_fold(0_u64, |total, change| {
            let bytes = match change {
                ScratchChange::Write { contents, .. } => {
                    u64::try_from(contents.len()).unwrap_or(u64::MAX)
                }
                ScratchChange::Delete { .. } => 0,
            };
            total.checked_add(bytes).ok_or(ScratchError::BoundExceeded {
                resource: "raw patch bytes",
                actual: u64::MAX,
                max: DEFAULT_MAX_BYTES,
            })
        })?;
        if raw_bytes > DEFAULT_MAX_BYTES {
            return Err(ScratchError::BoundExceeded {
                resource: "raw patch bytes",
                actual: raw_bytes,
                max: DEFAULT_MAX_BYTES,
            });
        }

        let mut normalized = Vec::with_capacity(changes.len());
        let mut paths = BTreeSet::new();
        for change in changes {
            let normalized_change = match change {
                ScratchChange::Write { path, contents } => ScratchChange::Write {
                    path: normalize_change_path(&path)?,
                    contents,
                },
                ScratchChange::Delete { path } => ScratchChange::Delete {
                    path: normalize_change_path(&path)?,
                },
            };
            let path = match &normalized_change {
                ScratchChange::Write { path, .. } | ScratchChange::Delete { path } => path,
            };
            if !paths.insert(path.clone()) {
                return Err(ScratchError::DuplicatePatchPath { path: path.clone() });
            }
            normalized.push(normalized_change);
        }
        normalized.sort_by(|left, right| patch_path(left).cmp(patch_path(right)));
        Ok(Self {
            changes: normalized,
        })
    }

    /// Return the canonical changes in path order.
    #[must_use]
    pub fn changes(&self) -> &[ScratchChange] {
        &self.changes
    }

    fn preflight(&self, limits: ScratchLimits) -> Result<u64, ScratchError> {
        let change_count = u64::try_from(self.changes.len()).unwrap_or(u64::MAX);
        if self.changes.len() > limits.max_files {
            return Err(ScratchError::BoundExceeded {
                resource: "patch files",
                actual: change_count,
                max: u64::try_from(limits.max_files).unwrap_or(u64::MAX),
            });
        }

        let raw_bytes = self.changes.iter().try_fold(0_u64, |total, change| {
            let bytes = match change {
                ScratchChange::Write { contents, .. } => {
                    u64::try_from(contents.len()).unwrap_or(u64::MAX)
                }
                ScratchChange::Delete { .. } => 0,
            };
            total.checked_add(bytes).ok_or(ScratchError::BoundExceeded {
                resource: "raw patch bytes",
                actual: u64::MAX,
                max: limits.max_bytes,
            })
        })?;
        if raw_bytes > limits.max_bytes {
            return Err(ScratchError::BoundExceeded {
                resource: "raw patch bytes",
                actual: raw_bytes,
                max: limits.max_bytes,
            });
        }

        patch_encoded_len(&self.changes, limits.max_evidence_bytes)
    }

    fn encode(&self) -> Result<Vec<u8>, ScratchError> {
        #[cfg(all(test, unix))]
        PATCH_ENCODE_CALLED.with(|called| called.set(true));
        let wire = WirePatch {
            version: 1,
            changes: self
                .changes
                .iter()
                .map(|change| match change {
                    ScratchChange::Write { path, contents } => WireChange::Write {
                        path,
                        content_hex: hex_encode(contents),
                    },
                    ScratchChange::Delete { path } => WireChange::Delete { path },
                })
                .collect(),
        };
        serde_json::to_vec(&wire).map_err(|source| ScratchError::Serialization { source })
    }
}

/// The three independent inline Evidence records produced by one scratch capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScratchEvidence {
    /// The pre-apply snapshot used as the verification base.
    pub base: Evidence,
    /// The post-apply or post-verification workspace result.
    pub result: Evidence,
    /// The complete inline patch used for the candidate.
    pub patch: Evidence,
}

/// Runtime-owned, single-use authorization for one exact, engine-verified scratch apply.
///
/// The runtime is the only constructor. An authorization is bound to its candidate, patch,
/// staged base snapshot, non-forgeable workspace-instance nonce, and [`VerifiedFix`].
/// [`ScratchWorkspace::apply_verified`] consumes it by value, so identical workspace bytes do not
/// make the authorization replayable and every later apply attempt needs a fresh runtime-owned
/// verification.
///
/// External crates cannot invoke the authorization mint:
///
/// ```compile_fail
/// use diagnostic_triage_engine::verification::SafeFixComparisonInput;
/// use diagnostic_triage_runtime::ScratchWorkspace;
///
/// fn forge(workspace: &ScratchWorkspace, input: SafeFixComparisonInput<'_>) {
///     let _ = workspace.authorize_safe_fix(input);
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct SafeFixAuthorization {
    workspace_nonce: Uuid,
    candidate: FixCandidate,
    patch_sha256: Sha256Digest,
    base_snapshot_sha256: Sha256Digest,
    verified_fix: VerifiedFix,
}

impl SafeFixAuthorization {
    /// Return the candidate identity bound to this authorization.
    #[must_use]
    pub fn candidate_id(&self) -> &ObjectId {
        &self.candidate.fix_candidate_id
    }

    /// Return the deterministic patch digest bound to this authorization.
    #[must_use]
    pub fn patch_sha256(&self) -> &Sha256Digest {
        &self.patch_sha256
    }

    /// Return the staged base snapshot digest bound to this authorization.
    #[must_use]
    pub fn base_snapshot_sha256(&self) -> &Sha256Digest {
        &self.base_snapshot_sha256
    }

    /// Return the canonical output preserved from the successful engine comparison.
    #[must_use]
    pub fn verified_fix(&self) -> &VerifiedFix {
        &self.verified_fix
    }
}

/// A temporary workspace copied from explicitly selected repository paths.
#[derive(Debug)]
struct AppliedScratchState {
    patch_sha256: Sha256Digest,
    result_sha256: Sha256Digest,
    authorization_consumed: bool,
}

#[derive(Debug)]
pub struct ScratchWorkspace {
    tempdir: TempDir,
    repo_root: PathBuf,
    selected_paths: Vec<String>,
    workspace_nonce: Uuid,
    base: Evidence,
    applied: Option<AppliedScratchState>,
    limits: ScratchLimits,
}

impl ScratchWorkspace {
    /// Create a unique workspace and copy only the supplied repository-relative paths into it.
    ///
    /// The source repository is opened read-only. Symlinks and special files are rejected rather
    /// than followed, so a staged directory cannot escape the repository through a link. On Unix,
    /// each source file is opened with no-follow semantics and its opened descriptor is checked
    /// against the repository entry observed during traversal. Other platforms are unsupported
    /// because equivalent no-follow guarantees cannot be established here. Repository contents
    /// are trusted input: this is not a hostile same-user sandbox, and hard-linked source files
    /// remain supported as read-only content.
    ///
    /// # Errors
    ///
    /// Returns an error when the repository, selected paths, filesystem entries, or configured
    /// resource limits are invalid.
    pub fn stage<P: AsRef<str>>(
        repo_root: impl AsRef<Path>,
        paths: &[P],
        limits: ScratchLimits,
    ) -> Result<Self, ScratchError> {
        validate_limits(limits)?;
        let repo_root =
            fs::canonicalize(repo_root.as_ref()).map_err(|source| ScratchError::Io {
                operation: "canonicalize repository root",
                source,
            })?;
        if !repo_root.is_dir() {
            return Err(ScratchError::NotDirectory { path: repo_root });
        }
        if paths.len() > limits.max_entries {
            return Err(ScratchError::BoundExceeded {
                resource: "selected paths",
                actual: u64::try_from(paths.len()).unwrap_or(u64::MAX),
                max: u64::try_from(limits.max_entries).unwrap_or(u64::MAX),
            });
        }

        let mut normalized_paths = paths
            .iter()
            .map(|path| normalize_user_path(path.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        normalized_paths.sort();
        normalized_paths.dedup();
        prune_nested_paths(&mut normalized_paths);
        let source_files = collect_selected_files(&repo_root, &normalized_paths, limits)?.files;

        let tempdir = create_safe_tempdir("diagnostic-triage-scratch-", &repo_root)?;
        let staged = (|| {
            let mut copied_bytes = 0_u64;
            for (relative, source) in source_files {
                let destination = tempdir.path().join(relative_to_path(&relative));
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent).map_err(|source| ScratchError::Io {
                        operation: "create scratch parent",
                        source,
                    })?;
                }
                let remaining = limits.max_bytes.saturating_sub(copied_bytes);
                let copied = copy_bounded(source, &destination, remaining)?;
                copied_bytes =
                    copied_bytes
                        .checked_add(copied)
                        .ok_or(ScratchError::BoundExceeded {
                            resource: "bytes",
                            actual: u64::MAX,
                            max: limits.max_bytes,
                        })?;
            }
            make_snapshot_evidence(tempdir.path(), limits, None, SNAPSHOT_MEDIA_TYPE)
        })();
        let base = match staged {
            Ok(base) => base,
            Err(error) => {
                return Err(cleanup_failed_tempdir(
                    tempdir,
                    "cleanup failed scratch staging",
                    error,
                ));
            }
        };
        Ok(Self {
            tempdir,
            repo_root,
            selected_paths: normalized_paths,
            workspace_nonce: Uuid::now_v7(),
            base,
            applied: None,
            limits,
        })
    }

    /// Return the unique scratch directory for an external verifier or provider runner.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.tempdir.path()
    }

    pub(crate) fn source_repository_root(&self) -> &Path {
        &self.repo_root
    }

    pub(crate) fn contains_source_path(&self, value: &str) -> Result<bool, ScratchError> {
        let path = PathBuf::from(normalize_user_path(value)?);
        Ok(self
            .selected_paths
            .iter()
            .any(|selected| selected == "." || path.starts_with(selected)))
    }
    pub(crate) fn validate_source_unchanged(&self) -> Result<(), ScratchError> {
        let comparison = Self::stage(&self.repo_root, &self.selected_paths, self.limits)?;
        let unchanged = comparison.base.sha256 == self.base.sha256;
        comparison.cleanup()?;
        if !unchanged {
            return Err(ScratchError::BaseChanged);
        }
        Ok(())
    }

    /// Return the immutable base snapshot Evidence captured immediately after staging.
    #[must_use]
    pub fn base_evidence(&self) -> &Evidence {
        &self.base
    }

    /// Read one regular file through the hardened workspace descriptor boundary and prove that
    /// the returned bytes are the file recorded in the immutable staged base Evidence.
    pub(crate) fn read_immutable_base_file(
        &self,
        relative: &str,
        max_bytes: u64,
    ) -> Result<Vec<u8>, ScratchError> {
        let relative = normalize_change_path(relative)?;

        #[cfg(unix)]
        {
            let root = open_root_directory(self.path())?;
            let mut budget = TraversalBudget {
                entries: 0,
                max_entries: self.limits.max_entries,
                max_files: self.limits.max_files,
            };
            let (opened, _) = open_relative_entry(&root.file, self.path(), &relative, &mut budget)?;
            if opened.file_type != FileType::RegularFile {
                return Err(ScratchError::UnsupportedEntry {
                    path: self.path().join(relative_to_path(&relative)),
                });
            }

            let expected = self.base_snapshot_file(&relative)?;
            if expected.bytes > max_bytes {
                return Err(ScratchError::BoundExceeded {
                    resource: "base file bytes",
                    actual: expected.bytes,
                    max: max_bytes,
                });
            }

            let mode = opened.mode;
            let mut file = opened.file;
            let mut contents = Vec::with_capacity(
                usize::try_from(expected.bytes.min(max_bytes)).unwrap_or(usize::MAX),
            );
            if inject_immutable_base_read_failure_if_requested() {
                return Err(ScratchError::Io {
                    operation: "read immutable scratch base file",
                    source: io::Error::other("injected immutable-base read failure"),
                });
            }
            Read::by_ref(&mut file)
                .take(max_bytes)
                .read_to_end(&mut contents)
                .map_err(|source| ScratchError::Io {
                    operation: "read immutable scratch base file",
                    source,
                })?;
            if contents.len() as u64 == max_bytes {
                let mut extra = [0_u8; 1];
                let extra_read = file.read(&mut extra).map_err(|source| ScratchError::Io {
                    operation: "read immutable scratch base file",
                    source,
                })?;
                if extra_read != 0 {
                    return Err(ScratchError::BoundExceeded {
                        resource: "base file bytes",
                        actual: max_bytes.saturating_add(1),
                        max: max_bytes,
                    });
                }
            }
            let actual = u64::try_from(contents.len()).unwrap_or(u64::MAX);
            if actual > max_bytes {
                return Err(ScratchError::BoundExceeded {
                    resource: "base file bytes",
                    actual,
                    max: max_bytes,
                });
            }
            let final_stat = fstat(&file).map_err(|source| ScratchError::Io {
                operation: "inspect immutable scratch base file after read",
                source: io::Error::from_raw_os_error(source.raw_os_error()),
            })?;
            let final_type = FileType::from_raw_mode(final_stat.st_mode);
            if final_type != FileType::RegularFile
                || final_stat.st_dev != opened.device
                || final_stat.st_ino != opened.inode
                || permission_mode(&final_stat) != mode
                || actual != expected.bytes
                || mode != expected.mode
                || digest_bytes(&contents) != expected.sha256
            {
                return Err(ScratchError::BaseChanged);
            }
            Ok(contents)
        }

        #[cfg(not(unix))]
        {
            Err(ScratchError::NoFollowUnsupported)
        }
    }

    /// Preflight the exact canonical Evidence size for one write without allocating its bytes.
    pub(crate) fn preflight_write_patch_evidence(
        &self,
        relative: &str,
        contents_bytes: u64,
        max_evidence_bytes: u64,
    ) -> Result<u64, ScratchError> {
        let relative = normalize_change_path(relative)?;
        if contents_bytes > self.limits.max_bytes {
            return Err(ScratchError::BoundExceeded {
                resource: "raw patch bytes",
                actual: contents_bytes,
                max: self.limits.max_bytes,
            });
        }
        let effective_limit = max_evidence_bytes.min(u64::from(self.limits.max_evidence_bytes));
        let effective_limit =
            u32::try_from(effective_limit).map_err(|_| ScratchError::InvalidLimits {
                details: "patch Evidence preflight limit is not representable",
            })?;
        let encoded_len = saturated_len_add(
            u64::try_from(PATCH_JSON_PREFIX.len()).unwrap_or(u64::MAX),
            u64::try_from(PATCH_JSON_SUFFIX.len()).unwrap_or(u64::MAX),
        );
        let encoded_len = saturated_len_add(
            encoded_len,
            patch_encoded_len_for_write(&relative, contents_bytes)?,
        );
        ensure_evidence_size(encoded_len, effective_limit)
    }

    fn base_snapshot_file(&self, relative: &str) -> Result<SnapshotFile, ScratchError> {
        let content = self
            .base
            .content
            .as_deref()
            .ok_or(ScratchError::BaseChanged)?;
        let snapshot = serde_json::from_str::<SnapshotDocument>(content).map_err(|source| {
            ScratchError::OperationalIncomplete {
                operation: "decode immutable scratch base Evidence",
                details: source.to_string(),
            }
        })?;
        if snapshot.schema_version != SNAPSHOT_SCHEMA_VERSION {
            return Err(ScratchError::BaseChanged);
        }
        snapshot
            .files
            .into_iter()
            .find(|file| file.path.as_str() == relative)
            .ok_or_else(|| ScratchError::MissingPath {
                path: RepoPath::from_str(relative).expect("normalized scratch file path"),
            })
    }

    /// Capture base, current result, and patch as separate complete inline Evidence records.
    ///
    /// # Errors
    ///
    /// Returns an error when the workspace or patch cannot be bounded, encoded, or validated.
    pub fn capture(
        &self,
        patch: &ScratchPatch,
        result_execution_id: Option<ObjectId>,
    ) -> Result<ScratchEvidence, ScratchError> {
        patch.preflight(self.limits)?;
        let patch = make_patch_evidence(patch, self.limits)?;
        if let Some(applied) = &self.applied {
            if applied.patch_sha256 != patch.sha256 {
                return Err(ScratchError::PatchEvidenceMismatch);
            }
        }
        let result = make_snapshot_evidence(
            self.path(),
            self.limits,
            result_execution_id,
            RESULT_MEDIA_TYPE,
        )?;
        if self
            .applied
            .as_ref()
            .is_some_and(|applied| applied.result_sha256 != result.sha256)
        {
            return Err(ScratchError::VerificationResultChanged);
        }
        Ok(ScratchEvidence {
            base: self.base.clone(),
            result,
            patch,
        })
    }

    pub(crate) fn capture_applied(
        &self,
        patch: &ScratchPatch,
        result_execution_id: Option<ObjectId>,
    ) -> Result<ScratchEvidence, ScratchError> {
        if self.applied.is_none() {
            return Err(ScratchError::PatchNotApplied);
        }
        self.capture(patch, result_execution_id)
    }

    pub(crate) fn validate_applied_patch_evidence(
        &self,
        patch: &ScratchPatch,
        evidence: &Evidence,
    ) -> Result<(), ScratchError> {
        let applied = self.applied.as_ref().ok_or(ScratchError::PatchNotApplied)?;
        patch.preflight(self.limits)?;
        let encoded = patch.encode()?;
        validate_canonical_patch_evidence(evidence, &encoded)?;
        let encoded_len = u64::try_from(encoded.len()).unwrap_or(u64::MAX);
        if evidence.execution_id.is_some()
            || evidence.limit_bytes != self.limits.max_evidence_bytes
            || evidence.observed_bytes != encoded_len
            || applied.patch_sha256 != evidence.sha256
        {
            return Err(ScratchError::PatchEvidenceMismatch);
        }
        Ok(())
    }

    /// Apply an unverified patch transactionally to this private workspace for Provider checks.
    ///
    /// The original repository is never written. The immutable base Evidence remains available
    /// so a later [`Self::capture`] binds the patched result to the exact staged preimage.
    // LLM contract: STAGED -> CANDIDATE_BUILT -> PREFLIGHTED -> APPLIED -> VERIFY_READY;
    // pre-publication failure terminal: INCOMPLETE, with the previous workspace preserved.
    ///
    /// # Errors
    ///
    /// Returns an error when the patch, staged base, candidate result, or resource bounds are
    /// invalid. Failure before the private publication point preserves the prior workspace.
    pub fn apply_for_verification(
        &mut self,
        patch: &ScratchPatch,
    ) -> Result<PatchApplication, ScratchError> {
        let patch_evidence = make_patch_evidence(patch, self.limits)?;
        self.apply_to_private_workspace(patch, patch_evidence.sha256)
    }

    /// Compare one complete safe-fix input and mint runtime-owned apply authorization only when
    /// the engine returns a verified result.
    ///
    /// # Errors
    ///
    /// Returns [`ScratchError::CandidateNotAuthorized`] for an engine rejection and preserves
    /// malformed comparison input as [`ScratchError::Verification`].
    ///
    /// Trust boundary: this mint is crate-internal because comparison inputs are data, not proof;
    /// external callers must not turn caller-fabricated inputs into authorization. A future CLI
    /// path must invoke this only through runtime-owned verification orchestration.
    #[allow(
        dead_code,
        reason = "reserved for the runtime-owned verification path that the CLI will call"
    )]
    pub(crate) fn authorize_safe_fix(
        &self,
        input: SafeFixComparisonInput<'_>,
    ) -> Result<SafeFixAuthorization, ScratchError> {
        let candidate = input.candidate.clone();
        let (patch_sha256, base_snapshot_sha256) = match input.patch_application {
            PatchApplication::Applied {
                patch_sha256,
                base_snapshot_sha256,
            }
            | PatchApplication::Conflict {
                patch_sha256,
                base_snapshot_sha256,
                ..
            } => (patch_sha256.clone(), base_snapshot_sha256.clone()),
        };
        let verification =
            compare_safe_fix(input).map_err(|source| ScratchError::Verification { source })?;
        let SafeFixVerification::Verified(verified_fix) = verification else {
            return Err(ScratchError::CandidateNotAuthorized);
        };
        Ok(SafeFixAuthorization {
            workspace_nonce: self.workspace_nonce,
            candidate,
            patch_sha256,
            base_snapshot_sha256,
            verified_fix,
        })
    }

    /// Apply a candidate patch to a private candidate workspace only after a pure engine
    /// verification, then publish it transactionally.
    ///
    /// This method never writes to the original repository. It checks that the current scratch
    /// snapshot is still the staged base, copies that base into an unexposed candidate directory,
    /// applies and validates every change there, and swaps the published [`TempDir`] only after
    /// all pre-publication operations succeed. A pre-publication error leaves the published
    /// workspace byte-identical. After the publication commit point, failure to remove the
    /// replaced directory is returned as [`ScratchError::PublishedCleanupIncomplete`], carrying
    /// the committed [`PatchApplication`] so callers cannot mistake the result for an unapplied
    /// candidate.
    ///
    /// The candidate path is not exposed before success, so the concurrency boundary is the
    /// same-process owner of this workspace: callers must not concurrently mutate or use a
    /// retained path while this method runs. This does not claim hostile same-user sandboxing.
    // LLM contract: VERIFIED -> CANDIDATE_BUILT -> PREFLIGHTED -> APPLIED -> PUBLISHED;
    // pre-publication failure terminal: INCOMPLETE, with the previous workspace preserved;
    // post-publication cleanup failure terminal: PUBLISHED_CLEANUP_INCOMPLETE, candidate committed.
    ///
    /// # Errors
    ///
    /// Returns an error when the authorization bindings, candidate, patch evidence, staged base,
    /// resource limits, or filesystem state do not match.
    pub fn apply_verified(
        &mut self,
        candidate: &FixCandidate,
        patch: &ScratchPatch,
        patch_evidence: &Evidence,
        authorization: SafeFixAuthorization,
    ) -> Result<PatchApplication, ScratchError> {
        let SafeFixAuthorization {
            workspace_nonce,
            candidate: authorized_candidate,
            patch_sha256,
            base_snapshot_sha256,
            verified_fix: _verified_fix,
        } = authorization;
        if workspace_nonce != self.workspace_nonce
            || authorized_candidate != *candidate
            || patch_sha256 != patch_evidence.sha256
            || base_snapshot_sha256 != self.base.sha256
        {
            return Err(ScratchError::CandidateNotAuthorized);
        }
        candidate.validate()?;
        if candidate.applicability != Applicability::Safe || !candidate.tool_native {
            return Err(ScratchError::CandidateNotAuthorized);
        }
        patch.preflight(self.limits)?;
        let encoded_patch = patch.encode()?;
        validate_patch_evidence(candidate, patch_evidence, &encoded_patch)?;

        if self
            .applied
            .as_ref()
            .is_some_and(|applied| applied.authorization_consumed)
        {
            return Err(ScratchError::AuthorizationAlreadyConsumed);
        }
        if self.applied.is_some() {
            self.validate_source_unchanged()?;
            self.capture_applied(patch, None)?;
            let Some(applied) = self.applied.as_mut() else {
                return Err(ScratchError::PatchNotApplied);
            };
            applied.authorization_consumed = true;
            return Ok(PatchApplication::Applied {
                patch_sha256: patch_evidence.sha256.clone(),
                base_snapshot_sha256: self.base.sha256.clone(),
            });
        }

        let result = self.apply_to_private_workspace(patch, patch_evidence.sha256.clone());
        if let Some(applied) = &mut self.applied {
            applied.authorization_consumed = true;
        }
        result
    }

    fn apply_to_private_workspace(
        &mut self,
        patch: &ScratchPatch,
        patch_sha256: Sha256Digest,
    ) -> Result<PatchApplication, ScratchError> {
        if self.applied.is_some() {
            return Err(ScratchError::PatchAlreadyApplied);
        }
        patch.preflight(self.limits)?;
        let current = scan_workspace(self.path(), self.limits)?;
        if digest_bytes(&current.encoded) != self.base.sha256 {
            return Err(ScratchError::BaseChanged);
        }

        let candidate =
            create_safe_tempdir("diagnostic-triage-scratch-candidate-", &self.repo_root)?;
        #[cfg(all(test, unix))]
        LAST_TRANSACTION_CANDIDATE_PATH.with(|path| {
            *path.borrow_mut() = Some(candidate.path().to_owned());
        });
        let prepared = (|| {
            let candidate_base =
                copy_workspace(self.path(), candidate.path(), &current, self.limits)?;
            preflight_changes(candidate.path(), &candidate_base, patch, self.limits)?;
            for change in &patch.changes {
                apply_change(candidate.path(), change)?;
            }
            // A final bounded scan validates the complete candidate result before publication.
            scan_workspace(candidate.path(), self.limits)
        })();
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(cleanup_failed_tempdir(
                    candidate,
                    "cleanup failed transactional candidate",
                    error,
                ));
            }
        };
        let result_sha256 = digest_bytes(&prepared.encoded);

        let application = PatchApplication::Applied {
            patch_sha256: patch_sha256.clone(),
            base_snapshot_sha256: self.base.sha256.clone(),
        };
        let old_tempdir = std::mem::replace(&mut self.tempdir, candidate);
        self.applied = Some(AppliedScratchState {
            patch_sha256,
            result_sha256,
            authorization_consumed: false,
        });
        let cleanup_result = old_tempdir.close();
        #[cfg(all(test, unix))]
        let cleanup_result = inject_replaced_workspace_cleanup_result(cleanup_result);
        if let Err(source) = cleanup_result {
            return Err(ScratchError::PublishedCleanupIncomplete {
                application,
                source,
            });
        }

        Ok(application)
    }

    /// Explicitly remove the unique workspace and surface cleanup failures as incomplete errors.
    /// Dropping a workspace without calling this method uses [`TempDir`]'s best-effort cleanup and
    /// cannot report a failure; callers requiring cleanup evidence must call this method.
    ///
    /// # Errors
    ///
    /// Returns an error when the temporary workspace cannot be removed.
    pub fn cleanup(self) -> Result<(), ScratchError> {
        self.tempdir
            .close()
            .map_err(|source| ScratchError::OperationalIncomplete {
                operation: "cleanup scratch workspace",
                details: source.to_string(),
            })
    }
}

#[derive(Debug, Error)]
pub enum ScratchError {
    #[error("invalid repository-relative path {path:?}: {reason}")]
    InvalidPath { path: String, reason: &'static str },
    #[error("repository path does not exist: {path}")]
    MissingPath { path: RepoPath },
    #[error("repository path is not a directory: {path}")]
    NotDirectory { path: PathBuf },
    #[error("symlink path rejected: {path}")]
    SymlinkPath { path: PathBuf },
    #[error("temporary workspace location is inside the original repository: {path}")]
    UnsafeTempDir { path: PathBuf },
    #[error("no-follow regular-file opens are unsupported on this platform")]
    NoFollowUnsupported,
    #[error("source file changed between traversal and descriptor open: {path}")]
    SourceChanged { path: PathBuf },
    #[error("copied scratch base changed during transactional preparation")]
    CandidateBaseChanged,
    #[error("unsupported filesystem entry: {path}")]
    UnsupportedEntry { path: PathBuf },
    #[error("filesystem entry is not valid UTF-8: {path}")]
    NonUtf8Path { path: PathBuf },
    #[error("{resource} bound exceeded: {actual} > {max}")]
    BoundExceeded {
        resource: &'static str,
        actual: u64,
        max: u64,
    },
    #[error("duplicate patch target: {path}")]
    DuplicatePatchPath { path: String },
    #[error("patch target is missing: {path}")]
    MissingPatchTarget { path: String },
    #[error("scratch base changed before explicit apply")]
    BaseChanged,
    #[error("private verification result changed after patch application")]
    VerificationResultChanged,
    #[error("candidate is not authorized for explicit scratch apply")]
    CandidateNotAuthorized,
    #[error("candidate patch evidence does not match the deterministic patch")]
    PatchEvidenceMismatch,
    #[error("a patch was already applied to this private workspace")]
    PatchAlreadyApplied,
    #[error("the verified safe-fix authorization was already consumed")]
    AuthorizationAlreadyConsumed,
    #[error("the private workspace has no applied patch to verify")]
    PatchNotApplied,
    #[error("candidate patch evidence is not complete inline PATCH evidence")]
    InvalidPatchEvidence,
    #[error("safe-fix verification input is invalid: {source}")]
    Verification {
        #[source]
        source: VerificationError,
    },
    #[error("invalid scratch limits: {details}")]
    InvalidLimits { details: &'static str },
    #[error("operational/incomplete scratch operation {operation}: {details}")]
    OperationalIncomplete {
        operation: &'static str,
        details: String,
    },
    #[error("scratch patch was published, but the replaced workspace cleanup failed: {source}")]
    PublishedCleanupIncomplete {
        application: PatchApplication,
        #[source]
        source: io::Error,
    },
    #[error("I/O failure during {operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("failed to encode scratch evidence: {source}")]
    Serialization { source: serde_json::Error },
    #[error(transparent)]
    Contract(#[from] ContractError),
}

impl ScratchError {
    /// Return the committed application carried by a post-publication cleanup failure.
    #[must_use]
    pub fn published_application(&self) -> Option<&PatchApplication> {
        match self {
            Self::PublishedCleanupIncomplete { application, .. } => Some(application),
            _ => None,
        }
    }
}

#[derive(Deserialize, Serialize)]
struct SnapshotDocument {
    schema_version: String,
    files: Vec<SnapshotFile>,
    total_bytes: u64,
}

#[derive(Deserialize, Serialize)]
struct SnapshotFile {
    path: RepoPath,
    bytes: u64,
    #[cfg(unix)]
    mode: u32,
    sha256: Sha256Digest,
}

struct WorkspaceScan {
    encoded: Vec<u8>,
    total_bytes: u64,
}

const PATCH_JSON_PREFIX: &str = "{\"version\":1,\"changes\":[";
const PATCH_JSON_SUFFIX: &str = "]}";
const PATCH_WRITE_PREFIX: &str = "{\"kind\":\"WRITE\",\"path\":";
const PATCH_WRITE_CONTENT_PREFIX: &str = ",\"content_hex\":\"";
const PATCH_WRITE_SUFFIX: &str = "\"}";
const PATCH_DELETE_PREFIX: &str = "{\"kind\":\"DELETE\",\"path\":";
const PATCH_DELETE_SUFFIX: &str = "}";
const SNAPSHOT_JSON_PREFIX: &str =
    "{\"schema_version\":\"diagnostic-triage.scratch-snapshot/v1\",\"files\":[";
const SNAPSHOT_TOTAL_BYTES_PREFIX: &str = "],\"total_bytes\":";
const SNAPSHOT_JSON_SUFFIX: &str = "}";

#[derive(Serialize)]
struct WirePatch<'a> {
    version: u8,
    changes: Vec<WireChange<'a>>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "UPPERCASE")]
enum WireChange<'a> {
    Write { path: &'a str, content_hex: String },
    Delete { path: &'a str },
}

#[derive(Default)]
struct ByteCounter {
    bytes: u64,
}

impl Write for ByteCounter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let bytes = u64::try_from(buffer.len())
            .map_err(|_| io::Error::other("serialized JSON length overflow"))?;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| io::Error::other("serialized JSON length overflow"))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn serialized_json_len(value: &(impl Serialize + ?Sized)) -> Result<u64, ScratchError> {
    let mut counter = ByteCounter::default();
    serde_json::to_writer(&mut counter, value)
        .map_err(|source| ScratchError::Serialization { source })?;
    Ok(counter.bytes)
}

fn saturated_len_add(left: u64, right: u64) -> u64 {
    left.saturating_add(right)
}

fn decimal_len(mut value: u64) -> u64 {
    let mut digits = 1_u64;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}

fn ensure_evidence_size(actual: u64, max_evidence_bytes: u32) -> Result<u64, ScratchError> {
    let max = u64::from(max_evidence_bytes);
    if actual > max {
        return Err(ScratchError::BoundExceeded {
            resource: "Evidence bytes",
            actual,
            max,
        });
    }
    Ok(actual)
}

fn patch_encoded_len(
    changes: &[ScratchChange],
    max_evidence_bytes: u32,
) -> Result<u64, ScratchError> {
    let mut encoded_len = saturated_len_add(
        u64::try_from(PATCH_JSON_PREFIX.len()).unwrap_or(u64::MAX),
        u64::try_from(PATCH_JSON_SUFFIX.len()).unwrap_or(u64::MAX),
    );
    ensure_evidence_size(encoded_len, max_evidence_bytes)?;

    for (index, change) in changes.iter().enumerate() {
        if index > 0 {
            encoded_len = saturated_len_add(encoded_len, 1);
        }
        let change_len = match change {
            ScratchChange::Write { contents, .. } => patch_encoded_len_for_write(
                patch_path(change),
                u64::try_from(contents.len()).unwrap_or(u64::MAX),
            )?,
            ScratchChange::Delete { .. } => {
                let path_len = serialized_json_len(patch_path(change))?;
                [PATCH_DELETE_PREFIX.len(), PATCH_DELETE_SUFFIX.len()]
                    .into_iter()
                    .map(|length| u64::try_from(length).unwrap_or(u64::MAX))
                    .fold(path_len, saturated_len_add)
            }
        };
        encoded_len = saturated_len_add(encoded_len, change_len);
        ensure_evidence_size(encoded_len, max_evidence_bytes)?;
    }
    Ok(encoded_len)
}

fn patch_encoded_len_for_write(path: &str, contents_bytes: u64) -> Result<u64, ScratchError> {
    let path_len = serialized_json_len(path)?;
    let content_hex_len = contents_bytes.saturating_mul(2);
    Ok([
        PATCH_WRITE_PREFIX.len(),
        PATCH_WRITE_CONTENT_PREFIX.len(),
        PATCH_WRITE_SUFFIX.len(),
    ]
    .into_iter()
    .map(|length| u64::try_from(length).unwrap_or(u64::MAX))
    .fold(path_len, saturated_len_add)
    .saturating_add(content_hex_len))
}

fn snapshot_encoded_len(
    encoded_files_len: u64,
    total_bytes: u64,
    max_evidence_bytes: u32,
) -> Result<u64, ScratchError> {
    let encoded_len = [
        u64::try_from(SNAPSHOT_JSON_PREFIX.len()).unwrap_or(u64::MAX),
        encoded_files_len,
        u64::try_from(SNAPSHOT_TOTAL_BYTES_PREFIX.len()).unwrap_or(u64::MAX),
        decimal_len(total_bytes),
        u64::try_from(SNAPSHOT_JSON_SUFFIX.len()).unwrap_or(u64::MAX),
    ]
    .into_iter()
    .fold(0_u64, saturated_len_add);
    ensure_evidence_size(encoded_len, max_evidence_bytes)
}

fn validate_limits(limits: ScratchLimits) -> Result<(), ScratchError> {
    if limits.max_entries == 0 {
        return Err(ScratchError::InvalidLimits {
            details: "max_entries must be positive",
        });
    }
    if limits.max_evidence_bytes == 0 {
        return Err(ScratchError::InvalidLimits {
            details: "max_evidence_bytes must be positive",
        });
    }
    if limits.max_evidence_bytes > DEFAULT_MAX_EVIDENCE_BYTES {
        return Err(ScratchError::InvalidLimits {
            details: "max_evidence_bytes exceeds the Evidence contract limit",
        });
    }
    Ok(())
}

fn create_safe_tempdir(prefix: &str, repo_root: &Path) -> Result<TempDir, ScratchError> {
    let temp_parent =
        fs::canonicalize(std::env::temp_dir()).map_err(|source| ScratchError::Io {
            operation: "canonicalize temporary directory parent",
            source,
        })?;
    if temp_parent.starts_with(repo_root) {
        return Err(ScratchError::UnsafeTempDir { path: temp_parent });
    }
    let tempdir = Builder::new()
        .prefix(prefix)
        .tempdir_in(temp_parent)
        .map_err(|source| ScratchError::Io {
            operation: "create temporary scratch directory",
            source,
        })?;
    validate_created_tempdir(tempdir, repo_root)
}

fn validate_created_tempdir(tempdir: TempDir, repo_root: &Path) -> Result<TempDir, ScratchError> {
    let temp_path = match fs::canonicalize(tempdir.path()) {
        Ok(path) => path,
        Err(source) => {
            return Err(cleanup_failed_tempdir(
                tempdir,
                "cleanup scratch directory after location inspection failed",
                ScratchError::Io {
                    operation: "canonicalize temporary scratch directory",
                    source,
                },
            ));
        }
    };
    if temp_path.starts_with(repo_root) {
        return match tempdir.close() {
            Ok(()) => Err(ScratchError::UnsafeTempDir { path: temp_path }),
            Err(source) => Err(ScratchError::OperationalIncomplete {
                operation: "cleanup rejected scratch directory inside repository",
                details: format!(
                    "rejected temporary directory {} could not be removed: {source}",
                    temp_path.display()
                ),
            }),
        };
    }
    Ok(tempdir)
}

fn cleanup_failed_tempdir(
    tempdir: TempDir,
    operation: &'static str,
    primary: ScratchError,
) -> ScratchError {
    let path = tempdir.path().to_path_buf();
    match tempdir.close() {
        Ok(()) => primary,
        Err(source) => ScratchError::OperationalIncomplete {
            operation,
            details: format!(
                "primary failure: {primary}; temporary directory {} could not be removed: {source}",
                path.display()
            ),
        },
    }
}

fn normalize_user_path(value: &str) -> Result<String, ScratchError> {
    if value.len() > MAX_REPO_PATH_BYTES || value.chars().count() > MAX_REPO_PATH_CHARS {
        return Err(ScratchError::InvalidPath {
            path: bounded_path_label(value),
            reason: "path exceeds the RepoPath contract",
        });
    }
    if value.is_empty() || value.contains(['\\', '\0']) {
        return Err(ScratchError::InvalidPath {
            path: value.to_owned(),
            reason: "empty, backslash, or NUL",
        });
    }
    let path = Path::new(value);
    if path.is_absolute() {
        return Err(ScratchError::InvalidPath {
            path: value.to_owned(),
            reason: "absolute path",
        });
    }
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(component) => {
                let component = component
                    .to_str()
                    .ok_or_else(|| ScratchError::NonUtf8Path {
                        path: PathBuf::from(value),
                    })?;
                if components.is_empty()
                    && component.len() >= 2
                    && component.as_bytes()[0].is_ascii_alphabetic()
                    && component.as_bytes()[1] == b':'
                {
                    return Err(ScratchError::InvalidPath {
                        path: value.to_owned(),
                        reason: "drive-prefixed path",
                    });
                }
                if component.contains(['\\', '\0']) {
                    return Err(ScratchError::InvalidPath {
                        path: value.to_owned(),
                        reason: "backslash or NUL",
                    });
                }
                components.push(component.to_owned());
            }
            Component::ParentDir => {
                return Err(ScratchError::InvalidPath {
                    path: value.to_owned(),
                    reason: "parent traversal",
                });
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(ScratchError::InvalidPath {
                    path: value.to_owned(),
                    reason: "absolute or prefixed path",
                });
            }
        }
    }
    let normalized = if components.is_empty() {
        ".".to_owned()
    } else {
        components.join("/")
    };
    RepoPath::from_str(&normalized).map_err(|_| ScratchError::InvalidPath {
        path: value.to_owned(),
        reason: "path exceeds or violates the RepoPath contract",
    })?;
    Ok(normalized)
}

fn bounded_path_label(value: &str) -> String {
    const MAX_ERROR_PATH_CHARS: usize = 256;
    let mut characters = value.chars();
    let mut label = characters
        .by_ref()
        .take(MAX_ERROR_PATH_CHARS)
        .collect::<String>();
    if characters.next().is_some() {
        label.push('…');
    }
    label
}

fn normalize_change_path(value: &str) -> Result<String, ScratchError> {
    let normalized = normalize_user_path(value)?;
    if normalized == "." {
        return Err(ScratchError::InvalidPath {
            path: value.to_owned(),
            reason: "scratch patch target must be a file path",
        });
    }
    Ok(normalized)
}

fn relative_to_path(relative: &str) -> PathBuf {
    if relative == "." {
        PathBuf::new()
    } else {
        relative.split('/').collect()
    }
}

fn prune_nested_paths(paths: &mut Vec<String>) {
    let mut retained = BTreeSet::new();
    paths.retain(|path| {
        if retained.contains(".") {
            return false;
        }
        let mut ancestor = String::new();
        for component in path
            .split('/')
            .take(path.split('/').count().saturating_sub(1))
        {
            if !ancestor.is_empty() {
                ancestor.push('/');
            }
            ancestor.push_str(component);
            if retained.contains(&ancestor) {
                return false;
            }
        }
        retained.insert(path.clone())
    });
}

struct OpenedRegularFile {
    file: File,
    #[cfg(unix)]
    mode: u32,
}

struct CollectedFiles {
    files: BTreeMap<String, OpenedRegularFile>,
    entry_count: usize,
}

#[cfg(unix)]
#[derive(Debug)]
struct OpenedEntry {
    file: File,
    file_type: FileType,
    mode: u32,
    #[cfg(unix)]
    device: i32,
    #[cfg(unix)]
    inode: u64,
}

#[cfg(unix)]
struct TraversalBudget {
    entries: usize,
    max_entries: usize,
    max_files: usize,
}

#[cfg(unix)]
impl TraversalBudget {
    fn visit(&mut self) -> Result<(), ScratchError> {
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or(ScratchError::BoundExceeded {
                resource: "traversal entries",
                actual: u64::MAX,
                max: u64::try_from(self.max_entries).unwrap_or(u64::MAX),
            })?;
        if self.entries > self.max_entries {
            return Err(ScratchError::BoundExceeded {
                resource: "traversal entries",
                actual: u64::try_from(self.entries).unwrap_or(u64::MAX),
                max: u64::try_from(self.max_entries).unwrap_or(u64::MAX),
            });
        }
        Ok(())
    }
}

#[cfg(unix)]
fn collect_selected_files(
    root: &Path,
    selected_paths: &[String],
    limits: ScratchLimits,
) -> Result<CollectedFiles, ScratchError> {
    let root_entry = open_root_directory(root)?;
    let mut collected = CollectedFiles {
        files: BTreeMap::new(),
        entry_count: 0,
    };
    let mut budget = TraversalBudget {
        entries: 0,
        max_entries: limits.max_entries,
        max_files: limits.max_files,
    };
    for relative in selected_paths {
        let (entry, depth, already_charged) = if relative == "." {
            (
                OpenedEntry {
                    file: root_entry
                        .file
                        .try_clone()
                        .map_err(|source| ScratchError::Io {
                            operation: "duplicate repository root descriptor",
                            source,
                        })?,
                    file_type: root_entry.file_type,
                    mode: root_entry.mode,
                    device: root_entry.device,
                    inode: root_entry.inode,
                },
                0,
                false,
            )
        } else {
            let (entry, depth) =
                open_relative_entry(&root_entry.file, root, relative, &mut budget)?;
            (entry, depth, true)
        };
        collect_open_entry(
            root,
            relative,
            entry,
            depth,
            already_charged,
            &mut collected,
            &mut budget,
        )?;
    }
    collected.entry_count = budget.entries;
    Ok(collected)
}

#[cfg(not(unix))]
fn collect_selected_files(
    _root: &Path,
    _selected_paths: &[String],
    _limits: ScratchLimits,
) -> Result<CollectedFiles, ScratchError> {
    Err(ScratchError::NoFollowUnsupported)
}

#[cfg(unix)]
fn open_root_directory(path: &Path) -> Result<OpenedEntry, ScratchError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|source| ScratchError::Io {
        operation: "open repository root without following symlinks",
        source: io::Error::from_raw_os_error(source.raw_os_error()),
    })?;
    let file = File::from(descriptor);
    let stat = fstat(&file).map_err(|source| ScratchError::Io {
        operation: "inspect repository root descriptor",
        source: io::Error::from_raw_os_error(source.raw_os_error()),
    })?;
    let file_type = FileType::from_raw_mode(stat.st_mode);
    if file_type != FileType::Directory {
        return Err(ScratchError::NotDirectory {
            path: path.to_path_buf(),
        });
    }
    Ok(OpenedEntry {
        file,
        file_type,
        mode: permission_mode(&stat),
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

#[cfg(unix)]
fn open_relative_entry(
    root_descriptor: &File,
    root: &Path,
    relative: &str,
    budget: &mut TraversalBudget,
) -> Result<(OpenedEntry, usize), ScratchError> {
    let mut parent = root_descriptor
        .try_clone()
        .map_err(|source| ScratchError::Io {
            operation: "duplicate traversal root descriptor",
            source,
        })?;
    let component_count = relative.split('/').count();
    if component_count > MAX_TRAVERSAL_DEPTH {
        return Err(ScratchError::BoundExceeded {
            resource: "traversal depth",
            actual: u64::try_from(component_count).unwrap_or(u64::MAX),
            max: u64::try_from(MAX_TRAVERSAL_DEPTH).unwrap_or(u64::MAX),
        });
    }
    let mut component_relative = String::new();
    for (index, component) in relative.split('/').enumerate() {
        budget.visit()?;
        if index > 0 {
            component_relative.push('/');
        }
        component_relative.push_str(component);
        let display_path = root.join(relative_to_path(&component_relative));
        let opened = open_entry_no_follow(
            &parent,
            OsStr::new(component),
            &display_path,
            &component_relative,
        )?;
        if index + 1 == component_count {
            return Ok((opened, component_count));
        }
        if opened.file_type != FileType::Directory {
            return Err(ScratchError::NotDirectory { path: display_path });
        }
        parent = opened.file;
    }
    Err(ScratchError::MissingPath {
        path: RepoPath::from_str(relative).expect("validated repository path"),
    })
}

#[cfg(unix)]
fn open_entry_no_follow(
    parent: &File,
    name: &OsStr,
    display_path: &Path,
    relative: &str,
) -> Result<OpenedEntry, ScratchError> {
    let expected = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
        let source = io::Error::from_raw_os_error(source.raw_os_error());
        if source.kind() == io::ErrorKind::NotFound {
            ScratchError::MissingPath {
                path: RepoPath::from_str(relative).expect("validated repository path"),
            }
        } else {
            ScratchError::Io {
                operation: "inspect descriptor-relative entry",
                source,
            }
        }
    })?;
    let expected_type = FileType::from_raw_mode(expected.st_mode);
    if expected_type == FileType::Symlink {
        return Err(ScratchError::SymlinkPath {
            path: display_path.to_path_buf(),
        });
    }
    if expected_type != FileType::RegularFile && expected_type != FileType::Directory {
        return Err(ScratchError::UnsupportedEntry {
            path: display_path.to_path_buf(),
        });
    }

    #[cfg(all(test, unix))]
    run_open_entry_race_hook();

    let mut flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    if expected_type == FileType::Directory {
        flags |= OFlags::DIRECTORY;
    } else {
        // Prevent a regular-file-to-FIFO replacement from blocking before fstat rejects it.
        flags |= OFlags::NONBLOCK;
    }
    let descriptor =
        openat(parent, name, flags, Mode::empty()).map_err(|source| ScratchError::Io {
            operation: "open descriptor-relative entry without following symlinks",
            source: io::Error::from_raw_os_error(source.raw_os_error()),
        })?;
    let file = File::from(descriptor);
    let opened = fstat(&file).map_err(|source| ScratchError::Io {
        operation: "inspect descriptor-relative opened entry",
        source: io::Error::from_raw_os_error(source.raw_os_error()),
    })?;
    let opened_type = FileType::from_raw_mode(opened.st_mode);
    if opened_type != expected_type
        || opened.st_dev != expected.st_dev
        || opened.st_ino != expected.st_ino
    {
        return Err(ScratchError::SourceChanged {
            path: display_path.to_path_buf(),
        });
    }
    if opened_type != FileType::RegularFile && opened_type != FileType::Directory {
        return Err(ScratchError::UnsupportedEntry {
            path: display_path.to_path_buf(),
        });
    }
    Ok(OpenedEntry {
        file,
        file_type: opened_type,
        mode: permission_mode(&opened),
        device: opened.st_dev,
        inode: opened.st_ino,
    })
}

#[cfg(unix)]
fn permission_mode(stat: &Stat) -> u32 {
    u32::from(stat.st_mode) & PERMISSION_MODE_MASK
}

#[cfg(unix)]
fn collect_open_entry(
    root: &Path,
    relative: &str,
    entry: OpenedEntry,
    depth: usize,
    already_charged: bool,
    collected: &mut CollectedFiles,
    budget: &mut TraversalBudget,
) -> Result<(), ScratchError> {
    if !already_charged {
        budget.visit()?;
    }
    if entry.file_type == FileType::RegularFile {
        if !collected.files.contains_key(relative) && collected.files.len() >= budget.max_files {
            return Err(ScratchError::BoundExceeded {
                resource: "files",
                actual: u64::try_from(collected.files.len())
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
                max: u64::try_from(budget.max_files).unwrap_or(u64::MAX),
            });
        }
        collected.files.insert(
            relative.to_owned(),
            OpenedRegularFile {
                file: entry.file,
                mode: entry.mode,
            },
        );
        return Ok(());
    }
    if entry.file_type != FileType::Directory {
        return Err(ScratchError::UnsupportedEntry {
            path: root.join(relative_to_path(relative)),
        });
    }
    if depth >= MAX_TRAVERSAL_DEPTH {
        return Err(ScratchError::BoundExceeded {
            resource: "traversal depth",
            actual: u64::try_from(depth).unwrap_or(u64::MAX).saturating_add(1),
            max: u64::try_from(MAX_TRAVERSAL_DEPTH).unwrap_or(u64::MAX),
        });
    }

    let mut directory = Dir::read_from(&entry.file).map_err(|source| ScratchError::Io {
        operation: "read descriptor-relative directory",
        source: io::Error::from_raw_os_error(source.raw_os_error()),
    })?;
    for child in &mut directory {
        let child = child.map_err(|source| ScratchError::Io {
            operation: "read descriptor-relative directory entry",
            source: io::Error::from_raw_os_error(source.raw_os_error()),
        })?;
        let bytes = child.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let name = std::str::from_utf8(bytes).map_err(|_| ScratchError::NonUtf8Path {
            path: root
                .join(relative_to_path(relative))
                .join(OsStr::from_bytes(bytes)),
        })?;
        let child_relative = if relative == "." {
            name.to_owned()
        } else {
            format!("{relative}/{name}")
        };
        let child_relative = normalize_user_path(&child_relative)?;
        let display_path = root.join(relative_to_path(&child_relative));
        let opened = open_entry_no_follow(
            &entry.file,
            OsStr::new(name),
            &display_path,
            &child_relative,
        )?;
        collect_open_entry(
            root,
            &child_relative,
            opened,
            depth + 1,
            false,
            collected,
            budget,
        )?;
    }
    Ok(())
}

fn copy_bounded(
    mut source: OpenedRegularFile,
    destination: &Path,
    remaining: u64,
) -> Result<u64, ScratchError> {
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(|source| ScratchError::Io {
            operation: "create scratch file",
            source,
        })?;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES].into_boxed_slice();
    let mut total = 0_u64;
    loop {
        let available = remaining.saturating_sub(total);
        let requested = usize::try_from(available.min(COPY_BUFFER_BYTES as u64)).unwrap_or(0);
        let requested = if requested == 0 { 1 } else { requested };
        let read = source
            .file
            .read(&mut buffer[..requested])
            .map_err(|source| ScratchError::Io {
                operation: "read source file for copy",
                source,
            })?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(ScratchError::BoundExceeded {
                resource: "bytes",
                actual: u64::MAX,
                max: remaining,
            })?;
        if total > remaining {
            return Err(ScratchError::BoundExceeded {
                resource: "bytes",
                actual: total,
                max: remaining,
            });
        }
        output
            .write_all(&buffer[..read])
            .map_err(|source| ScratchError::Io {
                operation: "write scratch file",
                source,
            })?;
    }
    output.flush().map_err(|source| ScratchError::Io {
        operation: "flush scratch file",
        source,
    })?;
    #[cfg(unix)]
    fs::set_permissions(destination, fs::Permissions::from_mode(source.mode)).map_err(
        |source| ScratchError::Io {
            operation: "preserve scratch file mode",
            source,
        },
    )?;
    Ok(total)
}

fn copy_workspace(
    source_root: &Path,
    destination_root: &Path,
    expected: &WorkspaceScan,
    limits: ScratchLimits,
) -> Result<WorkspaceScan, ScratchError> {
    let files = collect_workspace_files(source_root, limits)?;

    let mut copied_bytes = 0_u64;
    for (relative, source) in files {
        let destination = destination_root.join(relative_to_path(&relative));
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|source| ScratchError::Io {
                operation: "create transactional scratch parent",
                source,
            })?;
        }
        let copied = copy_bounded(
            source,
            &destination,
            limits.max_bytes.saturating_sub(copied_bytes),
        )?;
        copied_bytes = copied_bytes
            .checked_add(copied)
            .ok_or(ScratchError::BoundExceeded {
                resource: "bytes",
                actual: u64::MAX,
                max: limits.max_bytes,
            })?;
    }

    let candidate = scan_workspace(destination_root, limits)?;
    if candidate.encoded != expected.encoded {
        return Err(ScratchError::CandidateBaseChanged);
    }
    Ok(candidate)
}

fn make_snapshot_evidence(
    root: &Path,
    limits: ScratchLimits,
    execution_id: Option<ObjectId>,
    media_type: &str,
) -> Result<Evidence, ScratchError> {
    let scan = scan_workspace(root, limits)?;
    make_evidence(
        EvidenceSource::Artifact,
        media_type,
        &scan.encoded,
        execution_id,
        limits,
    )
}

fn make_patch_evidence(
    patch: &ScratchPatch,
    limits: ScratchLimits,
) -> Result<Evidence, ScratchError> {
    let expected_len = patch.preflight(limits)?;
    let encoded = patch.encode()?;
    debug_assert_eq!(
        u64::try_from(encoded.len()).unwrap_or(u64::MAX),
        expected_len
    );
    make_evidence(
        EvidenceSource::Patch,
        PATCH_MEDIA_TYPE,
        &encoded,
        None,
        limits,
    )
}

fn make_evidence(
    source: EvidenceSource,
    media_type: &str,
    bytes: &[u8],
    execution_id: Option<ObjectId>,
    limits: ScratchLimits,
) -> Result<Evidence, ScratchError> {
    let retained_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if retained_bytes > u64::from(limits.max_evidence_bytes) {
        return Err(ScratchError::BoundExceeded {
            resource: "Evidence bytes",
            actual: retained_bytes,
            max: u64::from(limits.max_evidence_bytes),
        });
    }
    let content =
        String::from_utf8(bytes.to_owned()).map_err(|_| ScratchError::OperationalIncomplete {
            operation: "encode inline Evidence",
            details: "scratch Evidence must be UTF-8 JSON".to_owned(),
        })?;
    let evidence = Evidence {
        schema_version: EvidenceSchemaVersion::V1,
        evidence_id: fresh_object_id()?,
        execution_id,
        source,
        media_type: media_type.to_owned(),
        retained_bytes,
        observed_bytes: retained_bytes,
        limit_bytes: limits.max_evidence_bytes,
        truncated: false,
        sha256: digest_bytes(bytes),
        relative_path: None,
        content: Some(content),
    };
    evidence.validate()?;
    Ok(evidence)
}

fn scan_workspace(root: &Path, limits: ScratchLimits) -> Result<WorkspaceScan, ScratchError> {
    let files = collect_workspace_files(root, limits)?;
    let mut total_bytes = 0_u64;
    let mut snapshot_files = Vec::new();
    let mut encoded_files_len = 0_u64;
    snapshot_encoded_len(encoded_files_len, total_bytes, limits.max_evidence_bytes)?;
    for (relative, file) in files {
        let digested = digest_file(file, limits.max_bytes.saturating_sub(total_bytes))?;
        let next_total_bytes =
            total_bytes
                .checked_add(digested.bytes)
                .ok_or(ScratchError::BoundExceeded {
                    resource: "bytes",
                    actual: u64::MAX,
                    max: limits.max_bytes,
                })?;
        let snapshot_file = SnapshotFile {
            path: RepoPath::from_str(&relative).map_err(|_| ScratchError::InvalidPath {
                path: relative.clone(),
                reason: "workspace path is not canonical repository-relative UTF-8",
            })?,
            bytes: digested.bytes,
            #[cfg(unix)]
            mode: digested.mode,
            sha256: digested.sha256,
        };
        let separator_len = u64::from(!snapshot_files.is_empty());
        let next_encoded_files_len = saturated_len_add(
            saturated_len_add(encoded_files_len, separator_len),
            serialized_json_len(&snapshot_file)?,
        );
        snapshot_encoded_len(
            next_encoded_files_len,
            next_total_bytes,
            limits.max_evidence_bytes,
        )?;
        encoded_files_len = next_encoded_files_len;
        total_bytes = next_total_bytes;
        snapshot_files.push(snapshot_file);
    }
    let expected_len =
        snapshot_encoded_len(encoded_files_len, total_bytes, limits.max_evidence_bytes)?;
    let document = SnapshotDocument {
        schema_version: SNAPSHOT_SCHEMA_VERSION.to_owned(),
        files: snapshot_files,
        total_bytes,
    };
    #[cfg(all(test, unix))]
    SNAPSHOT_ENCODE_CALLED.with(|called| called.set(true));
    let encoded =
        serde_json::to_vec(&document).map_err(|source| ScratchError::Serialization { source })?;
    debug_assert_eq!(
        u64::try_from(encoded.len()).unwrap_or(u64::MAX),
        expected_len
    );
    Ok(WorkspaceScan {
        encoded,
        total_bytes: document.total_bytes,
    })
}

fn collect_workspace_files(
    root: &Path,
    limits: ScratchLimits,
) -> Result<BTreeMap<String, OpenedRegularFile>, ScratchError> {
    Ok(collect_selected_files(root, &[".".to_owned()], limits)?.files)
}

struct DigestedFile {
    bytes: u64,
    #[cfg(unix)]
    mode: u32,
    sha256: Sha256Digest,
}

fn digest_file(mut input: OpenedRegularFile, remaining: u64) -> Result<DigestedFile, ScratchError> {
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES].into_boxed_slice();
    let mut total = 0_u64;
    loop {
        let available = remaining.saturating_sub(total);
        let requested = usize::try_from(available.min(COPY_BUFFER_BYTES as u64)).unwrap_or(0);
        let requested = if requested == 0 { 1 } else { requested };
        let read = input
            .file
            .read(&mut buffer[..requested])
            .map_err(|source| ScratchError::Io {
                operation: "read file for digest",
                source,
            })?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(ScratchError::BoundExceeded {
                resource: "bytes",
                actual: u64::MAX,
                max: remaining,
            })?;
        if total > remaining {
            return Err(ScratchError::BoundExceeded {
                resource: "bytes",
                actual: total,
                max: remaining,
            });
        }
        digest.update(&buffer[..read]);
    }
    let value = format!("{:x}", digest.finalize());
    let value =
        Sha256Digest::from_str(&value).map_err(|_| ScratchError::OperationalIncomplete {
            operation: "create file digest",
            details: "SHA-256 output was not a contract digest".to_owned(),
        })?;
    Ok(DigestedFile {
        bytes: total,
        #[cfg(unix)]
        mode: input.mode,
        sha256: value,
    })
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    let value = format!("{:x}", Sha256::digest(bytes));
    Sha256Digest::from_str(&value).expect("SHA-256 output is a valid contract digest")
}

fn fresh_object_id() -> Result<ObjectId, ScratchError> {
    ObjectId::from_str(&Uuid::now_v7().to_string()).map_err(|_| {
        ScratchError::OperationalIncomplete {
            operation: "create Evidence identifier",
            details: "UUID v7 output was not a contract object identifier".to_owned(),
        }
    })
}

fn validate_patch_evidence(
    candidate: &FixCandidate,
    patch_evidence: &Evidence,
    encoded_patch: &[u8],
) -> Result<(), ScratchError> {
    if candidate.patch_evidence_id != patch_evidence.evidence_id {
        return Err(ScratchError::PatchEvidenceMismatch);
    }
    validate_canonical_patch_evidence(patch_evidence, encoded_patch)
}

fn validate_canonical_patch_evidence(
    patch_evidence: &Evidence,
    encoded_patch: &[u8],
) -> Result<(), ScratchError> {
    if patch_evidence.source != EvidenceSource::Patch
        || patch_evidence.media_type != PATCH_MEDIA_TYPE
        || patch_evidence.truncated
        || patch_evidence.content.is_none()
        || patch_evidence.relative_path.is_some()
    {
        return Err(ScratchError::InvalidPatchEvidence);
    }
    if patch_evidence.content.as_deref().map(str::as_bytes) != Some(encoded_patch)
        || patch_evidence.sha256 != digest_bytes(encoded_patch)
    {
        return Err(ScratchError::PatchEvidenceMismatch);
    }
    patch_evidence.validate()?;
    Ok(())
}

fn preflight_changes(
    root: &Path,
    current: &WorkspaceScan,
    patch: &ScratchPatch,
    limits: ScratchLimits,
) -> Result<(), ScratchError> {
    let CollectedFiles {
        files: opened_files,
        mut entry_count,
    } = collect_selected_files(root, &[".".to_owned()], limits)?;
    let mut files = opened_files.into_keys().collect::<BTreeSet<_>>();
    let mut prospective_entries = BTreeSet::new();
    let mut total_bytes = current.total_bytes;
    for change in &patch.changes {
        let relative = patch_path(change);
        validate_patch_depth(relative)?;
        if matches!(change, ScratchChange::Write { .. }) {
            preflight_write_entries(
                root,
                relative,
                &mut prospective_entries,
                &mut entry_count,
                limits,
            )?;
        }
        let target_path = change_path(root, relative);
        let existing = fs::symlink_metadata(&target_path);
        match (change, existing) {
            (ScratchChange::Write { contents, .. }, Ok(metadata)) => {
                if metadata.file_type().is_symlink() {
                    return Err(ScratchError::SymlinkPath { path: target_path });
                }
                if !metadata.is_file() {
                    return Err(ScratchError::UnsupportedEntry { path: target_path });
                }
                let old = metadata.len();
                total_bytes = total_bytes
                    .checked_sub(old)
                    .and_then(|value| value.checked_add(contents.len() as u64))
                    .ok_or(ScratchError::BoundExceeded {
                        resource: "bytes",
                        actual: u64::MAX,
                        max: limits.max_bytes,
                    })?;
            }
            (ScratchChange::Write { contents, .. }, Err(error))
                if error.kind() == io::ErrorKind::NotFound =>
            {
                files.insert(patch_path(change).to_owned());
                total_bytes = total_bytes.checked_add(contents.len() as u64).ok_or(
                    ScratchError::BoundExceeded {
                        resource: "bytes",
                        actual: u64::MAX,
                        max: limits.max_bytes,
                    },
                )?;
            }
            (ScratchChange::Delete { .. }, Ok(metadata)) => {
                if metadata.file_type().is_symlink() {
                    return Err(ScratchError::SymlinkPath { path: target_path });
                }
                if !metadata.is_file() {
                    return Err(ScratchError::UnsupportedEntry { path: target_path });
                }
                files.remove(patch_path(change));
                entry_count =
                    entry_count
                        .checked_sub(1)
                        .ok_or(ScratchError::OperationalIncomplete {
                            operation: "account deleted scratch patch entry",
                            details: "workspace entry count was unexpectedly zero".to_owned(),
                        })?;
                total_bytes = total_bytes.saturating_sub(metadata.len());
            }
            (ScratchChange::Delete { .. }, Err(error))
                if error.kind() == io::ErrorKind::NotFound =>
            {
                return Err(ScratchError::MissingPatchTarget {
                    path: target_path.to_string_lossy().into_owned(),
                });
            }
            (_, Err(source)) => {
                return Err(ScratchError::Io {
                    operation: "inspect scratch patch target",
                    source,
                });
            }
        }
    }
    if files.len() > limits.max_files {
        return Err(ScratchError::BoundExceeded {
            resource: "files",
            actual: files.len() as u64,
            max: limits.max_files as u64,
        });
    }
    if total_bytes > limits.max_bytes {
        return Err(ScratchError::BoundExceeded {
            resource: "bytes",
            actual: total_bytes,
            max: limits.max_bytes,
        });
    }
    Ok(())
}

fn validate_patch_depth(relative: &str) -> Result<(), ScratchError> {
    let depth = relative.split('/').count();
    if depth > MAX_TRAVERSAL_DEPTH {
        return Err(ScratchError::BoundExceeded {
            resource: "traversal depth",
            actual: u64::try_from(depth).unwrap_or(u64::MAX),
            max: u64::try_from(MAX_TRAVERSAL_DEPTH).unwrap_or(u64::MAX),
        });
    }
    Ok(())
}

fn preflight_write_entries(
    root: &Path,
    relative: &str,
    prospective_entries: &mut BTreeSet<String>,
    entry_count: &mut usize,
    limits: ScratchLimits,
) -> Result<(), ScratchError> {
    let component_count = relative.split('/').count();
    let mut display_path = root.to_path_buf();
    let mut relative_path = String::new();
    for (index, component) in relative.split('/').enumerate() {
        display_path.push(component);
        if !relative_path.is_empty() {
            relative_path.push('/');
        }
        relative_path.push_str(component);

        let missing = match fs::symlink_metadata(&display_path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ScratchError::SymlinkPath { path: display_path });
            }
            Ok(metadata) if index + 1 < component_count && !metadata.is_dir() => {
                return Err(ScratchError::UnsupportedEntry { path: display_path });
            }
            Ok(_) => false,
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(source) => {
                return Err(ScratchError::Io {
                    operation: "inspect prospective scratch patch path",
                    source,
                });
            }
        };

        if missing && prospective_entries.insert(relative_path.clone()) {
            *entry_count = entry_count
                .checked_add(1)
                .ok_or(ScratchError::BoundExceeded {
                    resource: "traversal entries",
                    actual: u64::MAX,
                    max: u64::try_from(limits.max_entries).unwrap_or(u64::MAX),
                })?;
            if *entry_count > limits.max_entries {
                return Err(ScratchError::BoundExceeded {
                    resource: "traversal entries",
                    actual: u64::try_from(*entry_count).unwrap_or(u64::MAX),
                    max: u64::try_from(limits.max_entries).unwrap_or(u64::MAX),
                });
            }
        }
    }
    Ok(())
}

fn change_path(root: &Path, relative: &str) -> PathBuf {
    root.join(relative_to_path(relative))
}

fn ensure_workspace_parents(root: &Path, relative: &Path) -> Result<(), ScratchError> {
    let mut current = root.to_path_buf();
    let components = relative.components().collect::<Vec<_>>();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        let Component::Normal(name) = component else {
            return Err(ScratchError::InvalidPath {
                path: relative.to_string_lossy().into_owned(),
                reason: "non-normal scratch path",
            });
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ScratchError::SymlinkPath { path: current });
            }
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Err(ScratchError::UnsupportedEntry { path: current }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|source| ScratchError::Io {
                    operation: "create scratch patch parent",
                    source,
                })?;
            }
            Err(source) => {
                return Err(ScratchError::Io {
                    operation: "inspect scratch patch parent",
                    source,
                });
            }
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
fn inject_apply_change_failure_on_call(call: usize) {
    APPLY_CHANGE_FAILURE_ON_CALL.with(|remaining| remaining.set(Some(call)));
}

#[cfg(all(test, unix))]
pub(crate) fn inject_open_entry_race(hook: impl FnOnce() + 'static) {
    OPEN_ENTRY_RACE_HOOK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(all(test, unix))]
pub(crate) fn inject_immutable_base_read_failure() {
    IMMUTABLE_BASE_READ_FAILURE.with(|failure| failure.set(true));
}

#[cfg(all(test, unix))]
fn inject_immutable_base_read_failure_if_requested() -> bool {
    IMMUTABLE_BASE_READ_FAILURE.with(|failure| failure.replace(false))
}

#[cfg(not(all(test, unix)))]
fn inject_immutable_base_read_failure_if_requested() -> bool {
    false
}

#[cfg(all(test, unix))]
fn run_open_entry_race_hook() {
    let hook = OPEN_ENTRY_RACE_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(all(test, unix))]
fn reset_patch_encode_marker() {
    PATCH_ENCODE_CALLED.with(|called| called.set(false));
}

#[cfg(all(test, unix))]
fn patch_encode_was_called() -> bool {
    PATCH_ENCODE_CALLED.with(Cell::get)
}

#[cfg(all(test, unix))]
fn reset_snapshot_encode_marker() {
    SNAPSHOT_ENCODE_CALLED.with(|called| called.set(false));
}

#[cfg(all(test, unix))]
fn snapshot_encode_was_called() -> bool {
    SNAPSHOT_ENCODE_CALLED.with(Cell::get)
}

#[cfg(all(test, unix))]
fn inject_replaced_workspace_cleanup_failure() {
    REPLACED_WORKSPACE_CLEANUP_FAILURE.with(|injected| injected.set(true));
}

#[cfg(all(test, unix))]
fn inject_replaced_workspace_cleanup_result(result: io::Result<()>) -> io::Result<()> {
    if REPLACED_WORKSPACE_CLEANUP_FAILURE.with(|injected| injected.replace(false)) {
        Err(io::Error::other(
            "test-injected replaced workspace cleanup failure",
        ))
    } else {
        result
    }
}

#[cfg(all(test, unix))]
fn take_transaction_candidate_path() -> PathBuf {
    LAST_TRANSACTION_CANDIDATE_PATH.with(|path| {
        path.borrow_mut()
            .take()
            .expect("transaction candidate path must be recorded")
    })
}

#[cfg(all(test, unix))]
fn should_inject_apply_change_failure() -> bool {
    APPLY_CHANGE_FAILURE_ON_CALL.with(|remaining| match remaining.get() {
        Some(1) => {
            remaining.set(None);
            true
        }
        Some(call) => {
            remaining.set(Some(call - 1));
            false
        }
        None => false,
    })
}

fn apply_change(root: &Path, change: &ScratchChange) -> Result<(), ScratchError> {
    #[cfg(all(test, unix))]
    if should_inject_apply_change_failure() {
        return Err(ScratchError::OperationalIncomplete {
            operation: "test-injected late scratch apply failure",
            details: "transactional candidate must not publish partial changes".to_owned(),
        });
    }

    let relative = relative_to_path(patch_path(change));
    let path = change_path(root, patch_path(change));
    match change {
        ScratchChange::Write { contents, .. } => {
            ensure_workspace_parents(root, &relative)?;
            #[cfg(unix)]
            let mode = replacement_mode(&path)?;
            let parent = path.parent().unwrap_or(root);
            let mut temporary =
                NamedTempFile::new_in(parent).map_err(|source| ScratchError::Io {
                    operation: "create atomic scratch patch file",
                    source,
                })?;
            temporary
                .write_all(contents)
                .and_then(|()| temporary.flush())
                .map_err(|source| ScratchError::Io {
                    operation: "write atomic scratch patch file",
                    source,
                })?;
            #[cfg(unix)]
            temporary
                .as_file()
                .set_permissions(fs::Permissions::from_mode(mode))
                .map_err(|source| ScratchError::Io {
                    operation: "set atomic scratch patch file mode",
                    source,
                })?;
            temporary.persist(&path).map_err(|error| ScratchError::Io {
                operation: "install scratch patch file",
                source: error.error,
            })?;
        }
        ScratchChange::Delete { .. } => {
            fs::remove_file(path).map_err(|source| ScratchError::Io {
                operation: "delete scratch patch file",
                source,
            })?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn replacement_mode(path: &Path) -> Result<u32, ScratchError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(ScratchError::SymlinkPath {
            path: path.to_path_buf(),
        }),
        Ok(metadata) if metadata.is_file() => Ok(metadata.mode() & PERMISSION_MODE_MASK),
        Ok(_) => Err(ScratchError::UnsupportedEntry {
            path: path.to_path_buf(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(SAFE_CREATE_MODE),
        Err(source) => Err(ScratchError::Io {
            operation: "inspect scratch replacement mode",
            source,
        }),
    }
}

fn patch_path(change: &ScratchChange) -> &str {
    match change {
        ScratchChange::Write { path, .. } | ScratchChange::Delete { path } => path,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::str::FromStr;

    use diagnostic_triage_contracts::model::{
        AdapterKind, Cache, CacheStatus, Category, Execution, ExecutionPhases,
        ExecutionSchemaVersion, ExecutionStatus, Finding, FindingState, FixCandidateSchemaVersion,
        MicroCategory, NotApplicable, Observation, ObservationSchemaVersion, Origin, Performance,
        PerformanceStatus, PhaseDuration, Retry, RetryStatus, Runner, RunnerStatus, Severity,
        Taxonomy, Tool, ToolchainFingerprint, Unavailable, VerificationAttribution,
    };
    use diagnostic_triage_contracts::{AdapterId, Nullable};
    use diagnostic_triage_engine::finding::build_finding_with_taxonomy;
    use tempfile::tempdir;

    fn limits() -> ScratchLimits {
        ScratchLimits {
            max_files: 16,
            max_entries: 64,
            max_bytes: 1024,
            max_evidence_bytes: 16_384,
        }
    }

    fn verification_tool() -> Tool {
        Tool {
            name: "scratch-fixture".to_owned(),
            version: "1.0.0".to_owned(),
            rule_id: Some("scratch.rule".to_owned()),
        }
    }

    fn verification_phases() -> ExecutionPhases {
        ExecutionPhases {
            queue: PhaseDuration::NotApplicable(NotApplicable::Value),
            setup: PhaseDuration::NotApplicable(NotApplicable::Value),
            run: PhaseDuration::NotApplicable(NotApplicable::Value),
            normalize: PhaseDuration::NotApplicable(NotApplicable::Value),
            total: PhaseDuration::NotApplicable(NotApplicable::Value),
        }
    }

    struct VerificationFixture {
        candidate: FixCandidate,
        targets: Vec<diagnostic_triage_contracts::Fingerprint>,
        evidence: Vec<Evidence>,
        executions: Vec<Execution>,
        patch_application: PatchApplication,
        before_findings: Vec<Finding>,
        after_findings: Vec<Finding>,
    }

    impl VerificationFixture {
        fn input(&self) -> SafeFixComparisonInput<'_> {
            SafeFixComparisonInput {
                candidate: &self.candidate,
                target_fingerprints: &self.targets,
                evidence: &self.evidence,
                executions: &self.executions,
                patch_application: &self.patch_application,
                before_findings: &self.before_findings,
                after_findings: &self.after_findings,
            }
        }
    }

    fn verification_fixture(
        workspace: &ScratchWorkspace,
        patch: &ScratchPatch,
    ) -> VerificationFixture {
        let execution_id = fresh_object_id().expect("execution id");
        let capture = workspace
            .capture(patch, Some(execution_id.clone()))
            .expect("capture");
        let result = capture.result;
        let observation = Observation {
            schema_version: ObservationSchemaVersion::V1,
            observation_id: fresh_object_id().expect("observation id"),
            tool: verification_tool(),
            language: "rust".parse().expect("language"),
            severity: Severity::Error,
            origin: Origin::Normal,
            message: "fixture diagnostic".to_owned(),
            location: None,
            symbol: None,
            expected: None,
            observed: None,
            evidence_ids: Vec::new(),
        };
        let mut finding = build_finding_with_taxonomy(
            &observation,
            &Taxonomy {
                category: Category::Type,
                micro_category: MicroCategory::IncompatibleType,
            },
        )
        .expect("finding");
        let candidate = FixCandidate {
            schema_version: FixCandidateSchemaVersion::V1,
            fix_candidate_id: fresh_object_id().expect("candidate id"),
            observation_ids: finding.observation_ids.clone(),
            applicability: Applicability::Safe,
            tool_native: true,
            patch_evidence_id: capture.patch.evidence_id.clone(),
        };
        finding.state = FindingState::FixProposed;
        finding.fix_candidate_id = Some(candidate.fix_candidate_id.clone());
        let targets = vec![finding.fingerprint.clone()];
        let execution = Execution {
            schema_version: ExecutionSchemaVersion::V1,
            execution_id,
            adapter_id: AdapterId::from_str("fixture.provider").expect("adapter id"),
            adapter_kind: AdapterKind::Provider,
            tool: verification_tool(),
            toolchain_fingerprint: ToolchainFingerprint::Unavailable(Unavailable::Value),
            required: true,
            status: ExecutionStatus::Complete,
            exit_code: Nullable(Some(0)),
            message: None,
            phases_ms: verification_phases(),
            performance: Performance {
                status: PerformanceStatus::NotEvaluated,
                budget_ms: 1,
            },
            cache: Cache {
                status: CacheStatus::NotApplicable,
                restore_ms: None,
                save_ms: None,
            },
            retry: Retry {
                status: RetryStatus::NotApplicable,
                attempt: None,
                same_revision: None,
                group_id: None,
            },
            runner: Runner {
                status: RunnerStatus::Unavailable,
                os: None,
                arch: None,
                image: None,
                fingerprint: None,
            },
            verification: Some(Box::new(VerificationAttribution {
                fix_candidate_id: candidate.fix_candidate_id.clone(),
                patch_sha256: capture.patch.sha256.clone(),
                base_snapshot_sha256: capture.base.sha256.clone(),
                base_snapshot_evidence_id: capture.base.evidence_id.clone(),
                target_fingerprints: targets.clone(),
                result_evidence_id: result.evidence_id.clone(),
            })),
        };
        VerificationFixture {
            candidate,
            targets,
            evidence: vec![capture.base.clone(), result, capture.patch.clone()],
            executions: vec![execution],
            patch_application: PatchApplication::Applied {
                patch_sha256: capture.patch.sha256,
                base_snapshot_sha256: capture.base.sha256,
            },
            before_findings: vec![finding],
            after_findings: Vec::new(),
        }
    }

    #[test]
    fn rejects_path_escape_forms() {
        let repo = tempdir().expect("repo");
        for path in [
            "/tmp/out",
            "../out",
            "nested/../../out",
            "a\\b",
            "a\0b",
            "C:/out",
        ] {
            let error = ScratchWorkspace::stage(repo.path(), &[path], limits())
                .expect_err("path must reject");
            assert!(matches!(error, ScratchError::InvalidPath { .. }));
        }

        let oversized = "p".repeat(4_097);
        let error = ScratchWorkspace::stage(repo.path(), &[oversized.as_str()], limits())
            .expect_err("oversized source path must reject before descriptor traversal");
        assert!(matches!(error, ScratchError::InvalidPath { .. }));
        let error = ScratchPatch::new(vec![ScratchChange::Delete { path: oversized }])
            .expect_err("oversized patch path must reject before encoding");
        assert!(matches!(error, ScratchError::InvalidPath { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let repo = tempdir().expect("repo");
        let outside = tempdir().expect("outside");
        fs::write(outside.path().join("secret.txt"), "secret").expect("secret");
        symlink(outside.path(), repo.path().join("escape")).expect("symlink");
        let error = ScratchWorkspace::stage(repo.path(), &["escape"], limits())
            .expect_err("symlink must reject");
        assert!(matches!(error, ScratchError::SymlinkPath { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn no_follow_open_rejects_symlink_replacement() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("directory");
        let path = directory.path().join("source.txt");
        let original = directory.path().join("original.txt");
        let outside = directory.path().join("outside.txt");
        fs::write(&path, b"expected").expect("source");
        fs::write(&outside, b"outside").expect("outside");
        let root = open_root_directory(directory.path()).expect("root descriptor");
        let raced_path = path.clone();
        inject_open_entry_race(move || {
            fs::rename(&raced_path, original).expect("retain original inode");
            symlink(&outside, &raced_path).expect("replace with symlink");
        });

        let error = open_entry_no_follow(&root.file, OsStr::new("source.txt"), &path, "source.txt")
            .expect_err("no-follow open must reject a symlink replacement");
        assert!(matches!(
            error,
            ScratchError::Io {
                operation: "open descriptor-relative entry without following symlinks",
                ..
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn no_follow_open_rejects_inode_replacement() {
        let directory = tempdir().expect("directory");
        let path = directory.path().join("source.txt");
        let original = directory.path().join("original.txt");
        fs::write(&path, b"expected").expect("source");
        let root = open_root_directory(directory.path()).expect("root descriptor");
        let raced_path = path.clone();
        inject_open_entry_race(move || {
            fs::rename(&raced_path, original).expect("retain original inode");
            fs::write(&raced_path, b"replacement").expect("replacement");
        });

        let error = open_entry_no_follow(&root.file, OsStr::new("source.txt"), &path, "source.txt")
            .expect_err("descriptor identity must reject an inode replacement");
        assert!(matches!(error, ScratchError::SourceChanged { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_relative_open_is_pinned_against_parent_symlink_replacement() {
        use std::os::unix::fs::symlink;

        let repo = tempdir().expect("repo");
        let outside = tempdir().expect("outside");
        fs::create_dir(repo.path().join("parent")).expect("parent");
        fs::write(repo.path().join("parent/source.txt"), b"expected").expect("source");
        fs::write(outside.path().join("source.txt"), b"outside").expect("outside source");

        let root = open_root_directory(repo.path()).expect("root descriptor");
        let mut budget = TraversalBudget {
            entries: 0,
            max_entries: limits().max_entries,
            max_files: limits().max_files,
        };
        let (parent, _) = open_relative_entry(&root.file, repo.path(), "parent", &mut budget)
            .expect("pinned parent descriptor");
        fs::rename(
            repo.path().join("parent"),
            repo.path().join("original-parent"),
        )
        .expect("move pinned parent");
        symlink(outside.path(), repo.path().join("parent")).expect("replace parent with symlink");

        let mut opened = open_entry_no_follow(
            &parent.file,
            OsStr::new("source.txt"),
            &repo.path().join("parent/source.txt"),
            "parent/source.txt",
        )
        .expect("descriptor-relative child open");
        let mut contents = Vec::new();
        opened
            .file
            .read_to_end(&mut contents)
            .expect("read pinned file");
        assert_eq!(contents, b"expected");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn no_follow_open_rejects_fifo_replacement_without_blocking() {
        use rustix::fs::{CWD, mkfifoat};

        let directory = tempdir().expect("directory");
        let path = directory.path().join("source.txt");
        fs::write(&path, b"expected").expect("source");
        let root = open_root_directory(directory.path()).expect("root descriptor");
        let raced_path = path.clone();
        inject_open_entry_race(move || {
            fs::remove_file(&raced_path).expect("remove original");
            mkfifoat(CWD, &raced_path, Mode::RUSR | Mode::WUSR).expect("replace with fifo");
        });

        let error = open_entry_no_follow(&root.file, OsStr::new("source.txt"), &path, "source.txt")
            .expect_err("nonblocking descriptor check must reject a FIFO replacement");
        assert!(matches!(error, ScratchError::SourceChanged { .. }));
    }

    #[test]
    fn enforces_file_and_byte_bounds() {
        let repo = tempdir().expect("repo");
        fs::write(repo.path().join("one"), b"one").expect("one");
        fs::write(repo.path().join("two"), b"two").expect("two");
        let error = ScratchWorkspace::stage(
            repo.path(),
            &["one", "two"],
            ScratchLimits {
                max_files: 1,
                ..limits()
            },
        )
        .expect_err("file bound");
        assert!(matches!(
            error,
            ScratchError::BoundExceeded {
                resource: "files",
                ..
            }
        ));

        let error = ScratchWorkspace::stage(
            repo.path(),
            &["one"],
            ScratchLimits {
                max_bytes: 2,
                ..limits()
            },
        )
        .expect_err("byte bound");
        assert!(matches!(
            error,
            ScratchError::BoundExceeded {
                resource: "bytes",
                ..
            }
        ));
    }

    #[test]
    fn enumeration_stops_at_configured_file_and_entry_bounds() {
        let repo = tempdir().expect("repo");
        fs::create_dir(repo.path().join("wide")).expect("wide");
        for index in 0..12 {
            fs::write(repo.path().join(format!("wide/{index:02}.txt")), b"x").expect("wide file");
        }
        let error = ScratchWorkspace::stage(
            repo.path(),
            &["wide"],
            ScratchLimits {
                max_files: 3,
                ..limits()
            },
        )
        .expect_err("enumeration must stop before collecting the whole directory");
        assert!(matches!(
            error,
            ScratchError::BoundExceeded {
                resource: "files",
                actual: 4,
                max: 3
            }
        ));

        fs::create_dir(repo.path().join("tree")).expect("tree");
        for index in 0..8 {
            fs::create_dir(repo.path().join(format!("tree/{index:02}"))).expect("tree directory");
        }
        let error = ScratchWorkspace::stage(
            repo.path(),
            &["tree"],
            ScratchLimits {
                max_entries: 3,
                ..limits()
            },
        )
        .expect_err("directory-only trees must be incrementally bounded");
        assert!(matches!(
            error,
            ScratchError::BoundExceeded {
                resource: "traversal entries",
                actual: 4,
                max: 3
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn direct_selected_path_charges_every_component_to_traversal_limits() {
        let repo = tempdir().expect("repo");
        fs::create_dir_all(repo.path().join("one/two")).expect("nested directories");
        fs::write(repo.path().join("one/two/file.txt"), b"content").expect("nested file");

        let Err(error) = collect_selected_files(
            repo.path(),
            &["one/two/file.txt".to_owned()],
            ScratchLimits {
                max_entries: 2,
                ..limits()
            },
        ) else {
            panic!("the third direct component must exceed the traversal budget");
        };
        assert!(matches!(
            error,
            ScratchError::BoundExceeded {
                resource: "traversal entries",
                actual: 3,
                max: 2
            }
        ));

        let files = collect_selected_files(
            repo.path(),
            &["one/two/file.txt".to_owned()],
            ScratchLimits {
                max_entries: 3,
                ..limits()
            },
        )
        .expect("each direct component must be charged exactly once");
        assert_eq!(
            files.files.into_keys().collect::<Vec<_>>(),
            ["one/two/file.txt"]
        );

        let components = vec!["d"; MAX_TRAVERSAL_DEPTH + 1];
        let deep_path = components.join("/");
        fs::create_dir_all(
            repo.path().join(
                components[..MAX_TRAVERSAL_DEPTH]
                    .iter()
                    .collect::<PathBuf>(),
            ),
        )
        .expect("deep directories");
        fs::write(repo.path().join(&deep_path), b"deep").expect("deep file");
        let Err(error) = collect_selected_files(
            repo.path(),
            std::slice::from_ref(&deep_path),
            ScratchLimits {
                max_entries: MAX_TRAVERSAL_DEPTH + 1,
                ..limits()
            },
        ) else {
            panic!("direct path depth must be bounded from the repository root");
        };
        assert!(matches!(
            error,
            ScratchError::BoundExceeded {
                resource: "traversal depth",
                actual,
                max
            } if actual == (MAX_TRAVERSAL_DEPTH + 1) as u64
                && max == MAX_TRAVERSAL_DEPTH as u64
        ));
    }

    #[test]
    fn patch_preflight_rejects_entry_and_depth_bounds_before_mkdir() {
        let root = tempdir().expect("scratch root");
        let entry_limits = ScratchLimits {
            max_entries: 1,
            ..limits()
        };
        let current = scan_workspace(root.path(), entry_limits).expect("empty scan");
        let patch = ScratchPatch::new(vec![ScratchChange::Write {
            path: "a/b/file.txt".to_owned(),
            contents: b"content".to_vec(),
        }])
        .expect("patch");

        let error = preflight_changes(root.path(), &current, &patch, entry_limits)
            .expect_err("prospective parent entries must be bounded before creation");
        assert!(matches!(
            error,
            ScratchError::BoundExceeded {
                resource: "traversal entries",
                actual: 2,
                max: 1
            }
        ));
        assert!(!root.path().join("a").exists());

        let path_beyond_depth_limit = vec!["d"; MAX_TRAVERSAL_DEPTH + 1].join("/");
        let depth_limited_patch = ScratchPatch::new(vec![ScratchChange::Write {
            path: path_beyond_depth_limit,
            contents: b"content".to_vec(),
        }])
        .expect("deep patch");
        let deep_limits = ScratchLimits {
            max_entries: MAX_TRAVERSAL_DEPTH + 2,
            ..limits()
        };
        let current = scan_workspace(root.path(), deep_limits).expect("empty deep scan");
        let error = preflight_changes(root.path(), &current, &depth_limited_patch, deep_limits)
            .expect_err("prospective patch depth must be bounded before creation");
        assert!(matches!(
            error,
            ScratchError::BoundExceeded {
                resource: "traversal depth",
                actual,
                max
            } if actual == (MAX_TRAVERSAL_DEPTH + 1) as u64
                && max == MAX_TRAVERSAL_DEPTH as u64
        ));
        assert!(!root.path().join("d").exists());
    }

    #[test]
    fn patch_constructor_bounds_input_before_normalization_and_sorting() {
        let changes = (0..=DEFAULT_MAX_FILES)
            .map(|index| ScratchChange::Delete {
                path: format!("file-{index}"),
            })
            .collect();
        let error = ScratchPatch::new(changes)
            .expect_err("patch item ceiling must apply before normalization");
        assert!(matches!(
            error,
            ScratchError::BoundExceeded {
                resource: "patch files",
                actual,
                max
            } if actual == (DEFAULT_MAX_FILES + 1) as u64
                && max == DEFAULT_MAX_FILES as u64
        ));

        let oversized_path = "p".repeat(MAX_REPO_PATH_BYTES + 1);
        let error = ScratchPatch::new(vec![ScratchChange::Delete {
            path: oversized_path,
        }])
        .expect_err("oversized path must reject before component allocation");
        let ScratchError::InvalidPath { path, .. } = error else {
            panic!("oversized path must produce the typed path error");
        };
        assert_eq!(path.chars().count(), 257);
        assert!(path.ends_with('…'));
    }

    #[test]
    fn patch_shape_is_rejected_before_hex_or_json_encoding() {
        let repo = tempdir().expect("repo");
        let workspace = ScratchWorkspace::stage(
            repo.path(),
            &[] as &[&str],
            ScratchLimits {
                max_files: 1,
                max_bytes: 2,
                ..limits()
            },
        )
        .expect("empty stage");
        let oversized = ScratchPatch::new(vec![ScratchChange::Write {
            path: "new.txt".to_owned(),
            contents: b"abc".to_vec(),
        }])
        .expect("patch");
        reset_patch_encode_marker();
        let error = workspace
            .capture(&oversized, None)
            .expect_err("raw bytes must fail before encoding");
        assert!(matches!(
            error,
            ScratchError::BoundExceeded {
                resource: "raw patch bytes",
                actual: 3,
                max: 2
            }
        ));
        assert!(!patch_encode_was_called());

        let too_many = ScratchPatch::new(vec![
            ScratchChange::Delete {
                path: "one".to_owned(),
            },
            ScratchChange::Delete {
                path: "two".to_owned(),
            },
        ])
        .expect("patch");
        reset_patch_encode_marker();
        let error = workspace
            .capture(&too_many, None)
            .expect_err("count must fail before encoding");
        assert!(matches!(
            error,
            ScratchError::BoundExceeded {
                resource: "patch files",
                actual: 2,
                max: 1
            }
        ));
        assert!(!patch_encode_was_called());
        workspace.cleanup().expect("cleanup");
    }

    #[test]
    fn long_paths_fail_evidence_preflight_before_full_encoding() {
        let long_path = "p".repeat(200);
        let bounded_limits = ScratchLimits {
            max_evidence_bytes: 128,
            ..limits()
        };

        let snapshot_repo = tempdir().expect("snapshot repo");
        fs::write(snapshot_repo.path().join(&long_path), b"x").expect("long-path file");
        reset_snapshot_encode_marker();
        let error = ScratchWorkspace::stage(snapshot_repo.path(), &[&long_path], bounded_limits)
            .expect_err("snapshot path and metadata must count toward Evidence bytes");
        assert!(matches!(
            error,
            ScratchError::BoundExceeded {
                resource: "Evidence bytes",
                ..
            }
        ));
        assert!(!snapshot_encode_was_called());

        let patch_repo = tempdir().expect("patch repo");
        let workspace = ScratchWorkspace::stage(patch_repo.path(), &[] as &[&str], bounded_limits)
            .expect("empty snapshot fits the Evidence bound");
        let patch = ScratchPatch::new(vec![ScratchChange::Delete { path: long_path }])
            .expect("long-path patch");
        reset_patch_encode_marker();
        let error = workspace
            .capture(&patch, None)
            .expect_err("patch path and JSON framing must count toward Evidence bytes");
        assert!(matches!(
            error,
            ScratchError::BoundExceeded {
                resource: "Evidence bytes",
                ..
            }
        ));
        assert!(!patch_encode_was_called());
        workspace.cleanup().expect("cleanup");
    }

    #[test]
    fn tmpdir_inside_repo_is_rejected_before_repo_mutation() {
        const CHILD_REPO: &str = "DIAGNOSTIC_TRIAGE_TMPDIR_TEST_REPO";
        if let Some(repo) = std::env::var_os(CHILD_REPO) {
            let error = ScratchWorkspace::stage(PathBuf::from(repo), &["tracked.txt"], limits())
                .expect_err("TMPDIR inside the repository must be rejected");
            assert!(matches!(error, ScratchError::UnsafeTempDir { .. }));
            return;
        }

        let repo = tempdir().expect("repo");
        fs::write(repo.path().join("tracked.txt"), b"unchanged").expect("tracked file");
        let modified_before = fs::metadata(repo.path())
            .expect("repo metadata before")
            .modified()
            .expect("repo modified time before");
        #[cfg(unix)]
        let original_permissions = fs::metadata(repo.path())
            .expect("repo permissions")
            .permissions();
        #[cfg(unix)]
        fs::set_permissions(repo.path(), fs::Permissions::from_mode(0o500))
            .expect("make repository parent read-only");
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("scratch::tests::tmpdir_inside_repo_is_rejected_before_repo_mutation")
            .arg("--nocapture")
            .env("TMPDIR", repo.path())
            .env(CHILD_REPO, repo.path())
            .output()
            .expect("run isolated TMPDIR regression");
        #[cfg(unix)]
        fs::set_permissions(repo.path(), original_permissions)
            .expect("restore repository permissions");
        assert!(
            output.status.success(),
            "child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read(repo.path().join("tracked.txt")).expect("tracked file remains"),
            b"unchanged"
        );
        let entries = fs::read_dir(repo.path())
            .expect("repo entries")
            .map(|entry| entry.expect("entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries, vec![OsStr::new("tracked.txt").to_os_string()]);
        assert_eq!(
            fs::metadata(repo.path())
                .expect("repo metadata after")
                .modified()
                .expect("repo modified time after"),
            modified_before
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_modes_survive_stage_and_apply_and_bind_snapshot_identity() {
        use std::os::unix::fs::PermissionsExt as _;

        let repo = tempdir().expect("repo");
        let original = repo.path().join("tool.sh");
        fs::write(&original, b"before").expect("source");
        fs::set_permissions(&original, fs::Permissions::from_mode(0o751)).expect("source mode");
        let mut workspace =
            ScratchWorkspace::stage(repo.path(), &["tool.sh"], limits()).expect("stage");
        let original_digest = workspace.base_evidence().sha256.clone();
        assert_eq!(
            fs::metadata(workspace.path().join("tool.sh"))
                .expect("staged metadata")
                .permissions()
                .mode()
                & PERMISSION_MODE_MASK,
            0o751
        );

        let patch = ScratchPatch::new(vec![
            ScratchChange::Write {
                path: "tool.sh".to_owned(),
                contents: b"after".to_vec(),
            },
            ScratchChange::Write {
                path: "new.txt".to_owned(),
                contents: b"new".to_vec(),
            },
        ])
        .expect("patch");
        let fixture = verification_fixture(&workspace, &patch);
        let authorization = workspace
            .authorize_safe_fix(fixture.input())
            .expect("authorization");
        workspace
            .apply_verified(
                &fixture.candidate,
                &patch,
                &fixture.evidence[2],
                authorization,
            )
            .expect("apply");
        let applied_mode = |path: &Path| {
            fs::metadata(path)
                .expect("applied metadata")
                .permissions()
                .mode()
                & PERMISSION_MODE_MASK
        };
        assert_eq!(applied_mode(&workspace.path().join("tool.sh")), 0o751);
        assert_eq!(
            applied_mode(&workspace.path().join("new.txt")),
            SAFE_CREATE_MODE
        );
        assert_eq!(applied_mode(&original), 0o751);
        assert_eq!(fs::read(&original).expect("original contents"), b"before");
        workspace.cleanup().expect("cleanup");

        fs::set_permissions(&original, fs::Permissions::from_mode(0o640)).expect("chmod source");
        let changed =
            ScratchWorkspace::stage(repo.path(), &["tool.sh"], limits()).expect("restage");
        assert_ne!(changed.base_evidence().sha256, original_digest);
        changed.cleanup().expect("cleanup changed");
    }

    #[test]
    fn staging_and_apply_do_not_mutate_original_and_digest_is_deterministic() {
        let repo = tempdir().expect("repo");
        fs::create_dir(repo.path().join("src")).expect("src");
        fs::write(repo.path().join("src/a.txt"), b"before").expect("a");
        let original = fs::read(repo.path().join("src/a.txt")).expect("original");
        let patch = ScratchPatch::new(vec![ScratchChange::Write {
            path: "src/a.txt".to_owned(),
            contents: b"after".to_vec(),
        }])
        .expect("patch");

        let first = ScratchWorkspace::stage(repo.path(), &["src"], limits()).expect("first");
        let second = ScratchWorkspace::stage(repo.path(), &["src"], limits()).expect("second");
        let first_capture = first.capture(&patch, None).expect("first capture");
        let second_capture = second.capture(&patch, None).expect("second capture");
        assert_eq!(first_capture.base.sha256, second_capture.base.sha256);
        assert_eq!(first_capture.base.content, second_capture.base.content);
        assert_eq!(
            fs::read(repo.path().join("src/a.txt")).expect("unchanged"),
            original
        );
        first.cleanup().expect("cleanup first");
        second.cleanup().expect("cleanup second");
    }

    #[test]
    fn verification_apply_preserves_base_and_mutates_only_private_workspace() {
        let repo = tempdir().expect("repo");
        fs::write(repo.path().join("file.txt"), b"before").expect("file");
        let mut workspace =
            ScratchWorkspace::stage(repo.path(), &["file.txt"], limits()).expect("stage");
        let base = workspace.base_evidence().clone();
        let patch = ScratchPatch::new(vec![ScratchChange::Write {
            path: "file.txt".to_owned(),
            contents: b"after".to_vec(),
        }])
        .expect("patch");

        let application = workspace
            .apply_for_verification(&patch)
            .expect("verification apply");
        let captured = workspace.capture(&patch, None).expect("capture result");

        assert_eq!(captured.base, base);
        assert_ne!(captured.result.sha256, captured.base.sha256);
        assert!(matches!(
            application,
            PatchApplication::Applied {
                patch_sha256,
                base_snapshot_sha256,
            } if patch_sha256 == captured.patch.sha256
                && base_snapshot_sha256 == captured.base.sha256
        ));
        assert_eq!(
            fs::read(workspace.path().join("file.txt")).unwrap(),
            b"after"
        );
        assert_eq!(fs::read(repo.path().join("file.txt")).unwrap(), b"before");
        let unrelated = ScratchPatch::new(vec![ScratchChange::Write {
            path: "file.txt".to_owned(),
            contents: b"unrelated".to_vec(),
        }])
        .expect("unrelated patch");
        assert!(matches!(
            workspace.capture(&unrelated, None),
            Err(ScratchError::PatchEvidenceMismatch)
        ));
        workspace.cleanup().expect("cleanup");
    }

    #[test]
    fn verification_capture_rejects_mutation_after_private_apply() {
        let repo = tempdir().expect("repo");
        fs::write(repo.path().join("file.txt"), b"before").expect("file");
        let mut workspace =
            ScratchWorkspace::stage(repo.path(), &["file.txt"], limits()).expect("stage");
        let patch = ScratchPatch::new(vec![ScratchChange::Write {
            path: "file.txt".to_owned(),
            contents: b"after".to_vec(),
        }])
        .expect("patch");
        workspace
            .apply_for_verification(&patch)
            .expect("verification apply");

        fs::write(workspace.path().join("file.txt"), b"provider mutation")
            .expect("mutate private workspace");

        assert!(matches!(
            workspace.capture(&patch, None),
            Err(ScratchError::VerificationResultChanged)
        ));
        assert_eq!(fs::read(repo.path().join("file.txt")).unwrap(), b"before");
        workspace.cleanup().expect("cleanup");
    }

    #[test]
    fn verification_workspace_rejects_a_second_patch_after_noop_apply() {
        let repo = tempdir().expect("repo");
        fs::write(repo.path().join("file.txt"), b"before").expect("file");
        let mut workspace =
            ScratchWorkspace::stage(repo.path(), &["file.txt"], limits()).expect("stage");
        let first = ScratchPatch::new(Vec::new()).expect("empty patch");
        let second = ScratchPatch::new(vec![ScratchChange::Write {
            path: "file.txt".to_owned(),
            contents: b"before".to_vec(),
        }])
        .expect("same-content patch");

        workspace
            .apply_for_verification(&first)
            .expect("first apply");
        assert!(matches!(
            workspace.apply_for_verification(&second),
            Err(ScratchError::PatchAlreadyApplied)
        ));
        workspace
            .capture(&first, None)
            .expect("first binding intact");
        assert_eq!(fs::read(repo.path().join("file.txt")).unwrap(), b"before");
        workspace.cleanup().expect("cleanup");
    }

    #[test]
    fn captured_result_is_directly_authorizable_with_result_media_type() {
        let repo = tempdir().expect("repo");
        fs::write(repo.path().join("file.txt"), b"before").expect("file");
        let workspace =
            ScratchWorkspace::stage(repo.path(), &["file.txt"], limits()).expect("stage");
        let patch = ScratchPatch::new(vec![ScratchChange::Write {
            path: "file.txt".to_owned(),
            contents: b"after".to_vec(),
        }])
        .expect("patch");
        let fixture = verification_fixture(&workspace, &patch);
        assert_eq!(fixture.evidence[1].media_type, RESULT_MEDIA_TYPE);
        workspace
            .authorize_safe_fix(fixture.input())
            .expect("capture result must authorize without media rewriting");
        workspace.cleanup().expect("cleanup");
    }

    #[test]
    fn explicit_apply_requires_runtime_authorization() {
        let repo = tempdir().expect("repo");
        fs::write(repo.path().join("file.txt"), b"before").expect("file");
        let mut workspace =
            ScratchWorkspace::stage(repo.path(), &["file.txt"], limits()).expect("stage");
        let staged_path = workspace.path().to_owned();
        let patch = ScratchPatch::new(vec![ScratchChange::Write {
            path: "file.txt".to_owned(),
            contents: b"after".to_vec(),
        }])
        .expect("patch");
        let fixture = verification_fixture(&workspace, &patch);
        let authorization = workspace
            .authorize_safe_fix(fixture.input())
            .expect("engine verification");
        assert_eq!(
            authorization.candidate_id(),
            &fixture.candidate.fix_candidate_id
        );
        assert_eq!(authorization.patch_sha256(), &fixture.evidence[2].sha256);
        assert_eq!(
            authorization.base_snapshot_sha256(),
            &fixture.evidence[0].sha256
        );
        assert_eq!(authorization.verified_fix().verified_targets.len(), 1);
        let application = workspace
            .apply_verified(
                &fixture.candidate,
                &patch,
                &fixture.evidence[2],
                authorization,
            )
            .expect("safe apply");
        let published_path = workspace.path().to_owned();
        assert_ne!(published_path, staged_path);
        assert!(!staged_path.exists(), "replaced workspace must be removed");
        assert_eq!(
            fs::read(published_path.join("file.txt")).expect("result"),
            b"after"
        );
        assert_eq!(
            fs::read(repo.path().join("file.txt")).expect("original"),
            b"before"
        );
        assert!(matches!(application, PatchApplication::Applied { .. }));
        workspace.cleanup().expect("cleanup");
        assert!(
            !published_path.exists(),
            "published workspace must be removed"
        );
    }

    #[test]
    fn post_publication_cleanup_failure_carries_committed_application() {
        let repo = tempdir().expect("repo");
        fs::write(repo.path().join("file.txt"), b"before").expect("file");
        let mut workspace =
            ScratchWorkspace::stage(repo.path(), &["file.txt"], limits()).expect("stage");
        let staged_path = workspace.path().to_owned();
        let patch = ScratchPatch::new(vec![ScratchChange::Write {
            path: "file.txt".to_owned(),
            contents: b"after".to_vec(),
        }])
        .expect("patch");
        let fixture = verification_fixture(&workspace, &patch);
        let authorization = workspace
            .authorize_safe_fix(fixture.input())
            .expect("authorization");

        inject_replaced_workspace_cleanup_failure();
        let error = workspace
            .apply_verified(
                &fixture.candidate,
                &patch,
                &fixture.evidence[2],
                authorization,
            )
            .expect_err("injected cleanup failure must be surfaced");
        let application = error
            .published_application()
            .expect("typed error must expose the committed application");
        assert!(matches!(application, PatchApplication::Applied { .. }));
        assert!(matches!(
            error,
            ScratchError::PublishedCleanupIncomplete { .. }
        ));
        assert_ne!(workspace.path(), staged_path.as_path());
        assert_eq!(
            fs::read(workspace.path().join("file.txt")).expect("published result"),
            b"after"
        );
        assert!(!staged_path.exists(), "replaced workspace was closed");
        workspace.cleanup().expect("cleanup published workspace");
    }

    #[test]
    fn authorization_is_bound_to_one_workspace_instance_even_with_identical_base() {
        let repo = tempdir().expect("repo");
        fs::write(repo.path().join("file.txt"), b"before").expect("file");
        let first = ScratchWorkspace::stage(repo.path(), &["file.txt"], limits()).expect("first");
        let mut second =
            ScratchWorkspace::stage(repo.path(), &["file.txt"], limits()).expect("second");
        assert_eq!(first.base_evidence().sha256, second.base_evidence().sha256);
        let patch = ScratchPatch::new(vec![ScratchChange::Write {
            path: "file.txt".to_owned(),
            contents: b"after".to_vec(),
        }])
        .expect("patch");
        let fixture = verification_fixture(&first, &patch);
        let authorization = first
            .authorize_safe_fix(fixture.input())
            .expect("authorization from first workspace");

        let error = second
            .apply_verified(
                &fixture.candidate,
                &patch,
                &fixture.evidence[2],
                authorization,
            )
            .expect_err("authorization must not replay to an identical workspace");
        assert!(matches!(error, ScratchError::CandidateNotAuthorized));
        assert_eq!(
            fs::read(second.path().join("file.txt")).expect("second remains unchanged"),
            b"before"
        );
        first.cleanup().expect("cleanup first");
        second.cleanup().expect("cleanup second");
    }

    #[test]
    fn authorization_binds_the_complete_candidate_identity() {
        let repo = tempdir().expect("repo");
        fs::write(repo.path().join("file.txt"), b"before").expect("file");
        let mut workspace =
            ScratchWorkspace::stage(repo.path(), &["file.txt"], limits()).expect("stage");
        let patch = ScratchPatch::new(vec![ScratchChange::Write {
            path: "file.txt".to_owned(),
            contents: b"after".to_vec(),
        }])
        .expect("patch");
        let fixture = verification_fixture(&workspace, &patch);
        let authorization = workspace
            .authorize_safe_fix(fixture.input())
            .expect("authorization");
        let mut tampered_candidate = fixture.candidate.clone();
        tampered_candidate.observation_ids =
            vec![fresh_object_id().expect("replacement observation id")];
        assert_eq!(
            tampered_candidate.fix_candidate_id,
            fixture.candidate.fix_candidate_id
        );

        let error = workspace
            .apply_verified(
                &tampered_candidate,
                &patch,
                &fixture.evidence[2],
                authorization,
            )
            .expect_err("same ObjectId must not authorize different candidate fields");
        assert!(matches!(error, ScratchError::CandidateNotAuthorized));
        assert_eq!(
            fs::read(workspace.path().join("file.txt")).expect("unchanged workspace"),
            b"before"
        );
        workspace.cleanup().expect("cleanup");
    }

    #[test]
    fn patch_evidence_requires_the_patch_media_type() {
        let repo = tempdir().expect("repo");
        fs::write(repo.path().join("file.txt"), b"before").expect("file");
        let mut workspace =
            ScratchWorkspace::stage(repo.path(), &["file.txt"], limits()).expect("stage");
        let patch = ScratchPatch::new(vec![ScratchChange::Write {
            path: "file.txt".to_owned(),
            contents: b"after".to_vec(),
        }])
        .expect("patch");
        let fixture = verification_fixture(&workspace, &patch);
        let authorization = workspace
            .authorize_safe_fix(fixture.input())
            .expect("authorization");
        let mut tampered_evidence = fixture.evidence[2].clone();
        tampered_evidence.media_type = SNAPSHOT_MEDIA_TYPE.to_owned();

        let error = workspace
            .apply_verified(
                &fixture.candidate,
                &patch,
                &tampered_evidence,
                authorization,
            )
            .expect_err("non-PATCH media type must be rejected");
        assert!(matches!(error, ScratchError::InvalidPatchEvidence));
        assert_eq!(
            fs::read(workspace.path().join("file.txt")).expect("unchanged workspace"),
            b"before"
        );
        workspace.cleanup().expect("cleanup");
    }

    #[test]
    fn late_multi_change_failure_keeps_published_workspace_byte_identical() {
        let repo = tempdir().expect("repo");
        fs::write(repo.path().join("a.txt"), b"before-a").expect("a");
        fs::write(repo.path().join("b.txt"), b"before-b").expect("b");
        let mut workspace =
            ScratchWorkspace::stage(repo.path(), &["a.txt", "b.txt"], limits()).expect("stage");
        let published_path = workspace.path().to_owned();
        let original_scan = scan_workspace(&published_path, limits())
            .expect("original scan")
            .encoded;
        let original_a = fs::read(published_path.join("a.txt")).expect("original a");
        let original_b = fs::read(published_path.join("b.txt")).expect("original b");
        let patch = ScratchPatch::new(vec![
            ScratchChange::Write {
                path: "a.txt".to_owned(),
                contents: b"after-a".to_vec(),
            },
            ScratchChange::Write {
                path: "b.txt".to_owned(),
                contents: b"after-b".to_vec(),
            },
        ])
        .expect("patch");
        let fixture = verification_fixture(&workspace, &patch);
        let authorization = workspace
            .authorize_safe_fix(fixture.input())
            .expect("engine verification");

        // The first candidate mutation succeeds; the second fails after preflight.
        inject_apply_change_failure_on_call(2);
        let error = workspace
            .apply_verified(
                &fixture.candidate,
                &patch,
                &fixture.evidence[2],
                authorization,
            )
            .expect_err("late candidate failure");
        let candidate_path = take_transaction_candidate_path();
        assert!(matches!(error, ScratchError::OperationalIncomplete { .. }));
        assert_eq!(workspace.path(), published_path.as_path());
        assert_eq!(
            scan_workspace(&published_path, limits())
                .expect("rollback scan")
                .encoded,
            original_scan
        );
        assert!(
            !candidate_path.exists(),
            "failed transactional candidate must be removed"
        );
        assert_eq!(
            fs::read(published_path.join("a.txt")).expect("unchanged a"),
            original_a
        );
        assert_eq!(
            fs::read(published_path.join("b.txt")).expect("unchanged b"),
            original_b
        );
        workspace.cleanup().expect("cleanup");
        assert!(
            !published_path.exists(),
            "rolled-back workspace must clean up"
        );
    }

    #[test]
    fn rejected_verification_never_yields_authorization() {
        let repo = tempdir().expect("repo");
        fs::write(repo.path().join("file.txt"), b"before").expect("file");
        let workspace =
            ScratchWorkspace::stage(repo.path(), &["file.txt"], limits()).expect("stage");
        let patch = ScratchPatch::new(vec![ScratchChange::Write {
            path: "file.txt".to_owned(),
            contents: b"after".to_vec(),
        }])
        .expect("patch");
        let mut fixture = verification_fixture(&workspace, &patch);
        fixture.candidate.applicability = Applicability::Unsafe;
        let forged = SafeFixVerification::Verified(VerifiedFix {
            verified_targets: Vec::new(),
            post_fix_findings: Vec::new(),
            new_lower_severity_fingerprints: Vec::new(),
        });
        let error = workspace
            .authorize_safe_fix(fixture.input())
            .expect_err("rejected comparison must not mint a token");
        assert!(matches!(error, ScratchError::CandidateNotAuthorized));
        let _ = forged;
        workspace.cleanup().expect("cleanup");
    }

    #[test]
    fn later_apply_requires_fresh_authorization_after_failed_attempt() {
        let repo = tempdir().expect("repo");
        fs::write(repo.path().join("file.txt"), b"before").expect("file");
        let mut workspace =
            ScratchWorkspace::stage(repo.path(), &["file.txt"], limits()).expect("stage");
        let patch = ScratchPatch::new(vec![ScratchChange::Write {
            path: "file.txt".to_owned(),
            contents: b"after".to_vec(),
        }])
        .expect("patch");
        let fixture = verification_fixture(&workspace, &patch);
        let authorization = workspace
            .authorize_safe_fix(fixture.input())
            .expect("engine verification");
        let mut wrong_candidate = fixture.candidate.clone();
        wrong_candidate.fix_candidate_id = fresh_object_id().expect("wrong candidate id");

        let error = workspace
            .apply_verified(
                &wrong_candidate,
                &patch,
                &fixture.evidence[2],
                authorization,
            )
            .expect_err("failed validation must consume the authorization");
        assert!(matches!(error, ScratchError::CandidateNotAuthorized));

        let fresh_authorization = workspace
            .authorize_safe_fix(fixture.input())
            .expect("fresh engine verification");
        workspace
            .apply_verified(
                &fixture.candidate,
                &patch,
                &fixture.evidence[2],
                fresh_authorization,
            )
            .expect("fresh authorization must permit the later apply");
        assert_eq!(
            fs::read(workspace.path().join("file.txt")).expect("result"),
            b"after"
        );
        workspace.cleanup().expect("cleanup");
    }

    #[test]
    fn authorization_cannot_cross_candidate_patch_or_base() {
        let repo = tempdir().expect("repo");
        fs::write(repo.path().join("file.txt"), b"before").expect("file");
        let mut workspace =
            ScratchWorkspace::stage(repo.path(), &["file.txt"], limits()).expect("stage");
        let patch = ScratchPatch::new(vec![ScratchChange::Write {
            path: "file.txt".to_owned(),
            contents: b"after".to_vec(),
        }])
        .expect("patch");
        let fixture = verification_fixture(&workspace, &patch);

        let mut other_candidate = fixture.candidate.clone();
        other_candidate.fix_candidate_id = fresh_object_id().expect("other candidate id");
        let authorization = workspace
            .authorize_safe_fix(fixture.input())
            .expect("fresh engine verification for candidate binding");
        let error = workspace
            .apply_verified(
                &other_candidate,
                &patch,
                &fixture.evidence[2],
                authorization,
            )
            .expect_err("candidate-bound authorization must not transfer");
        assert!(matches!(error, ScratchError::CandidateNotAuthorized));

        let other_patch = ScratchPatch::new(vec![ScratchChange::Write {
            path: "file.txt".to_owned(),
            contents: b"different patch".to_vec(),
        }])
        .expect("other patch");
        let other_capture = workspace
            .capture(&other_patch, None)
            .expect("other capture");
        let mut same_candidate_new_patch = fixture.candidate.clone();
        same_candidate_new_patch.patch_evidence_id = other_capture.patch.evidence_id.clone();
        let authorization = workspace
            .authorize_safe_fix(fixture.input())
            .expect("fresh engine verification for patch binding");
        let error = workspace
            .apply_verified(
                &same_candidate_new_patch,
                &other_patch,
                &other_capture.patch,
                authorization,
            )
            .expect_err("patch-bound authorization must not transfer");
        assert!(matches!(error, ScratchError::CandidateNotAuthorized));

        let other_repo = tempdir().expect("other repo");
        fs::write(other_repo.path().join("file.txt"), b"different base").expect("other file");
        let mut other_workspace =
            ScratchWorkspace::stage(other_repo.path(), &["file.txt"], limits())
                .expect("other stage");
        let authorization = workspace
            .authorize_safe_fix(fixture.input())
            .expect("fresh engine verification for base binding");
        let error = other_workspace
            .apply_verified(
                &fixture.candidate,
                &patch,
                &fixture.evidence[2],
                authorization,
            )
            .expect_err("base-bound authorization must not transfer");
        assert!(matches!(error, ScratchError::CandidateNotAuthorized));

        other_workspace.cleanup().expect("cleanup other");
        workspace.cleanup().expect("cleanup");
    }

    #[test]
    fn evidence_records_validate_as_complete_inline_records() {
        let repo = tempdir().expect("repo");
        fs::write(repo.path().join("file.txt"), b"content").expect("file");
        let workspace =
            ScratchWorkspace::stage(repo.path(), &["file.txt"], limits()).expect("stage");
        let patch = ScratchPatch::new(Vec::new()).expect("empty patch");
        let evidence = workspace.capture(&patch, None).expect("capture");
        evidence.base.validate().expect("base");
        evidence.result.validate().expect("result");
        evidence.patch.validate().expect("patch");
        assert_ne!(evidence.base.evidence_id, evidence.result.evidence_id);
        assert_ne!(evidence.base.evidence_id, evidence.patch.evidence_id);
        workspace.cleanup().expect("cleanup");
    }
}

#[cfg(all(test, not(unix)))]
mod non_unix_tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn staging_reports_typed_no_follow_unsupported() {
        let repo = tempdir().expect("repo");
        fs::write(repo.path().join("source.txt"), b"content").expect("source");

        let error = ScratchWorkspace::stage(repo.path(), &["source.txt"], ScratchLimits::default())
            .expect_err("non-Unix staging must reject unsupported no-follow traversal");

        assert!(matches!(error, ScratchError::NoFollowUnsupported));
    }
}
