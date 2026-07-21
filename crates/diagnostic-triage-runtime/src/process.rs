//! Bounded, shell-free child process execution.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

use std::{
    ffi::OsStr,
    io::{self, Read, Write},
    ops::{Deref, DerefMut},
    path::PathBuf,
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use thiserror::Error;
use wait_timeout::ChildExt;

use diagnostic_triage_contracts::protocol::RequestLimits;
#[cfg(unix)]
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
#[cfg(unix)]
use rustix::process::{Pid, Signal, kill_process_group};
#[cfg(unix)]
use std::os::unix::io::AsFd;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

const IO_CHUNK_BYTES: usize = 8 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const TERMINATION_GRACE: Duration = Duration::from_millis(250);
const PROCESS_GROUP_GRACE: Duration = Duration::from_millis(500);

/// Resource limits for one direct child invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessLimits {
    pub timeout: Duration,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
}

impl ProcessLimits {
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
    pub const DEFAULT_STDOUT_BYTES: usize = 16 * 1024 * 1024;
    pub const DEFAULT_STDERR_BYTES: usize = 4 * 1024 * 1024;

    /// Reject limits that cannot provide a meaningful protocol-v1 execution.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError::InvalidLimits`] for a zero value or a value
    /// above the protocol-v1 ceiling.
    pub fn validate(self) -> Result<Self, ProcessError> {
        if self.timeout < Duration::from_millis(1) || self.timeout.as_nanos() % 1_000_000 != 0 {
            return Err(ProcessError::InvalidLimits(
                "timeout must be a positive whole number of milliseconds",
            ));
        }
        if self.timeout > Self::DEFAULT_TIMEOUT {
            return Err(ProcessError::InvalidLimits(
                "timeout exceeds the protocol-v1 ceiling",
            ));
        }
        if self.max_stdout_bytes > Self::DEFAULT_STDOUT_BYTES {
            return Err(ProcessError::InvalidLimits(
                "max_stdout_bytes exceeds the protocol-v1 ceiling",
            ));
        }
        if self.max_stderr_bytes > Self::DEFAULT_STDERR_BYTES {
            return Err(ProcessError::InvalidLimits(
                "max_stderr_bytes exceeds the protocol-v1 ceiling",
            ));
        }
        Ok(self)
    }
}

impl TryFrom<&RequestLimits> for ProcessLimits {
    type Error = ProcessError;

    fn try_from(value: &RequestLimits) -> Result<Self, Self::Error> {
        Self {
            timeout: Duration::from_millis(value.timeout_ms),
            max_stdout_bytes: usize::try_from(value.max_stdout_bytes)
                .map_err(|_| ProcessError::InvalidLimits("max_stdout_bytes exceeds usize"))?,
            max_stderr_bytes: usize::try_from(value.max_stderr_bytes)
                .map_err(|_| ProcessError::InvalidLimits("max_stderr_bytes exceeds usize"))?,
        }
        .validate()
    }
}

impl Default for ProcessLimits {
    fn default() -> Self {
        Self {
            timeout: Self::DEFAULT_TIMEOUT,
            max_stdout_bytes: Self::DEFAULT_STDOUT_BYTES,
            max_stderr_bytes: Self::DEFAULT_STDERR_BYTES,
        }
    }
}

/// One executable plus an argv vector. No shell command string is accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessSpec {
    program: PathBuf,
    argv: Vec<String>,
    current_dir: Option<PathBuf>,
    stdin: Vec<u8>,
}

impl ProcessSpec {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            argv: Vec::new(),
            current_dir: None,
            stdin: Vec::new(),
        }
    }

    #[must_use]
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.argv.push(arg.into());
        self
    }

    #[must_use]
    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.argv.extend(args.into_iter().map(Into::into));
        self
    }

    /// Set a trusted runtime-owned working directory.
    ///
    /// Wire paths must be validated as repository-relative before the runtime
    /// resolves them beneath a repository or scratch root and calls this API.
    #[must_use]
    pub fn current_dir(mut self, current_dir: impl Into<PathBuf>) -> Self {
        self.current_dir = Some(current_dir.into());
        self
    }

    /// Require complete delivery of these bytes for an operationally complete
    /// outcome. If the child closes stdin early, the outcome is `INCOMPLETE`
    /// even when the child also reports a zero exit status.
    #[must_use]
    pub fn stdin(mut self, stdin: impl Into<Vec<u8>>) -> Self {
        self.stdin = stdin.into();
        self
    }

    fn validate(&self) -> Result<(), ProcessError> {
        if self.program.as_os_str().is_empty() {
            return Err(ProcessError::InvalidSpec("program must not be empty"));
        }
        reject_nul(self.program.as_os_str(), "program")?;
        for arg in &self.argv {
            if arg.contains('\0') {
                return Err(ProcessError::InvalidSpec("argv must not contain NUL"));
            }
        }
        if let Some(current_dir) = &self.current_dir {
            reject_nul(current_dir.as_os_str(), "current_dir")?;
            if !current_dir.is_dir() {
                return Err(ProcessError::InvalidCurrentDirectory {
                    path: current_dir.clone(),
                });
            }
        }
        Ok(())
    }
}

/// A captured stream. `bytes` never exceeds its configured limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedOutput {
    pub bytes: Vec<u8>,
    pub observed_bytes: u64,
    pub truncated: bool,
}

impl BoundedOutput {
    fn with_capacity(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(IO_CHUNK_BYTES)),
            observed_bytes: 0,
            truncated: false,
        }
    }

    fn append(&mut self, chunk: &[u8], limit: usize) {
        self.observed_bytes = self
            .observed_bytes
            .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        let available = limit.saturating_sub(self.bytes.len());
        self.bytes
            .extend_from_slice(&chunk[..chunk.len().min(available)]);
        self.truncated |= chunk.len() > available;
    }
}

/// Why a child invocation cannot be treated as operationally complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncompleteReason {
    HandshakeTimeout,
    HandshakeRejected,
    ManifestMissing,
    ProtocolViolation,
    RequestOrderViolation,
    Timeout,
    StdoutLimitExceeded,
    StderrLimitExceeded,
    StdinFailure,
    StdoutFailure,
    StderrFailure,
    UnrepresentableExitCode,
    TerminatedWithoutCode,
}

/// Process completion is deliberately separate from the tool's exit code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessState {
    Complete,
    Incomplete(IncompleteReason),
}

/// Result of one bounded invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessOutcome {
    pub state: ProcessState,
    pub exit_code: Option<u8>,
    pub stdout: BoundedOutput,
    pub stderr: BoundedOutput,
    /// Protocol-attributable run time, never greater than the requested limit.
    pub duration: Duration,
    /// Time spent terminating and draining after the attributable run phase.
    pub cleanup_duration: Duration,
}

/// Transport result for a manifest-first provider invocation.
pub(crate) struct ManifestFirstOutcome {
    pub(crate) process: ProcessOutcome,
    pub(crate) handshake_accepted: bool,
    pub(crate) request_bytes_written: usize,
}

/// Incremental disposition of one provider JSONL line after request delivery.
pub(crate) enum StreamLineDecision {
    Continue,
    Complete,
    Reject,
}

/// Failures that prevent even an incomplete process record from being trusted.
#[derive(Debug, Error)]
pub enum ProcessError {
    #[error("bounded process-group execution is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("invalid process specification: {0}")]
    InvalidSpec(&'static str),
    #[error("invalid process limits: {0}")]
    InvalidLimits(&'static str),
    #[error("current directory is not a directory: {path}")]
    InvalidCurrentDirectory { path: PathBuf },
    #[error("failed to spawn {program}: {source}")]
    Spawn {
        program: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("spawned child did not expose its {stream} pipe")]
    MissingPipe { stream: &'static str },
    #[error("failed to configure the {stream} pipe as nonblocking: {source}")]
    PipeConfiguration {
        stream: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("failed while waiting for child: {0}")]
    Wait(#[source] io::Error),
    #[error("failed to signal the child process group: {0}")]
    GroupSignal(#[source] io::Error),
    #[error("failed while waiting for the child process group: {0}")]
    GroupWait(#[source] io::Error),
    #[error("child process group remained live after termination")]
    GroupUnreaped,
    #[error("failed to terminate the group leader directly: {0}")]
    LeaderSignal(#[source] io::Error),
    #[error("failed while reaping the group leader: {0}")]
    Reap(#[source] io::Error),
    #[error("child could not be reaped after termination")]
    Unreaped,
    #[error("capture pipes remained open after process termination")]
    CaptureDrainTimeout,
    #[error("multiple process failures: {failures:?}")]
    MultipleFailures { failures: Vec<ProcessError> },
}

/// Execute one tool-native program directly, bounding time and output streams.
///
/// A non-zero exit remains a complete process outcome; protocol completion and
/// policy success are evaluated by later runtime layers. Provider protocol
/// sessions require a manifest-first handshake runner and must not use this
/// immediate-stdin helper.
///
/// This executor is not a hostile-code sandbox. Configured programs must be
/// trusted: Unix cleanup terminates the dedicated process group, but a program
/// that deliberately creates a new session can escape that group. The caller's
/// latency, captured output, and memory remain bounded even when an escaped
/// process retains an inherited pipe.
///
/// # Errors
///
/// Returns an error when the specification or limits are invalid, the child
/// cannot be spawned or reaped, or its pipes cannot be configured.
pub fn run_bounded(
    spec: &ProcessSpec,
    limits: ProcessLimits,
) -> Result<ProcessOutcome, ProcessError> {
    // v1 release targets are macOS and Linux. A direct-child fallback is not
    // equivalent to bounded process-tree cleanup, so non-Unix hosts fail
    // before spawning instead of making a false containment guarantee.
    if cfg!(not(unix)) {
        return Err(ProcessError::UnsupportedPlatform);
    }
    spec.validate()?;
    let limits = limits.validate()?;
    let started = Instant::now();
    let (mut child, mut pipes) = spawn_piped_child(spec)?;
    let mut capture = CaptureState::new(&limits);
    if spec.stdin.is_empty() {
        pipes.stdin.take();
        capture.stdin_done = true;
    }
    let mut stdin_offset = 0;
    let deadline = started.checked_add(limits.timeout).unwrap_or(started);
    let mut exit_status = None;
    let mut timing = RunTiming::new(started);

    // LLM contract: RUNNING -> DRAINING -> COMPLETE | INCOMPLETE; once
    // cleanup grace expires, local pipe handles are explicitly dropped.
    while !capture.is_finished(exit_status.as_ref()) {
        let mut made_progress = false;
        if pipes.stdin.is_some() {
            made_progress = write_stdin(
                &mut pipes.stdin,
                &spec.stdin,
                &mut stdin_offset,
                &mut capture,
            ) || made_progress;
        }
        if capture.failure.is_none() {
            made_progress = drain_output(Stream::Stdout, &mut pipes.stdout, &mut capture, &limits)
                || made_progress;
        }
        if capture.failure.is_none() {
            made_progress = drain_output(Stream::Stderr, &mut pipes.stderr, &mut capture, &limits)
                || made_progress;
        }
        if stop_failed(
            &mut child,
            &mut pipes,
            &mut capture,
            &limits,
            &mut exit_status,
            &mut timing,
        )? {
            break;
        }

        let leader_exited = match child_exited_without_reaping(&child) {
            Ok(exited) => exited,
            Err(source) => {
                return Err(cleanup_after_process_error(
                    &mut child,
                    &mut pipes,
                    &mut capture,
                    &limits,
                    &mut exit_status,
                    ProcessError::Wait(source),
                ));
            }
        };
        let now = Instant::now();
        if now >= deadline {
            capture.failure = Some(IncompleteReason::Timeout);
            timing.mark(limits);
            cleanup_execution(
                &mut child,
                &mut pipes,
                &mut capture,
                &limits,
                &mut exit_status,
            )?;
            break;
        }
        if leader_exited {
            timing.mark(limits);
            cleanup_execution(
                &mut child,
                &mut pipes,
                &mut capture,
                &limits,
                &mut exit_status,
            )?;
            break;
        }
        if !made_progress {
            std::thread::sleep(deadline.saturating_duration_since(now).min(POLL_INTERVAL));
        }
    }

    let run_duration = timing.run_duration.ok_or(ProcessError::Unreaped)?;

    Ok(finalize_outcome(
        started,
        limits,
        run_duration,
        &mut child,
        exit_status,
        capture,
    ))
}

/// Run a provider without writing request bytes until its first complete
/// stdout line has been accepted as the manifest.
///
/// The validator is invoked exactly once and before any request byte is
/// written. A rejected manifest, pre-request payload output, early EOF, or
/// handshake timeout becomes a bounded incomplete outcome.
pub(crate) fn run_bounded_manifest_first(
    spec: &ProcessSpec,
    limits: ProcessLimits,
    handshake_timeout: Duration,
    validate_manifest: impl FnOnce(&[u8]) -> bool,
    mut validate_stream_line: impl FnMut(&[u8]) -> StreamLineDecision,
) -> Result<ManifestFirstOutcome, ProcessError> {
    let limits = validate_manifest_first_spec(spec, limits, handshake_timeout)?;
    let started = Instant::now();
    let deadlines = PhaseDeadlines {
        total: started.checked_add(limits.timeout).unwrap_or(started),
        handshake: started.checked_add(handshake_timeout).unwrap_or(started),
    };
    let (mut child, mut pipes) = spawn_piped_child(spec)?;
    let mut capture = CaptureState::new(&limits);
    let mut validator = Some(validate_manifest);
    let mut handshake_accepted = false;
    let mut stream_complete = false;
    let mut stream_offset = 0;
    let mut request_bytes_written = 0;
    let mut exit_status = None;
    let mut timing = RunTiming::new(started);

    // LLM contract: MANIFEST_PENDING -> REQUEST_WRITING -> STREAMING -> COMPLETE | INCOMPLETE; request bytes are forbidden in MANIFEST_PENDING.
    while !capture.is_finished(exit_status.as_ref()) {
        let mut made_progress = false;
        enforce_phase_deadline(&mut capture, handshake_accepted, deadlines);
        if stop_failed(
            &mut child,
            &mut pipes,
            &mut capture,
            &limits,
            &mut exit_status,
            &mut timing,
        )? {
            break;
        }
        let request_phase = handshake_accepted;
        let stdout_before = capture.stdout.observed_bytes;
        if capture.failure.is_none() {
            made_progress = if request_phase {
                drain_output(Stream::Stdout, &mut pipes.stdout, &mut capture, &limits)
            } else {
                drain_output_until_idle(&mut pipes.stdout, &mut capture, &limits)
            } || made_progress;
        }
        if request_phase && !capture.stdin_done && capture.stdout.observed_bytes > stdout_before {
            capture.failure = Some(IncompleteReason::RequestOrderViolation);
        } else if !request_phase && capture.failure.is_none() {
            if let Some(line_end) = validate_available_manifest(&mut capture, &mut validator) {
                handshake_accepted = true;
                stream_offset = line_end;
            }
        }
        if !request_phase && handshake_accepted && Instant::now() >= deadlines.handshake {
            capture.failure = Some(IncompleteReason::HandshakeTimeout);
        }
        if capture.failure.is_none() && handshake_accepted && pipes.stdin.is_some() {
            made_progress = write_stdin(
                &mut pipes.stdin,
                &spec.stdin,
                &mut request_bytes_written,
                &mut capture,
            ) || made_progress;
        }
        if capture.failure.is_none() && capture.stdin_done {
            validate_stream_progress(
                &mut capture,
                &mut stream_offset,
                &mut stream_complete,
                &mut validate_stream_line,
            );
        }
        if capture.failure.is_none() {
            made_progress = drain_output(Stream::Stderr, &mut pipes.stderr, &mut capture, &limits)
                || made_progress;
        }

        if stop_failed(
            &mut child,
            &mut pipes,
            &mut capture,
            &limits,
            &mut exit_status,
            &mut timing,
        )? {
            break;
        }

        if finish_phase_iteration(
            &mut child,
            &mut pipes,
            &mut capture,
            &limits,
            &mut exit_status,
            &mut timing,
            IterationPhase {
                deadlines,
                handshake_accepted,
                made_progress,
            },
        )? {
            break;
        }
    }

    let process = finish_manifest(started, limits, &timing, &mut child, exit_status, capture)?;
    Ok(ManifestFirstOutcome {
        process,
        handshake_accepted,
        request_bytes_written,
    })
}

fn finish_manifest(
    started: Instant,
    limits: ProcessLimits,
    timing: &RunTiming,
    child: &mut ChildCleanupGuard,
    exit_status: Option<ExitStatus>,
    capture: CaptureState,
) -> Result<ProcessOutcome, ProcessError> {
    let run_duration = timing.run_duration.ok_or(ProcessError::Unreaped)?;
    Ok(finalize_outcome(
        started,
        limits,
        run_duration,
        child,
        exit_status,
        capture,
    ))
}

#[derive(Clone, Copy)]
struct PhaseDeadlines {
    total: Instant,
    handshake: Instant,
}

#[derive(Clone, Copy)]
struct IterationPhase {
    deadlines: PhaseDeadlines,
    handshake_accepted: bool,
    made_progress: bool,
}

struct RunTiming {
    started: Instant,
    run_duration: Option<Duration>,
}

impl RunTiming {
    fn new(started: Instant) -> Self {
        Self {
            started,
            run_duration: None,
        }
    }

    fn mark(&mut self, limits: ProcessLimits) {
        self.run_duration
            .get_or_insert_with(|| self.started.elapsed().min(limits.timeout));
    }
}

fn enforce_phase_deadline(
    capture: &mut CaptureState,
    handshake_accepted: bool,
    deadlines: PhaseDeadlines,
) {
    let now = Instant::now();
    if !handshake_accepted && now >= deadlines.handshake {
        capture.failure = Some(IncompleteReason::HandshakeTimeout);
    } else if now >= deadlines.total {
        capture.failure = Some(IncompleteReason::Timeout);
    }
}

fn finish_phase_iteration(
    child: &mut ChildCleanupGuard,
    pipes: &mut PipeHandles,
    capture: &mut CaptureState,
    limits: &ProcessLimits,
    exit_status: &mut Option<ExitStatus>,
    timing: &mut RunTiming,
    phase: IterationPhase,
) -> Result<bool, ProcessError> {
    let leader_exited = match child_exited_without_reaping(child) {
        Ok(exited) => exited,
        Err(source) => {
            return Err(cleanup_after_process_error(
                child,
                pipes,
                capture,
                limits,
                exit_status,
                ProcessError::Wait(source),
            ));
        }
    };
    let now = Instant::now();
    if now >= phase.deadlines.total {
        capture.failure = Some(IncompleteReason::Timeout);
    } else if !phase.handshake_accepted
        && (capture.stdout_done || leader_exited)
        && !capture.stdout.bytes.contains(&b'\n')
    {
        capture.failure = Some(IncompleteReason::ManifestMissing);
    }
    if stop_failed(child, pipes, capture, limits, exit_status, timing)? {
        return Ok(true);
    }
    if leader_exited {
        timing.mark(*limits);
        cleanup_execution(child, pipes, capture, limits, exit_status)?;
        return Ok(true);
    }
    if !phase.made_progress {
        let phase_deadline = if phase.handshake_accepted {
            phase.deadlines.total
        } else {
            phase.deadlines.handshake
        };
        std::thread::sleep(
            phase_deadline
                .saturating_duration_since(now)
                .min(POLL_INTERVAL),
        );
    }
    Ok(false)
}

fn stop_failed(
    child: &mut ChildCleanupGuard,
    pipes: &mut PipeHandles,
    capture: &mut CaptureState,
    limits: &ProcessLimits,
    exit_status: &mut Option<ExitStatus>,
    timing: &mut RunTiming,
) -> Result<bool, ProcessError> {
    if capture.failure.is_none() {
        return Ok(false);
    }
    timing.mark(*limits);
    cleanup_execution(child, pipes, capture, limits, exit_status)?;
    Ok(true)
}

fn cleanup_execution(
    child: &mut ChildCleanupGuard,
    pipes: &mut PipeHandles,
    capture: &mut CaptureState,
    limits: &ProcessLimits,
    exit_status: &mut Option<ExitStatus>,
) -> Result<(), ProcessError> {
    cleanup_execution_with_group_signal(
        child,
        pipes,
        capture,
        limits,
        exit_status,
        signal_process_group,
    )
}

fn cleanup_execution_with_group_signal(
    child: &mut ChildCleanupGuard,
    pipes: &mut PipeHandles,
    capture: &mut CaptureState,
    limits: &ProcessLimits,
    exit_status: &mut Option<ExitStatus>,
    group_signal: fn(u32) -> io::Result<()>,
) -> Result<(), ProcessError> {
    let mut errors = Vec::new();
    if let Err(error) = terminate_and_reap_with_group_signal(child, exit_status, group_signal) {
        push_error(&mut errors, error);
    }
    if let Err(error) = drain_after_termination(pipes, capture, limits) {
        push_error(&mut errors, error);
    }
    // Once the leader has been reaped, never let Drop signal the numeric PGID
    // again: the kernel may already have reused it for an unrelated group.
    if exit_status.is_some() {
        child.disarm();
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(combine_errors(errors))
    }
}

fn cleanup_after_process_error(
    child: &mut ChildCleanupGuard,
    pipes: &mut PipeHandles,
    capture: &mut CaptureState,
    limits: &ProcessLimits,
    exit_status: &mut Option<ExitStatus>,
    primary: ProcessError,
) -> ProcessError {
    cleanup_after_process_error_with_group_signal(
        child,
        pipes,
        capture,
        limits,
        exit_status,
        primary,
        signal_process_group,
    )
}

fn cleanup_after_process_error_with_group_signal(
    child: &mut ChildCleanupGuard,
    pipes: &mut PipeHandles,
    capture: &mut CaptureState,
    limits: &ProcessLimits,
    exit_status: &mut Option<ExitStatus>,
    primary: ProcessError,
    group_signal: fn(u32) -> io::Result<()>,
) -> ProcessError {
    let mut errors = vec![primary];
    if let Err(error) = cleanup_execution_with_group_signal(
        child,
        pipes,
        capture,
        limits,
        exit_status,
        group_signal,
    ) {
        push_error(&mut errors, error);
    }
    combine_errors(errors)
}

fn validate_available_manifest<F>(
    capture: &mut CaptureState,
    validator: &mut Option<F>,
) -> Option<usize>
where
    F: FnOnce(&[u8]) -> bool,
{
    let newline = capture
        .stdout
        .bytes
        .iter()
        .position(|byte| *byte == b'\n')?;
    let line_end = newline.saturating_add(1);
    if capture.stdout.observed_bytes != u64::try_from(line_end).unwrap_or(u64::MAX) {
        capture.failure = Some(IncompleteReason::RequestOrderViolation);
        return None;
    }
    let accepted = validator.take().expect("manifest validator is called once")(
        &capture.stdout.bytes[..line_end],
    );
    if accepted {
        Some(line_end)
    } else {
        capture.failure = Some(IncompleteReason::HandshakeRejected);
        None
    }
}

fn drain_output_until_idle<R: Read>(
    reader: &mut Option<R>,
    capture: &mut CaptureState,
    limits: &ProcessLimits,
) -> bool {
    let mut made_progress = false;
    while capture.failure.is_none() && drain_output(Stream::Stdout, reader, capture, limits) {
        made_progress = true;
    }
    made_progress
}

fn validate_stream_progress(
    capture: &mut CaptureState,
    stream_offset: &mut usize,
    stream_complete: &mut bool,
    validate_line: &mut impl FnMut(&[u8]) -> StreamLineDecision,
) {
    if *stream_complete && capture.stdout.bytes.len() > *stream_offset {
        capture.failure = Some(IncompleteReason::ProtocolViolation);
        return;
    }
    while let Some(newline) = capture.stdout.bytes[*stream_offset..]
        .iter()
        .position(|byte| *byte == b'\n')
    {
        let line_end = (*stream_offset).saturating_add(newline).saturating_add(1);
        match validate_line(&capture.stdout.bytes[*stream_offset..line_end]) {
            StreamLineDecision::Continue => *stream_offset = line_end,
            StreamLineDecision::Complete => {
                *stream_offset = line_end;
                *stream_complete = true;
            }
            StreamLineDecision::Reject => {
                capture.failure = Some(IncompleteReason::ProtocolViolation);
                return;
            }
        }
        if *stream_complete && capture.stdout.bytes.len() > *stream_offset {
            capture.failure = Some(IncompleteReason::ProtocolViolation);
            return;
        }
    }
    if capture.stdout_done && *stream_offset < capture.stdout.bytes.len() {
        match validate_line(&capture.stdout.bytes[*stream_offset..]) {
            StreamLineDecision::Complete => {
                *stream_offset = capture.stdout.bytes.len();
                *stream_complete = true;
            }
            StreamLineDecision::Continue | StreamLineDecision::Reject => {
                capture.failure = Some(IncompleteReason::ProtocolViolation);
                return;
            }
        }
    }
    if capture.stdout_done && !*stream_complete {
        capture.failure = Some(IncompleteReason::ProtocolViolation);
    }
}

fn validate_manifest_first_spec(
    spec: &ProcessSpec,
    limits: ProcessLimits,
    handshake_timeout: Duration,
) -> Result<ProcessLimits, ProcessError> {
    if cfg!(not(unix)) {
        return Err(ProcessError::UnsupportedPlatform);
    }
    spec.validate()?;
    if spec.stdin.is_empty() {
        return Err(ProcessError::InvalidSpec(
            "manifest-first request must not be empty",
        ));
    }
    let limits = limits.validate()?;
    if handshake_timeout.is_zero() || handshake_timeout > limits.timeout {
        return Err(ProcessError::InvalidLimits(
            "handshake timeout must be positive and within total timeout",
        ));
    }
    Ok(limits)
}

fn spawn_piped_child(spec: &ProcessSpec) -> Result<(ChildCleanupGuard, PipeHandles), ProcessError> {
    spawn_piped_child_with_group_signal(spec, signal_process_group)
}

fn spawn_piped_child_with_group_signal(
    spec: &ProcessSpec,
    group_signal: fn(u32) -> io::Result<()>,
) -> Result<(ChildCleanupGuard, PipeHandles), ProcessError> {
    let mut child = ChildCleanupGuard::new(spawn_child(spec)?);
    let pipes = (|| {
        let stdin = child
            .stdin
            .take()
            .ok_or(ProcessError::MissingPipe { stream: "stdin" })?;
        let stdout = child
            .stdout
            .take()
            .ok_or(ProcessError::MissingPipe { stream: "stdout" })?;
        let stderr = child
            .stderr
            .take()
            .ok_or(ProcessError::MissingPipe { stream: "stderr" })?;
        let pipes = PipeHandles::new(stdin, stdout, stderr);
        pipes.configure_nonblocking()?;
        Ok(pipes)
    })();
    match pipes {
        Ok(pipes) => Ok((child, pipes)),
        Err(primary) => Err(cleanup_spawn_failure(&mut child, primary, group_signal)),
    }
}

fn cleanup_spawn_failure(
    child: &mut ChildCleanupGuard,
    primary: ProcessError,
    group_signal: fn(u32) -> io::Result<()>,
) -> ProcessError {
    let mut errors = vec![primary];
    let mut exit_status = None;
    if let Err(error) = terminate_and_reap_with_group_signal(child, &mut exit_status, group_signal)
    {
        push_error(&mut errors, error);
    }
    if exit_status.is_some() {
        child.disarm();
    }
    combine_errors(errors)
}

fn finalize_outcome(
    started: Instant,
    limits: ProcessLimits,
    duration: Duration,
    child: &mut ChildCleanupGuard,
    exit_status: Option<ExitStatus>,
    capture: CaptureState,
) -> ProcessOutcome {
    let native_exit_code = exit_status.as_ref().and_then(ExitStatus::code);
    let exit_code = native_exit_code.and_then(|code| u8::try_from(code).ok());
    let state = match capture.failure {
        Some(reason) => ProcessState::Incomplete(reason),
        None if exit_status.is_some() && exit_code.is_some() => ProcessState::Complete,
        None if native_exit_code.is_some() => {
            ProcessState::Incomplete(IncompleteReason::UnrepresentableExitCode)
        }
        None => ProcessState::Incomplete(IncompleteReason::TerminatedWithoutCode),
    };
    let exit_code = (state == ProcessState::Complete)
        .then_some(exit_code)
        .flatten();
    let duration = duration.min(limits.timeout);
    child.disarm();
    ProcessOutcome {
        state,
        exit_code,
        stdout: capture.stdout,
        stderr: capture.stderr,
        duration,
        cleanup_duration: started.elapsed().saturating_sub(duration),
    }
}

#[cfg(unix)]
fn child_exited_without_reaping(child: &Child) -> io::Result<bool> {
    use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};

    let pid = i32::try_from(child.id())
        .ok()
        .and_then(Pid::from_raw)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "child pid must be nonzero"))?;
    waitid(
        WaitId::Pid(pid),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    )
    .map(|status| status.is_some())
    .map_err(io::Error::from)
}

#[cfg(not(unix))]
fn child_exited_without_reaping(_: &Child) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "process groups are unsupported",
    ))
}

/// Ensures every post-spawn error path terminates the process group and reaps
/// its leader before ownership is released.
struct ChildCleanupGuard {
    child: Child,
    armed: bool,
}

impl ChildCleanupGuard {
    fn new(child: Child) -> Self {
        Self { child, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Deref for ChildCleanupGuard {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.child
    }
}

impl DerefMut for ChildCleanupGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.child
    }
}

impl Drop for ChildCleanupGuard {
    fn drop(&mut self) {
        if self.armed {
            let mut exit_status = None;
            let _ignored = terminate_and_reap(&mut self.child, &mut exit_status);
        }
    }
}

fn spawn_child(spec: &ProcessSpec) -> Result<Child, ProcessError> {
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(current_dir) = &spec.current_dir {
        command.current_dir(current_dir);
    }
    #[cfg(unix)]
    command.process_group(0);
    command.spawn().map_err(|source| ProcessError::Spawn {
        program: spec.program.clone(),
        source,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stream {
    Stdout,
    Stderr,
}

struct PipeHandles {
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
}

impl PipeHandles {
    fn new(stdin: ChildStdin, stdout: ChildStdout, stderr: ChildStderr) -> Self {
        Self {
            stdin: Some(stdin),
            stdout: Some(stdout),
            stderr: Some(stderr),
        }
    }

    fn configure_nonblocking(&self) -> Result<(), ProcessError> {
        set_pipe_nonblocking(self.stdin.as_ref().expect("stdin pipe exists"), "stdin")?;
        set_pipe_nonblocking(self.stdout.as_ref().expect("stdout pipe exists"), "stdout")?;
        set_pipe_nonblocking(self.stderr.as_ref().expect("stderr pipe exists"), "stderr")?;
        Ok(())
    }

    fn drop_all(&mut self) {
        self.stdin.take();
        self.stdout.take();
        self.stderr.take();
    }
}

#[cfg(unix)]
fn set_pipe_nonblocking<T: AsFd>(pipe: &T, stream: &'static str) -> Result<(), ProcessError> {
    let flags = fcntl_getfl(pipe).map_err(|source| ProcessError::PipeConfiguration {
        stream,
        source: source.into(),
    })?;
    fcntl_setfl(pipe, flags | OFlags::NONBLOCK).map_err(|source| ProcessError::PipeConfiguration {
        stream,
        source: source.into(),
    })
}

#[cfg(not(unix))]
fn set_pipe_nonblocking<T>(_: &T, _: &'static str) -> Result<(), ProcessError> {
    Err(ProcessError::UnsupportedPlatform)
}

struct CaptureState {
    stdin_done: bool,
    stdout_done: bool,
    stderr_done: bool,
    stdout: BoundedOutput,
    stderr: BoundedOutput,
    failure: Option<IncompleteReason>,
}

impl CaptureState {
    fn new(limits: &ProcessLimits) -> Self {
        Self {
            stdin_done: false,
            stdout_done: false,
            stderr_done: false,
            stdout: BoundedOutput::with_capacity(limits.max_stdout_bytes),
            stderr: BoundedOutput::with_capacity(limits.max_stderr_bytes),
            failure: None,
        }
    }

    fn is_finished(&self, status: Option<&ExitStatus>) -> bool {
        status.is_some() && self.stdin_done && self.stdout_done && self.stderr_done
    }

    fn accept_output(&mut self, stream: Stream, chunk: &[u8], limits: &ProcessLimits) {
        let (output, limit, reason) = match stream {
            Stream::Stdout => (
                &mut self.stdout,
                limits.max_stdout_bytes,
                IncompleteReason::StdoutLimitExceeded,
            ),
            Stream::Stderr => (
                &mut self.stderr,
                limits.max_stderr_bytes,
                IncompleteReason::StderrLimitExceeded,
            ),
        };
        output.append(chunk, limit);
        if output.truncated {
            self.failure.get_or_insert(reason);
        }
    }

    fn mark_output_done(&mut self, stream: Stream) {
        match stream {
            Stream::Stdout => self.stdout_done = true,
            Stream::Stderr => self.stderr_done = true,
        }
    }

    fn mark_output_failure(&mut self, stream: Stream) {
        self.mark_output_done(stream);
        self.failure.get_or_insert(match stream {
            Stream::Stdout => IncompleteReason::StdoutFailure,
            Stream::Stderr => IncompleteReason::StderrFailure,
        });
    }
}

fn write_stdin(
    stdin: &mut Option<ChildStdin>,
    input: &[u8],
    offset: &mut usize,
    capture: &mut CaptureState,
) -> bool {
    let Some(pipe) = stdin.as_mut() else {
        return false;
    };
    let end = (*offset).saturating_add(IO_CHUNK_BYTES).min(input.len());
    match pipe.write(&input[*offset..end]) {
        Ok(0) => {
            stdin.take();
            capture.stdin_done = true;
            capture
                .failure
                .get_or_insert(IncompleteReason::StdinFailure);
            false
        }
        Ok(size) => {
            *offset += size;
            if *offset == input.len() {
                stdin.take();
                capture.stdin_done = true;
            }
            true
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => false,
        Err(error) if error.kind() == io::ErrorKind::Interrupted => false,
        Err(_) => {
            stdin.take();
            capture.stdin_done = true;
            capture
                .failure
                .get_or_insert(IncompleteReason::StdinFailure);
            false
        }
    }
}

fn drain_output<R: Read>(
    stream: Stream,
    reader: &mut Option<R>,
    capture: &mut CaptureState,
    limits: &ProcessLimits,
) -> bool {
    let Some(pipe) = reader.as_mut() else {
        return false;
    };
    let mut buffer = [0_u8; IO_CHUNK_BYTES];
    match pipe.read(&mut buffer) {
        Ok(0) => {
            reader.take();
            capture.mark_output_done(stream);
            false
        }
        Ok(size) => {
            capture.accept_output(stream, &buffer[..size], limits);
            true
        }
        Err(error)
            if error.kind() == io::ErrorKind::WouldBlock
                || error.kind() == io::ErrorKind::Interrupted =>
        {
            false
        }
        Err(_) => {
            reader.take();
            capture.mark_output_failure(stream);
            false
        }
    }
}

fn terminate_and_reap(
    child: &mut Child,
    exit_status: &mut Option<ExitStatus>,
) -> Result<(), ProcessError> {
    terminate_and_reap_with_group_signal(child, exit_status, signal_process_group)
}

fn terminate_and_reap_with_group_signal(
    child: &mut Child,
    exit_status: &mut Option<ExitStatus>,
    group_signal: fn(u32) -> io::Result<()>,
) -> Result<(), ProcessError> {
    let process_group = child.id();
    let deadline = Instant::now()
        .checked_add(PROCESS_GROUP_GRACE)
        .unwrap_or_else(Instant::now);
    let mut errors = Vec::new();
    let leader_exited_before_signal = if exit_status.is_some() {
        true
    } else {
        match child_exited_without_reaping(child) {
            Ok(exited) => exited,
            Err(source) => {
                errors.push(ProcessError::Wait(source));
                false
            }
        }
    };
    let group_signal_error = if exit_status.is_some() {
        None
    } else {
        group_signal(process_group).err()
    };
    let group_signal_failed = group_signal_error.is_some();
    if exit_status.is_none() {
        match child.try_wait() {
            Ok(status) => *exit_status = status,
            Err(source) => errors.push(ProcessError::Reap(source)),
        }
    }
    if exit_status.is_none() && group_signal_failed {
        if let Err(source) = child.kill() {
            errors.push(ProcessError::LeaderSignal(source));
        }
    }
    if exit_status.is_none() {
        match child.wait_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(status) => *exit_status = status,
            Err(source) => errors.push(ProcessError::Reap(source)),
        }
    }
    if exit_status.is_none() {
        errors.push(ProcessError::Unreaped);
    }
    let group_wait = wait_for_process_group(process_group, deadline);
    let zombie_only_permission_race = matches!(
        (&group_signal_error, &group_wait),
        (Some(source), Ok(true))
            if source.kind() == io::ErrorKind::PermissionDenied
                && leader_exited_before_signal
                && exit_status.is_some()
    );
    if let Some(source) = group_signal_error {
        if !zombie_only_permission_race {
            errors.push(ProcessError::GroupSignal(source));
        }
    }
    match group_wait {
        Ok(true) => {}
        Ok(false) => errors.push(ProcessError::GroupUnreaped),
        Err(source) => errors.push(ProcessError::GroupWait(source)),
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(combine_errors(errors))
    }
}

#[cfg(unix)]
fn signal_process_group(process_group: u32) -> io::Result<()> {
    let process_group = i32::try_from(process_group)
        .ok()
        .and_then(Pid::from_raw)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "process group must be nonzero")
        })?;
    match kill_process_group(process_group, Signal::KILL) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(error) => Err(io::Error::from(error)),
    }
}

#[cfg(not(unix))]
fn signal_process_group(_: u32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "process groups are unsupported",
    ))
}

#[cfg(unix)]
fn process_group_exists(process_group: u32) -> io::Result<bool> {
    use rustix::process::test_kill_process_group;

    let process_group = i32::try_from(process_group)
        .ok()
        .and_then(Pid::from_raw)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "process group must be nonzero")
        })?;
    map_process_group_probe(test_kill_process_group(process_group))
}

#[cfg(unix)]
fn map_process_group_probe(result: Result<(), rustix::io::Errno>) -> io::Result<bool> {
    use rustix::io::Errno;

    match result {
        Err(Errno::SRCH) => Ok(false),
        Ok(()) => Ok(true),
        Err(Errno::PERM) => Err(io::Error::from(Errno::PERM)),
        Err(error) => Err(io::Error::from(error)),
    }
}

#[cfg(not(unix))]
fn process_group_exists(_: u32) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "process groups are unsupported",
    ))
}

fn wait_for_process_group(process_group: u32, deadline: Instant) -> io::Result<bool> {
    wait_for_process_group_with_probe(process_group, deadline, process_group_exists)
}

fn wait_for_process_group_with_probe(
    process_group: u32,
    deadline: Instant,
    probe: fn(u32) -> io::Result<bool>,
) -> io::Result<bool> {
    loop {
        let permission_denied = match probe(process_group) {
            Ok(false) => return Ok(true),
            Ok(true) => None,
            Err(source) if source.kind() == io::ErrorKind::PermissionDenied => Some(source),
            Err(source) => return Err(source),
        };
        let wait = deadline.saturating_duration_since(Instant::now());
        if wait.is_zero() {
            return permission_denied.map_or(Ok(false), Err);
        }
        std::thread::sleep(wait.min(POLL_INTERVAL));
    }
}

fn push_error(errors: &mut Vec<ProcessError>, error: ProcessError) {
    match error {
        ProcessError::MultipleFailures { failures } => errors.extend(failures),
        error => errors.push(error),
    }
}

fn combine_errors(mut errors: Vec<ProcessError>) -> ProcessError {
    if errors.len() == 1 {
        errors.pop().expect("one process error is present")
    } else {
        ProcessError::MultipleFailures { failures: errors }
    }
}

fn drain_after_termination(
    pipes: &mut PipeHandles,
    capture: &mut CaptureState,
    limits: &ProcessLimits,
) -> Result<(), ProcessError> {
    pipes.stdin.take();
    capture.stdin_done = true;
    let deadline = Instant::now()
        .checked_add(TERMINATION_GRACE)
        .unwrap_or_else(Instant::now);
    while !(capture.stdin_done && capture.stdout_done && capture.stderr_done) {
        let mut made_progress = false;
        if capture.failure.is_some() || pipes.stdout.is_some() {
            made_progress |= drain_output(Stream::Stdout, &mut pipes.stdout, capture, limits);
        }
        if capture.failure.is_some() || pipes.stderr.is_some() {
            made_progress |= drain_output(Stream::Stderr, &mut pipes.stderr, capture, limits);
        }
        if capture.stdout_done && capture.stderr_done {
            break;
        }
        let now = Instant::now();
        let wait = deadline.saturating_duration_since(now);
        if wait.is_zero() {
            break;
        }
        if !made_progress {
            std::thread::sleep(wait.min(POLL_INTERVAL));
        }
    }
    let drained = capture.stdout_done && capture.stderr_done;
    // A descendant may have escaped the process group and retained a write
    // end. Never let that inherited handle extend the caller's lifetime.
    pipes.drop_all();
    if drained {
        Ok(())
    } else {
        Err(ProcessError::CaptureDrainTimeout)
    }
}

fn reject_nul(value: &OsStr, field: &'static str) -> Result<(), ProcessError> {
    if value.to_string_lossy().contains('\0') {
        return Err(ProcessError::InvalidSpec(match field {
            "program" => "program must not contain NUL",
            "current_dir" => "current_dir must not contain NUL",
            _ => "process value must not contain NUL",
        }));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        IO_CHUNK_BYTES, IncompleteReason, ProcessError, ProcessLimits, ProcessSpec, ProcessState,
        StreamLineDecision, run_bounded, run_bounded_manifest_first,
    };
    use std::time::Duration;
    use tempfile::tempdir;

    fn limits(stdout: usize, stderr: usize) -> ProcessLimits {
        ProcessLimits {
            timeout: Duration::from_secs(2),
            max_stdout_bytes: stdout,
            max_stderr_bytes: stderr,
        }
    }

    fn shell(script: &str) -> ProcessSpec {
        ProcessSpec::new("/bin/sh").args(["-c", script])
    }

    #[test]
    fn manifest_boundary_never_hides_pre_request_payload() {
        for line_bytes in [IO_CHUNK_BYTES - 1, IO_CHUNK_BYTES, IO_CHUNK_BYTES + 1] {
            let directory = tempdir().unwrap();
            let marker = directory.path().join("request-received");
            let manifest = "m".repeat(line_bytes - 1);
            let spec = ProcessSpec::new("/bin/sh")
                .args([
                    "-c",
                    "printf '%s\\nTAIL\\n' \"$1\"; if IFS= read -r request; then : > \"$2\"; fi",
                    "sh",
                    &manifest,
                    marker.to_str().unwrap(),
                ])
                .stdin(b"request\n".to_vec());
            let result = run_bounded_manifest_first(
                &spec,
                limits(32 * 1024, 4 * 1024),
                Duration::from_secs(1),
                |_| true,
                |_| StreamLineDecision::Continue,
            )
            .unwrap();

            assert_eq!(result.request_bytes_written, 0, "line bytes {line_bytes}");
            assert_eq!(
                result.process.state,
                ProcessState::Incomplete(IncompleteReason::RequestOrderViolation),
                "line bytes {line_bytes}"
            );
            assert!(!marker.exists(), "line bytes {line_bytes}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn manifest_first_leader_exit_kills_closed_stdio_delayed_writer() {
        let directory = tempdir().unwrap();
        let marker = directory.path().join("late-write");
        let spec = ProcessSpec::new("/bin/sh")
            .args([
                "-c",
                r#"printf 'manifest\n'; IFS= read -r request; (sleep 0.2; printf late > "$1") </dev/null >/dev/null 2>&1 & printf 'done\n'; exit 0"#,
                "sh",
                marker.to_str().unwrap(),
            ])
            .stdin(b"request\n".to_vec());

        let outcome = run_bounded_manifest_first(
            &spec,
            limits(1024, 64),
            Duration::from_secs(1),
            |line| line == b"manifest\n",
            |line| {
                if line == b"done\n" {
                    StreamLineDecision::Complete
                } else {
                    StreamLineDecision::Reject
                }
            },
        )
        .expect("manifest-first cleanup succeeds");

        assert!(outcome.handshake_accepted);
        assert_eq!(outcome.process.state, ProcessState::Complete);
        assert_eq!(outcome.process.exit_code, Some(0));
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            !marker.exists(),
            "completion published while a delayed same-group writer survived"
        );
    }

    #[cfg(unix)]
    fn assert_process_disappears(raw_pid: i32) {
        use rustix::process::{Pid, test_kill_process};

        let pid = Pid::from_raw(raw_pid).expect("pid is positive");
        for _ in 0..25 {
            if test_kill_process(pid).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("descendant process {raw_pid} survived process-group termination");
    }

    fn contains_group_signal(error: &ProcessError) -> bool {
        match error {
            ProcessError::GroupSignal(_) => true,
            ProcessError::MultipleFailures { failures } => {
                failures.iter().any(contains_group_signal)
            }
            _ => false,
        }
    }

    fn contains_capture_drain_timeout(error: &ProcessError) -> bool {
        match error {
            ProcessError::CaptureDrainTimeout => true,
            ProcessError::MultipleFailures { failures } => {
                failures.iter().any(contains_capture_drain_timeout)
            }
            _ => false,
        }
    }

    #[test]
    fn captures_stdout_stderr_and_stdin_without_a_shell_api() {
        let outcome = run_bounded(
            &shell("IFS= read -r line; printf '%s' \"$line\"; printf 'warning' >&2")
                .stdin(b"request\n".to_vec()),
            limits(1024, 1024),
        )
        .expect("process completes");

        assert_eq!(outcome.state, ProcessState::Complete);
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(outcome.stdout.bytes, b"request");
        assert_eq!(outcome.stderr.bytes, b"warning");
        assert!(!outcome.stdout.truncated);
    }

    #[test]
    fn preserves_nonzero_exit_as_a_completed_process() {
        let outcome = run_bounded(&shell("printf failure >&2; exit 7"), limits(64, 64))
            .expect("nonzero is still a process outcome");

        assert_eq!(outcome.state, ProcessState::Complete);
        assert_eq!(outcome.exit_code, Some(7));
        assert_eq!(outcome.stderr.bytes, b"failure");
    }

    #[test]
    fn timeout_terminates_the_child_and_is_incomplete() {
        let started = std::time::Instant::now();
        let outcome = run_bounded(
            &shell("while :; do :; done"),
            ProcessLimits {
                timeout: Duration::from_millis(40),
                max_stdout_bytes: 64,
                max_stderr_bytes: 64,
            },
        )
        .expect("timeout is a structured outcome");

        assert_eq!(
            outcome.state,
            ProcessState::Incomplete(IncompleteReason::Timeout)
        );
        assert_eq!(outcome.exit_code, None);
        assert!(outcome.duration <= Duration::from_millis(40));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn stdout_overflow_is_truncated_and_incomplete() {
        let outcome = run_bounded(
            &shell("i=0; while [ \"$i\" -lt 1000 ]; do printf x; i=$((i + 1)); done"),
            limits(32, 64),
        )
        .expect("overflow is a structured outcome");

        assert_eq!(
            outcome.state,
            ProcessState::Incomplete(IncompleteReason::StdoutLimitExceeded)
        );
        assert_eq!(outcome.stdout.bytes.len(), 32);
        assert!(outcome.stdout.observed_bytes > 32);
        assert!(outcome.stdout.truncated);
        assert_eq!(outcome.exit_code, None);
    }

    #[test]
    fn continuous_output_has_bounded_queueing_and_termination_latency() {
        let started = std::time::Instant::now();
        let outcome = run_bounded(&shell("yes"), limits(1, 64)).expect("bounded outcome");

        assert_eq!(
            outcome.state,
            ProcessState::Incomplete(IncompleteReason::StdoutLimitExceeded)
        );
        assert_eq!(outcome.stdout.bytes.len(), 1);
        assert!(outcome.stdout.truncated);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn stderr_overflow_is_truncated_and_incomplete() {
        let outcome = run_bounded(
            &shell("i=0; while [ \"$i\" -lt 1000 ]; do printf y >&2; i=$((i + 1)); done"),
            limits(64, 32),
        )
        .expect("overflow is a structured outcome");

        assert_eq!(
            outcome.state,
            ProcessState::Incomplete(IncompleteReason::StderrLimitExceeded)
        );
        assert_eq!(outcome.stderr.bytes.len(), 32);
        assert!(outcome.stderr.truncated);
    }

    #[test]
    fn output_at_the_exact_limit_is_complete() {
        let outcome =
            run_bounded(&shell("printf 12345678"), limits(8, 8)).expect("exact boundary completes");

        assert_eq!(outcome.state, ProcessState::Complete);
        assert_eq!(outcome.stdout.bytes, b"12345678");
        assert_eq!(outcome.stdout.observed_bytes, 8);
        assert!(!outcome.stdout.truncated);
    }

    #[test]
    fn simultaneous_streams_are_drained_without_deadlock() {
        let outcome = run_bounded(
            &shell("i=0; while [ \"$i\" -lt 1000 ]; do printf x; printf y >&2; i=$((i + 1)); done"),
            limits(2048, 2048),
        )
        .expect("both pipes drain");

        assert_eq!(outcome.state, ProcessState::Complete);
        assert_eq!(outcome.stdout.bytes.len(), 1000);
        assert_eq!(outcome.stderr.bytes.len(), 1000);
    }

    #[test]
    fn blocked_stdin_writer_still_obeys_timeout() {
        let started = std::time::Instant::now();
        let outcome = run_bounded(
            &shell("while :; do :; done").stdin(vec![b'x'; 1024 * 1024]),
            ProcessLimits {
                timeout: Duration::from_millis(40),
                max_stdout_bytes: 64,
                max_stderr_bytes: 64,
            },
        )
        .expect("blocked stdin is terminated");

        assert_eq!(
            outcome.state,
            ProcessState::Incomplete(IncompleteReason::Timeout)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn zero_capture_limit_is_valid_and_rejects_the_first_byte() {
        let empty = run_bounded(&shell("exit 0"), limits(0, 0)).expect("zero capture is valid");
        assert_eq!(empty.state, ProcessState::Complete);

        let output = run_bounded(&shell("printf x"), limits(0, 0)).expect("bounded outcome");
        assert_eq!(
            output.state,
            ProcessState::Incomplete(IncompleteReason::StdoutLimitExceeded)
        );
        assert!(output.stdout.bytes.is_empty());
        assert_eq!(output.stdout.observed_bytes, 1);
        assert_eq!(output.exit_code, None);
    }

    #[test]
    fn timeout_must_use_protocol_millisecond_precision() {
        let error = run_bounded(
            &shell("exit 0"),
            ProcessLimits {
                timeout: Duration::from_micros(1500),
                max_stdout_bytes: 0,
                max_stderr_bytes: 0,
            },
        )
        .unwrap_err();

        assert!(matches!(error, ProcessError::InvalidLimits(_)));
    }

    #[cfg(unix)]
    #[test]
    fn timeout_terminates_descendants_in_the_child_process_group() {
        let outcome = run_bounded(
            &shell(
                "while :; do :; done & descendant=$!; printf '%s\\n' \"$descendant\"; while :; do :; done",
            ),
            ProcessLimits {
                timeout: Duration::from_millis(80),
                max_stdout_bytes: 64,
                max_stderr_bytes: 64,
            },
        )
        .expect("timeout is structured");
        let raw_pid = String::from_utf8(outcome.stdout.bytes)
            .expect("pid is utf8")
            .trim()
            .parse::<i32>()
            .expect("pid is numeric");
        assert_process_disappears(raw_pid);
    }

    #[cfg(unix)]
    #[test]
    fn leader_exit_kills_inherited_pipe_descendant_and_preserves_status() {
        let outcome = run_bounded(
            &shell("while :; do :; done & descendant=$!; printf '%s\\n' \"$descendant\"; exit 0"),
            ProcessLimits {
                timeout: Duration::from_millis(80),
                max_stdout_bytes: 64,
                max_stderr_bytes: 64,
            },
        )
        .expect("orphaned pipe holder is terminated after leader exit");
        assert_eq!(outcome.state, ProcessState::Complete);
        assert_eq!(outcome.exit_code, Some(0));
        assert!(outcome.duration < Duration::from_secs(1));
        assert!(outcome.cleanup_duration > Duration::ZERO);
        let raw_pid = String::from_utf8(outcome.stdout.bytes)
            .expect("pid is utf8")
            .trim()
            .parse::<i32>()
            .expect("pid is numeric");
        assert_process_disappears(raw_pid);
    }

    #[cfg(unix)]
    #[test]
    fn zero_exit_kills_closed_stdio_descendant_and_preserves_status() {
        assert_closed_stdio_descendant_is_killed(0);
    }

    #[cfg(unix)]
    #[test]
    fn nonzero_exit_kills_closed_stdio_descendant_and_preserves_status() {
        assert_closed_stdio_descendant_is_killed(7);
    }

    #[cfg(unix)]
    fn assert_closed_stdio_descendant_is_killed(exit_code: u8) {
        let started = std::time::Instant::now();
        let outcome = run_bounded(
            &shell(&format!(
                "sleep 5 </dev/null >/dev/null 2>&1 & descendant=$!; printf '%s\\n' \"$descendant\"; exit {exit_code}"
            )),
            limits(64, 64),
        )
        .expect("leader status and descendant cleanup are both preserved");

        assert_eq!(outcome.state, ProcessState::Complete);
        assert_eq!(outcome.exit_code, Some(exit_code));
        assert!(started.elapsed() < Duration::from_secs(1));
        let raw_pid = String::from_utf8(outcome.stdout.bytes)
            .expect("pid is utf8")
            .trim()
            .parse::<i32>()
            .expect("pid is numeric");
        assert_process_disappears(raw_pid);
    }

    #[cfg(unix)]
    #[test]
    fn transient_group_probe_permission_error_is_retried() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static PROBE_CALLS: AtomicUsize = AtomicUsize::new(0);
        fn deny_once_then_absent(_: u32) -> std::io::Result<bool> {
            if PROBE_CALLS.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
            }
            Ok(false)
        }

        PROBE_CALLS.store(0, Ordering::SeqCst);
        let reaped = super::wait_for_process_group_with_probe(
            1,
            std::time::Instant::now() + Duration::from_millis(100),
            deny_once_then_absent,
        )
        .expect("a transient group-probe EPERM is retried");

        assert!(reaped);
        assert_eq!(PROBE_CALLS.load(Ordering::SeqCst), 2);
    }

    #[cfg(unix)]
    #[test]
    fn persistent_group_probe_permission_error_is_typed() {
        fn always_deny(_: u32) -> std::io::Result<bool> {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        }

        let error =
            super::wait_for_process_group_with_probe(1, std::time::Instant::now(), always_deny)
                .expect_err("a persistent group-probe EPERM must propagate");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        let production_error =
            super::map_process_group_probe(Err(rustix::io::Errno::PERM)).unwrap_err();
        assert_eq!(
            production_error.kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[cfg(unix)]
    #[test]
    fn zombie_only_permission_error_never_resignals_after_reap() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static SIGNAL_CALLS: AtomicUsize = AtomicUsize::new(0);
        fn deny_and_count(_: u32) -> std::io::Result<()> {
            SIGNAL_CALLS.fetch_add(1, Ordering::SeqCst);
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        }

        let (mut child, mut pipes) =
            super::spawn_piped_child(&ProcessSpec::new("/usr/bin/true")).unwrap();
        while !super::child_exited_without_reaping(&child).unwrap() {
            std::thread::sleep(Duration::from_millis(1));
        }
        let mut capture = super::CaptureState::new(&limits(64, 64));
        let mut exit_status = None;
        SIGNAL_CALLS.store(0, Ordering::SeqCst);

        super::cleanup_execution_with_group_signal(
            &mut child,
            &mut pipes,
            &mut capture,
            &limits(64, 64),
            &mut exit_status,
            deny_and_count,
        )
        .expect("zombie-only EPERM is resolved by a non-destructive probe");

        assert_eq!(SIGNAL_CALLS.load(Ordering::SeqCst), 1);
        assert!(exit_status.is_some());
        assert!(!child.armed, "reaped PGID must not remain armed");
    }

    #[cfg(unix)]
    #[test]
    fn escaped_session_pipe_holder_is_a_bounded_typed_failure() {
        let directory = tempdir().unwrap();
        let marker = directory.path().join("escaped-pid");
        let started = std::time::Instant::now();
        let result = run_bounded(&escaped_pipe_holder(&marker), limits(64, 64));
        let escaped_pid = std::fs::read_to_string(&marker)
            .expect("escaped process records its pid")
            .trim()
            .parse::<u32>()
            .expect("pid is numeric");
        super::signal_process_group(escaped_pid)
            .expect("test cleanup terminates escaped process group");

        let error = result.expect_err("an escaped pipe holder is incomplete");
        assert!(contains_capture_drain_timeout(&error), "error: {error:?}");
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_preserves_multiple_failures_and_disarms_reaped_pgid() {
        fn always_fail(_: u32) -> std::io::Result<()> {
            Err(std::io::Error::other("injected group-signal failure"))
        }

        let directory = tempdir().unwrap();
        let marker = directory.path().join("escaped-pid");
        let limits = limits(64, 64);
        let (mut child, mut pipes) =
            super::spawn_piped_child(&escaped_pipe_holder(&marker)).unwrap();
        while !marker.exists() || !super::child_exited_without_reaping(&child).unwrap() {
            std::thread::sleep(Duration::from_millis(1));
        }
        let mut capture = super::CaptureState::new(&limits);
        let mut exit_status = None;
        let error = super::cleanup_execution_with_group_signal(
            &mut child,
            &mut pipes,
            &mut capture,
            &limits,
            &mut exit_status,
            always_fail,
        )
        .expect_err("both injected signal and escaped-pipe failures propagate");
        let escaped_pid = std::fs::read_to_string(&marker)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        super::signal_process_group(escaped_pid)
            .expect("test cleanup terminates escaped process group");

        assert!(contains_group_signal(&error), "error: {error:?}");
        assert!(contains_capture_drain_timeout(&error), "error: {error:?}");
        assert!(exit_status.is_some());
        assert!(!child.armed, "cleanup error must not re-arm a reaped PGID");
    }

    #[cfg(unix)]
    #[test]
    fn wait_failure_and_cleanup_failure_are_both_retained() {
        fn signal_then_fail(process_group: u32) -> std::io::Result<()> {
            super::signal_process_group(process_group)?;
            Err(std::io::Error::other("injected group-signal failure"))
        }

        let limits = limits(64, 64);
        let (mut child, mut pipes) =
            super::spawn_piped_child(&shell("while :; do :; done")).unwrap();
        let mut capture = super::CaptureState::new(&limits);
        let mut exit_status = None;
        let error = super::cleanup_after_process_error_with_group_signal(
            &mut child,
            &mut pipes,
            &mut capture,
            &limits,
            &mut exit_status,
            ProcessError::Wait(std::io::Error::other("injected wait failure")),
            signal_then_fail,
        );

        let ProcessError::MultipleFailures { failures } = error else {
            panic!("primary and cleanup failures must be aggregated");
        };
        assert!(
            failures
                .iter()
                .any(|error| matches!(error, ProcessError::Wait(_)))
        );
        assert!(failures.iter().any(contains_group_signal));
        assert!(exit_status.is_some());
        assert!(!child.armed, "reaped PGID must not remain armed");
    }

    #[cfg(unix)]
    fn escaped_pipe_holder(marker: &std::path::Path) -> ProcessSpec {
        ProcessSpec::new("python3").args([
            "-c",
            r#"import os, sys, time
child = os.fork()
if child == 0:
    os.setsid()
    with open(sys.argv[1], "w", encoding="ascii") as marker:
        marker.write(str(os.getpid()))
    time.sleep(60)
while not os.path.exists(sys.argv[1]) or os.path.getsize(sys.argv[1]) == 0:
    time.sleep(0.01)
os._exit(0)"#,
            marker.to_str().expect("marker path is UTF-8"),
        ])
    }

    #[test]
    fn invalid_spec_and_limits_fail_before_spawn() {
        assert!(matches!(
            run_bounded(&ProcessSpec::new(""), ProcessLimits::default()),
            Err(ProcessError::InvalidSpec(_))
        ));
        assert!(matches!(
            run_bounded(
                &shell("exit 0"),
                ProcessLimits {
                    timeout: Duration::ZERO,
                    ..ProcessLimits::default()
                }
            ),
            Err(ProcessError::InvalidLimits(_))
        ));
    }

    #[test]
    fn default_limits_match_the_protocol_contract() {
        assert_eq!(ProcessLimits::DEFAULT_TIMEOUT, Duration::from_secs(600));
        assert_eq!(ProcessLimits::DEFAULT_STDOUT_BYTES, 16 * 1024 * 1024);
        assert_eq!(ProcessLimits::DEFAULT_STDERR_BYTES, 4 * 1024 * 1024);
    }
}
