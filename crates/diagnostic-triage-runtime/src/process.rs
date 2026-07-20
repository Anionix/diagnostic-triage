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
    #[error("child could not be reaped after termination")]
    Unreaped,
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
    let mut child = ChildCleanupGuard::new(spawn_child(spec)?);
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

    let mut capture = CaptureState::new(&limits);
    let mut pipes = PipeHandles::new(stdin, stdout, stderr);
    pipes.configure_nonblocking()?;
    if spec.stdin.is_empty() {
        pipes.stdin.take();
        capture.stdin_done = true;
    }
    let mut stdin_offset = 0;
    let deadline = started.checked_add(limits.timeout).unwrap_or(started);
    let mut exit_status = None;

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
        if capture.failure.is_some() {
            terminate_and_reap(&mut child, &mut exit_status)?;
            drain_after_termination(&mut pipes, &mut capture, &limits);
            break;
        }

        exit_status = child.try_wait().map_err(ProcessError::Wait)?;
        let now = Instant::now();
        if now >= deadline {
            capture.failure = Some(IncompleteReason::Timeout);
            terminate_and_reap(&mut child, &mut exit_status)?;
            drain_after_termination(&mut pipes, &mut capture, &limits);
            break;
        }
        if capture.is_finished(exit_status.as_ref()) {
            break;
        }
        if !made_progress {
            std::thread::sleep(deadline.saturating_duration_since(now).min(POLL_INTERVAL));
        }
    }

    if exit_status.is_none() {
        exit_status = child.try_wait().map_err(ProcessError::Wait)?;
    }

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
    let wall_duration = started.elapsed();
    let duration = wall_duration.min(limits.timeout);
    child.disarm();
    Ok(ProcessOutcome {
        state,
        exit_code,
        stdout: capture.stdout,
        stderr: capture.stderr,
        duration,
        cleanup_duration: wall_duration.saturating_sub(duration),
    })
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
    // The group must be signalled even when its leader has already exited:
    // descendants can keep inherited pipes open after the leader is reaped.
    let kill_error = kill_child_tree(child).err();
    if exit_status.is_none() {
        *exit_status = child.try_wait().map_err(ProcessError::Wait)?;
    }
    if exit_status.is_none() {
        *exit_status = child
            .wait_timeout(TERMINATION_GRACE)
            .map_err(ProcessError::Wait)?;
        if exit_status.is_none() {
            return Err(ProcessError::Unreaped);
        }
    }
    if let Some(kill_error) = kill_error {
        return Err(ProcessError::Wait(kill_error));
    }
    Ok(())
}

#[cfg(unix)]
fn kill_child_tree(child: &mut Child) -> io::Result<()> {
    let group = Pid::from_child(child);
    match kill_process_group(group, Signal::KILL) {
        Ok(()) => Ok(()),
        Err(error) if error == rustix::io::Errno::SRCH => {
            if child.try_wait()?.is_some() {
                Ok(())
            } else {
                child.kill()
            }
        }
        Err(first_error) => {
            // A very short program can become a zombie between `try_wait`
            // and `killpg` (EPERM on macOS). Reap it, then retry the group so
            // live descendants are still terminated rather than ignored.
            if child.wait_timeout(POLL_INTERVAL)?.is_none() {
                let _ignored = child.kill();
                // `terminate_and_reap` bounded-waits and reaps the leader
                // before it propagates this process-group failure.
                return Err(first_error.into());
            }
            match kill_process_group(group, Signal::KILL) {
                Ok(()) => Ok(()),
                Err(error) if error == rustix::io::Errno::SRCH => Ok(()),
                Err(error) => Err(error.into()),
            }
        }
    }
}

#[cfg(not(unix))]
fn kill_child_tree(child: &mut Child) -> io::Result<()> {
    child.kill()
}

fn drain_after_termination(
    pipes: &mut PipeHandles,
    capture: &mut CaptureState,
    limits: &ProcessLimits,
) {
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
    // A descendant may have escaped the process group and retained a write
    // end. Never let that inherited handle extend the caller's lifetime.
    pipes.drop_all();
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
        IncompleteReason, ProcessError, ProcessLimits, ProcessSpec, ProcessState, run_bounded,
    };
    use std::time::Duration;

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
    fn timeout_kills_descendants_after_the_group_leader_exits() {
        let outcome = run_bounded(
            &shell("while :; do :; done & descendant=$!; printf '%s\\n' \"$descendant\"; exit 0"),
            ProcessLimits {
                timeout: Duration::from_millis(80),
                max_stdout_bytes: 64,
                max_stderr_bytes: 64,
            },
        )
        .expect("orphaned pipe holder is terminated");
        assert_eq!(
            outcome.state,
            ProcessState::Incomplete(IncompleteReason::Timeout)
        );
        let raw_pid = String::from_utf8(outcome.stdout.bytes)
            .expect("pid is utf8")
            .trim()
            .parse::<i32>()
            .expect("pid is numeric");
        assert_process_disappears(raw_pid);
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
