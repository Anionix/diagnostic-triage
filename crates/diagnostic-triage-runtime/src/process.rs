//! Bounded, shell-free child process execution.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

use std::{
    ffi::OsStr,
    io::{self, Read, Write},
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError},
    thread,
    time::{Duration, Instant},
};

use thiserror::Error;
use wait_timeout::ChildExt;

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
        if self.timeout.is_zero() {
            return Err(ProcessError::InvalidLimits("timeout must be non-zero"));
        }
        if self.max_stdout_bytes == 0 {
            return Err(ProcessError::InvalidLimits(
                "max_stdout_bytes must be non-zero",
            ));
        }
        if self.max_stderr_bytes == 0 {
            return Err(ProcessError::InvalidLimits(
                "max_stderr_bytes must be non-zero",
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

    #[must_use]
    pub fn current_dir(mut self, current_dir: impl Into<PathBuf>) -> Self {
        self.current_dir = Some(current_dir.into());
        self
    }

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
    pub exit_code: Option<i32>,
    pub stdout: BoundedOutput,
    pub stderr: BoundedOutput,
    pub duration: Duration,
}

/// Failures that prevent even an incomplete process record from being trusted.
#[derive(Debug, Error)]
pub enum ProcessError {
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
    #[error("failed while waiting for child: {0}")]
    Wait(#[source] io::Error),
    #[error("child could not be reaped after termination")]
    Unreaped,
    #[error("process I/O workers disconnected before completion")]
    WorkerDisconnected,
}

/// Execute one program directly, bounding wall time and both output streams.
///
/// A non-zero exit remains a complete process outcome; protocol completion and
/// policy success are evaluated by later runtime layers.
///
/// # Errors
///
/// Returns an error when the specification or limits are invalid, the child
/// cannot be spawned or reaped, or an I/O worker disconnects unexpectedly.
pub fn run_bounded(
    spec: &ProcessSpec,
    limits: ProcessLimits,
) -> Result<ProcessOutcome, ProcessError> {
    spec.validate()?;
    let limits = limits.validate()?;
    let started = Instant::now();
    let mut child = spawn_child(spec)?;
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

    let (sender, receiver) = mpsc::channel();
    let stdin_worker = spawn_stdin_worker(stdin, spec.stdin.clone(), sender.clone());
    let stdout_worker = spawn_reader_worker(Stream::Stdout, stdout, sender.clone());
    let stderr_worker = spawn_reader_worker(Stream::Stderr, stderr, sender.clone());
    drop(sender);

    let mut capture = CaptureState::new(&limits);
    let deadline = started.checked_add(limits.timeout).unwrap_or(started);
    let mut exit_status = None;

    while !capture.is_finished(exit_status.as_ref()) {
        drain_ready_events(&receiver, &mut capture, &limits)?;
        if capture.failure.is_some() {
            terminate_and_reap(&mut child, &mut exit_status)?;
            drain_after_termination(&receiver, &mut capture, &limits);
            break;
        }

        exit_status = child.try_wait().map_err(ProcessError::Wait)?;
        if capture.is_finished(exit_status.as_ref()) {
            break;
        }

        let now = Instant::now();
        if now >= deadline {
            capture.failure = Some(IncompleteReason::Timeout);
            terminate_and_reap(&mut child, &mut exit_status)?;
            drain_after_termination(&receiver, &mut capture, &limits);
            break;
        }
        let wait = deadline.saturating_duration_since(now).min(POLL_INTERVAL);
        receive_one(&receiver, &mut capture, &limits, wait)?;
    }

    if exit_status.is_none() {
        exit_status = child.try_wait().map_err(ProcessError::Wait)?;
    }
    join_if_finished(stdin_worker, capture.stdin_done);
    join_if_finished(stdout_worker, capture.stdout_done);
    join_if_finished(stderr_worker, capture.stderr_done);

    let exit_code = exit_status.as_ref().and_then(ExitStatus::code);
    let state = match capture.failure {
        Some(reason) => ProcessState::Incomplete(reason),
        None if exit_status.is_some() && exit_code.is_some() => ProcessState::Complete,
        None => ProcessState::Incomplete(IncompleteReason::TerminatedWithoutCode),
    };
    Ok(ProcessOutcome {
        state,
        exit_code,
        stdout: capture.stdout,
        stderr: capture.stderr,
        duration: started.elapsed(),
    })
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

enum IoEvent {
    Stdin(Result<(), io::Error>),
    Data(Stream, Vec<u8>),
    End(Stream, Result<(), io::Error>),
}

fn spawn_stdin_worker(
    mut stdin: impl Write + Send + 'static,
    input: Vec<u8>,
    sender: mpsc::Sender<IoEvent>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let result = stdin.write_all(&input).and_then(|()| stdin.flush());
        drop(stdin);
        let _ignored = sender.send(IoEvent::Stdin(result));
    })
}

fn spawn_reader_worker(
    stream: Stream,
    mut reader: impl Read + Send + 'static,
    sender: mpsc::Sender<IoEvent>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0_u8; IO_CHUNK_BYTES];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    let _ignored = sender.send(IoEvent::End(stream, Ok(())));
                    return;
                }
                Ok(size) => {
                    if sender
                        .send(IoEvent::Data(stream, buffer[..size].to_vec()))
                        .is_err()
                    {
                        return;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    let _ignored = sender.send(IoEvent::End(stream, Err(error)));
                    return;
                }
            }
        }
    })
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

    fn accept(&mut self, event: IoEvent, limits: &ProcessLimits) {
        match event {
            IoEvent::Stdin(result) => {
                self.stdin_done = true;
                if result.is_err() {
                    self.failure.get_or_insert(IncompleteReason::StdinFailure);
                }
            }
            IoEvent::Data(Stream::Stdout, chunk) => {
                self.stdout.append(&chunk, limits.max_stdout_bytes);
                if self.stdout.truncated {
                    self.failure
                        .get_or_insert(IncompleteReason::StdoutLimitExceeded);
                }
            }
            IoEvent::Data(Stream::Stderr, chunk) => {
                self.stderr.append(&chunk, limits.max_stderr_bytes);
                if self.stderr.truncated {
                    self.failure
                        .get_or_insert(IncompleteReason::StderrLimitExceeded);
                }
            }
            IoEvent::End(Stream::Stdout, result) => {
                self.stdout_done = true;
                if result.is_err() {
                    self.failure.get_or_insert(IncompleteReason::StdoutFailure);
                }
            }
            IoEvent::End(Stream::Stderr, result) => {
                self.stderr_done = true;
                if result.is_err() {
                    self.failure.get_or_insert(IncompleteReason::StderrFailure);
                }
            }
        }
    }
}

fn drain_ready_events(
    receiver: &Receiver<IoEvent>,
    capture: &mut CaptureState,
    limits: &ProcessLimits,
) -> Result<(), ProcessError> {
    loop {
        match receiver.try_recv() {
            Ok(event) => capture.accept(event, limits),
            Err(TryRecvError::Empty) => return Ok(()),
            Err(TryRecvError::Disconnected)
                if capture.stdin_done && capture.stdout_done && capture.stderr_done =>
            {
                return Ok(());
            }
            Err(TryRecvError::Disconnected) => return Err(ProcessError::WorkerDisconnected),
        }
    }
}

fn receive_one(
    receiver: &Receiver<IoEvent>,
    capture: &mut CaptureState,
    limits: &ProcessLimits,
    wait: Duration,
) -> Result<(), ProcessError> {
    match receiver.recv_timeout(wait) {
        Ok(event) => {
            capture.accept(event, limits);
            Ok(())
        }
        Err(RecvTimeoutError::Timeout) => Ok(()),
        Err(RecvTimeoutError::Disconnected)
            if capture.stdin_done && capture.stdout_done && capture.stderr_done =>
        {
            Ok(())
        }
        Err(RecvTimeoutError::Disconnected) => Err(ProcessError::WorkerDisconnected),
    }
}

fn terminate_and_reap(
    child: &mut Child,
    exit_status: &mut Option<ExitStatus>,
) -> Result<(), ProcessError> {
    if exit_status.is_none() {
        *exit_status = child.try_wait().map_err(ProcessError::Wait)?;
    }
    if exit_status.is_none() {
        if let Err(kill_error) = child.kill() {
            *exit_status = child.try_wait().map_err(ProcessError::Wait)?;
            if exit_status.is_none() {
                return Err(ProcessError::Wait(kill_error));
            }
        }
    }
    if exit_status.is_none() {
        *exit_status = child
            .wait_timeout(TERMINATION_GRACE)
            .map_err(ProcessError::Wait)?;
        if exit_status.is_none() {
            return Err(ProcessError::Unreaped);
        }
    }
    Ok(())
}

fn drain_after_termination(
    receiver: &Receiver<IoEvent>,
    capture: &mut CaptureState,
    limits: &ProcessLimits,
) {
    let deadline = Instant::now()
        .checked_add(TERMINATION_GRACE)
        .unwrap_or_else(Instant::now);
    while !(capture.stdin_done && capture.stdout_done && capture.stderr_done) {
        let wait = deadline.saturating_duration_since(Instant::now());
        if wait.is_zero() {
            return;
        }
        match receiver.recv_timeout(wait.min(POLL_INTERVAL)) {
            Ok(event) => capture.accept(event, limits),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn join_if_finished(worker: thread::JoinHandle<()>, finished: bool) {
    if finished {
        let _ignored = worker.join();
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
