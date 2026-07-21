//! Provider-local bounded, shell-free child process execution.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

use std::{
    ffi::OsStr,
    io::{self, Read},
    ops::{Deref, DerefMut},
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError},
    thread,
    time::{Duration, Instant},
};

use diagnostic_triage_contracts::protocol::RequestLimits;
use thiserror::Error;
use wait_timeout::ChildExt;

const IO_CHUNK_BYTES: usize = 8 * 1024;
const CAPTURE_QUEUE_DEPTH: usize = 4;
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const TERMINATION_GRACE: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessLimits {
    pub(crate) timeout: Duration,
    pub(crate) max_stdout_bytes: usize,
    pub(crate) max_stderr_bytes: usize,
}

impl ProcessLimits {
    const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
    const DEFAULT_STDOUT_BYTES: usize = 16 * 1024 * 1024;
    const DEFAULT_STDERR_BYTES: usize = 4 * 1024 * 1024;

    pub(crate) fn validate(self) -> Result<Self, ProcessError> {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProcessSpec {
    program: PathBuf,
    argv: Vec<String>,
    current_dir: Option<PathBuf>,
}

impl ProcessSpec {
    pub(crate) fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            argv: Vec::new(),
            current_dir: None,
        }
    }

    #[must_use]
    pub(crate) fn arg(mut self, arg: impl Into<String>) -> Self {
        self.argv.push(arg.into());
        self
    }

    #[must_use]
    pub(crate) fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.argv.extend(args.into_iter().map(Into::into));
        self
    }

    #[must_use]
    pub(crate) fn current_dir(mut self, current_dir: impl Into<PathBuf>) -> Self {
        self.current_dir = Some(current_dir.into());
        self
    }

    fn validate(&self) -> Result<(), ProcessError> {
        if self.program.as_os_str().is_empty() {
            return Err(ProcessError::InvalidSpec("program must not be empty"));
        }
        reject_nul(self.program.as_os_str(), "program")?;
        if self.argv.iter().any(|arg| arg.contains('\0')) {
            return Err(ProcessError::InvalidSpec("argv must not contain NUL"));
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BoundedOutput {
    pub(crate) bytes: Vec<u8>,
    pub(crate) observed_bytes: u64,
    pub(crate) truncated: bool,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IncompleteReason {
    Timeout,
    StdoutLimitExceeded,
    StderrLimitExceeded,
    StdoutFailure,
    StderrFailure,
    UnrepresentableExitCode,
    TerminatedWithoutCode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessState {
    Complete,
    Incomplete(IncompleteReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProcessOutcome {
    pub(crate) state: ProcessState,
    pub(crate) exit_code: Option<u8>,
    pub(crate) stdout: BoundedOutput,
    pub(crate) stderr: BoundedOutput,
    pub(crate) duration: Duration,
    pub(crate) cleanup_duration: Duration,
}

#[derive(Debug, Error)]
pub(crate) enum ProcessError {
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
    #[error("failed to spawn the {stream} capture worker: {source}")]
    CaptureSpawn {
        stream: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("failed while waiting for child: {0}")]
    Wait(#[source] io::Error),
    #[cfg(unix)]
    #[error("failed to terminate the child process group: {0}")]
    ProcessGroup(#[source] io::Error),
    #[error("child could not be reaped after termination")]
    Unreaped,
    #[error("capture pipes remained open after process termination")]
    CaptureDrainTimeout,
}

pub(crate) fn run_bounded(
    spec: &ProcessSpec,
    limits: ProcessLimits,
) -> Result<ProcessOutcome, ProcessError> {
    spec.validate()?;
    let limits = limits.validate()?;
    let started = Instant::now();
    let mut child = ChildCleanupGuard::new(spawn_child(spec)?);
    let stdout = child
        .stdout
        .take()
        .ok_or(ProcessError::MissingPipe { stream: "stdout" })?;
    let stderr = child
        .stderr
        .take()
        .ok_or(ProcessError::MissingPipe { stream: "stderr" })?;
    let (capture_sender, capture_receiver) = mpsc::sync_channel(CAPTURE_QUEUE_DEPTH);
    spawn_capture(stdout, Stream::Stdout, capture_sender.clone())?;
    spawn_capture(stderr, Stream::Stderr, capture_sender.clone())?;
    drop(capture_sender);

    let deadline = started.checked_add(limits.timeout).unwrap_or(started);
    let mut capture = CaptureState::new(&limits);
    let mut exit_status = None;
    let (failure, duration) = loop {
        drain_capture_events(&capture_receiver, &mut capture, &limits);
        if let Some(reason) = capture.failure {
            break (Some(reason), started.elapsed().min(limits.timeout));
        }
        if exit_status.is_some() && capture.is_done() {
            break (None, started.elapsed().min(limits.timeout));
        }

        let now = Instant::now();
        if now >= deadline {
            break (Some(IncompleteReason::Timeout), limits.timeout);
        }
        let wait = deadline.saturating_duration_since(now).min(POLL_INTERVAL);
        if exit_status.is_none() {
            exit_status = child.wait_timeout(wait).map_err(ProcessError::Wait)?;
        } else {
            receive_capture_event(&capture_receiver, &mut capture, &limits, wait);
        }
    };

    let cleanup_started = Instant::now();
    if failure.is_some() {
        terminate_group_and_reap(&mut child, &mut exit_status)?;
        drain_after_termination(&capture_receiver, &mut capture, &limits);
        if !capture.is_done() {
            return Err(ProcessError::CaptureDrainTimeout);
        }
    }
    child.disarm();

    let native_exit_code = exit_status.as_ref().and_then(ExitStatus::code);
    let representable_exit_code = native_exit_code.and_then(|code| u8::try_from(code).ok());
    let state = match failure {
        Some(reason) => ProcessState::Incomplete(reason),
        None if representable_exit_code.is_some() => ProcessState::Complete,
        None if native_exit_code.is_some() => {
            ProcessState::Incomplete(IncompleteReason::UnrepresentableExitCode)
        }
        None => ProcessState::Incomplete(IncompleteReason::TerminatedWithoutCode),
    };
    let exit_code = (state == ProcessState::Complete)
        .then_some(representable_exit_code)
        .flatten();

    Ok(ProcessOutcome {
        state,
        exit_code,
        stdout: capture.stdout,
        stderr: capture.stderr,
        duration,
        cleanup_duration: cleanup_started.elapsed(),
    })
}

struct ChildCleanupGuard {
    child: Child,
    process_group: u32,
    armed: bool,
}

impl ChildCleanupGuard {
    fn new(child: Child) -> Self {
        let process_group = child.id();
        Self {
            child,
            process_group,
            armed: true,
        }
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
            let _ignored =
                terminate_process_group(&mut self.child, self.process_group, &mut exit_status);
        }
    }
}

fn spawn_child(spec: &ProcessSpec) -> Result<Child, ProcessError> {
    let mut command = Command::new(&spec.program);
    command
        .args(&spec.argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(current_dir) = &spec.current_dir {
        command.current_dir(current_dir);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        command.process_group(0);
    }
    command.spawn().map_err(|source| ProcessError::Spawn {
        program: spec.program.clone(),
        source,
    })
}

#[derive(Clone, Copy)]
enum Stream {
    Stdout,
    Stderr,
}

enum CaptureEvent {
    Chunk(Stream, Vec<u8>),
    Done(Stream),
    Failed(Stream),
}

fn spawn_capture<R: Read + Send + 'static>(
    reader: R,
    stream: Stream,
    sender: SyncSender<CaptureEvent>,
) -> Result<(), ProcessError> {
    let stream_name = match stream {
        Stream::Stdout => "stdout",
        Stream::Stderr => "stderr",
    };
    thread::Builder::new()
        .name(format!("ruff-{stream_name}-capture"))
        .spawn(move || capture_stream(reader, stream, &sender))
        .map(drop)
        .map_err(|source| ProcessError::CaptureSpawn {
            stream: stream_name,
            source,
        })
}

fn capture_stream<R: Read>(mut reader: R, stream: Stream, sender: &SyncSender<CaptureEvent>) {
    let mut buffer = [0_u8; IO_CHUNK_BYTES];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => {
                let _ignored = sender.send(CaptureEvent::Done(stream));
                break;
            }
            Ok(size) => {
                if sender
                    .send(CaptureEvent::Chunk(stream, buffer[..size].to_vec()))
                    .is_err()
                {
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                let _ignored = sender.send(CaptureEvent::Failed(stream));
                break;
            }
        }
    }
}

struct CaptureState {
    stdout: BoundedOutput,
    stderr: BoundedOutput,
    stdout_done: bool,
    stderr_done: bool,
    failure: Option<IncompleteReason>,
}

impl CaptureState {
    fn new(limits: &ProcessLimits) -> Self {
        Self {
            stdout: BoundedOutput::with_capacity(limits.max_stdout_bytes),
            stderr: BoundedOutput::with_capacity(limits.max_stderr_bytes),
            stdout_done: false,
            stderr_done: false,
            failure: None,
        }
    }

    fn is_done(&self) -> bool {
        self.stdout_done && self.stderr_done
    }

    fn accept(&mut self, event: CaptureEvent, limits: &ProcessLimits) {
        match event {
            CaptureEvent::Chunk(Stream::Stdout, chunk) => {
                self.stdout.append(&chunk, limits.max_stdout_bytes);
                if self.stdout.truncated {
                    self.failure
                        .get_or_insert(IncompleteReason::StdoutLimitExceeded);
                }
            }
            CaptureEvent::Chunk(Stream::Stderr, chunk) => {
                self.stderr.append(&chunk, limits.max_stderr_bytes);
                if self.stderr.truncated {
                    self.failure
                        .get_or_insert(IncompleteReason::StderrLimitExceeded);
                }
            }
            CaptureEvent::Done(Stream::Stdout) => self.stdout_done = true,
            CaptureEvent::Done(Stream::Stderr) => self.stderr_done = true,
            CaptureEvent::Failed(Stream::Stdout) => {
                self.stdout_done = true;
                self.failure.get_or_insert(IncompleteReason::StdoutFailure);
            }
            CaptureEvent::Failed(Stream::Stderr) => {
                self.stderr_done = true;
                self.failure.get_or_insert(IncompleteReason::StderrFailure);
            }
        }
    }

    fn mark_disconnected(&mut self) {
        if !self.stdout_done {
            self.failure.get_or_insert(IncompleteReason::StdoutFailure);
            self.stdout_done = true;
        }
        if !self.stderr_done {
            self.failure.get_or_insert(IncompleteReason::StderrFailure);
            self.stderr_done = true;
        }
    }
}

fn drain_capture_events(
    receiver: &Receiver<CaptureEvent>,
    capture: &mut CaptureState,
    limits: &ProcessLimits,
) {
    for _ in 0..CAPTURE_QUEUE_DEPTH {
        match receiver.try_recv() {
            Ok(event) => capture.accept(event, limits),
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => {
                capture.mark_disconnected();
                break;
            }
        }
    }
}

fn receive_capture_event(
    receiver: &Receiver<CaptureEvent>,
    capture: &mut CaptureState,
    limits: &ProcessLimits,
    wait: Duration,
) {
    match receiver.recv_timeout(wait) {
        Ok(event) => capture.accept(event, limits),
        Err(RecvTimeoutError::Timeout) => {}
        Err(RecvTimeoutError::Disconnected) => capture.mark_disconnected(),
    }
}

fn drain_after_termination(
    receiver: &Receiver<CaptureEvent>,
    capture: &mut CaptureState,
    limits: &ProcessLimits,
) {
    let deadline = Instant::now()
        .checked_add(TERMINATION_GRACE)
        .unwrap_or_else(Instant::now);
    while !capture.is_done() {
        let wait = deadline.saturating_duration_since(Instant::now());
        if wait.is_zero() {
            break;
        }
        receive_capture_event(receiver, capture, limits, wait.min(POLL_INTERVAL));
    }
}

fn terminate_group_and_reap(
    child: &mut ChildCleanupGuard,
    exit_status: &mut Option<ExitStatus>,
) -> Result<(), ProcessError> {
    terminate_process_group(&mut child.child, child.process_group, exit_status)
}

fn terminate_process_group(
    child: &mut Child,
    process_group: u32,
    exit_status: &mut Option<ExitStatus>,
) -> Result<(), ProcessError> {
    #[cfg(unix)]
    let group_signal_error = signal_process_group(process_group).err();

    #[cfg(not(unix))]
    let _ = process_group;

    if exit_status.is_none() {
        *exit_status = child.try_wait().map_err(ProcessError::Wait)?;
    }

    #[cfg(not(unix))]
    if exit_status.is_none() {
        child.kill().map_err(ProcessError::Wait)?;
    }

    #[cfg(unix)]
    let fatal_group_signal = if let Some(error) = group_signal_error {
        if exit_status.is_none() {
            child.kill().map_err(ProcessError::Wait)?;
            Some(error)
        } else {
            None
        }
    } else {
        None
    };

    if exit_status.is_none() {
        *exit_status = child
            .wait_timeout(TERMINATION_GRACE)
            .map_err(ProcessError::Wait)?;
    }
    if exit_status.is_none() {
        return Err(ProcessError::Unreaped);
    }

    #[cfg(unix)]
    if let Some(error) = fatal_group_signal {
        return Err(ProcessError::ProcessGroup(error));
    }

    Ok(())
}

#[cfg(unix)]
fn signal_process_group(process_group: u32) -> io::Result<()> {
    let status = Command::new("/bin/kill")
        .args(["-s", "KILL", &format!("-{process_group}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("/bin/kill exited with {status}")))
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
    use super::{ProcessError, ProcessLimits, ProcessSpec, run_bounded};
    use std::time::Duration;

    #[cfg(unix)]
    use super::{IncompleteReason, ProcessState};
    #[cfg(unix)]
    use std::{
        process::{Command, Stdio},
        thread,
        time::Instant,
    };

    #[test]
    fn rejects_a_missing_current_directory_before_spawn() {
        let missing = std::env::temp_dir().join(format!(
            "diagnostic-triage-missing-cwd-{}",
            std::process::id()
        ));
        let result = run_bounded(
            &ProcessSpec::new("unused-program").current_dir(&missing),
            ProcessLimits {
                timeout: Duration::from_millis(10),
                max_stdout_bytes: 0,
                max_stderr_bytes: 0,
            },
        );

        assert!(matches!(
            result,
            Err(ProcessError::InvalidCurrentDirectory { path }) if path == missing
        ));
    }

    #[cfg(unix)]
    #[test]
    fn leader_exit_with_descendant_held_pipes_remains_bounded() {
        let started = Instant::now();
        let outcome = run_bounded(
            &ProcessSpec::new("/bin/sh").args([
                "-c",
                r#"while :; do :; done & descendant=$!; printf '%s\n' "$descendant"; exit 0"#,
            ]),
            ProcessLimits {
                timeout: Duration::from_millis(80),
                max_stdout_bytes: 64,
                max_stderr_bytes: 64,
            },
        )
        .expect("descendant-held pipes produce a typed outcome");

        assert_eq!(
            outcome.state,
            ProcessState::Incomplete(IncompleteReason::Timeout)
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        let descendant = String::from_utf8(outcome.stdout.bytes)
            .expect("pid is UTF-8")
            .trim()
            .to_owned();
        assert_process_stopped(&descendant);
    }

    #[cfg(unix)]
    fn assert_process_stopped(pid: &str) {
        for _ in 0..25 {
            let status = Command::new("/bin/kill")
                .args(["-s", "0", pid])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("kill is available on supported Unix targets");
            if !status.success() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("descendant process {pid} survived process-group termination");
    }
}
