//! Provider-local bounded, shell-free child process execution.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

use std::{
    ffi::OsStr,
    io::{self, Read},
    ops::{Deref, DerefMut},
    path::PathBuf,
    process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use diagnostic_triage_contracts::protocol::RequestLimits;
use thiserror::Error;
use wait_timeout::ChildExt;

#[cfg(unix)]
use std::os::fd::AsFd;

const IO_CHUNK_BYTES: usize = 8 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(5);
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
    #[error("bounded provider process-group execution is unsupported on this platform")]
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
    #[error("failed to spawn the {stream} capture worker: {source}")]
    CaptureSpawn {
        stream: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("failed to configure the {stream} capture pipe: {source}")]
    CaptureConfiguration {
        stream: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("{0} capture thread panicked")]
    CapturePanic(&'static str),
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

pub(crate) fn run_bounded(
    spec: &ProcessSpec,
    limits: ProcessLimits,
) -> Result<ProcessOutcome, ProcessError> {
    run_bounded_with_group_signal(spec, limits, signal_process_group)
}

fn run_bounded_with_group_signal(
    spec: &ProcessSpec,
    limits: ProcessLimits,
    group_signal: fn(u32) -> io::Result<()>,
) -> Result<ProcessOutcome, ProcessError> {
    if cfg!(not(unix)) {
        return Err(ProcessError::UnsupportedPlatform);
    }
    spec.validate()?;
    let limits = limits.validate()?;
    let started = Instant::now();
    let mut child = ChildCleanupGuard::new(spawn_child(spec)?);
    let stdout_overflow = Arc::new(AtomicBool::new(false));
    let stderr_overflow = Arc::new(AtomicBool::new(false));
    let mut readers = match CaptureReaders::spawn(
        &mut child,
        limits,
        Arc::clone(&stdout_overflow),
        Arc::clone(&stderr_overflow),
    ) {
        Ok(readers) => readers,
        Err(error) => return Err(cleanup_setup_failure(&mut child, error, group_signal)),
    };

    let deadline = started.checked_add(limits.timeout).unwrap_or(started);
    let mut forced_reason = None;
    let mut exit_status = None;
    let mut errors = Vec::new();
    loop {
        if stdout_overflow.load(Ordering::Acquire) {
            forced_reason = Some(IncompleteReason::StdoutLimitExceeded);
        } else if stderr_overflow.load(Ordering::Acquire) {
            forced_reason = Some(IncompleteReason::StderrLimitExceeded);
        } else if Instant::now() >= deadline {
            forced_reason = Some(IncompleteReason::Timeout);
        }
        if forced_reason.is_some() {
            break;
        }

        let wait = deadline
            .saturating_duration_since(Instant::now())
            .min(POLL_INTERVAL);
        match child.wait_timeout(wait) {
            Ok(Some(status)) => {
                exit_status = Some(status);
                break;
            }
            Ok(None) => {}
            Err(source) => {
                errors.push(ProcessError::Wait(source));
                break;
            }
        }
    }

    let duration = started.elapsed().min(limits.timeout);
    let cleanup_started = Instant::now();
    let (status, stdout, stderr) =
        finish_execution(&mut child, &mut readers, exit_status, errors, group_signal)?;
    let cleanup_duration = cleanup_started.elapsed();

    let failure = forced_reason
        .or_else(|| stdout.failed.then_some(IncompleteReason::StdoutFailure))
        .or_else(|| stderr.failed.then_some(IncompleteReason::StderrFailure))
        .or_else(|| {
            stdout
                .output
                .truncated
                .then_some(IncompleteReason::StdoutLimitExceeded)
        })
        .or_else(|| {
            stderr
                .output
                .truncated
                .then_some(IncompleteReason::StderrLimitExceeded)
        });

    let native_exit_code = status.code();
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
        stdout: stdout.output,
        stderr: stderr.output,
        duration,
        cleanup_duration,
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
            let _ignored = terminate_child(
                &mut self.child,
                self.process_group,
                &mut exit_status,
                signal_process_group,
            );
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

struct CapturedStream {
    output: BoundedOutput,
    failed: bool,
}

fn capture(
    mut reader: impl Read,
    limit: usize,
    overflow: &AtomicBool,
    cancel: &AtomicBool,
) -> CapturedStream {
    let mut output = BoundedOutput::with_capacity(limit);
    let mut buffer = [0_u8; IO_CHUNK_BYTES];
    loop {
        if cancel.load(Ordering::Acquire) {
            break;
        }
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(size) => {
                output.append(&buffer[..size], limit);
                if output.truncated {
                    overflow.store(true, Ordering::Release);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(POLL_INTERVAL);
            }
            Err(_) => {
                return CapturedStream {
                    output,
                    failed: true,
                };
            }
        }
    }
    CapturedStream {
        output,
        failed: false,
    }
}

fn spawn_reader<R>(
    reader: R,
    limit: usize,
    overflow: Arc<AtomicBool>,
    cancel: Arc<AtomicBool>,
    stream: &'static str,
) -> Result<thread::JoinHandle<CapturedStream>, ProcessError>
where
    R: Read + Send + 'static,
{
    thread::Builder::new()
        .name(format!("ruff-{stream}-capture"))
        .spawn(move || capture(reader, limit, &overflow, &cancel))
        .map_err(|source| ProcessError::CaptureSpawn { stream, source })
}

fn join_reader(
    handle: thread::JoinHandle<CapturedStream>,
    stream: &'static str,
) -> Result<CapturedStream, ProcessError> {
    handle
        .join()
        .map_err(|_| ProcessError::CapturePanic(stream))
}

#[cfg(unix)]
fn configure_nonblocking<R>(reader: R, stream: &'static str) -> Result<R, ProcessError>
where
    R: AsFd,
{
    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};

    let flags = fcntl_getfl(&reader).map_err(|source| ProcessError::CaptureConfiguration {
        stream,
        source: source.into(),
    })?;
    fcntl_setfl(&reader, flags | OFlags::NONBLOCK).map_err(|source| {
        ProcessError::CaptureConfiguration {
            stream,
            source: source.into(),
        }
    })?;
    Ok(reader)
}

#[cfg(not(unix))]
fn configure_nonblocking<R>(_: R, _: &'static str) -> Result<R, ProcessError> {
    Err(ProcessError::UnsupportedPlatform)
}

struct JoinedCaptures {
    stdout: Option<CapturedStream>,
    stderr: Option<CapturedStream>,
    errors: Vec<ProcessError>,
}

struct CaptureReaders {
    stdout: Option<thread::JoinHandle<CapturedStream>>,
    stderr: Option<thread::JoinHandle<CapturedStream>>,
    cancel: Arc<AtomicBool>,
}

impl CaptureReaders {
    fn spawn(
        child: &mut ChildCleanupGuard,
        limits: ProcessLimits,
        stdout_overflow: Arc<AtomicBool>,
        stderr_overflow: Arc<AtomicBool>,
    ) -> Result<Self, ProcessError> {
        let stdout = child
            .stdout
            .take()
            .ok_or(ProcessError::MissingPipe { stream: "stdout" })?;
        let stderr = child
            .stderr
            .take()
            .ok_or(ProcessError::MissingPipe { stream: "stderr" })?;
        let stdout: ChildStdout = configure_nonblocking(stdout, "stdout")?;
        let stderr: ChildStderr = configure_nonblocking(stderr, "stderr")?;
        let cancel = Arc::new(AtomicBool::new(false));
        let stdout = spawn_reader(
            stdout,
            limits.max_stdout_bytes,
            stdout_overflow,
            Arc::clone(&cancel),
            "stdout",
        )?;
        let stderr = match spawn_reader(
            stderr,
            limits.max_stderr_bytes,
            stderr_overflow,
            Arc::clone(&cancel),
            "stderr",
        ) {
            Ok(handle) => handle,
            Err(error) => {
                cancel.store(true, Ordering::Release);
                let mut errors = vec![error];
                if let Err(error) = join_reader(stdout, "stdout") {
                    errors.push(error);
                }
                return Err(combine_errors(errors));
            }
        };
        Ok(Self {
            stdout: Some(stdout),
            stderr: Some(stderr),
            cancel,
        })
    }

    fn is_finished(&self) -> bool {
        self.stdout
            .as_ref()
            .is_none_or(thread::JoinHandle::is_finished)
            && self
                .stderr
                .as_ref()
                .is_none_or(thread::JoinHandle::is_finished)
    }

    fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }

    fn join_all(&mut self) -> JoinedCaptures {
        let mut captures = JoinedCaptures {
            stdout: None,
            stderr: None,
            errors: Vec::new(),
        };
        if let Some(handle) = self.stdout.take() {
            match join_reader(handle, "stdout") {
                Ok(output) => captures.stdout = Some(output),
                Err(error) => captures.errors.push(error),
            }
        }
        if let Some(handle) = self.stderr.take() {
            match join_reader(handle, "stderr") {
                Ok(output) => captures.stderr = Some(output),
                Err(error) => captures.errors.push(error),
            }
        }
        captures
    }
}

impl Drop for CaptureReaders {
    fn drop(&mut self) {
        self.cancel();
        let _joined = self.join_all();
    }
}

fn cleanup_setup_failure(
    child: &mut ChildCleanupGuard,
    error: ProcessError,
    group_signal: fn(u32) -> io::Result<()>,
) -> ProcessError {
    let mut errors = vec![error];
    let mut exit_status = None;
    let termination = terminate_and_reap(child, &mut exit_status, group_signal);
    if let Err(error) = termination {
        push_error(&mut errors, error);
    }
    combine_errors(errors)
}

fn finish_execution(
    child: &mut ChildCleanupGuard,
    readers: &mut CaptureReaders,
    mut exit_status: Option<ExitStatus>,
    mut errors: Vec<ProcessError>,
    group_signal: fn(u32) -> io::Result<()>,
) -> Result<(ExitStatus, CapturedStream, CapturedStream), ProcessError> {
    let termination = terminate_and_reap(child, &mut exit_status, group_signal);
    if let Err(error) = termination {
        push_error(&mut errors, error);
    }
    let drain_deadline = Instant::now()
        .checked_add(TERMINATION_GRACE)
        .unwrap_or_else(Instant::now);
    while !readers.is_finished() && Instant::now() < drain_deadline {
        thread::sleep(POLL_INTERVAL);
    }
    if !readers.is_finished() {
        readers.cancel();
        errors.push(ProcessError::CaptureDrainTimeout);
    }
    let captures = readers.join_all();
    for error in captures.errors {
        push_error(&mut errors, error);
    }
    if !errors.is_empty() {
        return Err(combine_errors(errors));
    }
    // Keep the guard armed until process-group cleanup and every capture
    // reader have completed successfully; only then may completion publish.
    child.disarm();
    Ok((
        exit_status.expect("reaped status was checked"),
        captures.stdout.expect("stdout join was checked"),
        captures.stderr.expect("stderr join was checked"),
    ))
}

fn terminate_and_reap(
    child: &mut ChildCleanupGuard,
    exit_status: &mut Option<ExitStatus>,
    group_signal: fn(u32) -> io::Result<()>,
) -> Result<(), ProcessError> {
    terminate_child(
        &mut child.child,
        child.process_group,
        exit_status,
        group_signal,
    )
}

fn terminate_child(
    child: &mut Child,
    process_group: u32,
    exit_status: &mut Option<ExitStatus>,
    group_signal: fn(u32) -> io::Result<()>,
) -> Result<(), ProcessError> {
    let deadline = Instant::now()
        .checked_add(TERMINATION_GRACE)
        .unwrap_or_else(Instant::now);
    let mut errors = Vec::new();
    let group_signal_failed = match group_signal(process_group) {
        Ok(()) => false,
        Err(source) => {
            errors.push(ProcessError::GroupSignal(source));
            true
        }
    };
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
    match wait_for_process_group(process_group, deadline) {
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
    use rustix::process::{Pid, Signal, kill_process_group};

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
    use rustix::{
        io::Errno,
        process::{Pid, test_kill_process_group},
    };

    let process_group = i32::try_from(process_group)
        .ok()
        .and_then(Pid::from_raw)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "process group must be nonzero")
        })?;
    match test_kill_process_group(process_group) {
        Ok(()) => Ok(true),
        Err(Errno::SRCH) => Ok(false),
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
    loop {
        if !process_group_exists(process_group)? {
            return Ok(true);
        }
        let wait = deadline.saturating_duration_since(Instant::now());
        if wait.is_zero() {
            return Ok(false);
        }
        thread::sleep(wait.min(POLL_INTERVAL));
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
    use super::{ProcessState, run_bounded_with_group_signal, signal_process_group};
    #[cfg(unix)]
    use std::{
        fs,
        process::{Command, Stdio},
        sync::{
            Mutex, MutexGuard,
            atomic::{AtomicU64, Ordering},
        },
        thread,
        time::Instant,
    };

    #[cfg(unix)]
    static PROCESS_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[cfg(unix)]
    fn process_test_guard() -> MutexGuard<'static, ()> {
        PROCESS_TEST_LOCK
            .lock()
            .expect("process test lock is healthy")
    }

    #[cfg(unix)]
    fn signal_then_fail(process_group: u32) -> std::io::Result<()> {
        signal_process_group(process_group)?;
        Err(std::io::Error::other("injected group-signal failure"))
    }

    #[cfg(unix)]
    static NEXT_ESCAPED_MARKER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn rejects_a_missing_current_directory_before_spawn() {
        #[cfg(unix)]
        let _guard = process_test_guard();
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
        let _guard = process_test_guard();
        let started = Instant::now();
        let outcome = run_bounded(
            &ProcessSpec::new("/bin/sh").args([
                "-c",
                r#"sleep 5 </dev/null >/dev/null 2>&1 & descendant=$!; printf '%s\n' "$descendant"; exit "$1""#,
                "sh",
                &exit_code.to_string(),
            ]),
            ProcessLimits {
                timeout: Duration::from_secs(2),
                max_stdout_bytes: 64,
                max_stderr_bytes: 64,
            },
        )
        .expect("leader status and descendant cleanup are both preserved");

        assert_eq!(outcome.state, ProcessState::Complete);
        assert_eq!(outcome.exit_code, Some(exit_code));
        assert!(started.elapsed() < Duration::from_secs(1));
        let descendant = String::from_utf8(outcome.stdout.bytes)
            .expect("pid is UTF-8")
            .trim()
            .to_owned();
        assert_process_stopped(&descendant);
    }

    #[cfg(unix)]
    fn assert_process_stopped(pid: &str) {
        use rustix::{
            io::Errno,
            process::{Pid, test_kill_process},
        };

        let pid = Pid::from_raw(pid.parse().expect("pid is numeric")).expect("pid is nonzero");
        for _ in 0..50 {
            match test_kill_process(pid) {
                Err(Errno::SRCH) => return,
                Ok(()) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("failed to probe descendant {pid:?}: {error}"),
            }
        }
        panic!("descendant process {pid:?} survived process-group termination");
    }

    #[cfg(unix)]
    fn contains_group_signal(error: &ProcessError) -> bool {
        match error {
            ProcessError::GroupSignal(_) => true,
            ProcessError::MultipleFailures { failures } => {
                failures.iter().any(contains_group_signal)
            }
            _ => false,
        }
    }

    #[cfg(unix)]
    struct ProcessGroupGuard(Option<u32>);

    #[cfg(unix)]
    impl ProcessGroupGuard {
        fn terminate(mut self) {
            let process_group = self.0.take().expect("process group is armed");
            signal_process_group(process_group)
                .expect("test cleanup terminates escaped process group");
        }
    }

    #[cfg(unix)]
    impl Drop for ProcessGroupGuard {
        fn drop(&mut self) {
            if let Some(process_group) = self.0.take() {
                let _ignored = signal_process_group(process_group);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn group_signal_failure_is_typed_after_reap_and_reader_join() {
        let _guard = process_test_guard();

        // The injected signal seam is required because a same-user child cannot
        // portably induce EPERM. Restoring the legacy "ignore after reap" branch
        // makes this assertion fail even though the seam itself still compiles.
        let error = run_bounded_with_group_signal(
            &ProcessSpec::new("/bin/sh")
                .args(["-c", "sleep 5 </dev/null >/dev/null 2>&1 & exit 0"]),
            ProcessLimits {
                timeout: Duration::from_secs(2),
                max_stdout_bytes: 64,
                max_stderr_bytes: 64,
            },
            signal_then_fail,
        )
        .expect_err("injected group-signal failures must propagate");

        assert!(contains_group_signal(&error));
    }

    #[cfg(unix)]
    #[test]
    fn escaped_session_pipe_holder_is_cancelled_and_readers_join_before_return() {
        let _guard = process_test_guard();
        let python = Command::new("python3")
            .args(["-c", "import os"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("python3 is required to test the Python provider process boundary");
        assert!(
            python.success(),
            "python3 must execute for this provider test"
        );

        let marker = std::env::temp_dir().join(format!(
            "diagnostic-triage-python-{}-{}-escaped",
            std::process::id(),
            NEXT_ESCAPED_MARKER.fetch_add(1, Ordering::Relaxed)
        ));
        let started = Instant::now();
        let threads_before = os_thread_count();
        let result = run_bounded(
            &ProcessSpec::new("/bin/sh").args([
                "-c",
                r#"python3 -c 'import os,sys,time; os.setsid(); marker=open(sys.argv[1],"w"); marker.write(str(os.getpid())); marker.close(); exec("while True:\n time.sleep(1)")' "$1" & while [ ! -s "$1" ]; do sleep 0.01; done; exit 0"#,
                "sh",
                &marker.to_string_lossy(),
            ]),
            ProcessLimits {
                timeout: Duration::from_secs(2),
                max_stdout_bytes: 64,
                max_stderr_bytes: 64,
            },
        );
        let threads_after = os_thread_count();
        let escaped = fs::read_to_string(&marker).expect("escaped process records its pid");
        let escaped_pid = escaped.trim().parse().expect("pid is numeric");
        let cleanup = ProcessGroupGuard(Some(escaped_pid));

        assert!(
            matches!(result, Err(ProcessError::CaptureDrainTimeout)),
            "escaped pipe holder must force joined-reader cleanup: {result:?}"
        );
        assert_eq!(
            threads_after, threads_before,
            "run_bounded must not return with detached capture workers"
        );
        assert!(started.elapsed() < Duration::from_secs(1));

        cleanup.terminate();
        assert_process_stopped(escaped.trim());
        fs::remove_file(marker).expect("test marker is removable");
    }

    #[cfg(unix)]
    fn os_thread_count() -> usize {
        let pid = std::process::id().to_string();
        let mut command = Command::new("ps");
        #[cfg(target_os = "linux")]
        command.args(["-L", "-p", &pid]);
        #[cfg(not(target_os = "linux"))]
        command.args(["-M", "-p", &pid]);
        let output = command
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .expect("ps is required to observe test-process thread ownership");
        assert!(
            output.status.success(),
            "ps failed while counting threads: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("ps output is UTF-8")
            .lines()
            .skip(1)
            .filter(|line| !line.trim().is_empty())
            .count()
    }
}
