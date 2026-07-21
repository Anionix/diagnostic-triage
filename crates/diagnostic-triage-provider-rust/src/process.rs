//! Bounded, direct-argv Cargo process execution.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

use std::{
    ffi::OsStr,
    io::{self, Read},
    ops::{Deref, DerefMut},
    path::Path,
    process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use thiserror::Error;
use wait_timeout::ChildExt;

#[cfg(unix)]
use rustix::{
    io::Errno,
    process::{Pid, Signal, kill_process_group, test_kill_process_group},
};
#[cfg(unix)]
use std::os::fd::AsFd;

const POLL_INTERVAL: Duration = Duration::from_millis(5);
const TERMINATION_GRACE: Duration = Duration::from_millis(250);
const PROCESS_GROUP_GRACE: Duration = Duration::from_millis(500);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessLimits {
    pub timeout: Duration,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CapturedOutput {
    pub bytes: Vec<u8>,
    pub observed_bytes: u64,
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IncompleteReason {
    Timeout,
    StdoutOverflow,
    StderrOverflow,
    TerminatedWithoutCode,
    UnrepresentableExitCode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessState {
    Complete,
    Incomplete(IncompleteReason),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProcessOutcome {
    pub state: ProcessState,
    pub exit_code: Option<u8>,
    pub stdout: CapturedOutput,
    pub stderr: CapturedOutput,
    pub duration: Duration,
}

#[derive(Debug, Error)]
pub(crate) enum ProcessError {
    #[error("Cargo request budget was exhausted before the next process step")]
    BudgetExhausted,
    #[error("bounded Cargo process-group execution is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("failed to spawn Cargo: {0}")]
    Spawn(#[source] io::Error),
    #[error("spawned Cargo process did not expose {0}")]
    MissingPipe(&'static str),
    #[error("failed while waiting for Cargo: {0}")]
    Wait(#[source] io::Error),
    #[error("failed to configure the Cargo {stream} capture pipe: {source}")]
    CaptureConfiguration {
        stream: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("failed to capture Cargo {stream}: {source}")]
    Capture {
        stream: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("failed to spawn the Cargo {stream} capture worker: {source}")]
    CaptureSpawn {
        stream: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("Cargo {0} capture thread panicked")]
    CapturePanic(&'static str),
    #[error("Cargo child could not be reaped after termination")]
    Unreaped,
    #[error("failed to signal the Cargo process group: {0}")]
    GroupSignal(#[source] io::Error),
    #[error("failed while waiting for the Cargo process group: {0}")]
    GroupWait(#[source] io::Error),
    #[error("Cargo process group remained live after termination")]
    GroupUnreaped,
    #[error("failed to terminate the Cargo group leader directly: {0}")]
    LeaderSignal(#[source] io::Error),
    #[error("failed while reaping the Cargo group leader: {0}")]
    Reap(#[source] io::Error),
    #[error("Cargo capture pipes remained open after process termination")]
    CaptureDrainTimeout,
    #[error("multiple Cargo process failures: {failures:?}")]
    MultipleFailures { failures: Vec<ProcessError> },
}

pub(crate) fn run_direct(
    program: &OsStr,
    argv: &[String],
    current_dir: &Path,
    limits: ProcessLimits,
) -> Result<ProcessOutcome, ProcessError> {
    run_direct_with_group_signal(program, argv, current_dir, limits, signal_process_group)
}

fn run_direct_with_group_signal(
    program: &OsStr,
    argv: &[String],
    current_dir: &Path,
    limits: ProcessLimits,
    group_signal: fn(u32) -> io::Result<()>,
) -> Result<ProcessOutcome, ProcessError> {
    run_direct_with_reader_probe(program, argv, current_dir, limits, group_signal, None)
}

#[cfg(test)]
fn run_direct_with_group_signal_and_reader_probe(
    program: &OsStr,
    argv: &[String],
    current_dir: &Path,
    limits: ProcessLimits,
    group_signal: fn(u32) -> io::Result<()>,
    reader_join_probe: Arc<AtomicUsize>,
) -> Result<ProcessOutcome, ProcessError> {
    run_direct_with_reader_probe(
        program,
        argv,
        current_dir,
        limits,
        group_signal,
        Some(reader_join_probe),
    )
}

fn run_direct_with_reader_probe(
    program: &OsStr,
    argv: &[String],
    current_dir: &Path,
    limits: ProcessLimits,
    group_signal: fn(u32) -> io::Result<()>,
    reader_join_probe: Option<Arc<AtomicUsize>>,
) -> Result<ProcessOutcome, ProcessError> {
    if cfg!(not(unix)) {
        return Err(ProcessError::UnsupportedPlatform);
    }
    let started = Instant::now();
    let mut command = Command::new(program);
    command
        .args(argv)
        .current_dir(current_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        command.process_group(0);
    }
    let mut child = ChildGuard::new(command.spawn().map_err(ProcessError::Spawn)?);
    let stdout_overflow = Arc::new(AtomicBool::new(false));
    let stderr_overflow = Arc::new(AtomicBool::new(false));
    let mut readers = match spawn_capture_readers(
        &mut child,
        limits,
        Arc::clone(&stdout_overflow),
        Arc::clone(&stderr_overflow),
        reader_join_probe,
    ) {
        Ok(readers) => readers,
        Err(error) => return Err(cleanup_setup_failure(&mut child, error, group_signal)),
    };
    let deadline = started.checked_add(limits.timeout).unwrap_or(started);
    let mut forced_reason = None;
    let exit_status = None;
    let mut errors = Vec::new();

    loop {
        if stdout_overflow.load(Ordering::Acquire) {
            forced_reason = Some(IncompleteReason::StdoutOverflow);
        } else if stderr_overflow.load(Ordering::Acquire) {
            forced_reason = Some(IncompleteReason::StderrOverflow);
        } else if Instant::now() >= deadline {
            forced_reason = Some(IncompleteReason::Timeout);
        }
        if forced_reason.is_some() {
            break;
        }

        let wait = deadline
            .saturating_duration_since(Instant::now())
            .min(POLL_INTERVAL);
        match child_exited_without_reaping(&child) {
            Ok(true) => break,
            Ok(false) => thread::sleep(wait),
            Err(source) => {
                errors.push(ProcessError::Wait(source));
                break;
            }
        }
    }

    let duration = started.elapsed().min(limits.timeout);
    let (status, stdout, stderr) =
        finish_execution(&mut child, &mut readers, exit_status, errors, group_signal)?;
    let reason = forced_reason
        .or_else(|| stdout.truncated.then_some(IncompleteReason::StdoutOverflow))
        .or_else(|| stderr.truncated.then_some(IncompleteReason::StderrOverflow));
    let native_code = status.code();
    let converted_code = native_code.and_then(|code| u8::try_from(code).ok());
    let state = reason.map_or_else(
        || match (native_code, converted_code) {
            (Some(_), Some(_)) => ProcessState::Complete,
            (Some(_), None) => ProcessState::Incomplete(IncompleteReason::UnrepresentableExitCode),
            (None, _) => ProcessState::Incomplete(IncompleteReason::TerminatedWithoutCode),
        },
        ProcessState::Incomplete,
    );

    Ok(ProcessOutcome {
        state,
        exit_code: (state == ProcessState::Complete)
            .then_some(converted_code)
            .flatten(),
        stdout,
        stderr,
        duration,
    })
}

#[cfg(unix)]
fn child_exited_without_reaping(child: &Child) -> io::Result<bool> {
    use rustix::process::{WaitId, WaitIdOptions, waitid};

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

fn spawn_capture_readers(
    child: &mut ChildGuard,
    limits: ProcessLimits,
    stdout_overflow: Arc<AtomicBool>,
    stderr_overflow: Arc<AtomicBool>,
    reader_join_probe: Option<Arc<AtomicUsize>>,
) -> Result<CaptureReaders, ProcessError> {
    let stdout = child
        .stdout
        .take()
        .ok_or(ProcessError::MissingPipe("stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or(ProcessError::MissingPipe("stderr"))?;
    CaptureReaders::spawn(
        configure_nonblocking(stdout, "stdout")?,
        configure_nonblocking(stderr, "stderr")?,
        limits,
        stdout_overflow,
        stderr_overflow,
        reader_join_probe,
    )
}

fn cleanup_setup_failure(
    child: &mut ChildGuard,
    error: ProcessError,
    group_signal: fn(u32) -> io::Result<()>,
) -> ProcessError {
    let mut errors = vec![error];
    let mut exit_status = None;
    let termination = terminate_and_reap(child, &mut exit_status, group_signal);
    if let Err(error) = termination {
        push_error(&mut errors, error);
    }
    if exit_status.is_some() {
        child.disarm();
    }
    combine_errors(errors)
}

fn finish_execution(
    child: &mut ChildGuard,
    readers: &mut CaptureReaders,
    mut exit_status: Option<ExitStatus>,
    mut errors: Vec<ProcessError>,
    group_signal: fn(u32) -> io::Result<()>,
) -> Result<(ExitStatus, CapturedOutput, CapturedOutput), ProcessError> {
    let termination = terminate_and_reap(child, &mut exit_status, group_signal);
    if let Err(error) = termination {
        push_error(&mut errors, error);
    }
    if exit_status.is_some() {
        child.disarm();
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
    // The reaped leader's numeric PGID may be reused while readers drain, so
    // cleanup errors must never arm a second destructive group signal.
    Ok((
        exit_status.expect("reaped status was checked"),
        captures.stdout.expect("stdout join was checked"),
        captures.stderr.expect("stderr join was checked"),
    ))
}

fn spawn_reader<R>(
    reader: R,
    limit: usize,
    overflow: Arc<AtomicBool>,
    cancel: Arc<AtomicBool>,
    stream: &'static str,
) -> Result<thread::JoinHandle<io::Result<CapturedOutput>>, ProcessError>
where
    R: Read + Send + 'static,
{
    thread::Builder::new()
        .name(format!("cargo-{stream}-capture"))
        .spawn(move || capture(reader, limit, &overflow, &cancel))
        .map_err(|source| ProcessError::CaptureSpawn { stream, source })
}

fn capture(
    mut reader: impl Read,
    limit: usize,
    overflow: &AtomicBool,
    cancel: &AtomicBool,
) -> io::Result<CapturedOutput> {
    let mut bytes = Vec::with_capacity(limit.min(8192));
    let mut observed_bytes = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        if cancel.load(Ordering::Acquire) {
            break;
        }
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                observed_bytes =
                    observed_bytes.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
                let retained = count.min(limit.saturating_sub(bytes.len()));
                bytes.extend_from_slice(&buffer[..retained]);
                if retained != count {
                    overflow.store(true, Ordering::Release);
                }
            }
            Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
            Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(POLL_INTERVAL);
            }
            Err(source) => return Err(source),
        }
    }
    Ok(CapturedOutput {
        truncated: observed_bytes > u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        bytes,
        observed_bytes,
    })
}

fn join_reader(
    handle: thread::JoinHandle<io::Result<CapturedOutput>>,
    stream: &'static str,
) -> Result<CapturedOutput, ProcessError> {
    handle
        .join()
        .map_err(|_| ProcessError::CapturePanic(stream))?
        .map_err(|source| ProcessError::Capture { stream, source })
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
    stdout: Option<CapturedOutput>,
    stderr: Option<CapturedOutput>,
    errors: Vec<ProcessError>,
}

struct CaptureReaders {
    stdout: Option<thread::JoinHandle<io::Result<CapturedOutput>>>,
    stderr: Option<thread::JoinHandle<io::Result<CapturedOutput>>>,
    cancel: Arc<AtomicBool>,
    reader_join_probe: Option<Arc<AtomicUsize>>,
}

impl CaptureReaders {
    fn spawn(
        stdout: ChildStdout,
        stderr: ChildStderr,
        limits: ProcessLimits,
        stdout_overflow: Arc<AtomicBool>,
        stderr_overflow: Arc<AtomicBool>,
        reader_join_probe: Option<Arc<AtomicUsize>>,
    ) -> Result<Self, ProcessError> {
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
            reader_join_probe,
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
                Ok(output) => {
                    captures.stdout = Some(output);
                    if let Some(probe) = &self.reader_join_probe {
                        probe.fetch_add(1, Ordering::Release);
                    }
                }
                Err(error) => captures.errors.push(error),
            }
        }
        if let Some(handle) = self.stderr.take() {
            match join_reader(handle, "stderr") {
                Ok(output) => {
                    captures.stderr = Some(output);
                    if let Some(probe) = &self.reader_join_probe {
                        probe.fetch_add(1, Ordering::Release);
                    }
                }
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

struct ChildGuard {
    child: Child,
    process_group: u32,
    armed: bool,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self {
            process_group: child.id(),
            child,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Deref for ChildGuard {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.child
    }
}

impl DerefMut for ChildGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.child
    }
}

impl Drop for ChildGuard {
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

fn terminate_and_reap(
    child: &mut ChildGuard,
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
    let pid = process_group_pid(process_group)?;
    match kill_process_group(pid, Signal::KILL) {
        Ok(()) | Err(Errno::SRCH) => Ok(()),
        Err(error) => Err(error.into()),
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
    let pid = process_group_pid(process_group)?;
    map_process_group_probe(test_kill_process_group(pid))
}

#[cfg(unix)]
fn map_process_group_probe(result: Result<(), Errno>) -> io::Result<bool> {
    match result {
        Err(Errno::SRCH) => Ok(false),
        Ok(()) => Ok(true),
        Err(Errno::PERM) => Err(io::Error::from(Errno::PERM)),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn process_group_pid(process_group: u32) -> io::Result<Pid> {
    let raw_pid = i32::try_from(process_group)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "process-group ID overflow"))?;
    Pid::from_raw(raw_pid).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "process-group ID must be positive",
        )
    })
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

#[cfg(test)]
mod tests {
    use super::{
        IncompleteReason, ProcessError, ProcessLimits, ProcessState, run_direct,
        run_direct_with_group_signal, run_direct_with_group_signal_and_reader_probe,
        signal_process_group,
    };
    use std::{
        ffi::OsStr,
        path::Path,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    fn limits(stdout: usize, stderr: usize) -> ProcessLimits {
        ProcessLimits {
            timeout: Duration::from_secs(2),
            max_stdout_bytes: stdout,
            max_stderr_bytes: stderr,
        }
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

    #[cfg(unix)]
    fn assert_process_disappears(raw_pid: &str) {
        for _ in 0..25 {
            let probe = Command::new("ps")
                .args(["-p", raw_pid, "-o", "pid="])
                .stdin(Stdio::null())
                .output()
                .expect("ps is available on supported Unix targets");
            if !probe.status.success() || probe.stdout.trim_ascii().is_empty() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("descendant process {raw_pid} survived process-group termination");
    }

    #[cfg(unix)]
    fn assert_closed_stdio_descendant_is_killed(exit_code: u8) {
        let started = Instant::now();
        let outcome = run_direct(
            OsStr::new("/bin/sh"),
            &[
                "-c".to_owned(),
                r#"sleep 5 </dev/null >/dev/null 2>&1 & descendant=$!; printf '%s\n' "$descendant"; exit "$1""#
                    .to_owned(),
                "sh".to_owned(),
                exit_code.to_string(),
            ],
            Path::new("."),
            limits(64, 64),
        )
        .expect("leader status and descendant cleanup are both preserved");

        assert_eq!(outcome.state, ProcessState::Complete);
        assert_eq!(outcome.exit_code, Some(exit_code));
        assert!(started.elapsed() < Duration::from_secs(1));
        let descendant = String::from_utf8(outcome.stdout.bytes)
            .expect("pid is UTF-8")
            .trim()
            .to_owned();
        assert_process_disappears(&descendant);
    }

    #[test]
    #[cfg(unix)]
    fn direct_argv_preserves_nonzero_exit_as_complete() {
        let outcome = run_direct(OsStr::new("false"), &[], Path::new("."), limits(64, 64))
            .expect("false must be executable in the test environment");

        assert_eq!(outcome.state, ProcessState::Complete);
        assert_eq!(outcome.exit_code, Some(1));
    }

    #[test]
    #[cfg(unix)]
    fn timeout_is_bounded_and_incomplete() {
        let mut process_limits = limits(64, 64);
        process_limits.timeout = Duration::from_millis(30);
        let outcome = run_direct(
            OsStr::new("sleep"),
            &["1".to_owned()],
            Path::new("."),
            process_limits,
        )
        .expect("sleep must be executable in the test environment");

        assert_eq!(
            outcome.state,
            ProcessState::Incomplete(IncompleteReason::Timeout)
        );
        assert_eq!(outcome.exit_code, None);
        assert!(outcome.duration <= Duration::from_millis(30));
    }

    #[test]
    #[cfg(unix)]
    fn stdout_overflow_is_truncated_and_incomplete() {
        let outcome = run_direct(
            OsStr::new("printf"),
            &["0123456789abcdef".to_owned()],
            Path::new("."),
            limits(8, 64),
        )
        .expect("printf must be executable in the test environment");

        assert_eq!(
            outcome.state,
            ProcessState::Incomplete(IncompleteReason::StdoutOverflow)
        );
        assert_eq!(outcome.stdout.bytes, b"01234567");
        assert!(outcome.stdout.truncated);
        assert!(outcome.stdout.observed_bytes > 8);
    }

    #[test]
    #[cfg(unix)]
    fn simultaneous_streams_are_drained_without_deadlock() {
        let outcome = run_direct(
            OsStr::new("/bin/sh"),
            &[
                "-c".to_owned(),
                r#"i=0; while [ "$i" -lt 10000 ]; do printf 'xxxxxxxx'; printf 'yyyyyyyy' >&2; i=$((i + 1)); done"#.to_owned(),
            ],
            Path::new("."),
            limits(100_000, 100_000),
        )
        .expect("both streams complete within their independent bounds");

        assert_eq!(outcome.state, ProcessState::Complete);
        assert_eq!(outcome.stdout.observed_bytes, 80_000);
        assert_eq!(outcome.stderr.observed_bytes, 80_000);
    }

    #[test]
    #[cfg(unix)]
    fn signal_termination_has_no_invented_exit_code() {
        let outcome = run_direct(
            OsStr::new("/bin/sh"),
            &["-c".to_owned(), "kill -TERM $$".to_owned()],
            Path::new("."),
            limits(64, 64),
        )
        .expect("signal termination is a typed process outcome");

        assert_eq!(
            outcome.state,
            ProcessState::Incomplete(IncompleteReason::TerminatedWithoutCode)
        );
        assert_eq!(outcome.exit_code, None);
    }

    #[test]
    #[cfg(unix)]
    fn zero_exit_kills_closed_stdio_delayed_descendant_and_preserves_status() {
        assert_closed_stdio_descendant_is_killed(0);
    }

    #[test]
    #[cfg(unix)]
    fn nonzero_exit_kills_closed_stdio_delayed_descendant_and_preserves_status() {
        assert_closed_stdio_descendant_is_killed(7);
    }

    #[test]
    #[cfg(unix)]
    fn zombie_only_permission_error_is_suppressed_without_resignal() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static SIGNAL_CALLS: AtomicUsize = AtomicUsize::new(0);
        fn deny_and_count(_: u32) -> std::io::Result<()> {
            SIGNAL_CALLS.fetch_add(1, Ordering::SeqCst);
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        }

        SIGNAL_CALLS.store(0, Ordering::SeqCst);
        let outcome = run_direct_with_group_signal(
            OsStr::new("/usr/bin/true"),
            &[],
            Path::new("."),
            limits(64, 64),
            deny_and_count,
        )
        .expect("a zombie-only EPERM is resolved by the post-reap retry");

        assert_eq!(outcome.state, ProcessState::Complete);
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(SIGNAL_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    #[cfg(unix)]
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
            Instant::now() + Duration::from_millis(100),
            deny_once_then_absent,
        )
        .expect("a transient group-probe EPERM is retried");

        assert!(reaped);
        assert_eq!(PROBE_CALLS.load(Ordering::SeqCst), 2);
    }

    #[test]
    #[cfg(unix)]
    fn persistent_group_probe_permission_error_is_typed() {
        fn always_deny(_: u32) -> std::io::Result<bool> {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        }

        let error = super::wait_for_process_group_with_probe(1, Instant::now(), always_deny)
            .expect_err("a persistent group-probe EPERM must propagate");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        let production_error =
            super::map_process_group_probe(Err(rustix::io::Errno::PERM)).unwrap_err();
        assert_eq!(
            production_error.kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    #[cfg(unix)]
    fn cleanup_time_is_excluded_from_tool_duration() {
        fn delayed_signal(process_group: u32) -> std::io::Result<()> {
            thread::sleep(Duration::from_millis(100));
            signal_process_group(process_group)
        }

        let started = Instant::now();
        let outcome = run_direct_with_group_signal(
            OsStr::new("/usr/bin/true"),
            &[],
            Path::new("."),
            limits(64, 64),
            delayed_signal,
        )
        .expect("delayed cleanup remains a complete process outcome");

        assert!(
            started.elapsed().saturating_sub(outcome.duration) >= Duration::from_millis(80),
            "cleanup delay leaked into tool duration"
        );
    }

    #[test]
    #[cfg(unix)]
    fn group_signal_failure_is_typed_after_reap_and_reader_join() {
        fn signal_then_fail(process_group: u32) -> std::io::Result<()> {
            signal_process_group(process_group)?;
            Err(std::io::Error::other("injected group-signal failure"))
        }

        let error = run_direct_with_group_signal(
            OsStr::new("/bin/sh"),
            &[
                "-c".to_owned(),
                "sleep 5 </dev/null >/dev/null 2>&1 & exit 0".to_owned(),
            ],
            Path::new("."),
            limits(64, 64),
            signal_then_fail,
        )
        .expect_err("injected group-signal failures must propagate");

        assert!(contains_group_signal(&error), "error: {error:?}");
    }

    #[test]
    #[cfg(unix)]
    fn escaped_session_pipe_holder_is_cancelled_and_readers_join_before_return() {
        use std::{
            fs,
            sync::{
                Arc,
                atomic::{AtomicU64, AtomicUsize, Ordering},
            },
        };

        static NEXT_MARKER: AtomicU64 = AtomicU64::new(0);
        let python_check = Command::new("python3")
            .args(["-c", "import os; os.getpid()"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("the Unix process-group regression test requires python3");
        assert!(
            python_check.success(),
            "the Unix process-group regression test requires python3"
        );
        let marker = std::env::temp_dir().join(format!(
            "diagnostic-triage-cargo-{}-{}-escaped",
            std::process::id(),
            NEXT_MARKER.fetch_add(1, Ordering::Relaxed)
        ));
        let started = Instant::now();
        let reader_join_probe = Arc::new(AtomicUsize::new(0));
        let result = run_direct_with_group_signal_and_reader_probe(
            OsStr::new("python3"),
            &[
                "-c".to_owned(),
                r#"import os, sys, time
child = os.fork()
if child == 0:
    os.setsid()
    with open(sys.argv[1], "w", encoding="ascii") as marker:
        marker.write(str(os.getpid()))
    time.sleep(60)
while not os.path.exists(sys.argv[1]) or os.path.getsize(sys.argv[1]) == 0:
    time.sleep(0.01)
os._exit(0)"#
                    .to_owned(),
                marker.to_string_lossy().into_owned(),
            ],
            Path::new("."),
            limits(64, 64),
            signal_process_group,
            Arc::clone(&reader_join_probe),
        );
        let escaped = fs::read_to_string(&marker).expect("escaped process records its pid");
        let readers_joined = reader_join_probe.load(Ordering::Acquire) == 2;
        signal_process_group(escaped.trim().parse().expect("pid is numeric"))
            .expect("test cleanup terminates escaped process group");
        let _removed = fs::remove_file(marker);

        assert!(
            matches!(result, Err(ProcessError::CaptureDrainTimeout)),
            "result: {result:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(
            readers_joined,
            "capture readers must be joined before run returns"
        );
        assert_process_disappears(escaped.trim());
    }
}
