//! Bounded, direct-argv Biome process execution.

// LLM contract: DISCOVERED -> NORMALIZED -> CLASSIFIED -> FIX_PROPOSED -> VERIFIED -> REPORTED; execution terminal: INCOMPLETE | UNSUPPORTED.

use std::{
    ffi::OsStr,
    io::{self, Read},
    ops::{Deref, DerefMut},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use thiserror::Error;
use wait_timeout::ChildExt;

const POLL_INTERVAL: Duration = Duration::from_millis(5);
const TERMINATION_GRACE: Duration = Duration::from_millis(250);

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
    #[error("failed to spawn Biome: {0}")]
    Spawn(#[source] io::Error),
    #[error("spawned Biome process did not expose {0}")]
    MissingPipe(&'static str),
    #[error("failed while waiting for Biome: {0}")]
    Wait(#[source] io::Error),
    #[error("failed to capture Biome {stream}: {source}")]
    Capture {
        stream: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("failed to spawn the Biome {stream} capture worker: {source}")]
    CaptureSpawn {
        stream: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("Biome {0} capture thread panicked")]
    CapturePanic(&'static str),
    #[error("Biome child could not be reaped after termination")]
    Unreaped,
    #[error("Biome capture pipes remained open after process termination")]
    CaptureDrainTimeout,
}

pub(crate) fn run_direct(
    program: &OsStr,
    argv: &[String],
    current_dir: &Path,
    limits: ProcessLimits,
) -> Result<ProcessOutcome, ProcessError> {
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
    let stdout = child
        .stdout
        .take()
        .ok_or(ProcessError::MissingPipe("stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or(ProcessError::MissingPipe("stderr"))?;
    let stdout_overflow = Arc::new(AtomicBool::new(false));
    let stderr_overflow = Arc::new(AtomicBool::new(false));
    let stdout_reader = spawn_reader(
        stdout,
        limits.max_stdout_bytes,
        Arc::clone(&stdout_overflow),
        "stdout",
    )?;
    let stderr_reader = spawn_reader(
        stderr,
        limits.max_stderr_bytes,
        Arc::clone(&stderr_overflow),
        "stderr",
    )?;
    let deadline = started.checked_add(limits.timeout).unwrap_or(started);
    let mut forced_reason = None;

    let mut exit_status = None;
    loop {
        if stdout_overflow.load(Ordering::Acquire) {
            forced_reason = Some(IncompleteReason::StdoutOverflow);
        } else if stderr_overflow.load(Ordering::Acquire) {
            forced_reason = Some(IncompleteReason::StderrOverflow);
        } else if Instant::now() >= deadline {
            forced_reason = Some(IncompleteReason::Timeout);
        }
        if forced_reason.is_some() {
            terminate_and_reap(&mut child, &mut exit_status)?;
            break;
        }

        let wait = deadline
            .saturating_duration_since(Instant::now())
            .min(POLL_INTERVAL);
        if exit_status.is_none() {
            exit_status = child.wait_timeout(wait).map_err(ProcessError::Wait)?;
        } else if stdout_reader.is_finished() && stderr_reader.is_finished() {
            break;
        } else {
            thread::sleep(wait);
        }
    }

    let drain_deadline = Instant::now()
        .checked_add(TERMINATION_GRACE)
        .unwrap_or_else(Instant::now);
    while !(stdout_reader.is_finished() && stderr_reader.is_finished())
        && Instant::now() < drain_deadline
    {
        thread::sleep(POLL_INTERVAL);
    }
    if !(stdout_reader.is_finished() && stderr_reader.is_finished()) {
        return Err(ProcessError::CaptureDrainTimeout);
    }

    let stdout = join_reader(stdout_reader, "stdout")?;
    let stderr = join_reader(stderr_reader, "stderr")?;
    let status = exit_status.ok_or(ProcessError::Unreaped)?;
    child.disarm();
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
        duration: started.elapsed().min(limits.timeout),
    })
}

fn spawn_reader<R>(
    reader: R,
    limit: usize,
    overflow: Arc<AtomicBool>,
    stream: &'static str,
) -> Result<thread::JoinHandle<io::Result<CapturedOutput>>, ProcessError>
where
    R: Read + Send + 'static,
{
    thread::Builder::new()
        .name(format!("biome-{stream}-capture"))
        .spawn(move || capture(reader, limit, &overflow))
        .map_err(|source| ProcessError::CaptureSpawn { stream, source })
}

fn capture(
    mut reader: impl Read,
    limit: usize,
    overflow: &AtomicBool,
) -> io::Result<CapturedOutput> {
    let mut bytes = Vec::with_capacity(limit.min(8192));
    let mut observed_bytes = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        observed_bytes = observed_bytes.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
        let retained = count.min(limit.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&buffer[..retained]);
        if retained != count {
            overflow.store(true, Ordering::Release);
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
            let _ignored = terminate_child(&mut self.child, self.process_group, &mut exit_status);
        }
    }
}

fn terminate_and_reap(
    child: &mut ChildGuard,
    exit_status: &mut Option<ExitStatus>,
) -> Result<(), ProcessError> {
    terminate_child(&mut child.child, child.process_group, exit_status)
}

fn terminate_child(
    child: &mut Child,
    process_group: u32,
    exit_status: &mut Option<ExitStatus>,
) -> Result<(), ProcessError> {
    #[cfg(unix)]
    let _group_signal = signal_process_group(process_group);
    #[cfg(not(unix))]
    let _ = process_group;

    if exit_status.is_none() {
        *exit_status = child.try_wait().map_err(ProcessError::Wait)?;
    }
    if exit_status.is_none() {
        child.kill().map_err(ProcessError::Wait)?;
        *exit_status = child
            .wait_timeout(TERMINATION_GRACE)
            .map_err(ProcessError::Wait)?;
    }
    if exit_status.is_none() {
        return Err(ProcessError::Unreaped);
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

#[cfg(test)]
mod tests {
    use super::{IncompleteReason, ProcessLimits, ProcessState, run_direct};
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
    fn leader_exit_with_descendant_held_pipes_is_bounded() {
        let started = Instant::now();
        let mut process_limits = limits(64, 64);
        process_limits.timeout = Duration::from_millis(80);
        let outcome = run_direct(
            OsStr::new("/bin/sh"),
            &[
                "-c".to_owned(),
                r#"while :; do :; done & descendant=$!; printf '%s\n' "$descendant"; exit 0"#
                    .to_owned(),
            ],
            Path::new("."),
            process_limits,
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
        for _ in 0..25 {
            let status = Command::new("/bin/kill")
                .args(["-s", "0", &descendant])
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
        panic!("descendant process {descendant} survived process-group termination");
    }
}
