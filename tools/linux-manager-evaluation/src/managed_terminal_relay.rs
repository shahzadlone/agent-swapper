//! Fixed hosted target through two owned terminals; never a provider launcher.
#![forbid(unsafe_code)]
#[path = "fresh_entry.rs"]
mod fresh_entry;
#[allow(
    dead_code,
    reason = "shared exclusive child waiter; owner never signals a child group"
)]
#[path = "job_control.rs"]
mod job_control;
#[path = "outer_terminal.rs"]
mod outer_terminal;
#[path = "terminal_owner.rs"]
mod terminal_owner;

use crate::journal_client::{
    Bound, Closed, Identity, JobEvent, Running, StartCause, StartFailure, TargetExit,
    TransitionFailure,
};
use agentswapper_linux_runtime::signals::Signals;
use outer_terminal::{Terminal, require};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    termios,
};
use std::{
    cell::Cell,
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::{self, IsTerminal, Write},
    os::{
        fd::{AsFd, BorrowedFd},
        unix::fs::OpenOptionsExt,
    },
    path::Path,
    time::{Duration, Instant},
};

const CAPACITY: usize = 16_384;

fn marker(directory: &Path, name: &str, value: &str) -> io::Result<()> {
    fs::write(directory.join(format!("{name}.tmp")), value)?;
    fs::rename(directory.join(format!("{name}.tmp")), directory.join(name))
}

/// Qualification journal boundary. Implementations may confirm durable intent
/// and spawn observation, but cannot manufacture production custody receipts.
pub trait AdmissionJournal: Sized {
    fn open(directory: &Path) -> io::Result<Self>;
    fn lease(&self) -> io::Result<BorrowedFd<'_>>;
    fn confirm_intent(&mut self, pid: u32) -> io::Result<()>;
    fn observe_spawn(&mut self, pid: u32) -> io::Result<()>;
    fn release_lease(&mut self);
    fn audit_retired(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Existing synced-file fixture journal; never a production completion record.
pub struct FileJournal {
    directory: std::path::PathBuf,
    lease: Option<File>,
}
impl AdmissionJournal for FileJournal {
    fn open(directory: &Path) -> io::Result<Self> {
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("lease"))?;
        lease.try_lock().map_err(io::Error::other)?;
        Ok(Self {
            directory: directory.to_owned(),
            lease: Some(lease),
        })
    }
    fn lease(&self) -> io::Result<BorrowedFd<'_>> {
        self.lease
            .as_ref()
            .map(AsFd::as_fd)
            .ok_or_else(|| io::Error::other("fixture lease already released"))
    }
    fn confirm_intent(&mut self, pid: u32) -> io::Result<()> {
        durable_record(&self.directory, "intent", pid)
    }
    fn observe_spawn(&mut self, pid: u32) -> io::Result<()> {
        durable_record(&self.directory, "spawn-observed", pid)
    }
    fn release_lease(&mut self) {
        drop(self.lease.take());
    }
}

fn durable_record(directory: &Path, name: &str, pid: u32) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(name))?;
    writeln!(file, "fixed target PID: {pid}; outcome unresolved")?;
    file.sync_all()?;
    File::open(directory)?.sync_all()
}

fn write_queue(fd: impl AsFd, queue: &mut VecDeque<u8>) -> io::Result<()> {
    if queue.is_empty() {
        return Ok(());
    }
    match rustix::io::write(fd, queue.make_contiguous()) {
        Ok(count) => {
            require(count > 0, "terminal write made no progress")?;
            queue.drain(..count);
        }
        Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn read_queue(fd: impl AsFd, queue: &mut VecDeque<u8>, inner: bool) -> io::Result<bool> {
    let mut bytes = [0_u8; 4096];
    let capacity = bytes.len().min(CAPACITY.saturating_sub(queue.len()));
    require(capacity > 0, "reading a full relay queue")?;
    match rustix::io::read(fd, &mut bytes[..capacity]) {
        Ok(0) => Ok(true),
        Ok(count) => {
            queue.extend(&bytes[..count]);
            Ok(false)
        }
        Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => Ok(false),
        Err(rustix::io::Errno::IO) if inner => Ok(true),
        Err(error) => Err(error.into()),
    }
}

fn resize(terminal: &Terminal, master: impl AsFd) -> io::Result<()> {
    let size = termios::tcgetwinsize(terminal)?;
    termios::tcsetwinsize(master, size)?;
    Ok(())
}

struct Drain {
    idle: Instant,
    total: Instant,
    known_exit: bool,
}
impl Drain {
    fn new(known_exit: bool) -> Self {
        let now = Instant::now();
        Self {
            idle: now + Duration::from_secs(if known_exit { 5 } else { 2 }),
            total: now + Duration::from_secs(if known_exit { 15 } else { 2 }),
            known_exit,
        }
    }
    fn progress(&mut self) {
        if self.known_exit {
            self.idle = Instant::now() + Duration::from_secs(5);
        }
    }
    fn expired(&self) -> bool {
        let now = Instant::now();
        now >= self.idle || now >= self.total
    }
}

fn relay(
    directory: &Path,
    signals: &Signals,
    terminal: &mut Terminal,
    running: &mut Running,
) -> io::Result<Option<nix::sys::signal::Signal>> {
    let master = running
        .terminal()
        .ok_or_else(|| io::Error::other("managed relay has no inner terminal"))?
        .try_clone_to_owned()?;
    let mut input = VecDeque::new();
    let mut output = VecDeque::new();
    let mut paused = false;
    let mut stopped = false;
    let mut inner_closed = false;
    let mut control_closed = false;
    let mut draining = None;
    let mut high_water = [0_usize; 2];
    let mut backpressured = false;
    let until = Instant::now() + Duration::from_secs(55);
    loop {
        require(
            Instant::now() < until,
            "managed relay exceeded fixture lifetime",
        )?;
        let notices = signals.drain()?;
        if let Some(signal) = notices.terminate {
            marker(
                directory,
                "cancelled",
                "pending output deliberately discarded",
            )?;
            return Ok(Some(signal));
        }
        require(
            !notices.stop,
            "external suspension is unsupported for an active managed target",
        )?;
        if notices.resized && !inner_closed {
            resize(terminal, &master)?;
        }
        if !control_closed {
            match running.poll_job()? {
                JobEvent::Pending => {}
                JobEvent::Closed => {
                    control_closed = true;
                    draining = Some(Drain::new(false));
                }
                JobEvent::Exited(status) => {
                    marker(directory, "observed-exit", &format!("{status:?}"))?;
                    // Still drain terminal bytes and independently retire the
                    // original scope. A target exit is not all-writer custody.
                    control_closed = true;
                    draining = Some(Drain::new(true));
                }
                JobEvent::Stopped(signal) => {
                    require(!stopped, "duplicate pending inner stop")?;
                    stopped = true;
                    terminal.restore()?;
                    marker(directory, "restored-before-stop", &signal.to_string())?;
                    let resumed = signals.suspend()?;
                    if let Some(signal) = resumed.terminate {
                        return Ok(Some(signal));
                    }
                    paused = true;
                    marker(
                        directory,
                        if resumed.continued {
                            "continued"
                        } else {
                            "discarded-stop"
                        },
                        "observed",
                    )?;
                    // A queued exit may have arrived while we were stopped.
                    // Observe it before any foreground resume attempt.
                    continue;
                }
            }
        }
        let foreground = terminal.foreground()?;
        if paused && foreground {
            if !control_closed {
                // A resume observation may itself discover target death.
                resize(terminal, &master)?;
                terminal.enter()?;
                match running.resume_or_observe()? {
                    JobEvent::Pending => {
                        marker(directory, "resumed-foreground", "raw")?;
                    }
                    JobEvent::Exited(status) => {
                        marker(directory, "observed-exit", &format!("{status:?}"))?;
                        control_closed = true;
                        draining = Some(Drain::new(true));
                    }
                    JobEvent::Closed => {
                        control_closed = true;
                        draining = Some(Drain::new(false));
                    }
                    JobEvent::Stopped(_) => {
                        return Err(io::Error::other("duplicate pending inner stop"));
                    }
                }
            } else {
                // Reacquire only the outer terminal for exact-byte draining.
                // An authenticated dead target is never resumed or resized.
                terminal.enter()?;
                marker(directory, "drain-resumed-foreground", "raw")?;
            }
            paused = false;
            stopped = false;
        }
        require(
            !terminal.is_raw() || foreground,
            "relay lost foreground while raw",
        )?;
        if control_closed && inner_closed && output.is_empty() {
            marker(directory, "drained", "inner EOF and queued output consumed")?;
            break;
        }
        if draining.as_ref().is_some_and(Drain::expired) {
            if running.observed_exit().is_some() {
                // Bounded output loss is distinct from a verified exit. In the
                // background, never steal the terminal merely to drain bytes.
                marker(
                    directory,
                    "output-truncated",
                    "bounded final drain expired; target status preserved",
                )?;
                break;
            }
            return Err(io::Error::other("terminal output drain remained blocked"));
        }
        let active = foreground && terminal.is_raw() && !paused;
        let mut outer_events = PollFlags::empty();
        let mut inner_events = PollFlags::empty();
        if active {
            if !control_closed && input.len() < CAPACITY {
                outer_events |= PollFlags::IN;
            }
            if !output.is_empty() {
                outer_events |= PollFlags::OUT;
            }
            if !inner_closed && output.len() < CAPACITY {
                inner_events |= PollFlags::IN;
            }
            if !control_closed && !input.is_empty() {
                inner_events |= PollFlags::OUT;
            }
        }
        let mut ready = vec![
            PollFd::new(&terminal, outer_events),
            PollFd::new(signals, PollFlags::IN),
        ];
        // An unrequested HUP is always reported. Omit the inner descriptor
        // when no progress is possible, so blocked final output cannot spin
        // on that HUP for the entire drain deadline.
        if !inner_events.is_empty() {
            ready.push(PollFd::new(&master, inner_events));
        }
        let count = match poll(
            &mut ready,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 10_000_000,
            }),
        ) {
            Err(rustix::io::Errno::INTR) => continue,
            value => value?,
        };
        if count == 0 && output.len() == CAPACITY && active && !backpressured {
            marker(directory, "backpressure", &output.len().to_string())?;
            backpressured = true;
        }
        let outer = ready[0].revents();
        let inner = ready.get(2).map_or(PollFlags::empty(), PollFd::revents);
        require(
            !outer.intersects(PollFlags::ERR | PollFlags::NVAL),
            "outer terminal failed",
        )?;
        require(
            !inner.contains(PollFlags::NVAL),
            "inner descriptor became invalid",
        )?;
        require(
            !outer.contains(PollFlags::HUP),
            "outer terminal disconnected",
        )?;
        if active {
            if outer.contains(PollFlags::OUT) {
                let queued = output.len();
                write_queue(&terminal, &mut output)?;
                if output.len() < queued
                    && let Some(drain) = &mut draining
                {
                    drain.progress();
                }
            }
            // HUP may coexist with remaining PTY output. Drain before EIO;
            // never use terminal closure as a containment or exit receipt.
            if !inner_closed
                && output.len() < CAPACITY
                && inner.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR)
            {
                let queued = output.len();
                inner_closed = read_queue(&master, &mut output, true)?;
                if output.len() > queued
                    && let Some(drain) = &mut draining
                {
                    drain.progress();
                }
            }
            if !control_closed && inner.contains(PollFlags::OUT) {
                write_queue(&master, &mut input)?;
            }
            if !control_closed && outer.contains(PollFlags::IN) {
                require(
                    !read_queue(&terminal, &mut input, false)?,
                    "outer terminal input closed",
                )?;
            }
        }
        high_water[0] = high_water[0].max(input.len());
        high_water[1] = high_water[1].max(output.len());
        require(
            high_water.iter().all(|count| *count <= CAPACITY),
            "relay buffer exceeded bound",
        )?;
    }
    marker(
        directory,
        "buffers",
        &format!("{}:{}", high_water[0], high_water[1]),
    )?;
    Ok(None)
}

struct AdmissionFailure {
    error: io::Error,
    closed: Box<Closed>,
}
impl From<TransitionFailure> for AdmissionFailure {
    fn from(failure: TransitionFailure) -> Self {
        Self {
            error: failure.error,
            closed: failure.closed,
        }
    }
}
impl From<StartFailure<io::Error>> for AdmissionFailure {
    fn from(failure: StartFailure<io::Error>) -> Self {
        Self {
            error: match failure.cause {
                StartCause::Journal(error) | StartCause::Transport(error) => error,
            },
            closed: failure.closed,
        }
    }
}
fn admission_barrier(directory: &Path, phase: &str) -> io::Result<()> {
    match std::env::var("ASWP_CI_ADMISSION_HOLD") {
        Err(std::env::VarError::NotPresent) => return Ok(()),
        Ok(value)
            if matches!(
                value.as_str(),
                "go" | "release" | "go-send" | "release-send" | "raw-entry"
            ) =>
        {
            if value != phase {
                return Ok(());
            }
        }
        _ => return Err(io::Error::other("invalid admission fixture barrier")),
    }
    marker(directory, "admission-held", phase)?;
    let until = Instant::now() + Duration::from_secs(4);
    while !directory.join("admission-release").exists() {
        require(Instant::now() < until, "admission fixture barrier expired")?;
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}
fn retire_closed(directory: &Path, closed: Closed, identity: &Identity) -> io::Result<()> {
    match closed.retire() {
        Ok(retired) => {
            require(
                retired.identity == *identity,
                "relay retirement observation failed",
            )?;
            if let Some(error) = retired.connection_close_error {
                // The original scope is already proven retired. A bus close
                // error is diagnostic, not a reversal of that observation.
                let _ = marker(directory, "retirement-connection-error", &error.to_string());
            }
            marker(
                directory,
                "retired",
                "original scope and child retired; journal policy unchanged",
            )
        }
        Err(failure) => {
            // A bounded observation failure stays unresolved. Closing control
            // requests cleanup, but cannot turn a timeout into retirement.
            let _ = marker(
                directory,
                "retirement-unresolved",
                &failure.error.to_string(),
            );
            Err(failure.error)
        }
    }
}
struct AdmissionMode {
    owned: bool,
    exec_gate: bool,
}

fn admit<J: AdmissionJournal>(
    directory: &Path,
    bound: Bound,
    journal: &mut J,
    terminal: &mut Terminal,
    cancelled: &Cell<Option<nix::sys::signal::Signal>>,
    mode: AdmissionMode,
) -> Result<Running, AdmissionFailure> {
    let prepared = match journal.lease() {
        Ok(lease) => bound.prepare(lease).map_err(AdmissionFailure::from)?,
        Err(error) => {
            return Err(AdmissionFailure {
                error,
                closed: Box::new(bound.close()),
            });
        }
    };
    let identity = prepared.identity();
    let until = prepared.admission_deadline();
    let target = prepared.pid();
    let ready =
        (|| {
            resize(
                terminal,
                prepared
                    .terminal()
                    .ok_or_else(|| io::Error::other("prepared terminal absent"))?,
            )?;
            marker(directory, if mode.owned { "session-ready" } else { "ready" },
            &serde_json::json!({"pid":std::process::id(), "group":terminal.group().as_raw_pid(),
                "session":rustix::process::getsid(None)?.as_raw_pid(), "target":target,
                "guardian":identity.guardian_pid, "invocation":identity.invocation}).to_string())?;
            admission_barrier(directory, "go")?;
            terminal.wait_for_admission(until, cancelled)
        })();
    if let Err(error) = ready {
        return Err(AdmissionFailure {
            error,
            closed: Box::new(prepared.close()),
        });
    }
    let mut running = prepared
        .start_after_checked(
            [0x41; 16],
            // Journaling is synchronous; pending signals stay queued until
            // the final permit, after the transaction and manager recheck.
            |pid| journal.confirm_intent(pid),
            || {
                admission_barrier(directory, "go-send")?;
                terminal.wait_for_admission(until, cancelled)?;
                if mode.exec_gate {
                    return Ok(());
                }
                admission_barrier(directory, "raw-entry")?;
                terminal.enter_for_admission(until, cancelled)
            },
        )
        .map_err(AdmissionFailure::from)?;
    if mode.exec_gate {
        let held = running.hold_exec().map_err(AdmissionFailure::from)?;
        let observed = (|| {
            held.observe_held()?;
            marker(directory, "exec-held", &target.to_string())?;
            admission_barrier(directory, "release")?;
            terminal.wait_for_admission(until, cancelled)
        })();
        if let Err(error) = observed {
            return Err(AdmissionFailure {
                error,
                closed: Box::new(held.close()),
            });
        }
        running = held
            .release_after_checked(
                |pid| journal.observe_spawn(pid),
                || {
                    admission_barrier(directory, "release-send")?;
                    terminal.wait_for_admission(until, cancelled)?;
                    admission_barrier(directory, "raw-entry")?;
                    terminal.enter_for_admission(until, cancelled)
                },
            )
            .map_err(AdmissionFailure::from)?;
    }
    Ok(running)
}

fn run<J: AdmissionJournal>(
    directory: &Path,
    owner: Option<rustix::process::Pid>,
) -> io::Result<u8> {
    if let Some(parent) = owner {
        require(
            rustix::process::getppid() == Some(parent),
            "terminal owner vanished before managed child admission",
        )?;
        // This kills only the relay helper on owner loss. The root manager
        // independently retires the provider-free inner scope after EOF.
        nix::sys::prctl::set_pdeathsig(Some(nix::sys::signal::Signal::SIGKILL))?;
        require(
            rustix::process::getppid() == Some(parent),
            "terminal owner vanished during managed child admission",
        )?;
        nix::sys::signal::SigSet::empty().thread_set_mask()?;
    }
    // Signal blocking precedes runtime creation. A newly created thread
    // inherits this mask; no already-running CLI thread is modified here.
    let signals = Signals::new()?;
    let mut terminal = match owner {
        Some(parent) => outer_terminal::capture_for_group(directory, &signals, parent)?,
        None => outer_terminal::capture(directory, &signals)?,
    };
    let prefix = std::env::var("ASWP_ACTIVATION_PREFIX").map_err(io::Error::other)?;
    // Signals and terminal admission precede opening the journal. A real Store
    // implementation commits its run intent here, before any target preparation.
    let mut journal = J::open(directory)?;
    let exec_gate = match std::env::var("ASWP_CI_EXEC_GATE") {
        Ok(value) if value == "1" => true,
        Err(std::env::VarError::NotPresent) => false,
        _ => return Err(io::Error::other("invalid fixed exec-gate mode")),
    };
    let bound = if exec_gate {
        Bound::connect_exec_control(&prefix)?
    } else {
        Bound::connect_job_control(&prefix)?
    };
    let identity = bound.identity();
    let cancelled = Cell::new(None);
    let admitted = admit(
        directory,
        bound,
        &mut journal,
        &mut terminal,
        &cancelled,
        AdmissionMode {
            owned: owner.is_some(),
            exec_gate,
        },
    );
    journal.release_lease();
    let mut running = match admitted {
        Ok(running) => running,
        Err(failure) => {
            let _ = marker(directory, "admission-error", &failure.error.to_string());
            let retired = retire_closed(directory, *failure.closed, &identity)
                .and_then(|()| journal.audit_retired());
            drop(terminal);
            signals.finish_after_cleanup(cancelled.get())?;
            return Err(match retired {
                Ok(()) => failure.error,
                Err(error) => error,
            });
        }
    };
    // Every error after admission reaches the same restoration/retirement path.
    let outcome = (|| {
        // The admission guard may consume a resize notice; refresh from the
        // actual outer terminal after detach rather than resizing a trace stop.
        resize(
            &terminal,
            running
                .terminal()
                .ok_or_else(|| io::Error::other("running terminal absent"))?,
        )?;
        require(
            terminal.is_raw(),
            "final grant did not commit raw terminal entry",
        )?;
        marker(directory, "relay-ready", "raw")?;
        if owner.is_some() {
            marker(directory, "child-ready", &std::process::id().to_string())?;
        }
        relay(directory, &signals, &mut terminal, &mut running)
    })();
    if let Err(error) = &outcome {
        let _ = marker(directory, "relay-error", &error.to_string());
    }
    // Restore promptly even if manager observation takes longer or fails.
    let restored = terminal.restore();
    let disconnected = (|| -> io::Result<bool> {
        let mut watched = [PollFd::new(&terminal, PollFlags::empty())];
        poll(
            &mut watched,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )?;
        Ok(watched[0].revents().contains(PollFlags::HUP))
    })();
    if restored.is_ok() {
        let _ = marker(directory, "restored", "complete");
    } else {
        let _ = marker(
            directory,
            "restoration-unavailable",
            if matches!(disconnected, Ok(true)) {
                "owned outer terminal disconnected"
            } else {
                "terminal restoration failed"
            },
        );
    }
    let target_exit = running.observed_exit();
    let retired =
        retire_closed(directory, running.close(), &identity).and_then(|()| journal.audit_retired());
    drop(terminal);
    // A vanished master cannot be restored. Record that limit without
    // skipping independent scope retirement or hiding a delivered fatal signal.
    let termination = outcome.as_ref().ok().copied().flatten();
    let restoration = match disconnected {
        Ok(true) if termination.is_some() => Ok(()),
        Ok(_) => restored,
        Err(error) => Err(error),
    };
    // Final signal policy runs even when a cleanup observation failed. Its
    // return never completes the unresolved journal or supplies a scope receipt.
    signals.finish_after_cleanup(termination)?;
    retired?;
    restoration?;
    outcome?;
    if !exec_gate {
        return Ok(0);
    }
    match target_exit {
        Some(TargetExit::Code { code }) => Ok(code),
        Some(TargetExit::Signal { signal, .. }) => Ok(128 + signal),
        None => {
            marker(
                directory,
                "target-outcome-unresolved",
                "no authenticated target exit",
            )?;
            Err(io::Error::other(
                "managed target outcome remains unresolved",
            ))
        }
    }
}

/// Fixed fixture roles only. Environment and owned-terminal gates remain active.
pub fn entry<J: AdmissionJournal>() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args_os().collect();
    let result = match args.as_slice() {
        [_, role, path] if role == "--fresh-entry" => fresh_entry::start(Path::new(path), false),
        [_, role, path] if role == "--fresh-entry-fail" => {
            fresh_entry::start(Path::new(path), true)
        }
        [_, role, path] if role == "--fresh-owner" => fresh_entry::restore(Path::new(path))
            .and_then(|()| terminal_owner::run(Path::new(path), true)),
        [_, path] => run::<J>(Path::new(path), None),
        [_, role, path] if role == "--owned-parent" => terminal_owner::run(Path::new(path), true),
        [_, role, path, parent] if role == "--owned-child" => parent
            .to_str()
            .and_then(|text| text.parse::<i32>().ok())
            .and_then(rustix::process::Pid::from_raw)
            .ok_or_else(|| io::Error::other("invalid managed terminal owner PID"))
            .and_then(|pid| run::<J>(Path::new(path), Some(pid))),
        _ => Err(io::Error::other(
            "requires the hosted owned-terminal harness",
        )),
    };
    match result {
        Ok(code) => std::process::ExitCode::from(code),
        Err(error) => {
            // The original stderr description may be blocking and share a full
            // outer PTY. A diagnostic must not hang after bounded cleanup. The
            // admitted harness reads the private relay-error marker instead.
            if !io::stderr().is_terminal() {
                eprintln!("managed terminal relay: {error}");
            }
            std::process::ExitCode::from(125)
        }
    }
}
