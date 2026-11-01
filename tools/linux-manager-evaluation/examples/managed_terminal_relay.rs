//! Fixed hosted target through two owned terminals; never a provider launcher.
#![forbid(unsafe_code)]
#[path = "../src/outer_terminal.rs"]
mod outer_terminal;

use aswp_linux_manager_evaluation::journal_client::{Bound, JobEvent, Running};
use outer_terminal::{Signals, Terminal, require};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    termios,
};
use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::{fd::AsFd, unix::fs::OpenOptionsExt},
    path::Path,
    time::{Duration, Instant},
};

const CAPACITY: usize = 16_384;

fn marker(directory: &Path, name: &str, value: &str) -> io::Result<()> {
    fs::write(directory.join(format!("{name}.tmp")), value)?;
    fs::rename(directory.join(format!("{name}.tmp")), directory.join(name))
}

fn durable_intent(directory: &Path, pid: u32) -> io::Result<()> {
    // This component uses a synced fixture intent. The separate real Store
    // tests qualify SQLite policy; this file never completes a production run.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("intent"))?;
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
    let size = termios::tcgetwinsize(&terminal.fd)?;
    termios::tcsetwinsize(master, size)?;
    Ok(())
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
    let until = Instant::now() + Duration::from_secs(25);
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
            "external relay suspension is not yet qualified",
        )?;
        if notices.resized && !inner_closed {
            resize(terminal, &master)?;
        }
        if !control_closed {
            match running.poll_job()? {
                JobEvent::Pending => {}
                JobEvent::Closed => {
                    control_closed = true;
                    draining = Some(Instant::now() + Duration::from_secs(2));
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
                }
            }
        }
        let foreground = terminal.foreground()?;
        if paused && foreground && !control_closed {
            // Resize and raw-mode ownership are restored before asking the
            // guardian to continue its original, still-unreaped child group.
            resize(terminal, &master)?;
            terminal.enter()?;
            running.resume()?;
            paused = false;
            stopped = false;
            marker(directory, "resumed-foreground", "raw")?;
        }
        require(
            !terminal.raw || foreground,
            "relay lost foreground while raw",
        )?;
        if control_closed && inner_closed && output.is_empty() {
            marker(directory, "drained", "inner EOF and queued output consumed")?;
            break;
        }
        if let Some(deadline) = draining {
            require(
                Instant::now() < deadline,
                "terminal output drain remained blocked",
            )?;
        }
        let active = foreground && terminal.raw && !paused;
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
        let mut ready = [
            PollFd::new(&terminal.fd, outer_events),
            PollFd::new(&master, inner_events),
            PollFd::new(&signals.file, PollFlags::IN),
        ];
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
        let inner = ready[1].revents();
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
                write_queue(&terminal.fd, &mut output)?;
            }
            // HUP may coexist with remaining PTY output. Drain before EIO;
            // never use terminal closure as a containment or exit receipt.
            if !inner_closed
                && output.len() < CAPACITY
                && inner.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR)
            {
                inner_closed = read_queue(&master, &mut output, true)?;
            }
            if !control_closed && inner.contains(PollFlags::OUT) {
                write_queue(&master, &mut input)?;
            }
            if !control_closed && outer.contains(PollFlags::IN) {
                require(
                    !read_queue(&terminal.fd, &mut input, false)?,
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

fn run(directory: &Path) -> io::Result<()> {
    // Signal blocking precedes runtime creation. A newly created thread
    // inherits this mask; no already-running CLI thread is modified here.
    let signals = Signals::new()?;
    let mut terminal = Terminal::capture(directory)?;
    let prefix = std::env::var("ASWP_ACTIVATION_PREFIX").map_err(io::Error::other)?;
    let lease = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("lease"))?;
    lease.try_lock().map_err(io::Error::other)?;
    let bound = Bound::connect_job_control(&prefix)?;
    let prepared = bound
        .prepare(lease.as_fd())
        .map_err(|failure| failure.error)?;
    drop(lease);
    let identity = prepared.identity();
    let target = prepared.pid();
    resize(
        &terminal,
        prepared
            .terminal()
            .ok_or_else(|| io::Error::other("prepared terminal absent"))?,
    )?;
    marker(
        directory,
        "ready",
        &serde_json::json!({
            "pid": std::process::id(), "group": terminal.group.as_raw_pid(),
            "session": rustix::process::getsid(None)?.as_raw_pid(),
            "target": target, "guardian": identity.guardian_pid, "invocation": identity.invocation
        })
        .to_string(),
    )?;
    let mut running = prepared
        .start_after([0x41; 16], |pid| durable_intent(directory, pid))
        .map_err(|failure| io::Error::other(format!("{failure:?}")))?;
    terminal.enter()?;
    marker(directory, "relay-ready", "raw")?;
    let outcome = relay(directory, &signals, &mut terminal, &mut running);
    // Restore promptly even if manager observation takes longer or fails.
    terminal.restore()?;
    marker(directory, "restored", "complete")?;
    let retired = running.close().retire().map_err(|failure| failure.error)?;
    require(
        retired.identity == identity && retired.connection_close_error.is_none(),
        "relay retirement observation failed",
    )?;
    marker(
        directory,
        "retired",
        "original scope and child retired; journal policy unchanged",
    )?;
    drop(terminal);
    signals.finish(outcome?)
}

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    let result = match args.as_slice() {
        [_, path] => run(Path::new(path)),
        _ => Err(io::Error::other(
            "requires the hosted owned-terminal harness",
        )),
    };
    if let Err(error) = result {
        eprintln!("managed terminal relay: {error}");
        std::process::exit(125);
    }
}
