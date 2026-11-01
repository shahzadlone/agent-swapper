//! A surviving parent restores an owned terminal after its fixed child dies.
#![forbid(unsafe_code)]
#[allow(
    dead_code,
    reason = "shared exclusive child waiter; this probe never signals a child group"
)]
#[path = "../src/job_control.rs"]
mod job_control;
#[path = "../src/outer_terminal.rs"]
mod outer_terminal;
#[path = "../src/terminal_owner.rs"]
mod terminal_owner;
use agentswapper_linux_runtime::signals::Signals;
use nix::sys::signal::{SigSet, Signal};
use outer_terminal::require;
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    process::Pid,
};
use std::{
    fs,
    io::{self, IsTerminal, Write},
    path::Path,
    time::{Duration, Instant},
};

fn marker(directory: &Path, name: &str, value: &str) -> io::Result<()> {
    fs::write(directory.join(format!("{name}.tmp")), value)?;
    fs::rename(directory.join(format!("{name}.tmp")), directory.join(name))
}

fn child(directory: &Path, parent: Pid) -> io::Result<()> {
    require(
        rustix::process::getppid() == Some(parent),
        "terminal owner vanished before child admission",
    )?;
    // A stopped child cannot handle SIGTERM. Parent loss must close its
    // descriptors even under a same-session subreaper with no orphan SIGCONT.
    nix::sys::prctl::set_pdeathsig(Some(Signal::SIGKILL))?;
    require(
        rustix::process::getppid() == Some(parent),
        "terminal owner vanished during child admission",
    )?;
    // Fixed child entry point only. No terminal mode has changed yet. This
    // removes the fresh parent's inherited blocked mask before installing our
    // own event loop; it never changes an already multithreaded caller.
    SigSet::empty().thread_set_mask()?;
    let signals = Signals::new()?;
    let mut terminal = outer_terminal::capture_for_group(directory, &signals, parent)?;
    terminal.enter()?;
    marker(directory, "child-ready", &std::process::id().to_string())?;
    io::stdout().write_all(b"OWNED-CHILD-READY\r\n")?;
    let until = Instant::now() + Duration::from_secs(12);
    let mut paused = false;
    let mut input = Vec::new();
    loop {
        require(Instant::now() < until, "owned child deadline expired")?;
        let notices = signals.drain()?;
        if let Some(signal) = notices.terminate {
            if terminal.foreground()? {
                terminal.restore()?;
            }
            drop(terminal);
            return signals.finish(Some(signal));
        }
        require(
            !notices.stop,
            "external child suspension is outside this fixed probe",
        )?;
        if notices.continued {
            // A SIGSTOP cannot run child cleanup. The surviving owner restored
            // modes while we were stopped; a background continuation must wait
            // for foreground ownership before changing them again.
            paused = true;
        }
        if paused && terminal.foreground()? {
            terminal.enter()?;
            paused = false;
            marker(directory, "child-foreground", "raw")?;
            io::stdout().write_all(b"OWNED-CHILD-RESUMED\r\n")?;
        }
        if !paused {
            require(terminal.foreground()?, "child lost foreground while active")?;
            if let Some(index) = input.iter().position(|byte| *byte == b'\n') {
                let line: Vec<_> = input.drain(..=index).collect();
                match line.as_slice() {
                    b"exit\n" => {
                        terminal.restore()?;
                        return Ok(());
                    }
                    b"stop\n" => {
                        terminal.restore()?;
                        let resumed = signals.suspend()?;
                        if let Some(signal) = resumed.terminate {
                            drop(terminal);
                            return signals.finish(Some(signal));
                        }
                        paused = true;
                    }
                    _ => return Err(io::Error::other("unknown owned-child command")),
                }
            }
        }
        let mut watched = vec![PollFd::new(&signals, PollFlags::IN)];
        if !paused {
            watched.push(PollFd::new(&terminal, PollFlags::IN));
        }
        match poll(
            &mut watched,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 10_000_000,
            }),
        ) {
            Err(rustix::io::Errno::INTR) => continue,
            result => {
                result?;
            }
        }
        if watched
            .get(1)
            .is_some_and(|fd| fd.revents().contains(PollFlags::IN))
        {
            let mut bytes = [0; 32];
            match rustix::io::read(&terminal, &mut bytes) {
                Ok(0) => return Err(io::Error::other("owned child input ended")),
                Ok(count) => input.extend_from_slice(&bytes[..count]),
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            }
            require(input.len() <= 64, "owned child input exceeds fixed budget")?;
        }
    }
}

fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args_os().collect();
    let result = match args.as_slice() {
        [_, path] => terminal_owner::run(Path::new(path), false),
        [_, role, path, pid] if role == "--child" => pid
            .to_str()
            .and_then(|text| text.parse::<i32>().ok())
            .and_then(Pid::from_raw)
            .ok_or_else(|| io::Error::other("invalid owner PID"))
            .and_then(|pid| child(Path::new(path), pid))
            .map(|()| 0),
        _ => Err(io::Error::other(
            "requires the owned terminal-owner harness",
        )),
    };
    match result {
        Ok(code) => std::process::ExitCode::from(code),
        Err(error) => {
            if !io::stderr().is_terminal() {
                eprintln!("terminal owner fixture: {error}");
            }
            std::process::ExitCode::from(125)
        }
    }
}
