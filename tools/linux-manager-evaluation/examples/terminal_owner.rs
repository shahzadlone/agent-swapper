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
use nix::sys::{
    signal::{SigSet, Signal},
    wait::WaitStatus,
};
use outer_terminal::{Signals, Terminal, require};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    process::{Pid, PidfdFlags, pidfd_open},
};
use std::{
    fs,
    io::{self, IsTerminal, Write},
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

fn marker(directory: &Path, name: &str, value: &str) -> io::Result<()> {
    fs::write(directory.join(format!("{name}.tmp")), value)?;
    fs::rename(directory.join(format!("{name}.tmp")), directory.join(name))
}

struct Owner(Terminal);
impl Drop for Owner {
    fn drop(&mut self) {
        let _ = self.0.restore_saved();
    }
}

fn child(directory: &Path, parent: Pid) -> io::Result<()> {
    require(
        rustix::process::getppid() == Some(parent),
        "terminal owner vanished before child admission",
    )?;
    nix::sys::prctl::set_pdeathsig(Some(Signal::SIGTERM))?;
    require(
        rustix::process::getppid() == Some(parent),
        "terminal owner vanished during child admission",
    )?;
    // Fixed child entry point only. No terminal mode has changed yet. This
    // removes the fresh parent's inherited blocked mask before installing our
    // own event loop; it never changes an already multithreaded caller.
    SigSet::empty().thread_set_mask()?;
    let signals = Signals::new()?;
    let mut terminal = Terminal::capture_for_group(directory, parent)?;
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
        let mut watched = vec![PollFd::new(&signals.file, PollFlags::IN)];
        if !paused {
            watched.push(PollFd::new(&terminal.fd, PollFlags::IN));
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
            match rustix::io::read(&terminal.fd, &mut bytes) {
                Ok(0) => return Err(io::Error::other("owned child input ended")),
                Ok(count) => input.extend_from_slice(&bytes[..count]),
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            }
            require(input.len() <= 64, "owned child input exceeds fixed budget")?;
        }
    }
}

fn owner(directory: &Path) -> io::Result<()> {
    let signals = Signals::new()?;
    // Declared before child: error unwinding kills/reaps the fixed child before
    // this guard restores modes, then restores the parent's signal mask.
    let mut terminal = Owner(Terminal::capture(directory)?);
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("--child")
        .arg(directory)
        .arg(std::process::id().to_string())
        .env_clear()
        .env("ASWP_OWNED_OUTER_PTY", "1");
    let mut child = job_control::OwnedChild::new(command.spawn()?)?;
    drop(command);
    let child_pid =
        Pid::from_raw(child.pid.as_raw()).ok_or_else(|| io::Error::other("invalid child PID"))?;
    let child_fd = pidfd_open(child_pid, PidfdFlags::empty())?;
    let until = Instant::now() + Duration::from_secs(15);
    let mut ready = false;
    let mut cancellation = None;
    let result;
    loop {
        require(Instant::now() < until, "terminal owner deadline expired")?;
        let notices = signals.drain()?;
        if let Some(signal) = notices.terminate {
            cancellation = Some(signal);
            rustix::process::pidfd_send_signal(&child_fd, rustix::process::Signal::TERM)?;
            rustix::process::pidfd_send_signal(&child_fd, rustix::process::Signal::CONT)?;
        }
        require(
            !notices.stop,
            "external owner suspension is outside this fixed probe",
        )?;
        if !ready && directory.join("child-ready").exists() {
            require(
                fs::read_to_string(directory.join("child-ready"))? == child.pid.to_string(),
                "owned child readiness differs",
            )?;
            marker(directory, "ready", &serde_json::json!({"pid":std::process::id(),
                "group":terminal.0.group.as_raw_pid(), "session":rustix::process::getsid(None)?.as_raw_pid(),
                "child":child.pid.as_raw()}).to_string())?;
            ready = true;
        }
        match child.poll()? {
            WaitStatus::StillAlive | WaitStatus::Continued(_) => {}
            WaitStatus::Stopped(_, signal) => {
                terminal.0.restore_saved()?;
                marker(
                    directory,
                    "owner-restored-stop",
                    &(signal as i32).to_string(),
                )?;
                let resumed = signals.suspend()?;
                if let Some(signal) = resumed.terminate {
                    cancellation = Some(signal);
                    rustix::process::pidfd_send_signal(&child_fd, rustix::process::Signal::TERM)?;
                    rustix::process::pidfd_send_signal(&child_fd, rustix::process::Signal::CONT)?;
                }
            }
            WaitStatus::Exited(_, code) => {
                result = (Some(code), None);
                break;
            }
            WaitStatus::Signaled(_, signal, _) => {
                result = (None, Some(signal));
                break;
            }
            _ => return Err(io::Error::other("unexpected owned child wait status")),
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    if terminal.0.foreground()? {
        terminal.0.restore_saved()?;
        marker(
            directory,
            "owner-restored-exit",
            &format!("{:?}:{:?}", result.0, result.1.map(|s| s as i32)),
        )?;
    } else {
        // The shell may have changed its modes after bg. We already restored
        // at the child's stop and must not overwrite the new foreground owner.
        marker(
            directory,
            "owner-background-exit",
            "foreground owner unchanged",
        )?;
    }
    drop(child);
    drop(terminal);
    signals.finish(cancellation.or(result.1))?;
    require(result.0 == Some(0), "fixed child did not exit successfully")
}

fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    let result = match args.as_slice() {
        [_, path] => owner(Path::new(path)),
        [_, role, path, pid] if role == "--child" => pid
            .to_str()
            .and_then(|text| text.parse::<i32>().ok())
            .and_then(Pid::from_raw)
            .ok_or_else(|| io::Error::other("invalid owner PID"))
            .and_then(|pid| child(Path::new(path), pid)),
        _ => Err(io::Error::other(
            "requires the owned terminal-owner harness",
        )),
    };
    if let Err(error) = result {
        if !io::stderr().is_terminal() {
            eprintln!("terminal owner fixture: {error}");
        }
        std::process::exit(125);
    }
}
