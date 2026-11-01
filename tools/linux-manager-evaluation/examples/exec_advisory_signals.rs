//! Signal-delivery stops before exec, using the actual guardian child owner.
#![forbid(unsafe_code)]
#[allow(
    dead_code,
    reason = "this probe uses only the exclusive exec child owner"
)]
#[path = "../src/job_control.rs"]
mod job_control;

use agentswapper_linux_runtime::admission_transport as transport;
use nix::sys::{
    ptrace,
    signal::{Signal, raise},
    wait::WaitStatus,
};
use std::{
    fs, io,
    os::{fd::AsFd, unix::process::CommandExt},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
fn shim(directory: &Path, initial: Option<Signal>) -> io::Result<()> {
    let input = io::stdin().as_fd().try_clone_to_owned()?;
    let peer = nix::sys::socket::getsockopt(&input, nix::sys::socket::sockopt::PeerCredentials)?;
    require(
        peer.pid() == nix::unistd::getppid().as_raw()
            && peer.uid() == rustix::process::getuid().as_raw(),
        "shim lacks original parent gate",
    )?;
    ptrace::traceme()?;
    if let Some(signal) = initial {
        raise(signal)?;
    }
    raise(Signal::SIGSTOP)?;
    let until = Instant::now() + Duration::from_secs(5);
    transport::send_until(&input, b"READY", &[], until)?;
    let previous =
        rustix::net::sockopt::socket_timeout(&input, rustix::net::sockopt::Timeout::Recv)?;
    transport::receive_control_until(&input, transport::GO, until)?;
    require(
        rustix::net::sockopt::socket_timeout(&input, rustix::net::sockopt::Timeout::Recv)?
            == previous,
        "interrupted receive changed the caller timeout",
    )?;
    drop(input);
    Err(Command::new(std::env::current_exe()?)
        .arg("--target")
        .arg(directory)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .exec())
}
fn target(directory: &Path) -> io::Result<()> {
    require(
        fs::read_to_string("/proc/self/status")?
            .lines()
            .any(|line| line == "TracerPid:\t0"),
        "target instructions remained traced",
    )?;
    fs::write(directory.join("executed"), "fixed target after detach")
}
fn suite() -> io::Result<()> {
    for (signal, benign, initial) in [
        (Signal::SIGWINCH, true, true),
        (Signal::SIGCHLD, true, true),
        (Signal::SIGWINCH, true, false),
        (Signal::SIGCHLD, true, false),
        (Signal::SIGINT, false, false),
        (Signal::SIGTERM, false, false),
        (Signal::SIGTSTP, false, false),
        (Signal::SIGSTOP, false, false),
        (Signal::SIGTRAP, false, false),
    ] {
        let directory = tempfile::tempdir()?;
        let (control, input) = transport::pair()?;
        let mut command = Command::new(std::env::current_exe()?);
        command
            .arg(match (initial, signal) {
                (true, Signal::SIGWINCH) => "--shim-initial-winch",
                (true, Signal::SIGCHLD) => "--shim-initial-chld",
                _ => "--shim",
            })
            .arg(directory.path())
            .env_clear()
            .stdin(Stdio::from(input))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let mut child = job_control::OwnedChild::new(command.spawn()?)?;
        drop(command);
        let pid = rustix::process::Pid::from_raw(child.pid.as_raw())
            .ok_or_else(|| io::Error::other("invalid owned child PID"))?;
        let handle = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())?;
        let until = Instant::now() + Duration::from_secs(5);
        child.arm_exec(until)?;
        transport::receive_control_until(&control, b"READY", until)?;
        if !initial {
            rustix::process::pidfd_send_signal(
                &handle,
                rustix::process::Signal::from_named_raw(signal as i32)
                    .ok_or_else(|| io::Error::other("unknown fixed signal"))?,
            )?;
            // Do not consume a wait status outside the sole owner. The trace stop
            // must exist before GO, preventing a timing-only advisory signal test.
            loop {
                let stat = fs::read_to_string(format!("/proc/{}/stat", child.pid))?;
                if stat
                    .rsplit_once(") ")
                    .is_some_and(|(_, fields)| fields.starts_with("t "))
                {
                    break;
                }
                require(
                    Instant::now() < until,
                    "signal did not enter trace delivery stop",
                )?;
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        require(
            !directory.path().join("executed").exists(),
            "target ran before GO",
        )?;
        transport::send_until(&control, transport::GO, &[], until)?;
        let held = child.hold_exec(until);
        if held.is_ok() != benign {
            return Err(io::Error::other(format!(
                "pre-exec signal {signal} policy differed: {held:?}"
            )));
        }
        require(
            !directory.path().join("executed").exists(),
            "target ran before held release",
        )?;
        if benign {
            child.release_exec()?;
            require(
                child.next(until)? == WaitStatus::Exited(child.pid, 0),
                "released target failed",
            )?;
            require(
                directory.path().join("executed").exists(),
                "released target did not execute",
            )?;
        }
        drop(child);
        let mut watched = [rustix::event::PollFd::new(
            &handle,
            rustix::event::PollFlags::IN,
        )];
        rustix::event::poll(
            &mut watched,
            Some(&rustix::event::Timespec {
                tv_sec: 1,
                tv_nsec: 0,
            }),
        )?;
        require(
            watched[0].revents().contains(rustix::event::PollFlags::IN),
            "original child survived cleanup",
        )?;
        require(
            directory.path().join("executed").exists() == benign,
            "refused signal executed target",
        )?;
        println!(
            "exec-advisory-{signal}-{}: pass",
            if initial { "initial" } else { "armed" }
        );
    }
    println!(
        "::notice::pre-exec signal policy: four advisory stops continued to held exec, five termination/stop/trap signals withheld execution; all original child handles retired"
    );
    Ok(())
}
fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args_os().collect();
    let result = match args.as_slice() {
        [_] => suite(),
        [_, role, directory] if role == "--shim" => shim(Path::new(directory), None),
        [_, role, directory] if role == "--shim-initial-winch" => {
            shim(Path::new(directory), Some(Signal::SIGWINCH))
        }
        [_, role, directory] if role == "--shim-initial-chld" => {
            shim(Path::new(directory), Some(Signal::SIGCHLD))
        }
        [_, role, directory] if role == "--target" => target(Path::new(directory)),
        _ => Err(io::Error::other("unknown fixed exec signal role")),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("exec advisory probe: {error}");
            std::process::ExitCode::from(125)
        }
    }
}
