//! Signal-delivery stops before exec, using the actual guardian child owner.
#![forbid(unsafe_code)]
#[allow(
    dead_code,
    reason = "this probe uses only the exclusive exec child owner"
)]
#[path = "../src/job_control.rs"]
mod job_control;
#[allow(dead_code, reason = "this probe uses the actual journal start gate")]
#[path = "../src/journal_protocol.rs"]
mod journal_protocol;

use admission_transport as transport;
use agentswapper_linux_runtime::admission_transport;
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
fn shim(directory: &Path, initial: Option<Signal>, start_gate: bool) -> io::Result<()> {
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
    if start_gate {
        transport::send_until(&input, b"START-READY", &[], until)?;
        require(
            journal_protocol::receive_start(&input, until)? == [0x63; 16],
            "interrupted start gate changed the nonce",
        )?;
        require(
            !rustix::net::sockopt::socket_passcred(&input)?,
            "interrupted start gate changed credential mode",
        )?;
    }
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
    for (signal, benign, phase) in [
        (Signal::SIGWINCH, true, "initial"),
        (Signal::SIGCHLD, true, "initial"),
        (Signal::SIGWINCH, true, "armed"),
        (Signal::SIGCHLD, true, "armed"),
        (Signal::SIGWINCH, true, "start"),
        (Signal::SIGCHLD, true, "start"),
        (Signal::SIGINT, false, "armed"),
        (Signal::SIGTERM, false, "armed"),
        (Signal::SIGTSTP, false, "armed"),
        (Signal::SIGSTOP, false, "armed"),
        (Signal::SIGTRAP, false, "armed"),
    ] {
        let directory = tempfile::tempdir()?;
        let (control, input) = transport::pair()?;
        let mut command = Command::new(std::env::current_exe()?);
        command
            .arg(match (phase, signal) {
                ("initial", Signal::SIGWINCH) => "--shim-initial-winch",
                ("initial", Signal::SIGCHLD) => "--shim-initial-chld",
                ("start", _) => "--shim-start",
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
        if phase == "start" {
            transport::send_until(&control, transport::GO, &[], until)?;
            transport::receive_control_until(&control, b"START-READY", until)?;
        }
        if phase != "initial" {
            // The shim's only blocking operation after READY is the timed
            // receive. Observe it sleeping before interrupting, so the probe
            // exercises EINTR rather than only an earlier delivery stop.
            wait_state(child.pid, 'S', until)?;
            rustix::process::pidfd_send_signal(
                &handle,
                rustix::process::Signal::from_named_raw(signal as i32)
                    .ok_or_else(|| io::Error::other("unknown fixed signal"))?,
            )?;
            // Do not consume a wait status outside the sole owner. The trace stop
            // must exist before GO, preventing a timing-only advisory signal test.
            wait_state(child.pid, 't', until)?;
        }
        require(
            !directory.path().join("executed").exists(),
            "target ran before GO",
        )?;
        if phase == "start" {
            transport::send_until(
                &control,
                &journal_protocol::start_packet(&[0x63; 16]),
                &[],
                until,
            )?;
        } else {
            transport::send_until(&control, transport::GO, &[], until)?;
        }
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
        println!("exec-advisory-{signal}-{phase}: pass");
    }
    println!(
        "::notice::pre-exec signal policy: six advisory stops continued to held exec, five termination/stop/trap signals withheld execution; all original child handles retired"
    );
    Ok(())
}
fn wait_state(pid: nix::unistd::Pid, expected: char, until: Instant) -> io::Result<()> {
    loop {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        if stat
            .rsplit_once(") ")
            .is_some_and(|(_, fields)| fields.starts_with(&format!("{expected} ")))
        {
            return Ok(());
        }
        require(
            Instant::now() < until,
            "shim did not reach expected kernel state",
        )?;
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args_os().collect();
    let result = match args.as_slice() {
        [_] => suite(),
        [_, role, directory] if role == "--shim" => shim(Path::new(directory), None, false),
        [_, role, directory] if role == "--shim-start" => shim(Path::new(directory), None, true),
        [_, role, directory] if role == "--shim-initial-winch" => {
            shim(Path::new(directory), Some(Signal::SIGWINCH), false)
        }
        [_, role, directory] if role == "--shim-initial-chld" => {
            shim(Path::new(directory), Some(Signal::SIGCHLD), false)
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
