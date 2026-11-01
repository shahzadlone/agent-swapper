//! A process-pending stop at the final unmask boundary must stop only once.
#![forbid(unsafe_code)]
#[allow(dead_code, reason = "this probe uses only the exclusive child waiter")]
#[path = "../src/job_control.rs"]
mod job_control;
#[allow(
    dead_code,
    reason = "exercise the exact private signal-delivery primitive"
)]
#[path = "../../../crates/agentswapper-linux-runtime/src/signals.rs"]
mod signals;
use nix::sys::{
    signal::{Signal, kill},
    wait::WaitStatus,
};
use std::{
    io,
    os::unix::process::CommandExt,
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
fn child() -> io::Result<()> {
    let signals = signals::Signals::new()?;
    // This is the process-directed copy that can arrive after suspend's last
    // drain, from the surviving owner forwarding the tty's group signal.
    kill(nix::unistd::getpid(), Signal::SIGTSTP)?;
    signals.suspend_blocked()?;
    signals.finish_after_cleanup(None)
}
fn suite() -> io::Result<()> {
    let child = Command::new(std::env::current_exe()?)
        .arg("--child")
        .env_clear()
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let mut child = job_control::OwnedChild::new(child)?;
    let until = Instant::now() + Duration::from_secs(5);
    require(
        child.next(until)? == WaitStatus::Stopped(child.pid, Signal::SIGTSTP),
        "queued stop did not suspend the original child",
    )?;
    child.resume()?;
    let final_state = loop {
        let state = child.next(until)?;
        if !matches!(state, WaitStatus::Continued(_)) {
            break state;
        }
    };
    if final_state != WaitStatus::Exited(child.pid, 7) {
        return Err(io::Error::other(format!(
            "queued stop repeated after one continuation: {final_state:?}"
        )));
    }
    println!("queued-group-stop-coalesces-before-unmask: pass");
    Ok(())
}
fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args().collect();
    let (result, code) = match args.as_slice() {
        [_] => (suite(), 0),
        [_, role] if role == "--child" => (child(), 7),
        _ => (
            Err(io::Error::other("unknown queued-stop fixture role")),
            125,
        ),
    };
    match result {
        Ok(()) => std::process::ExitCode::from(code),
        Err(error) => {
            eprintln!("queued stop probe: {error}");
            std::process::ExitCode::from(125)
        }
    }
}
