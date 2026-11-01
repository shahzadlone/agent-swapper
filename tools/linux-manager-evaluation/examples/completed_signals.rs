//! Completed-job signal policy in fresh, exclusively owned child processes.
#![forbid(unsafe_code)]
#[allow(dead_code, reason = "this probe only uses the exclusive child waiter")]
#[path = "../src/job_control.rs"]
mod job_control;
use agentswapper_linux_runtime::signals::Signals;
use nix::sys::{
    signal::{Signal, raise},
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

fn child(mode: &str) -> io::Result<()> {
    let signals = Signals::new()?;
    raise(Signal::SIGTSTP)?;
    if mode != "stop" {
        raise(Signal::SIGTERM)?;
    }
    signals.finish_after_cleanup(if mode == "explicit" {
        Some(Signal::SIGINT)
    } else {
        None
    })
}
fn suite() -> io::Result<()> {
    for mode in ["stop", "fatal", "explicit"] {
        let child = Command::new(std::env::current_exe()?)
            .args(["--child", mode])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()?;
        let mut child = job_control::OwnedChild::new(child)?;
        let state = child.next(Instant::now() + Duration::from_secs(3))?;
        let expected = match mode {
            "stop" => WaitStatus::Exited(child.pid, 7),
            "fatal" => WaitStatus::Signaled(child.pid, Signal::SIGTERM, false),
            _ => WaitStatus::Signaled(child.pid, Signal::SIGINT, false),
        };
        if state != expected {
            return Err(io::Error::other(format!(
                "completed {mode}: {state:?}, expected {expected:?}"
            )));
        }
        println!("completed-signals-{mode}: pass");
    }
    Ok(())
}
fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args().collect();
    let (result, code) = match args.as_slice() {
        [_] => (suite(), 0),
        [_, role, mode]
            if role == "--child" && matches!(mode.as_str(), "stop" | "fatal" | "explicit") =>
        {
            (child(mode), 7)
        }
        _ => (
            Err(io::Error::other("unknown completed-signal fixture role")),
            125,
        ),
    };
    match result {
        Ok(()) => std::process::ExitCode::from(code),
        Err(error) => {
            eprintln!("completed signal probe: {error}");
            std::process::ExitCode::from(125)
        }
    }
}
