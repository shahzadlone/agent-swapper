//! Surviving parent for fixed owned-terminal qualification executables.
use crate::{
    job_control,
    outer_terminal::{Signals, Terminal, require},
};
use nix::sys::wait::WaitStatus;
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    process::{Pid, PidfdFlags, pidfd_open},
};
use std::{
    fs, io,
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

pub(crate) fn run(directory: &Path, managed: bool) -> io::Result<()> {
    let signals = Signals::new()?;
    // Declared before child: error unwinding kills/reaps the fixed child before
    // this guard restores modes, then restores the parent's signal mask.
    let mut terminal = Owner(Terminal::capture(directory)?);
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg(if managed { "--owned-child" } else { "--child" })
        .arg(directory)
        .arg(std::process::id().to_string())
        .env_clear()
        .env("ASWP_OWNED_OUTER_PTY", "1");
    if managed {
        for key in [
            "GITHUB_ACTIONS",
            "RUNNER_ENVIRONMENT",
            "ASWP_CI_SOCKET_ACTIVATION",
            "GITHUB_RUN_ID",
            "GITHUB_RUN_ATTEMPT",
            "ASWP_ACTIVATION_PREFIX",
            "ASWP_CI_ACTIVATED_JOURNAL",
        ] {
            command.env(
                key,
                std::env::var_os(key)
                    .ok_or_else(|| io::Error::other("missing hosted owner fixture environment"))?,
            );
        }
    }
    let mut child = job_control::OwnedChild::new(command.spawn()?)?;
    drop(command);
    let child_pid =
        Pid::from_raw(child.pid.as_raw()).ok_or_else(|| io::Error::other("invalid child PID"))?;
    let child_fd = pidfd_open(child_pid, PidfdFlags::empty())?;
    let until = Instant::now() + Duration::from_secs(if managed { 55 } else { 15 });
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
            let mut value = serde_json::json!({"pid":std::process::id(),
                "group":terminal.0.group.as_raw_pid(), "session":rustix::process::getsid(None)?.as_raw_pid(),
                "child":child.pid.as_raw()});
            if managed {
                let details: serde_json::Value =
                    serde_json::from_slice(&fs::read(directory.join("session-ready"))?)
                        .map_err(io::Error::other)?;
                require(
                    details["pid"].as_i64() == Some(child.pid.as_raw() as i64)
                        && details["group"].as_u64() == Some(u64::from(std::process::id())),
                    "managed child terminal topology differs",
                )?;
                for key in ["target", "guardian"] {
                    require(
                        details[key]
                            .as_u64()
                            .is_some_and(|pid| (2..=u32::MAX as u64).contains(&pid)),
                        "invalid managed fixture PID metadata",
                    )?;
                    value[key] = details[key].clone();
                }
                require(
                    details["invocation"].as_str().is_some_and(|text| {
                        text.len() == 32 && text.bytes().all(|b| b.is_ascii_hexdigit())
                    }),
                    "invalid managed fixture invocation metadata",
                )?;
                value["invocation"] = details["invocation"].clone();
            }
            marker(directory, "ready", &value.to_string())?;
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
    let mut watched = [PollFd::new(&terminal.0.fd, PollFlags::empty())];
    poll(
        &mut watched,
        Some(&Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )?;
    if watched[0].revents().contains(PollFlags::HUP) {
        marker(
            directory,
            "owner-restoration-unavailable",
            "owned outer terminal disconnected",
        )?;
    } else if terminal.0.foreground()? {
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
