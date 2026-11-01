//! Hosted fixed-target PTY2 mode. All child waits belong to one owner.
use crate::{
    activated_guardian, activated_journal, admission_transport as transport,
    job_control::{self, OwnedChild},
    journal_protocol, require,
};
use nix::sys::{signal::Signal, wait::WaitStatus};
use std::{
    fs, io,
    os::{
        fd::{AsFd, OwnedFd},
        unix::process::{CommandExt, ExitStatusExt},
    },
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

fn readable(fd: &OwnedFd) -> io::Result<bool> {
    let mut watched = [rustix::event::PollFd::new(fd, rustix::event::PollFlags::IN)];
    let count = rustix::event::poll(
        &mut watched,
        Some(&rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )?;
    require(
        !watched[0]
            .revents()
            .intersects(rustix::event::PollFlags::NVAL | rustix::event::PollFlags::ERR),
        "invalid job-control channel",
    )?;
    Ok(count == 1)
}
fn hangup(slave: &OwnedFd) -> io::Result<bool> {
    // POLLHUP is reported even without requested events. Never consume input.
    let mut watched = [rustix::event::PollFd::new(
        slave,
        rustix::event::PollFlags::empty(),
    )];
    rustix::event::poll(
        &mut watched,
        Some(&rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )?;
    require(
        !watched[0]
            .revents()
            .contains(rustix::event::PollFlags::NVAL),
        "invalid retained terminal slave",
    )?;
    Ok(watched[0].revents().contains(rustix::event::PollFlags::HUP))
}

pub(crate) fn serve(
    channel: &OwnedFd,
    prefix: &str,
    directory: &Path,
    invocation: &str,
    exec_gate: bool,
) -> io::Result<()> {
    let admission_deadline = Instant::now() + Duration::from_secs(15);
    let _lease =
        activated_journal::acquire_lease(channel, directory, invocation, admission_deadline)?;
    job_control::dispositions()?;
    job_control::blocked_job_signals()?;
    let own = rustix::process::getpid();
    if rustix::process::getsid(None)? != own {
        rustix::process::setsid()?;
    }
    require(
        rustix::process::getpgrp() == own,
        "guardian is not its session group leader",
    )?;
    let stat = fs::read_to_string("/proc/self/stat")?;
    require(
        stat.rsplit_once(") ")
            .and_then(|(_, fields)| fields.split_whitespace().nth(4))
            == Some("0"),
        "guardian already has a controlling terminal",
    )?;
    let (master, slave) = crate::terminal::pair()?;
    rustix::process::ioctl_tiocsctty(&slave)?;
    require(
        rustix::termios::tcgetsid(&slave)? == own && rustix::termios::tcgetpgrp(&slave)? == own,
        "guardian did not acquire the owned terminal",
    )?;
    let (grant, input) = transport::pair()?;
    let mut command = Command::new("/proc/self/exe");
    command
        .args([
            if exec_gate {
                "--activation-exec-shim"
            } else {
                "--activation-job-shim"
            },
            prefix,
        ])
        .arg(directory)
        .env_clear()
        .process_group(0)
        .stdin(Stdio::from(input))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    activated_journal::fixture_environment(&mut command)?;
    let mut child = OwnedChild::new(command.spawn()?)?;
    drop(command);
    if exec_gate {
        child.arm_exec(admission_deadline)?;
    }
    activated_guardian::wait_until(admission_deadline, || {
        require(
            child.poll()? == WaitStatus::StillAlive,
            "gated job changed state before readiness",
        )?;
        match fs::read_to_string(directory.join("ready")) {
            Ok(pid) => {
                require(pid == child.pid.to_string(), "job readiness PID differs")?;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    })?;
    let prepared = serde_json::to_vec(&serde_json::json!({"kind": "aswp-fixture-prepared-1", "child": child.pid.as_raw(), "invocation": invocation})).map_err(io::Error::other)?;
    transport::send_until(channel, &prepared, &[master.as_fd()], admission_deadline)?;
    drop(master);
    let nonce = match journal_protocol::receive_start(channel, admission_deadline) {
        Ok(nonce) => nonce,
        Err(error) if journal_protocol::is_withdrawal(&error) => {
            require(
                child.poll()? == WaitStatus::StillAlive,
                "job died before withdrawal",
            )?;
            fs::write(directory.join("guardian-withdrawn-before-go"), invocation)?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    require(
        child.poll()? == WaitStatus::StillAlive,
        "job changed state before GO",
    )?;
    let group = rustix::process::Pid::from_raw(child.pid.as_raw())
        .ok_or_else(|| io::Error::other("invalid child group"))?;
    rustix::termios::tcsetpgrp(&slave, group)?;
    transport::send_until(&grant, transport::GO, &[slave.as_fd()], admission_deadline)?;
    transport::send_until(
        &grant,
        &journal_protocol::start_packet(&nonce),
        &[],
        admission_deadline,
    )?;
    drop(grant);
    if exec_gate {
        child.hold_exec(admission_deadline)?;
        let held = serde_json::to_vec(&serde_json::json!({
            "kind": "aswp-fixture-exec-held-1", "child": child.pid.as_raw(),
            "invocation": invocation, "nonce": journal_protocol::encoded(&nonce),
        }))
        .map_err(io::Error::other)?;
        transport::send_until(channel, &held, &[], admission_deadline)?;
        // A distinct frame is required after durable spawn observation. EOF,
        // ordinary job resume, wrong identities and deadline loss all refuse.
        journal_protocol::receive_exec_release(
            channel,
            &nonce,
            child.pid.as_raw() as u32,
            admission_deadline,
        )?;
        child.release_exec()?;
    }
    let until = Instant::now() + Duration::from_secs(55);
    let mut sequence = 0_u64;
    let mut stopped = false;
    let report_terminal = |raw: rustix::process::WaitStatus, sequence| -> io::Result<bool> {
        let status = std::process::ExitStatus::from_raw(raw.as_raw());
        let exit = if let Some(code) = status.code() {
            Some(journal_protocol::TargetExit::Code {
                code: u8::try_from(code).map_err(io::Error::other)?,
            })
        } else if let Some(signal) = status.signal() {
            Some(journal_protocol::TargetExit::Signal {
                signal: u8::try_from(signal).map_err(io::Error::other)?,
                core_dumped: status.core_dumped(),
            })
        } else {
            None
        };
        let Some(exit) = exit else {
            return Ok(false);
        };
        if exec_gate {
            report_exit(
                channel,
                invocation,
                u32::try_from(group.as_raw_pid()).map_err(io::Error::other)?,
                &nonce,
                sequence,
                exit,
                until,
            )?;
        }
        // A diagnostic write cannot suppress the authenticated terminal result.
        if let Err(error) = record_exit(directory, status.code(), status.signal()) {
            let _ = fs::write(
                directory.join("guardian-exit-record-error"),
                error.to_string(),
            );
        }
        Ok(true)
    };
    activated_guardian::wait_until(until, || {
        let raw = child.poll_raw()?;
        if let Some(raw) = raw
            && report_terminal(raw, sequence)?
        {
            return Ok(true);
        }
        if hangup(&slave)? {
            fs::write(directory.join("guardian-terminal-hangup"), invocation)?;
            return Ok(true);
        }
        // Only nonterminal stops/continuations need nix's named-signal enum.
        // Raw terminal status has already revoked numeric PID authority and
        // preserves real-time signals instead of losing a valid outcome.
        let state = raw
            .map(|raw| WaitStatus::from_raw(child.pid, raw.as_raw()))
            .transpose()?
            .unwrap_or(WaitStatus::StillAlive);
        match state {
            WaitStatus::StillAlive => {}
            WaitStatus::Stopped(_, signal) => {
                require(
                    !stopped
                        && sequence < 8
                        && matches!(
                            signal,
                            Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU
                        ),
                    "unexpected job stop",
                )?;
                sequence += 1;
                stopped = true;
                let packet = serde_json::to_vec(&serde_json::json!({"kind": "aswp-fixture-stopped-1", "child": child.pid.as_raw(),
                    "invocation": invocation, "nonce": journal_protocol::encoded(&nonce), "sequence": sequence, "signal": signal as i32})).map_err(io::Error::other)?;
                transport::send_until(
                    channel,
                    &packet,
                    &[],
                    until.min(Instant::now() + Duration::from_secs(1)),
                )?;
            }
            WaitStatus::Continued(_) => require(!stopped, "job resumed outside its control grant")?,
            _ => return Err(io::Error::other("unexpected traced job state")),
        }
        let eof = if stopped && readable(channel)? {
            match journal_protocol::receive_resume(channel, &nonce, sequence, until) {
                Ok(()) => {
                    // Hosted fault boundary: prove a terminal wait observed
                    // inside the resume path is reported, never discarded.
                    if directory.join("resume-hold").exists() {
                        fs::write(directory.join("resume-held"), "before owned wait")?;
                        activated_guardian::wait_until(
                            until.min(Instant::now() + Duration::from_secs(3)),
                            || Ok(directory.join("resume-release").exists()),
                        )?;
                    }
                    let raw = child.poll_raw()?;
                    if let Some(raw) = raw
                        && report_terminal(raw, sequence)?
                    {
                        return Ok(true);
                    }
                    require(raw.is_none(), "stopped job changed state before resume")?;
                    rustix::termios::tcsetpgrp(&slave, group)?;
                    child.resume()?;
                    stopped = false;
                    false
                }
                Err(error) if journal_protocol::is_withdrawal(&error) => true,
                Err(error) => return Err(error),
            }
        } else if stopped {
            false
        } else {
            transport::eof(channel)?
        };
        if eof {
            fs::write(directory.join("guardian-clean-eof"), invocation)?;
        }
        Ok(eof)
    })?;
    // Scope cleanup remains manager-owned; no journal completion is emitted.
    Ok(())
}

fn report_exit(
    channel: &OwnedFd,
    invocation: &str,
    child: u32,
    nonce: &[u8; 16],
    sequence: u64,
    status: journal_protocol::TargetExit,
    until: Instant,
) -> io::Result<()> {
    let status = status.validate()?;
    let packet = serde_json::to_vec(&serde_json::json!({
        "kind": "aswp-fixture-exit-1", "invocation": invocation, "child": child,
        "nonce": journal_protocol::encoded(nonce), "sequence": sequence, "status": status,
    }))
    .map_err(io::Error::other)?;
    // No PID operation follows reaping. Sending the already observed status
    // does not wait for a client acknowledgement or postpone scope cleanup.
    transport::send_until(
        channel,
        &packet,
        &[],
        until.min(Instant::now() + Duration::from_secs(1)),
    )
}

fn record_exit(directory: &Path, code: Option<i32>, signal: Option<i32>) -> io::Result<()> {
    fs::write(
        directory.join("target-exit.tmp"),
        format!("{code:?}:{signal:?}"),
    )?;
    fs::rename(
        directory.join("target-exit.tmp"),
        directory.join("target-exit"),
    )
}
