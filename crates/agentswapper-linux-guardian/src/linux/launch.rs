//! The guardian's launch phase on the authenticated activation channel:
//! receive the client's zeroizing launch envelope, take ownership of a fresh
//! session, spawn the installed exec-shim image in its own process group
//! under this tracer, and once the shim holds, bind the inner PTY as the
//! session's controlling terminal and grant the foreground to the shim's
//! group. The durable-intent-gated transfer (slave, nonce, envelope) still
//! precedes the shim's only exec path. The launch confirms the kernel's
//! exec trap to the client, releases on the client's exec release,
//! detaches, and then mediates the target's job-control lifetime: every
//! direct-child stop reaches the client as an authenticated notice, and
//! only the client's exact resume grant continues the target. The manager
//! owns the scope throughout.
use agentswapper_linux_runtime::child_waiter::ChildWaiter;
use agentswapper_linux_runtime::{
    admission_transport as transport, launch_envelope::LaunchEnvelope, launch_protocol,
    target_exit::TargetExit,
};
use agentswapper_linux_runtime::{job_control, terminal};
use nix::sys::{ptrace, signal::Signal};
use rustix::process::{Pid, WaitStatus};
use std::{
    io,
    os::fd::{AsFd, OwnedFd},
    os::unix::process::CommandExt,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

/// The admission budget: every frame through the terminal master backhaul
/// must complete within it. The target's own lifetime and each stop/resume
/// exchange are handled by bounded windows in the active phase instead: a
/// long session never inherits this deadline.
const LAUNCH_BUDGET: Duration = Duration::from_secs(60);
/// Direct-child stops are reported within one short window; a client that
/// cannot observe the notice in time ends the session honestly.
const NOTICE_WINDOW: Duration = Duration::from_secs(1);
/// Each resume-grant receive, exit-report send and manager observation gets
/// a fresh bounded window rather than any session-wide deadline.
const ACTIVE_WINDOW: Duration = Duration::from_secs(8);
const ACTIVE_POLL: Duration = Duration::from_millis(10);

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

fn net_send(socket: &OwnedFd, bytes: &[u8], deadline: Instant) -> io::Result<()> {
    transport::send_until(socket, bytes, &[], deadline)
}

/// Whether the control channel has a queued record or has closed. Never
/// consumes: the caller decides what the event means.
fn control_event(channel: &OwnedFd) -> io::Result<bool> {
    let mut ready = [rustix::event::PollFd::new(
        channel,
        rustix::event::PollFlags::IN,
    )];
    match rustix::event::poll(
        &mut ready,
        Some(&rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    ) {
        Err(rustix::io::Errno::INTR) => return Ok(false),
        value => value?,
    };
    Ok(ready[0].revents().intersects(
        rustix::event::PollFlags::IN
            | rustix::event::PollFlags::HUP
            | rustix::event::PollFlags::ERR,
    ))
}

/// Take ownership of a fresh session, before the exec-shim exists: this
/// service process becomes its session leader with no controlling
/// terminal, on default job-signal dispositions, and blocks the terminal
/// stop signals so its own terminal-change grants below cannot stop the
/// only process that mediates the session. The stop-signal mask is also
/// the spawn's inheritance witness: the shim requires it from inside (see
/// `shim.rs`). This replaces the former shim-side `setsid`: that made the
/// target's initial group ORPHANED, and a default-disposition SIGTSTP to
/// an orphaned group is discarded by the kernel, so ordinary suspension
/// could never work.
fn prepare_session() -> io::Result<()> {
    job_control::require_default_job_dispositions()?;
    let own = rustix::process::getpid();
    if rustix::process::getsid(None)? != own {
        // A group leader that is not a session leader cannot setsid: refuse
        // rather than fork around, because the authenticated service MainPID
        // must remain this guardian.
        rustix::process::setsid()?;
    }
    require(
        rustix::process::getpgrp() == own,
        "the guardian is not its session group leader",
    )?;
    // The pre-exec `comm`-terminated stat fields are state, ppid, pgrp,
    // session, tty_nr: a nonzero tty_nr means an inherited controlling
    // terminal, which this service must never have. If the setsid above
    // ran, its new session has no controlling terminal by construction; a
    // pre-existing session leader needs the check.
    let stat = std::fs::read_to_string("/proc/self/stat")?;
    let fields = stat
        .rsplit_once(") ")
        .ok_or_else(|| io::Error::other("unreadable guardian stat"))?
        .1;
    let tty_nr = fields
        .split_whitespace()
        .nth(4)
        .ok_or_else(|| io::Error::other("unreadable guardian stat"))?;
    require(
        tty_nr == "0",
        "the guardian already has a controlling terminal",
    )?;
    // A blocked stop signal is treated by the kernel's terminal-change check
    // as ignored, so the foreground grants below proceed instead of
    // stopping the session's only mediator.
    job_control::block_stop_signals()
}

/// Bind the session's controlling terminal and grant the foreground to the
/// raised exec-shim's group. This runs only once the shim's group exists
/// and holds: binding earlier would leave this guardian's own group as the
/// terminal's foreground, and any pre-handoff refusal that closed the
/// master would then hang up the guardian itself instead of a child that
/// provably cannot run past its control receive. The kernel assigns a
/// fresh controlling terminal's foreground to the session leader; the
/// grant below moves it to the shim's group before anything can read or
/// close the slave.
fn grant_session(slave: &OwnedFd, group: Pid) -> io::Result<()> {
    let own = rustix::process::getpid();
    // The safe ioctl uses argument zero: acquire an unowned terminal, never
    // steal one.
    rustix::process::ioctl_tiocsctty(slave)?;
    rustix::termios::tcsetpgrp(slave, group)?;
    require(
        rustix::termios::tcgetsid(slave)? == own && rustix::termios::tcgetpgrp(slave)? == group,
        "the guardian did not own the granted terminal",
    )
}

fn trace_stop(child: nix::unistd::Pid, deadline: Instant) -> io::Result<Signal> {
    // Poll rather than block: a stuck shim must hit the deadline, not park
    // inside the kernel past it.
    loop {
        require(
            Instant::now() < deadline,
            "the exec shim missed its tracer deadline",
        )?;
        match nix::sys::wait::waitpid(
            child,
            Some(nix::sys::wait::WaitPidFlag::__WALL | nix::sys::wait::WaitPidFlag::WNOHANG),
        ) {
            Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                thread::sleep(Duration::from_millis(5));
            }
            Ok(nix::sys::wait::WaitStatus::Stopped(_, signal)) => return Ok(signal),
            Ok(status) => {
                return Err(io::Error::other(format!(
                    "the exec shim left the tracer hold: {status:?}"
                )));
            }
            Err(nix::Error::ECHILD) => return Err(io::Error::other("the exec shim exited")),
            Err(nix::Error::EINTR) => {}
            Err(error) => return Err(io::Error::other(format!("tracer wait failed: {error}"))),
        }
    }
}

/// Nonblocking drain of the held terminal master at a refusal point. A
/// refused shim writes its diagnostic to the slave; the bytes sit in the
/// PTY buffer where the not-yet-dispatched master can still read them, so
/// the refusal reaches the journal alongside the reaper's own evidence.
fn master_residue(master: &OwnedFd) -> String {
    let saved = match rustix::fs::fcntl_getfl(master) {
        Ok(flags) => flags,
        Err(_) => return String::new(),
    };
    let _ = rustix::fs::fcntl_setfl(master, saved | rustix::fs::OFlags::NONBLOCK);
    let mut text = Vec::new();
    let mut buffer = [0_u8; 256];
    while text.len() < 1024 {
        match rustix::io::read(master, &mut buffer) {
            Ok(0) => break,
            Ok(count) => text.extend_from_slice(&buffer[..count]),
            Err(_) => break,
        }
    }
    let _ = rustix::fs::fcntl_setfl(master, saved);
    String::from_utf8_lossy(&text)
        .chars()
        .filter(|c| !c.is_control())
        .take(240)
        .collect()
}

fn wait_trap(child: nix::unistd::Pid, deadline: Instant, master: &OwnedFd) -> io::Result<()> {
    loop {
        require(Instant::now() < deadline, "the held exec deadline expired")?;
        match nix::sys::wait::waitpid(
            child,
            Some(nix::sys::wait::WaitPidFlag::__WALL | nix::sys::wait::WaitPidFlag::WNOHANG),
        ) {
            Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                thread::sleep(Duration::from_millis(5));
            }
            Ok(nix::sys::wait::WaitStatus::PtraceEvent(_, _, event))
                if event == nix::libc::PTRACE_EVENT_EXEC =>
            {
                return Ok(());
            }
            // Typeahead stop signals already queued before the held exec are
            // suppressed here so the launch protocol stays byte-exact; job
            // control proper begins with the granted, released target.
            Ok(nix::sys::wait::WaitStatus::Stopped(
                _,
                Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU,
            )) => {
                ptrace::cont(child, None)
                    .map_err(|error| io::Error::other(format!("tracer resume failed: {error}")))?;
            }
            Ok(nix::sys::wait::WaitStatus::Signaled(_, Signal::SIGKILL, _)) => {
                return Err(io::Error::other("the held target was killed before exec"));
            }
            Ok(status) => {
                let residue = master_residue(master);
                let suffix = if residue.is_empty() {
                    String::new()
                } else {
                    format!("; shim diagnostics: {residue}")
                };
                return Err(io::Error::other(format!(
                    "the shim left the tracer hold: {status:?}{suffix}"
                )));
            }
            Err(nix::Error::EINTR) => {}
            Err(error) => return Err(io::Error::other(format!("tracer wait failed: {error}"))),
        }
    }
}

/// Decode a reaped raw wait status into the pinned exit shape.
fn exit_from_raw(raw: WaitStatus) -> io::Result<TargetExit> {
    TargetExit::from_raw(raw.as_raw())?.validate()
}

/// The active phase: an unbounded session with bounded windows. Every direct
///-child stop is an authenticated notice, a resume happens only for the one
/// reported sequence after a post-grant death recheck, and a client that
/// withdraws or sends unsolicited control never gets a silent substitute.
fn active_wait(
    waiter: &mut ChildWaiter,
    session_tty: &OwnedFd,
    channel: &OwnedFd,
    nonce: &[u8; 16],
    child: u32,
) -> io::Result<()> {
    let group = Pid::from_raw(
        i32::try_from(child).map_err(|_| io::Error::other("invalid owned child PID"))?,
    )
    .ok_or_else(|| io::Error::other("invalid owned child PID"))?;
    let mut sequence: u64 = 0;
    // Exactly one continuation is authorized per accepted resume grant;
    // anything else is a witness of unsolicited resumption.
    let mut resume_granted = false;
    let exit: Option<WaitStatus> = 'session: loop {
        // Unsolicited control while the target runs: the client owns the
        // channel and sends nothing until it has a notice to answer or an
        // exit to observe. The resume-acceptance loop below owns the only
        // window in which control data is expected.
        if control_event(channel)? {
            return if launch_protocol::peer_withdrew(channel, Instant::now() + ACTIVE_WINDOW)? {
                Err(io::Error::other(
                    "the launch client withdrew while the target ran",
                ))
            } else {
                Err(io::Error::other(
                    "unsolicited client control data while the target ran",
                ))
            };
        }
        let Some(raw) = waiter.poll()? else {
            thread::sleep(ACTIVE_POLL);
            continue;
        };
        if raw.exited() || raw.signaled() {
            break Some(raw);
        }
        if raw.continued() {
            // The waiter polls WCONTINUED, so the guardian's own authorized
            // SIGCONT reports here; exactly that one continuation is
            // consumable, and only against the grant that caused it.
            require(
                resume_granted,
                "the target was resumed outside its control grant",
            )?;
            resume_granted = false;
            continue;
        }
        if raw.stopped() {
            let signal = raw
                .stopping_signal()
                .and_then(|signal| Signal::try_from(signal).ok())
                .ok_or_else(|| io::Error::other("unreadable job stop"))?;
            require(
                sequence < launch_protocol::MAX_STOP_SEQUENCE
                    && matches!(
                        signal,
                        Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU
                    ),
                "unexpected job stop",
            )?;
            sequence += 1;
            net_send(
                channel,
                &launch_protocol::stop_notice_packet(nonce, child, signal as u16, sequence),
                Instant::now() + NOTICE_WINDOW,
            )?;
            // Resume acceptance: the grant belongs to exactly this
            // sequence, and death while stopped is an honest exit, not a
            // fault.
            loop {
                match waiter.poll() {
                    Ok(Some(raw)) if raw.exited() || raw.signaled() => break 'session Some(raw),
                    Ok(Some(raw)) if raw.continued() => {
                        return Err(io::Error::other(
                            "the target was resumed outside its control grant",
                        ));
                    }
                    Ok(Some(raw)) if raw.stopped() => {
                        return Err(io::Error::other(
                            "the stopped target reported a second job stop",
                        ));
                    }
                    Ok(Some(raw)) => {
                        return Err(io::Error::other(format!(
                            "unexpected traced job state: {raw:?}"
                        )));
                    }
                    Ok(None) => {}
                    Err(error) => return Err(error),
                }
                if control_event(channel)? {
                    match launch_protocol::receive_resume_grant(
                        channel,
                        nonce,
                        sequence,
                        Instant::now() + ACTIVE_WINDOW,
                    ) {
                        Ok(()) => {
                            // The grant is evidence, never authority to
                            // signal a dead identity: one post-grant poll
                            // precedes the foreground grant and SIGCONT.
                            if let Some(raw) = waiter.poll()? {
                                if raw.exited() || raw.signaled() {
                                    break 'session Some(raw);
                                }
                                return Err(io::Error::other(
                                    "the stopped target changed state before resume",
                                ));
                            }
                            rustix::termios::tcsetpgrp(session_tty, group)?;
                            require(
                                !waiter.is_reaped()
                                    && rustix::process::getpgid(Some(group))? == group,
                                "the target's group is gone or was recycled",
                            )?;
                            rustix::process::kill_process_group(
                                group,
                                rustix::process::Signal::CONT,
                            )
                            .map_err(|error| io::Error::other(format!("resume failed: {error}")))?;
                            resume_granted = true;
                            break;
                        }
                        Err(error) if launch_protocol::is_withdrawal(&error) => {
                            return Err(io::Error::other(
                                "the launch client withdrew while the target was stopped",
                            ));
                        }
                        Err(error) => return Err(error),
                    }
                }
                thread::sleep(ACTIVE_POLL);
            }
            continue;
        }
        return Err(io::Error::other(format!(
            "unexpected traced job state: {raw:?}"
        )));
    };
    let exit = match exit {
        Some(raw) => exit_from_raw(raw)?,
        None => unreachable!("the loop only breaks with a terminal status"),
    };
    eprintln!("guardian: target exited {exit:?}");
    net_send(
        channel,
        &launch_protocol::exit_report_packet(nonce, &exit)?,
        Instant::now() + ACTIVE_WINDOW,
    )?;
    Ok(())
}

/// Run one launch on the authenticated channel. `unit` is the guardian's
/// own unit name, `shim_path` the installed exec-shim image.
pub fn serve(channel: &OwnedFd, unit: &str, invocation: &str, shim_path: &Path) -> io::Result<()> {
    require(
        !invocation.is_empty(),
        "launch requires the service invocation",
    )?;
    let deadline = Instant::now() + LAUNCH_BUDGET;
    // The client's launch data travels only over the authenticated
    // connection, never in helper argv or the helper environment.
    let envelope = LaunchEnvelope::receive_from_until(channel, deadline)?;
    eprintln!("guardian: envelope received");
    let (master, slave) = terminal::pair()?;
    // The guardian keeps one slave descriptor for the whole session: the
    // foreground re-grants at resume need a terminal descriptor, and the
    // session's controlling-terminal binding stays observable until this
    // service exits.
    let session_tty = slave.try_clone()?;
    // The session is taken before the spawn so the shim inherits the
    // blocked stop-signal mask as its spawn witness; the terminal binding
    // and foreground grant come only after the shim's group holds.
    prepare_session()?;
    let (control_client, control_shim) = transport::pair()?;
    let mut command = Command::new(shim_path);
    command
        .args(["exec-shim", unit])
        .stdin(Stdio::from(control_shim.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave.try_clone()?))
        // The shim's group exists before its first instruction runs, so it
        // can verify - never configure - its own group from inside.
        .process_group(0)
        .env_clear();
    let child = command.spawn()?;
    drop(control_shim);
    let pid = nix::unistd::Pid::from_raw(child.id() as i32);
    // The same identity in the terminal/process-group vocabulary.
    let group = Pid::from_raw(child.id() as i32)
        .ok_or_else(|| io::Error::other("invalid owned child PID"))?;
    // The shim stops itself at the tracer hold before any launch data.
    let stopped = trace_stop(pid, deadline)?;
    require(
        stopped == Signal::SIGSTOP,
        "the exec shim did not stop at its tracer hold",
    )?;
    require(
        rustix::process::getpgid(Some(group))? == group,
        "the exec shim did not take its own group",
    )?;
    ptrace::setoptions(
        pid,
        ptrace::Options::PTRACE_O_TRACEEXEC | ptrace::Options::PTRACE_O_EXITKILL,
    )
    .map_err(|error| io::Error::other(format!("tracer options failed: {error}")))?;
    ptrace::cont(pid, None)
        .map_err(|error| io::Error::other(format!("tracer resume failed: {error}")))?;
    // The shim's group exists, so the terminal binding and the foreground
    // grant can never leave the guardian's own group as the terminal's
    // foreground. The trusted shim still holds inside its control receive:
    // it reads nothing and cannot run until the durable-intent-gated
    // transfer below, so the grant stays inert until the launch data
    // proves the launch. (Its stdio slave descriptors are open but
    // untouched: the control receive comes first.)
    grant_session(&slave, group)?;
    // The durable run intent arrives before the slave transfer: the shim
    // execs only after the nonce and the envelope follow this gate.
    let nonce = launch_protocol::receive_launch_gate_open(channel, deadline)?;
    eprintln!("guardian: run gate received");
    transport::send_until(&control_client, transport::GO, &[slave.as_fd()], deadline)?;
    eprintln!("guardian: slave transferred");
    drop(slave);
    net_send(
        &control_client,
        &launch_protocol::launch_gate_packet(&nonce),
        deadline,
    )?;
    envelope.send_to_until(&control_client, deadline)?;
    eprintln!("guardian: envelope transferred");
    // The kernel's exec trap is the only exec evidence; the shim's exit
    // code and any EOF prove nothing.
    eprintln!("guardian: awaiting exec trap");
    wait_trap(pid, deadline, &master)?;
    eprintln!("guardian: exec trapped child={}", pid);
    let child_id = child.id();
    net_send(
        channel,
        &launch_protocol::exec_event_packet(&nonce, child_id),
        deadline,
    )?;
    eprintln!("guardian: exec event sent");
    launch_protocol::receive_exec_release(channel, &nonce, child_id, deadline)?;
    eprintln!("guardian: exec released child={child_id}");
    // Detach rather than continue: the released target runs untraced, so its
    // own children's signals (a shell's SIGCHLD from forking a command) are
    // delivered normally instead of arriving as tracer stops. The guardian
    // remains the parent and still owns the direct child's only wait path.
    ptrace::detach(pid, None)
        .map_err(|error| io::Error::other(format!("release failed: {error}")))?;
    // The client owns the master for the target's lifetime: terminal bytes
    // flow between the client's outer terminal and the master while this
    // guardian mediates the session's job control.
    transport::send_until(channel, transport::GO, &[master.as_fd()], deadline)?;
    drop(master);
    let mut waiter = ChildWaiter::new(child)?;
    active_wait(&mut waiter, &session_tty, channel, &nonce, child_id)?;
    // The channel's clean disconnect and the manager-owned scope retirement
    // follow when this service exits.
    Ok(())
}
