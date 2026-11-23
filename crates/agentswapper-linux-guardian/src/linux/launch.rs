//! The guardian's launch phase on the authenticated activation channel:
//! receive the client's zeroizing launch envelope, create the inner PTY,
//! spawn the installed exec-shim image under this tracer, transfer the
//! terminal slave, run nonce and envelope, hold the exec at the kernel's
//! exec trap, confirm the exec to the client, release on the client's
//! exec release, wait the direct child, and report the authenticated
//! target exit. The manager owns the scope throughout.
use agentswapper_linux_runtime::terminal;
use agentswapper_linux_runtime::{
    admission_transport as transport, launch_envelope::LaunchEnvelope, launch_protocol,
    target_exit::TargetExit,
};
use nix::sys::{
    ptrace,
    signal::Signal,
    wait::{WaitPidFlag, WaitStatus, waitpid},
};
use std::{
    io,
    os::fd::{AsFd, OwnedFd},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const LAUNCH_BUDGET: Duration = Duration::from_secs(60);

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

fn trace_stop(child: nix::unistd::Pid, deadline: Instant) -> io::Result<WaitStatus> {
    loop {
        require(
            Instant::now() < deadline,
            "the exec shim missed its tracer deadline",
        )?;
        let status = waitpid(child, Some(WaitPidFlag::__WALL))
            .map_err(|error| io::Error::other(format!("tracer wait failed: {error}")))?;
        match status {
            WaitStatus::Stopped(
                _,
                Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU,
            ) => {
                return Ok(status);
            }
            WaitStatus::StillAlive => continue,
            _ => return Ok(status),
        }
    }
}

fn wait_trap(child: nix::unistd::Pid, deadline: Instant) -> io::Result<()> {
    loop {
        require(Instant::now() < deadline, "the held exec deadline expired")?;
        let status = waitpid(child, Some(WaitPidFlag::__WALL))
            .map_err(|error| io::Error::other(format!("tracer wait failed: {error}")))?;
        match status {
            WaitStatus::PtraceEvent(_, Signal::SIGTRAP, event)
                if event == nix::libc::PTRACE_EVENT_EXEC =>
            {
                return Ok(());
            }
            WaitStatus::Stopped(
                _,
                Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU,
            ) => {
                ptrace::cont(child, None)
                    .map_err(|error| io::Error::other(format!("tracer resume failed: {error}")))?;
            }
            WaitStatus::Signaled(_, Signal::SIGKILL, _) => {
                return Err(io::Error::other("the held target was killed before exec"));
            }
            WaitStatus::StillAlive => continue,
            other => {
                return Err(io::Error::other(format!(
                    "the shim left the tracer hold: {other:?}"
                )));
            }
        }
    }
}

fn wait_exit(child: nix::unistd::Pid, deadline: Instant) -> io::Result<TargetExit> {
    loop {
        require(
            Instant::now() < deadline,
            "the target exit deadline expired",
        )?;
        let status = waitpid(child, Some(WaitPidFlag::__WALL))
            .map_err(|error| io::Error::other(format!("target wait failed: {error}")))?;
        match status {
            WaitStatus::Exited(..) | WaitStatus::Signaled(..) => {
                let raw = match &status {
                    WaitStatus::Exited(_, code) => code << 8,
                    WaitStatus::Signaled(_, signal, core) => {
                        (*signal) as i32 | if *core { 0x80 } else { 0 }
                    }
                    _ => unreachable!("matched above"),
                };
                return TargetExit::from_raw(raw)?.validate();
            }
            WaitStatus::Stopped(
                _,
                Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU,
            ) => {
                ptrace::cont(child, None)
                    .map_err(|error| io::Error::other(format!("tracer resume failed: {error}")))?;
            }
            WaitStatus::StillAlive => continue,
            other => {
                return Err(io::Error::other(format!(
                    "the target left the tracer: {other:?}"
                )));
            }
        }
    }
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
    let (control_client, control_shim) = transport::pair()?;
    let mut command = Command::new(shim_path);
    command
        .args(["exec-shim", unit])
        .stdin(Stdio::from(control_shim.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave.try_clone()?))
        .env_clear();
    let child = command.spawn()?;
    drop(control_shim);
    let pid = nix::unistd::Pid::from_raw(child.id() as i32);
    // The shim stops itself at the tracer hold before any launch data.
    let status = trace_stop(pid, deadline)?;
    require(
        matches!(status, WaitStatus::Stopped(_, Signal::SIGSTOP)),
        "the exec shim did not stop at its tracer hold",
    )?;
    ptrace::setoptions(
        pid,
        ptrace::Options::PTRACE_O_TRACEEXEC | ptrace::Options::PTRACE_O_EXITKILL,
    )
    .map_err(|error| io::Error::other(format!("tracer options failed: {error}")))?;
    ptrace::cont(pid, None)
        .map_err(|error| io::Error::other(format!("tracer resume failed: {error}")))?;
    // Transfer the terminal slave, then the client's nonce, then the
    // envelope. The shim execs only after all three arrive.
    transport::send_until(&control_client, transport::GO, &[slave.as_fd()], deadline)?;
    drop(slave);
    let nonce = launch_protocol::receive_launch_gate_open(channel, deadline)?;
    net_send(
        &control_client,
        &launch_protocol::launch_gate_packet(&nonce),
        deadline,
    )?;
    envelope.send_to_until(&control_client, deadline)?;
    // The kernel's exec trap is the only exec evidence; the shim's exit
    // code and any EOF prove nothing.
    wait_trap(pid, deadline)?;
    eprintln!("guardian: exec trapped child={}", pid);
    let child_id = child.id();
    net_send(
        channel,
        &launch_protocol::exec_event_packet(&nonce, child_id),
        deadline,
    )?;
    launch_protocol::receive_exec_release(channel, &nonce, child_id, deadline)?;
    eprintln!("guardian: exec released child={child_id}");
    // Detach rather than continue: the released target runs untraced, so its
    // own children's signals (a shell's SIGCHLD from forking a command) are
    // delivered normally instead of arriving as tracer stops. The guardian
    // remains the parent and still waits the direct child's exit.
    ptrace::detach(pid, None)
        .map_err(|error| io::Error::other(format!("release failed: {error}")))?;
    // The client owns the master for the target's lifetime: terminal bytes
    // flow between the client's outer terminal and the master while this
    // tracer waits the direct child. The client's clean disconnect and the
    // manager-owned scope retirement follow when this service exits.
    transport::send_until(channel, transport::GO, &[master.as_fd()], deadline)?;
    drop(master);
    let exit = wait_exit(pid, deadline)?;
    eprintln!("guardian: target exited {exit:?}");
    net_send(
        channel,
        &launch_protocol::exit_report_packet(&nonce, &exit)?,
        deadline,
    )?;
    // The channel's clean disconnect and the manager-owned scope retirement
    // follow when this service exits.
    Ok(())
}

fn net_send(socket: &OwnedFd, bytes: &[u8], deadline: Instant) -> io::Result<()> {
    transport::send_until(socket, bytes, &[], deadline)
}
