//! Fixed, provider-free inner-session experiment. Never touches the caller's TTY.
//! The guardian owns the session; its direct child owns the foreground group.
#![forbid(unsafe_code)]
#[path = "../src/job_control.rs"]
mod job_control;
#[path = "../src/terminal.rs"]
mod terminal;
use agentswapper_linux_runtime::admission_transport as transport;
use job_control::{JOB_SIGNALS, OwnedChild, blocked_job_signals, dispositions, target_signals};

use nix::sys::{
    signal::{SigSet, SigmaskHow, Signal, pthread_sigmask},
    wait::WaitStatus,
};
use std::{
    fs,
    io::{self, Write},
    os::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        unix::process::CommandExt,
    },
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn pending_pre_go_input() -> io::Result<()> {
    let expected = (1_u64 << (Signal::SIGINT as u32 - 1)) | (1_u64 << (Signal::SIGTSTP as u32 - 1));
    let until = deadline();
    loop {
        let status = fs::read_to_string("/proc/self/status")?;
        let mut pending = 0;
        for field in ["SigPnd:", "ShdPnd:"] {
            let value = status
                .lines()
                .find_map(|line| line.strip_prefix(field))
                .ok_or_else(|| io::Error::other("missing pending-signal witness"))?;
            pending |= u64::from_str_radix(value.trim(), 16).map_err(io::Error::other)?;
        }
        if pending & expected == expected {
            return Ok(());
        }
        require(
            Instant::now() < until,
            "pre-GO terminal input did not reach guardian",
        )?;
        thread::sleep(Duration::from_millis(5));
    }
}
fn parent_gate() -> io::Result<OwnedFd> {
    let gate = io::stdin().as_fd().try_clone_to_owned()?;
    let peer = nix::sys::socket::getsockopt(&gate, nix::sys::socket::sockopt::PeerCredentials)?;
    require(
        rustix::net::sockopt::socket_type(&gate)? == rustix::net::SocketType::SEQPACKET
            && peer.pid() == nix::unistd::getppid().as_raw()
            && peer.uid() == rustix::process::getuid().as_raw(),
        "private gate has wrong parent",
    )?;
    // Fixed fixture cleanup only, not descendant containment. Close the race
    // with parent death before registration; no arbitrary program is executed.
    nix::sys::prctl::set_pdeathsig(Signal::SIGKILL)?;
    require(
        peer.pid() == nix::unistd::getppid().as_raw(),
        "parent died during registration",
    )?;
    Ok(gate)
}
fn send(gate: &OwnedFd, packet: &[u8]) -> io::Result<()> {
    transport::send_until(gate, packet, &[], deadline())
}
fn receive(gate: &OwnedFd, packet: &[u8]) -> io::Result<()> {
    transport::receive_control_until(gate, packet, deadline())
}

fn guardian(directory: &Path) -> io::Result<()> {
    dispositions()?;
    let control = parent_gate()?;
    // The guardian must survive terminal input directed to its group before
    // GO and tcsetpgrp while it is in the background. This fresh process has
    // no other threads; the child explicitly clears the inherited mask.
    blocked_job_signals()?;
    let own = rustix::process::getpid();
    if rustix::process::getsid(None)? != own {
        rustix::process::setsid()?;
    }
    let (master, slave) = terminal::pair()?;
    rustix::process::ioctl_tiocsctty(&slave)?;
    rustix::termios::tcsetpgrp(&slave, own)?;
    let (grant, input) = transport::pair()?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("--shim")
        .arg(directory)
        .env_clear()
        .process_group(0)
        .stdin(Stdio::from(input))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = OwnedChild::new(command.spawn()?)?;
    drop(command);
    receive(&grant, b"GATED")?;
    transport::send_until(&control, transport::GO, &[master.as_fd()], deadline())?;
    drop(master);
    receive(&control, b"CHECK-INPUT")?;
    pending_pre_go_input()?;
    send(&control, b"INPUT-PENDING")?;
    receive(&control, b"GO")?;
    let group = rustix::process::Pid::from_raw(child.pid.as_raw())
        .ok_or_else(|| io::Error::other("invalid child group"))?;
    rustix::termios::tcsetpgrp(&slave, group)?;
    transport::send_until(&grant, transport::GO, &[slave.as_fd()], deadline())?;
    send(&grant, b"GO")?;
    drop(grant);

    for (signal, barrier) in [
        (Signal::SIGTSTP, None),
        (Signal::SIGTTIN, Some("read-background")),
        (Signal::SIGTTOU, Some("write-background")),
    ] {
        if let Some(barrier) = barrier {
            receive(&control, b"BACKGROUND")?;
            rustix::termios::tcsetpgrp(&slave, own)?;
            fs::write(directory.join(barrier), "ready")?;
        }
        require(
            child.next(deadline())? == WaitStatus::Stopped(child.pid, signal),
            "terminal did not produce the expected job-control stop",
        )?;
        send(&control, format!("STOP:{}", signal as i32).as_bytes())?;
        receive(&control, b"RESUME")?;
        rustix::termios::tcsetpgrp(&slave, group)?;
        child.resume()?;
        require(
            child.next(deadline())? == WaitStatus::Continued(child.pid),
            "child did not report continuation",
        )?;
        send(&control, b"CONTINUED")?;
    }
    require(
        child.next(deadline())? == WaitStatus::Signaled(child.pid, Signal::SIGINT, false),
        "foreground interrupt did not terminate target",
    )?;
    require(
        child.resume().is_err(),
        "group operation accepted after reap",
    )?;
    send(&control, b"INTERRUPTED")?;
    Ok(())
}

fn shim(directory: &Path) -> io::Result<()> {
    dispositions()?;
    let gate = parent_gate()?;
    let mask = SigSet::thread_get_mask()?;
    require(
        JOB_SIGNALS.into_iter().all(|signal| mask.contains(signal)),
        "gated shim did not inherit the guardian mask",
    )?;
    send(&gate, b"GATED")?;
    let slave = transport::receive_until(&gate, deadline())?;
    receive(&gate, b"GO")?;
    terminal::validate_slave(&slave)?;
    require(
        rustix::process::getsid(None)?
            == rustix::process::getppid().ok_or_else(|| io::Error::other("guardian absent"))?
            && rustix::process::getpgrp() == rustix::process::getpid()
            && rustix::termios::tcgetpgrp(&slave)? == rustix::process::getpid(),
        "shim is outside its guardian session or foreground group",
    )?;
    fuxix::io::cloexec_from(3, fuxix::io::Listed::now()).map_err(io::Error::from)?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("--target")
        .arg(directory)
        .env_clear()
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave));
    // Pinned std CommandExt::exec inherits the mask. Do not rely on an
    // implicit reset, and do not unblock until the foreground grant exists.
    pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&SigSet::empty()), None)?;
    Err(command.exec())
}

fn wait_file(path: &Path) -> io::Result<()> {
    let until = deadline();
    while !path.try_exists()? {
        require(Instant::now() < until, "background barrier expired")?;
        thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}
fn line(input: BorrowedFd<'_>) -> io::Result<Vec<u8>> {
    let until = deadline();
    let mut result = Vec::new();
    while result.len() < 128 && Instant::now() < until {
        let timeout = rustix::event::Timespec::try_from(Duration::from_millis(100))
            .map_err(io::Error::other)?;
        let mut poll = [rustix::event::PollFd::new(
            &input,
            rustix::event::PollFlags::IN,
        )];
        match rustix::event::poll(&mut poll, Some(&timeout)) {
            Ok(0) | Err(rustix::io::Errno::INTR) => continue,
            Ok(_) => {}
            Err(error) => return Err(error.into()),
        }
        let mut byte = [0];
        match rustix::io::read(input, &mut byte) {
            Ok(1) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Ok(_) => return Err(io::Error::other("target input ended")),
            Err(error) => return Err(error.into()),
        }
        if byte[0] == b'\n' {
            return Ok(result);
        }
        result.push(byte[0]);
    }
    Err(io::Error::other("target input expired or exceeded bounds"))
}
fn target(directory: &Path) -> io::Result<()> {
    target_signals()?;
    let own = rustix::process::getpid();
    let guardian = rustix::process::getppid().ok_or_else(|| io::Error::other("guardian absent"))?;
    require(
        rustix::process::getsid(None)? == guardian
            && rustix::process::getpgrp() == own
            && rustix::termios::tcgetsid(io::stdin())? == guardian
            && rustix::termios::tcgetpgrp(io::stdin())? == own,
        "target session topology differs",
    )?;
    let descriptors = fs::read_dir("/proc/self/fd")?.count();
    require(descriptors == 4, "target inherited non-stdio descriptors")?;
    fs::write(
        directory.join("target"),
        format!("{}:{}", guardian.as_raw_pid(), own.as_raw_pid()),
    )?;
    let mut output = io::stdout().lock();
    output.write_all(b"READY\n")?;
    output.flush()?;
    require(
        line(io::stdin().as_fd())? == b"ping",
        "post-suspend input differs",
    )?;
    output.write_all(b"PONG\n")?;
    output.flush()?;
    require(
        line(io::stdin().as_fd())? == b"background",
        "background command differs",
    )?;
    output.write_all(b"READ>\n")?;
    output.flush()?;
    wait_file(&directory.join("read-background"))?;
    // A real read, not a synthesized SIGTTIN. Queued input makes poll ready.
    require(
        line(io::stdin().as_fd())? == b"ping",
        "post-background read differs",
    )?;
    output.write_all(b"READ-OK\n")?;
    output.flush()?;
    require(
        line(io::stdin().as_fd())? == b"write-background",
        "background write command differs",
    )?;
    let saved = rustix::termios::tcgetattr(io::stdin())?;
    let mut stop_output = saved.clone();
    stop_output
        .local_modes
        .insert(rustix::termios::LocalModes::TOSTOP);
    rustix::termios::tcsetattr(
        io::stdin(),
        rustix::termios::OptionalActions::Now,
        &stop_output,
    )?;
    output.write_all(b"WRITE>\n")?;
    output.flush()?;
    wait_file(&directory.join("write-background"))?;
    output.write_all(b"WRITE-OK\n")?;
    output.flush()?;
    rustix::termios::tcsetattr(io::stdin(), rustix::termios::OptionalActions::Now, &saved)?;
    output.write_all(b"INTERRUPT>\n")?;
    output.flush()?;
    let _ = line(io::stdin().as_fd())?;
    Err(io::Error::other("target survived foreground interrupt"))
}

fn output(master: &OwnedFd, suffix: &[u8]) -> io::Result<Vec<u8>> {
    let until = deadline();
    let mut bytes = Vec::new();
    while Instant::now() < until && bytes.len() < 4096 {
        let mut chunk = [0_u8; 512];
        match rustix::io::read(master, &mut chunk) {
            Ok(n) if n > 0 => bytes.extend_from_slice(&chunk[..n]),
            Err(rustix::io::Errno::AGAIN) => thread::sleep(Duration::from_millis(5)),
            Ok(_) => return Err(io::Error::other("terminal ended before expected output")),
            Err(error) => return Err(error.into()),
        }
        if bytes.ends_with(suffix) {
            return Ok(bytes);
        }
    }
    Err(io::Error::other(format!(
        "terminal output expired; observed {:?}",
        String::from_utf8_lossy(&bytes)
    )))
}
fn input(master: &OwnedFd, bytes: &[u8]) -> io::Result<()> {
    require(
        rustix::io::write(master, bytes)? == bytes.len(),
        "short fixed terminal input",
    )
}
fn controller() -> io::Result<()> {
    dispositions()?;
    let directory = tempfile::tempdir()?;
    let (control, input_gate) = transport::pair()?;
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("--guardian")
        .arg(directory.path())
        .env_clear()
        .stdin(Stdio::from(input_gate))
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let mut guardian = OwnedChild::new(command.spawn()?)?;
    drop(command);
    let master = transport::receive_until(&control, deadline())?;
    terminal::validate_master(&master)?;
    let guardian_pid = rustix::process::Pid::from_raw(guardian.pid.as_raw())
        .ok_or_else(|| io::Error::other("invalid guardian PID"))?;
    require(
        rustix::termios::tcgetsid(&master)? == guardian_pid,
        "guardian does not own inner session",
    )?;
    require(
        !directory.path().join("target").try_exists()?,
        "target executed before GO",
    )?;
    // Pre-GO job-control input targets the blocked guardian group. Flush it
    // explicitly for this fixed test; this is not a production typeahead rule.
    input(&master, &[3, 26])?;
    send(&control, b"CHECK-INPUT")?;
    receive(&control, b"INPUT-PENDING")?;
    rustix::termios::tcflush(&master, rustix::termios::QueueSelector::IOFlush)?;
    send(&control, b"GO")?;
    output(&master, b"READY\r\n")?;
    input(&master, &[26])?;
    receive(&control, b"STOP:20")?;
    send(&control, b"RESUME")?;
    receive(&control, b"CONTINUED")?;
    input(&master, b"ping\n")?;
    output(&master, b"PONG\r\n")?;
    input(&master, b"background\n")?;
    output(&master, b"READ>\r\n")?;
    input(&master, b"ping\n")?;
    send(&control, b"BACKGROUND")?;
    receive(&control, b"STOP:21")?;
    send(&control, b"RESUME")?;
    receive(&control, b"CONTINUED")?;
    output(&master, b"READ-OK\r\n")?;
    input(&master, b"write-background\n")?;
    output(&master, b"WRITE>\r\n")?;
    send(&control, b"BACKGROUND")?;
    receive(&control, b"STOP:22")?;
    send(&control, b"RESUME")?;
    receive(&control, b"CONTINUED")?;
    output(&master, b"INTERRUPT>\r\n")?;
    input(&master, &[3])?;
    receive(&control, b"INTERRUPTED")?;
    require(
        guardian.next(deadline())? == WaitStatus::Exited(guardian.pid, 0),
        "guardian did not finish",
    )?;
    let until = deadline();
    loop {
        let mut bytes = [0; 128];
        match rustix::io::read(&master, &mut bytes) {
            Err(rustix::io::Errno::IO) => break,
            Ok(_) | Err(rustix::io::Errno::AGAIN) => {
                require(
                    Instant::now() < until,
                    "slave remains open after guardian exit",
                )?;
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error.into()),
        }
    }
    require(
        rustix::termios::tcgetsid(&master) == Err(rustix::io::Errno::NOTTY),
        "inner session remains",
    )?;
    println!(
        "::notice::guardian-owned session: terminal SIGTSTP, background-read SIGTTIN and TOSTOP SIGTTOU observed and resumed; foreground SIGINT and descriptor retirement passed; no outer relay or custody claim"
    );
    Ok(())
}
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    let result = match args.as_slice() {
        [_] => controller(),
        [_, role, directory] if role == "--guardian" => guardian(Path::new(directory)),
        [_, role, directory] if role == "--shim" => shim(Path::new(directory)),
        [_, role, directory] if role == "--target" => target(Path::new(directory)),
        _ => Err(io::Error::other("unknown fixed terminal role")),
    };
    if let Err(error) = result {
        eprintln!("terminal job-control experiment: {error}");
        std::process::exit(125);
    }
}
