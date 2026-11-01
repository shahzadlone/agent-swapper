//! Fixed cooperating writer for the real-lease/journal qualification only.
use crate::{activated_guardian, admission_transport as transport, journal_protocol, require};
use std::{
    fs::{self, File},
    io,
    os::{
        fd::{AsFd, OwnedFd},
        unix::fs::{DirBuilderExt, MetadataExt},
    },
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(crate) fn serve(
    channel: &OwnedFd,
    prefix: &str,
    directory: &Path,
    invocation: &str,
    terminal_requested: bool,
) -> io::Result<()> {
    require(
        !rustix::net::sockopt::socket_passcred(channel)?,
        "descriptor channel must not request credentials",
    )?;
    require(
        !rustix::fs::fcntl_getfl(channel)?.contains(rustix::fs::OFlags::NONBLOCK),
        "lease channel must be blocking",
    )?;
    let deadline = Instant::now() + Duration::from_secs(15);
    // ASWP-GO-1 is the existing descriptor envelope, not the start grant.
    let lease = File::from(transport::receive_until(channel, deadline)?);
    let meta = lease.metadata()?;
    if !(meta.is_file()
        && meta.uid() == rustix::process::getuid().as_raw()
        && meta.mode() & 0o7777 == 0o600
        && meta.nlink() == 1)
    {
        refused_lease(directory, invocation, "metadata")?;
        return Err(io::Error::other("invalid fixture profile lease"));
    }
    match lease.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            refused_lease(directory, invocation, "locked")?;
            return Err(io::Error::other(
                "fixture lease is locked by another open-file description",
            ));
        }
        Err(std::fs::TryLockError::Error(error)) => return Err(error),
    }
    fs::DirBuilder::new().mode(0o700).create(directory)?;
    let terminal = if terminal_requested {
        Some(crate::terminal::pair()?)
    } else {
        None
    };
    let (grant, child_input) = transport::pair()?;
    let mut command = Command::new("/proc/self/exe");
    command
        .args([
            if terminal_requested {
                "--activation-terminal-shim"
            } else {
                "--activation-gated-writer"
            },
            prefix,
        ])
        .arg(directory)
        .env_clear()
        .stdin(Stdio::from(child_input))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    fixture_environment(&mut command)?;
    let mut child = command.spawn()?;
    drop(command);
    activated_guardian::wait_until(deadline, || {
        require(
            child.try_wait()?.is_none(),
            "gated writer exited before readiness",
        )?;
        match fs::read_to_string(directory.join("ready")) {
            Ok(pid) => {
                require(
                    pid == child.id().to_string(),
                    "gated writer readiness PID differs",
                )?;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    })?;
    let prepared =
        serde_json::to_vec(&serde_json::json!({"kind": "aswp-fixture-prepared-1", "child": child.id(), "invocation": invocation}))
            .map_err(io::Error::other)?;
    let descriptors = terminal
        .as_ref()
        .map(|(master, _)| master.as_fd())
        .into_iter()
        .collect::<Vec<_>>();
    transport::send_until(channel, &prepared, &descriptors, deadline)?;
    drop(descriptors);
    // Only the client retains a master after this response. Keep its slave
    // behind the shim gate until the client has durably journaled the PID.
    let slave = terminal.map(|(master, slave)| {
        drop(master);
        slave
    });
    let nonce = match journal_protocol::receive_start(channel, deadline) {
        Ok(nonce) => nonce,
        Err(error) if journal_protocol::is_withdrawal(&error) => {
            require(
                child.try_wait()?.is_none(),
                "writer died before client withdrawal",
            )?;
            fs::write(directory.join("guardian-withdrawn-before-go"), invocation)?;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    require(child.try_wait()?.is_none(), "gated writer exited before GO")?;
    if let Some(slave) = slave {
        transport::send_until(&grant, transport::GO, &[slave.as_fd()], deadline)?;
    }
    transport::send_until(
        &grant,
        &journal_protocol::start_packet(&nonce),
        &[],
        deadline,
    )?;
    drop(grant);
    activated_guardian::wait_until(Instant::now() + Duration::from_secs(35), || {
        if let Some(status) = child.try_wait()? {
            require(terminal_requested, "gated writer exited before disconnect")?;
            use std::os::unix::process::ExitStatusExt;
            fs::write(
                directory.join("target-exit"),
                format!("{:?}:{:?}", status.code(), status.signal()),
            )?;
            return Ok(true);
        }
        if transport::eof(channel)? {
            fs::write(directory.join("guardian-clean-eof"), invocation)?;
            return Ok(true);
        }
        Ok(false)
    })?;
    // The manager kills remaining children when this main process exits.
    drop(lease);
    Ok(())
}

pub(crate) fn fixture_environment(command: &mut Command) -> io::Result<()> {
    for key in [
        "GITHUB_ACTIONS",
        "RUNNER_ENVIRONMENT",
        "ASWP_CI_SOCKET_ACTIVATION",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
    ] {
        command.env(key, std::env::var(key).map_err(io::Error::other)?);
    }
    Ok(())
}

fn refused_lease(directory: &Path, invocation: &str, reason: &str) -> io::Result<()> {
    let parent = directory
        .parent()
        .ok_or_else(|| io::Error::other("fixture parent absent"))?;
    // Fault attribution in the private fixture directory, never custody evidence.
    fs::write(parent.join(format!("{invocation}.lease-refused")), reason)
}

pub(crate) fn gated_ready(prefix: &str, directory: &Path) -> io::Result<()> {
    activated_guardian::writer_check(prefix, directory)?;
    let peer = crate::activation_packet::peer(io::stdin())?;
    require(
        rustix::net::sockopt::socket_type(io::stdin())? == rustix::net::SocketType::SEQPACKET
            && Some(peer.pid()) == rustix::process::getppid().map(|pid| pid.as_raw_pid())
            && peer.uid() == rustix::process::getuid().as_raw()
            && peer.gid() == rustix::process::getgid().as_raw(),
        "writer stdin is not its guardian's gate",
    )?;
    let null = fs::metadata("/dev/null")?;
    for stream in [io::stdout().as_fd(), io::stderr().as_fd()] {
        let stat = rustix::fs::fstat(stream)?;
        require(
            stat.st_dev == null.dev() && stat.st_ino == null.ino() && stat.st_rdev == null.rdev(),
            "writer output is not the null device",
        )?;
    }
    fs::write(directory.join("ready.tmp"), std::process::id().to_string())?;
    fs::rename(directory.join("ready.tmp"), directory.join("ready"))?;
    Ok(())
}

pub(crate) fn writer(prefix: &str, directory: &Path) -> io::Result<()> {
    gated_ready(prefix, directory)?;
    rustix::process::setsid()?;
    let nonce = journal_protocol::receive_start(
        io::stdin().as_fd(),
        Instant::now() + Duration::from_secs(18),
    )?;
    let nonce = journal_protocol::encoded(&nonce);
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut counter = 0_u64;
    while Instant::now() < deadline {
        fs::write(
            directory.join("heartbeat.tmp"),
            format!("{}:{nonce}:{counter}", std::process::id()),
        )?;
        fs::rename(directory.join("heartbeat.tmp"), directory.join("heartbeat"))?;
        counter += 1;
        thread::sleep(Duration::from_millis(20));
    }
    fs::write(directory.join("voluntary-exit"), "deadline")
}
