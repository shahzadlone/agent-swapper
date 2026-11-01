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
) -> io::Result<()> {
    require(
        !rustix::net::sockopt::socket_passcred(channel)?,
        "descriptor channel must not request credentials",
    )?;
    let deadline = Instant::now() + Duration::from_secs(15);
    // ASWP-GO-1 is the existing descriptor envelope, not the start grant.
    let lease = File::from(transport::receive_until(channel, deadline)?);
    let meta = lease.metadata()?;
    require(
        meta.is_file()
            && meta.uid() == rustix::process::getuid().as_raw()
            && meta.mode() & 0o7777 == 0o600
            && meta.nlink() == 1,
        "invalid fixture profile lease",
    )?;
    lease.try_lock().map_err(io::Error::other)?;
    fs::DirBuilder::new().mode(0o700).create(directory)?;
    let (grant, child_input) = transport::pair()?;
    let mut command = Command::new("/proc/self/exe");
    command
        .args(["--activation-gated-writer", prefix])
        .arg(directory)
        .env_clear()
        .stdin(Stdio::from(child_input))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for key in [
        "GITHUB_ACTIONS",
        "RUNNER_ENVIRONMENT",
        "ASWP_CI_SOCKET_ACTIVATION",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
    ] {
        command.env(key, std::env::var(key).map_err(io::Error::other)?);
    }
    let mut child = command.spawn()?;
    activated_guardian::wait_until(deadline, || {
        require(
            child.try_wait()?.is_none(),
            "gated writer exited before readiness",
        )?;
        Ok(directory.join("ready").exists())
    })?;
    let prepared =
        serde_json::to_vec(&serde_json::json!({"child": child.id(), "invocation": invocation}))
            .map_err(io::Error::other)?;
    transport::send_until(channel, &prepared, &[], deadline)?;
    let nonce = journal_protocol::receive_start(channel, deadline)?;
    require(child.try_wait()?.is_none(), "gated writer exited before GO")?;
    transport::send_until(
        &grant,
        &journal_protocol::start_packet(&nonce),
        &[],
        deadline,
    )?;
    drop(grant);
    activated_guardian::wait_until(Instant::now() + Duration::from_secs(35), || {
        require(
            child.try_wait()?.is_none(),
            "gated writer exited before disconnect",
        )?;
        transport::eof(channel)
    })?;
    fs::write(directory.join("guardian-clean-eof"), invocation)?;
    // The manager kills the remaining child when this main process exits.
    // Keep the duplicate lease alive through the complete guardian lifetime.
    drop(lease);
    Ok(())
}

pub(crate) fn writer(prefix: &str, directory: &Path) -> io::Result<()> {
    activated_guardian::writer_check(prefix, directory)?;
    rustix::process::setsid()?;
    fs::write(directory.join("ready"), std::process::id().to_string())?;
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
            format!("{nonce}:{counter}"),
        )?;
        fs::rename(directory.join("heartbeat.tmp"), directory.join("heartbeat"))?;
        counter += 1;
        thread::sleep(Duration::from_millis(20));
    }
    fs::write(directory.join("voluntary-exit"), "deadline")
}
