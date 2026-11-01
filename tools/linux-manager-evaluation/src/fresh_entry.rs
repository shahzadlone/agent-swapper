//! Fixed self-exec experiment. No target launch data or journal authority.
use agentswapper_linux_runtime::admission_transport as transport;
use std::{
    fs, io,
    os::{
        fd::AsFd,
        unix::{fs::MetadataExt, process::CommandExt},
    },
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
fn gate(directory: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(directory)?;
    require(
        std::env::var("ASWP_OWNED_OUTER_PTY").as_deref() == Ok("1")
            && directory.is_absolute()
            && meta.is_dir()
            && meta.uid() == rustix::process::getuid().as_raw()
            && meta.mode() & 0o077 == 0,
        "fresh entry requires its private owned-terminal fixture",
    )
}
fn marker(directory: &Path, name: &str) -> io::Result<()> {
    let threads = fs::read_dir("/proc/self/task")?
        .collect::<io::Result<Vec<_>>>()?
        .len();
    let value = serde_json::json!({"pid":std::process::id(),
        "group":rustix::process::getpgrp().as_raw_pid(), "threads":threads});
    fs::write(directory.join(name), value.to_string())
}
pub(crate) fn start(directory: &Path, fail_exec: bool) -> io::Result<u8> {
    gate(directory)?;
    let original = io::stdin().as_fd().try_clone_to_owned()?;
    let (sender, receiver) = transport::pair()?;
    transport::send_until(
        &sender,
        transport::GO,
        &[original.as_fd()],
        Instant::now() + Duration::from_secs(3),
    )?;
    drop(sender);
    let mut command = Command::new(if fail_exec {
        Path::new("/dev/null").to_owned()
    } else {
        std::env::current_exe()?
    });
    command
        .arg("--fresh-owner")
        .arg(directory)
        .stdin(Stdio::from(receiver))
        .env_clear();
    for key in [
        "ASWP_OWNED_OUTER_PTY",
        "ASWP_CI_EXEC_GATE",
        "GITHUB_ACTIONS",
        "RUNNER_ENVIRONMENT",
        "ASWP_CI_SOCKET_ACTIVATION",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "ASWP_ACTIVATION_PREFIX",
        "ASWP_CI_ACTIVATED_JOURNAL",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    // This is a real second thread. A fresh image must remove it while retaining
    // the original shell job identity. Exec failure releases and joins it.
    let (hold, release) = std::sync::mpsc::channel::<()>();
    let worker = std::thread::spawn(move || release.recv());
    let result = (|| {
        marker(directory, "entry-before.json")?;
        let error = command.exec();
        // exec can fail after its stdio changes. Restore the retained original
        // input before returning the failure; never start an owner on this path.
        rustix::stdio::dup2_stdin(&original)?;
        fs::write(
            directory.join("entry-exec-failed"),
            "original stdin restored",
        )?;
        Err(error)
    })();
    drop(hold);
    worker
        .join()
        .map_err(|_| io::Error::other("entry fixture thread panicked"))?
        .ok();
    result
}
pub(crate) fn restore(directory: &Path) -> io::Result<()> {
    gate(directory)?;
    let gate = io::stdin().as_fd().try_clone_to_owned()?;
    let peer = nix::sys::socket::getsockopt(&gate, nix::sys::socket::sockopt::PeerCredentials)?;
    require(
        peer.pid() == std::process::id() as i32
            && peer.uid() == rustix::process::getuid().as_raw()
            && peer.gid() == rustix::process::getgid().as_raw(),
        "bootstrap did not originate in this process",
    )?;
    let input = transport::receive_until(&gate, Instant::now() + Duration::from_secs(3))?;
    let expected: [u64; 3] = serde_json::from_slice(&fs::read(directory.join("terminal.json"))?)
        .map_err(io::Error::other)?;
    let stat = rustix::fs::fstat(&input)?;
    require(
        [stat.st_dev, stat.st_ino, stat.st_rdev] == expected,
        "bootstrap input is not the owned terminal",
    )?;
    require(
        std::env::var_os("ASWP_ENTRY_UNTRUSTED_CANARY").is_none(),
        "unexpected helper environment",
    )?;
    rustix::stdio::dup2_stdin(&input)?;
    drop(input);
    drop(gate);
    marker(directory, "entry-after.json")
}
