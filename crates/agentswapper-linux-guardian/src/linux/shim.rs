//! The exec-shim role. The guardian spawns this installed image with a
//! private control socket on standard input; the shim re-derives its own
//! image facts against the manifest, enters the tracer's hold at exec,
//! receives the terminal slave, the run nonce and the launch envelope, and
//! verifies from inside that its session and foreground group belong to the
//! guardian's granted topology before finally execing the captured target.
//! Its argv carries only its role and the manager-assigned unit name.
use crate::linux::parse_unit;
use agentswapper_linux_runtime::{
    admission_transport as transport, installed_manifest::InstalledManifest, job_control,
    launch_envelope::LaunchEnvelope, launch_protocol, self_image::SelfImage, terminal,
};
use std::os::unix::process::CommandExt;
use std::{
    io,
    os::fd::OwnedFd,
    time::{Duration, Instant},
};

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

const CONTROL_BUDGET: Duration = Duration::from_secs(30);

fn single_threaded() -> io::Result<()> {
    let threads = std::fs::read_dir("/proc/self/task")?
        .collect::<io::Result<Vec<_>>>()?
        .len();
    require(threads == 1, "the exec shim is not single-threaded")
}

fn bind_image(user: u32, generation: &str, role: &str) -> io::Result<()> {
    let group = rustix::process::getgid().as_raw();
    let manifest = InstalledManifest::open(user, group, generation)?;
    let (path, expected) = match role {
        "exec-shim" => manifest.exec_shim(),
        _ => return Err(io::Error::other("unknown helper role")),
    };
    require(
        path.file_name().and_then(|name| name.to_str()) == Some(role),
        "the installed helper path is unexpected",
    )?;
    let image = SelfImage::observe()?;
    require(
        image.sha256 == expected,
        "the running helper image does not match its installed digest",
    )?;
    require(
        image.uid == 0 && image.mode == 0o755 && image.nlink == 1,
        "the running helper is not the single root-owned installed image",
    )?;
    require(
        !image.noexec_or_nosuid && !image.file_capabilities,
        "the running helper image lost its protected mount and capability policy",
    )?;
    require(
        rustix::process::getuid().as_raw() == user && rustix::process::getgid().as_raw() == group,
        "the helper runs outside its installed identity",
    )
}

/// Run the exec-shim role for one launch. `control` is the guardian's
/// private transfer socket; `unit` is the manager-assigned unit name.
pub fn run(control: &OwnedFd, unit: &str) -> io::Result<()> {
    require(
        rustix::process::getuid().as_raw() == rustix::process::geteuid().as_raw()
            && rustix::process::getgid().as_raw() == rustix::process::getegid().as_raw(),
        "the exec shim requires matching real and effective identities",
    )?;
    let (user, generation) = parse_unit(unit)?;
    bind_image(user, &generation, "exec-shim")?;
    single_threaded()?;
    // Hostile inherited signal state would silently drop job-control
    // evidence; the shim refuses to start in one.
    job_control::require_default_job_dispositions()?;
    // Hold before exec: the tracer (the guardian) resumes this process after
    // installing its exec trap. The stop is raised before any launch data is
    // read, so a lost guardian never reaches a running target.
    nix::sys::ptrace::traceme()?;
    nix::sys::signal::raise(nix::sys::signal::Signal::SIGSTOP)?;
    // The guardian blocks the terminal stop signals before it operates on the
    // session's foreground group; the mask arrives with the spawn, so its
    // presence here is evidence of the controlled spawn itself.
    require(
        job_control::stop_signals_blocked()?,
        "the exec shim did not inherit the guardian's blocked stop signals",
    )?;
    let deadline = Instant::now() + CONTROL_BUDGET;
    let slave = transport::receive_until(control, deadline)?;
    terminal::validate_slave(&slave)?;
    let _nonce = launch_protocol::receive_launch_gate_open(control, deadline)?;
    let envelope = LaunchEnvelope::receive_from_until(control, deadline)?;
    // The target topology: the guardian owns the session, granted this
    // process its own group and the foreground before the transfer, and the
    // slave is the session's controlling terminal. Everything is verified,
    // nothing configured: a topology the guardian did not grant refuses
    // here, before the target's final exec.
    let parent = rustix::process::getppid()
        .ok_or_else(|| io::Error::other("the exec shim lost its parent guardian"))?;
    require(
        rustix::process::getsid(None)? == parent,
        "the exec shim is outside its guardian's session",
    )?;
    require(
        rustix::process::getpgrp() == rustix::process::getpid(),
        "the exec shim did not receive its own process group",
    )?;
    require(
        rustix::termios::tcgetsid(&slave)? == parent,
        "the terminal slave is outside the guardian's session",
    )?;
    require(
        rustix::termios::tcgetpgrp(&slave)? == rustix::process::getpgrp(),
        "the exec shim did not receive the foreground grant",
    )?;
    let mut command = envelope.command();
    command
        .stdin(std::process::Stdio::from(slave.try_clone()?))
        .stdout(std::process::Stdio::from(slave.try_clone()?))
        .stderr(std::process::Stdio::from(slave));
    // The exec preserves this thread's signal mask: the target must meet its
    // own signal contract with a default unblocked state, but the guardian's
    // stop signals stay masked until the foreground grant provably exists.
    job_control::clear_inherited_mask()?;
    // Exec preserves the PID the client's retained pidfd already bound.
    Err(command.exec())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn the_shim_role_refuses_outside_an_installed_host() -> std::io::Result<()> {
        let unit = format!("agentswapper-1000-{}@1-2-3.service", "0".repeat(31) + "1");
        let (control, _peer) = match rustix::net::socketpair(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::SEQPACKET,
            rustix::net::SocketFlags::CLOEXEC,
            None,
        ) {
            Ok(pair) => pair,
            Err(error) => {
                return Err(std::io::Error::other(error.to_string()));
            }
        };
        assert!(run(&control, &unit).is_err());
        Ok(())
    }
}
