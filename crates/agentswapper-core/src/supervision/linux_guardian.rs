//! Internal guardian for a delegated cgroup. Not yet wired to normal launches.
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::{BorrowedFd, OwnedFd},
    fs::OFlags,
    net::{RecvFlags, recv},
    process::{Pid, getpgid, getpgrp, getpid, getppid},
};
use std::{
    fs::File,
    io::{self, Write},
    os::fd::AsFd,
    os::unix::process::{CommandExt, ExitStatusExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use wait_timeout::ChildExt;

use super::{
    linux_admission_transport as transport, linux_cgroup as cgroup,
    linux_launch_envelope::LaunchEnvelope, linux_shim,
};

const STARTUP: Duration = Duration::from_secs(30);
const CLEANUP: Duration = Duration::from_secs(10);
const PID_PREFIX: &[u8] = b"ASWP-PID-1";
const EMPTY_PREFIX: &[u8] = b"ASWP-EMPTY-1";
pub(crate) const RETIRE: &[u8] = b"ASWP-RETIRE-1";
const RETIRED: &[u8] = b"ASWP-RETIRED-1";

/// Internal CLI role selector; scope and process group are not secret.
#[doc(hidden)]
pub const INTERNAL_ARG: &str = "__agentswapper_internal_linux_guardian_v1";

/// Start a guardian outside the foreground process group on a private channel.
/// The caller must choose a trusted executable containing the internal role.
#[allow(dead_code, reason = "normal launcher integration is not yet enabled")]
pub(crate) fn spawn_guardian(
    executable: &Path,
    scope: &Path,
    stdout: Stdio,
    stderr: Stdio,
) -> io::Result<(Child, OwnedFd)> {
    if !executable.is_absolute() || !scope.is_absolute() {
        return Err(io::Error::other("guardian paths must be absolute"));
    }
    let (channel, gate) = transport::pair()?;
    let guardian = Command::new(executable)
        .arg(INTERNAL_ARG)
        .arg(scope)
        .arg(getpgrp().as_raw_pid().to_string())
        .env_clear()
        .stdin(Stdio::from(gate))
        .stdout(stdout)
        .stderr(stderr)
        .process_group(0)
        .spawn()?;
    Ok((guardian, channel))
}

/// Clean an owned scope after the guardian is lost, while the caller retains
/// its lease. This does not recover a target status or create a receipt.
#[allow(dead_code, reason = "normal launcher integration is not yet enabled")]
pub(crate) fn recover_scope(scope: &mut cgroup::Group, deadline: Instant) -> io::Result<()> {
    cgroup::validate_scope(scope.parent(), scope.directory(), scope.path())?;
    scope.retire(deadline)?;
    cgroup::require(
        cgroup::events_missing(scope.directory())?,
        "scope retirement not observed",
    )
}

/// Transfer the scope, lease, launch and streams under one startup deadline.
/// The returned PID must be durably recorded before the caller sends GO.
/// This preparation is experimental and is not a production launch API.
#[allow(dead_code, reason = "normal launcher integration is not yet enabled")]
pub(crate) fn prepare(
    channel: &OwnedFd,
    capabilities: [BorrowedFd<'_>; 3],
    launch: &LaunchEnvelope,
    streams: [BorrowedFd<'_>; 3],
    deadline: Instant,
) -> io::Result<u32> {
    for fd in capabilities {
        transport::send_until(channel, transport::GO, &[fd], deadline)?;
    }
    launch.send_to_until(channel, deadline)?;
    for fd in streams {
        transport::send_until(channel, transport::GO, &[fd], deadline)?;
    }
    receive_pid(channel, deadline)
}

/// Durably record the admitted process before releasing its execution gate.
/// A journal or transport error deliberately leaves the run unresolved.
#[allow(dead_code, reason = "normal launcher integration is not yet enabled")]
pub(crate) fn record_and_go(
    store: &mut crate::Store,
    run: &str,
    pid: u32,
    channel: &OwnedFd,
    deadline: Instant,
) -> crate::Result<()> {
    store.observe_spawn(run, pid)?;
    transport::send_until(channel, transport::GO, &[], deadline)?;
    Ok(())
}

/// Wait for the guardian's empty report without limiting a live session's
/// duration. Only the owned child handle is used to detect guardian loss.
#[allow(dead_code, reason = "normal launcher integration is not yet enabled")]
pub(crate) fn wait_for_empty(channel: &OwnedFd, guardian: &mut Child) -> io::Result<i32> {
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: 250_000_000,
    };
    loop {
        let mut descriptors = [PollFd::new(channel, PollFlags::IN)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
        let events = descriptors[0].revents();
        if events.intersects(PollFlags::IN | PollFlags::HUP) {
            return receive_empty(channel, Instant::now() + CLEANUP);
        }
        if !events.is_empty() {
            return Err(io::Error::other("guardian control channel failed"));
        }
        if guardian.try_wait()?.is_some() {
            return Err(io::Error::other("guardian exited before reporting empty"));
        }
    }
}

/// Independently inspect the held scope before and after asking the guardian
/// to retire it. This observation is experimental and is not a stop receipt.
#[allow(dead_code, reason = "normal launcher integration is not yet enabled")]
pub(crate) fn retire_observed(
    channel: &OwnedFd,
    parent: &File,
    leaf: &File,
    path: &Path,
    deadline: Instant,
) -> io::Result<()> {
    cgroup::validate_scope(parent, leaf, path)?;
    cgroup::require(!cgroup::populated(leaf)?, "scope remains populated")?;
    cgroup::require(!cgroup::events_missing(leaf)?, "scope already retired")?;
    transport::send_until(channel, RETIRE, &[], deadline)?;
    receive_retired(channel, deadline)?;
    cgroup::require(
        cgroup::events_missing(leaf)?,
        "scope retirement not observed",
    )
}

#[allow(dead_code, reason = "normal launcher integration is not yet enabled")]
pub(crate) fn receive_pid(channel: impl AsFd, deadline: Instant) -> io::Result<u32> {
    let pid = u32::from_be_bytes(transport::receive_number_until(
        channel, PID_PREFIX, deadline,
    )?);
    if pid == 0 {
        return Err(io::Error::other("invalid guardian PID"));
    }
    Ok(pid)
}

#[allow(dead_code, reason = "normal launcher integration is not yet enabled")]
pub(crate) fn receive_empty(channel: impl AsFd, deadline: Instant) -> io::Result<i32> {
    let code = i32::from_be_bytes(transport::receive_number_until(
        channel,
        EMPTY_PREFIX,
        deadline,
    )?);
    if !(0..=255).contains(&code) {
        return Err(io::Error::other("invalid guardian exit status"));
    }
    Ok(code)
}

#[allow(dead_code, reason = "normal launcher integration is not yet enabled")]
pub(crate) fn receive_retired(channel: impl AsFd, deadline: Instant) -> io::Result<()> {
    transport::receive_control_until(channel, RETIRED, deadline)
}

struct Target(Child);
impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait_timeout(Duration::from_secs(3));
    }
}

struct Scope {
    parent: File,
    leaf: File,
    _lease: File,
    path: PathBuf,
    retired: bool,
}
impl Scope {
    fn stop(&self, deadline: Instant) -> io::Result<()> {
        cgroup::validate_scope(&self.parent, &self.leaf, &self.path)?;
        cgroup::control(&self.leaf, "cgroup.kill", OFlags::WRONLY)?.write_all(b"1\n")?;
        cgroup::until(deadline, || {
            Ok((!cgroup::populated(&self.leaf)?).then_some(()))
        })
    }
    fn retire_empty(&mut self, deadline: Instant) -> io::Result<()> {
        cgroup::retire_transferred(&self.parent, &self.leaf, &self.path, deadline)?;
        self.retired = true;
        Ok(())
    }
    fn stop_and_retire(&mut self, deadline: Instant) -> io::Result<()> {
        self.stop(deadline)?;
        self.retire_empty(deadline)
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        if !self.retired {
            let _ = self.stop_and_retire(Instant::now() + Duration::from_secs(3));
        }
    }
}

/// Execute the private guardian protocol over stdin. Errors leave the journal
/// unresolved; a successful message is not currently a production receipt.
#[doc(hidden)]
pub fn run_stdio(scope: &Path, foreground: i32) -> io::Result<()> {
    let foreground =
        Pid::from_raw(foreground).ok_or_else(|| io::Error::other("invalid foreground group"))?;
    run(io::stdin(), scope, foreground, Instant::now() + STARTUP)
}

fn run(channel: impl AsFd, path: &Path, foreground: Pid, deadline: Instant) -> io::Result<()> {
    if getpgrp() != getpid() || getpgrp() == foreground || getpgid(getppid())? != foreground {
        return Err(io::Error::other("guardian process group mismatch"));
    }
    let parent = File::from(transport::receive_until(&channel, deadline)?);
    let leaf = File::from(transport::receive_until(&channel, deadline)?);
    let lease = File::from(transport::receive_until(&channel, deadline)?);
    cgroup::validate_scope(&parent, &leaf, path)?;
    crate::private_fs::validate_file_metadata(&lease.metadata()?)
        .map_err(|_| io::Error::other("invalid guardian lease"))?;
    lease.try_lock().map_err(io::Error::other)?;
    let mut scope = Scope {
        parent,
        leaf,
        _lease: lease,
        path: path.to_owned(),
        retired: false,
    };
    let launch = LaunchEnvelope::receive_from_until(&channel, deadline)?;
    let input = File::from(transport::receive_until(&channel, deadline)?);
    let output = File::from(transport::receive_until(&channel, deadline)?);
    let diagnostic = File::from(transport::receive_until(&channel, deadline)?);
    let (grant, gate) = transport::pair()?;
    // Resolve the running image in the forked child, so replacing the CLI's
    // installed pathname cannot substitute a different shim between spawns.
    let mut command = Command::new("/proc/self/exe");
    command
        .arg(linux_shim::INTERNAL_ARG)
        .arg(path)
        .env_clear()
        .stdin(Stdio::from(gate))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(foreground.as_raw_pid());
    let mut target = Target(command.spawn()?);
    cgroup::control(&scope.leaf, "cgroup.procs", OFlags::WRONLY)?
        .write_all(format!("{}\n", target.0.id()).as_bytes())?;
    if !cgroup::contains(&scope.leaf, target.0.id())? {
        return Err(io::Error::other("guardian failed to admit shim"));
    }
    let channel = rustix::io::dup(&channel)?;
    let mut pid = PID_PREFIX.to_vec();
    pid.extend_from_slice(&target.0.id().to_be_bytes());
    transport::send_until(&channel, &pid, &[], deadline)?;
    transport::receive_control_until(&channel, transport::GO, deadline)?;
    for fd in [scope.parent.as_fd(), scope.leaf.as_fd()] {
        transport::send_until(&grant, transport::GO, &[fd], deadline)?;
    }
    launch.send_to_until(&grant, deadline)?;
    drop(launch);
    for fd in [input.as_fd(), output.as_fd(), diagnostic.as_fd()] {
        transport::send_until(&grant, transport::GO, &[fd], deadline)?;
    }
    transport::send_until(&grant, transport::GO, &[], deadline)?;
    drop(grant);
    drop([input, output, diagnostic]);
    let status = loop {
        let mut packet = [0_u8; 1];
        match recv(&channel, &mut packet, RecvFlags::DONTWAIT) {
            Ok((0, _)) => {
                scope.stop_and_retire(Instant::now() + CLEANUP)?;
                return Ok(());
            }
            Ok(_) => return Err(io::Error::other("unexpected guardian control message")),
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
        if let Some(status) = target.0.try_wait()? {
            break status;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let code = match (status.code(), status.signal()) {
        (Some(code), _) => code,
        (None, Some(signal)) => 128 + signal,
        _ => return Err(io::Error::other("target exit status unavailable")),
    };
    let deadline = Instant::now() + CLEANUP;
    scope.stop(deadline)?;
    let mut empty = EMPTY_PREFIX.to_vec();
    empty.extend_from_slice(&code.to_be_bytes());
    transport::send_until(&channel, &empty, &[], deadline)?;
    transport::receive_control_until(&channel, RETIRE, deadline)?;
    scope.retire_empty(deadline)?;
    transport::send_until(&channel, RETIRED, &[], deadline)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guardian_spawn_rejects_relative_or_missing_executables() -> io::Result<()> {
        assert!(
            spawn_guardian(
                Path::new("relative"),
                Path::new("/scope"),
                Stdio::null(),
                Stdio::null()
            )
            .is_err()
        );
        assert!(
            spawn_guardian(
                Path::new("/bin/true"),
                Path::new("relative"),
                Stdio::null(),
                Stdio::null()
            )
            .is_err()
        );
        let temp = tempfile::tempdir()?;
        assert!(
            spawn_guardian(
                &temp.path().join("missing"),
                Path::new("/scope"),
                Stdio::null(),
                Stdio::null()
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn live_session_waits_across_poll_intervals_and_guardian_loss_fails() -> io::Result<()> {
        let (sender, receiver) = transport::pair()?;
        let mut guardian = Target(Command::new("/bin/sleep").arg("10").spawn()?);
        let sender_thread = thread::spawn(move || -> io::Result<()> {
            thread::sleep(Duration::from_millis(700));
            let mut packet = EMPTY_PREFIX.to_vec();
            packet.extend_from_slice(&7_i32.to_be_bytes());
            transport::send(&sender, &packet, &[])
        });
        let start = Instant::now();
        assert_eq!(wait_for_empty(&receiver, &mut guardian.0)?, 7);
        assert!(start.elapsed() >= Duration::from_millis(500));
        sender_thread
            .join()
            .map_err(|_| io::Error::other("sender panicked"))??;

        let (_sender, receiver) = transport::pair()?;
        let mut exited = Target(Command::new("/bin/true").spawn()?);
        let start = Instant::now();
        assert!(wait_for_empty(&receiver, &mut exited.0).is_err());
        assert!(start.elapsed() < Duration::from_secs(5));

        let (sender, receiver) = transport::pair()?;
        let mut guardian = Target(Command::new("/bin/sleep").arg("10").spawn()?);
        transport::send(&sender, b"malformed", &[])?;
        assert!(wait_for_empty(&receiver, &mut guardian.0).is_err());
        Ok(())
    }

    #[test]
    fn retirement_refuses_invalid_scope_without_sending_control() -> io::Result<()> {
        let temp = tempfile::tempdir()?;
        let directory = File::open(temp.path())?;
        let (sender, receiver) = transport::pair()?;
        assert!(
            retire_observed(
                &sender,
                &directory,
                &directory,
                temp.path(),
                Instant::now() + Duration::from_secs(1),
            )
            .is_err()
        );
        let mut bytes = [0; 1];
        assert!(matches!(
            recv(&receiver, &mut bytes, RecvFlags::DONTWAIT),
            Err(rustix::io::Errno::AGAIN)
        ));
        Ok(())
    }

    #[test]
    fn gate_requires_recorded_pid_and_send_failure_keeps_run_unresolved() -> crate::Result<()> {
        let temp = tempfile::tempdir()?;
        let mut store = crate::Store::open(&temp.path().join("state"))?;
        let profile = store.register(crate::Harness::Claude, "work".parse()?)?;
        let lease = store.lease(profile.id)?;
        let run = store.begin_run(&lease, "run")?;
        let (sender, receiver) = transport::pair()?;
        let deadline = Instant::now() + Duration::from_secs(5);
        assert!(
            record_and_go(
                &mut store,
                &uuid::Uuid::new_v4().to_string(),
                42,
                &sender,
                deadline
            )
            .is_err()
        );
        let mut bytes = [0; 1];
        assert!(matches!(
            recv(&receiver, &mut bytes, RecvFlags::DONTWAIT),
            Err(rustix::io::Errno::AGAIN)
        ));
        record_and_go(&mut store, &run, 42, &sender, deadline)?;
        assert_eq!(store.run(&run)?.observed_pid, Some(42));
        transport::receive_control_until(&receiver, transport::GO, deadline)?;
        assert!(store.run(&run)?.outcome.is_none());

        let other = store.register(crate::Harness::Claude, "other".parse()?)?;
        let other_lease = store.lease(other.id)?;
        let other_run = store.begin_run(&other_lease, "run")?;
        let (sender, receiver) = transport::pair()?;
        drop(receiver);
        assert!(record_and_go(&mut store, &other_run, 43, &sender, deadline).is_err());
        assert_eq!(store.run(&other_run)?.observed_pid, Some(43));
        assert!(store.run(&other_run)?.outcome.is_none());
        assert!(store.verify()?.consistent);
        Ok(())
    }

    #[test]
    fn supervisor_preparation_preserves_order_and_waits_for_explicit_go() -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let (sender, receiver) = transport::pair()?;
        let files = (0..6)
            .map(|_| tempfile::tempfile())
            .collect::<io::Result<Vec<_>>>()?;
        let inodes = files
            .iter()
            .map(|file| file.metadata().map(|metadata| metadata.ino()))
            .collect::<io::Result<Vec<_>>>()?;
        let launch = LaunchEnvelope::capture("/bin/true".as_ref(), Path::new("/"), [], [], [])?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let receiver_thread = thread::spawn(move || -> io::Result<()> {
            for expected in &inodes[..3] {
                let file = File::from(transport::receive_until(&receiver, deadline)?);
                assert_eq!(file.metadata()?.ino(), *expected);
            }
            let received = LaunchEnvelope::receive_from_until(&receiver, deadline)?;
            assert_eq!(received.command().get_program(), "/bin/true");
            for expected in &inodes[3..] {
                let file = File::from(transport::receive_until(&receiver, deadline)?);
                assert_eq!(file.metadata()?.ino(), *expected);
            }
            let mut packet = PID_PREFIX.to_vec();
            packet.extend_from_slice(&42_u32.to_be_bytes());
            transport::send_until(&receiver, &packet, &[], deadline)?;
            transport::receive_control_until(&receiver, transport::GO, deadline)
        });
        let pid = prepare(
            &sender,
            [files[0].as_fd(), files[1].as_fd(), files[2].as_fd()],
            &launch,
            [files[3].as_fd(), files[4].as_fd(), files[5].as_fd()],
            deadline,
        )?;
        assert_eq!(pid, 42);
        assert!(!receiver_thread.is_finished());
        transport::send_until(&sender, transport::GO, &[], deadline)?;
        receiver_thread
            .join()
            .map_err(|_| io::Error::other("receiver panicked"))??;
        Ok(())
    }

    #[test]
    fn expired_supervisor_startup_never_transfers_a_capability() -> io::Result<()> {
        let (sender, receiver) = transport::pair()?;
        let file = tempfile::tempfile()?;
        let launch = LaunchEnvelope::capture("/bin/true".as_ref(), Path::new("/"), [], [], [])?;
        let error = prepare(
            &sender,
            [file.as_fd(), file.as_fd(), file.as_fd()],
            &launch,
            [file.as_fd(), file.as_fd(), file.as_fd()],
            Instant::now(),
        )
        .err()
        .ok_or_else(|| io::Error::other("expired preparation unexpectedly succeeded"))?;
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let mut bytes = [0; 1];
        assert!(matches!(
            recv(&receiver, &mut bytes, RecvFlags::DONTWAIT),
            Err(rustix::io::Errno::AGAIN)
        ));
        Ok(())
    }

    #[test]
    fn numeric_protocol_refuses_invalid_values_and_capabilities() -> io::Result<()> {
        for (prefix, value, extra_fd, valid) in [
            (PID_PREFIX, 42_u32, false, true),
            (PID_PREFIX, 0_u32, false, false),
            (PID_PREFIX, 42_u32, true, false),
            (EMPTY_PREFIX, 7_u32, false, true),
            (EMPTY_PREFIX, 256_u32, false, false),
        ] {
            let (sender, receiver) = transport::pair()?;
            let file = tempfile::tempfile()?;
            let mut packet = prefix.to_vec();
            packet.extend_from_slice(&value.to_be_bytes());
            let fds = if extra_fd { vec![file.as_fd()] } else { vec![] };
            transport::send(&sender, &packet, &fds)?;
            let deadline = Instant::now() + Duration::from_secs(1);
            let accepted = if prefix == PID_PREFIX {
                receive_pid(&receiver, deadline).is_ok()
            } else {
                receive_empty(&receiver, deadline).is_ok()
            };
            assert_eq!(accepted, valid);
        }
        let (sender, receiver) = transport::pair()?;
        transport::send(&sender, b"ASWP-PID-1-too-long", &[])?;
        assert!(receive_pid(&receiver, Instant::now() + Duration::from_secs(1)).is_err());
        let (sender, receiver) = transport::pair()?;
        transport::send(&sender, RETIRED, &[])?;
        receive_retired(&receiver, Instant::now() + Duration::from_secs(1))?;
        let (sender, receiver) = transport::pair()?;
        let file = tempfile::tempfile()?;
        transport::send(&sender, RETIRED, &[file.as_fd()])?;
        assert!(receive_retired(&receiver, Instant::now() + Duration::from_secs(1)).is_err());
        Ok(())
    }
}
