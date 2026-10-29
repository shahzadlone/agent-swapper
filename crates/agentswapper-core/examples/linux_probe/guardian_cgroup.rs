//! Combined cooperating-fixture experiment. No production journal or stop receipt.
use super::*;
use crate::cgroup;
use rustix::{
    net::{RecvFlags, recv},
    process::{Signal, getpid, kill_process_group},
};
use std::{fs::TryLockError, os::unix::process::ExitStatusExt};

pub(super) fn fixture(role: &str, directory: &Path, path: &Path) -> io::Result<()> {
    let parent = File::from(admission_transport::receive(io::stdin())?);
    let leaf = File::from(admission_transport::receive(io::stdin())?);
    let lease = File::from(admission_transport::receive(io::stdin())?);
    cgroup::validate_scope(&parent, &leaf, path)?;
    if role == "guardian-parent" {
        require(
            getpgrp() == getpid(),
            "fixture parent is not its own process group",
        )?;
        let (channel, gate) = admission_transport::pair()?;
        // Dropping Child must not kill the guardian. Parent death closes channel.
        let mut helper = command("guardian-scope", directory, path)?
            .stdin(Stdio::from(gate))
            .process_group(0)
            .spawn()?;
        for fd in [parent.as_fd(), leaf.as_fd(), lease.as_fd()] {
            admission_transport::send(&channel, admission_transport::GO, &[fd])?;
        }
        let deadline = Instant::now() + BUDGET;
        let mut killed = false;
        loop {
            if directory.join("kill-guardian").exists() && !killed {
                // Failure injection uses the parent's owned Child handle.
                helper.kill()?;
                killed = true;
            }
            if let Some(status) = helper.try_wait()? {
                require(
                    killed && status.signal() == Some(9),
                    "guardian ended unexpectedly",
                )?;
                empty_scope(&leaf, deadline)?;
                publish(
                    directory,
                    "parent-empty",
                    "guardian SIGKILL; kernel population zero; lease held",
                )?;
                until(deadline, || {
                    Ok(directory.join("release-parent").exists().then_some(()))
                })?;
                drop(lease);
                return publish(
                    directory,
                    "parent-finished",
                    "guardian loss handled; lease released after independent retirement",
                );
            }
            require(Instant::now() < deadline, "parent fixture deadline expired")?;
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    require(
        getpgrp() == getpid(),
        "guardian is not in a separate process group",
    )?;
    publish(directory, "guardian-pid", &std::process::id().to_string())?;
    let deadline = Instant::now() + BUDGET;
    let (mut shim, admission) = socket_shim(directory, path)?;
    let pid = shim.0.id();
    control(&leaf, "cgroup.procs", OFlags::WRONLY)?.write_all(format!("{pid}\n").as_bytes())?;
    require(
        contains(&leaf, pid)?,
        "guardian admission did not match owned shim",
    )?;
    admission.grant(&mut shim.0)?;
    require(
        until(deadline, || shim.0.try_wait())?.success(),
        "guardian's root fixture failed",
    )?;
    until(deadline, || Ok(heartbeat(directory, "heartbeat")))?;
    publish(
        directory,
        "guardian-ready",
        "detached writer active; lease held",
    )?;

    // Only the parent owns the peer. No target inherits this close-on-exec socket.
    until(deadline, || {
        let mut byte = [0_u8; 1];
        match recv(io::stdin(), &mut byte, RecvFlags::DONTWAIT) {
            Ok((0, _)) => Ok(Some(())),
            Ok(_) => Err(io::Error::other("unexpected guardian control packet")),
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => Ok(None),
            Err(error) => Err(error.into()),
        }
    })?;
    empty_scope(&leaf, deadline)?;
    publish(
        directory,
        "guardian-empty",
        "parent EOF; kernel population zero; lease held",
    )?;
    until(deadline, || {
        Ok(directory.join("release-guardian").exists().then_some(()))
    })?;
    drop(lease);
    publish(
        directory,
        "guardian-finished",
        "lease released after independent retirement",
    )
}

fn empty_scope(leaf: &File, deadline: Instant) -> io::Result<()> {
    control(leaf, "cgroup.kill", OFlags::WRONLY)?.write_all(b"1\n")?;
    until(deadline, || Ok((!populated(leaf)?).then_some(())))
}

struct Release(PathBuf);
impl Drop for Release {
    fn drop(&mut self) {
        let _ = publish(&self.0, "release-guardian", "fixture teardown");
        let _ = publish(&self.0, "release-parent", "fixture teardown");
        // Best-effort bounded error cleanup. Group's own drop is a separate backstop.
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.0.join("guardian-pid").exists()
            && !self.0.join("guardian-finished").exists()
            && !self.0.join("parent-finished").exists()
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn await_marker(directory: &Path, name: &str, deadline: Instant) -> io::Result<()> {
    until(deadline, || {
        if directory.join("fixture-failure").exists() {
            return Err(io::Error::other(fs::read_to_string(
                directory.join("fixture-failure"),
            )?));
        }
        Ok(directory.join(name).exists().then_some(()))
    })
}

fn assert_locked(directory: &Path) -> io::Result<()> {
    require(
        matches!(
            File::open(directory.join("lease"))?.try_lock(),
            Err(TryLockError::WouldBlock)
        ),
        "profile lease released before supervisor cleanup completed",
    )
}

pub(super) fn run(domain: &Domain) -> io::Result<()> {
    run_once(domain, false)?;
    run_once(domain, true)
}

fn run_once(domain: &Domain, guardian_loss: bool) -> io::Result<()> {
    let deadline = Instant::now() + BUDGET;
    let directory = tempfile::tempdir()?;
    let mut group = domain.create()?;
    // Test the capability boundary before starting any fixture work.
    require(
        cgroup::validate_scope(group.parent(), group.parent(), group.path()).is_err(),
        "guardian accepted its delegated parent as a kill scope",
    )?;
    require(
        cgroup::validate_scope(group.parent(), group.directory(), Path::new("..")).is_err(),
        "guardian accepted a traversal scope name",
    )?;
    let _release = Release(directory.path().to_owned());
    let lease = File::create_new(directory.path().join("lease"))?;
    lease.try_lock().map_err(io::Error::other)?;
    let mut outside = OwnedChild(command("control", directory.path(), group.path())?.spawn()?);
    let (channel, gate) = admission_transport::pair()?;
    let mut parent = OwnedChild(
        command("guardian-parent", directory.path(), group.path())?
            .stdin(Stdio::from(gate))
            .process_group(0)
            .spawn()?,
    );
    for fd in [
        group.parent().as_fd(),
        group.directory().as_fd(),
        lease.as_fd(),
    ] {
        admission_transport::send(&channel, admission_transport::GO, &[fd])?;
    }
    // The controller must not retain either a peer of the guardian's channel or
    // a copy of its lease. Independent openers now test the transferred ownership.
    drop(channel);
    await_marker(directory.path(), "guardian-ready", deadline)?;
    drop(lease);
    let guardian = until(deadline, || Ok(pid_file(directory.path(), "guardian-pid")))?;
    let leaf = until(deadline, || Ok(heartbeat(directory.path(), "heartbeat")))?;
    let middle = until(deadline, || Ok(pid_file(directory.path(), "middle-pid")))?;
    let control_writer = until(deadline, || {
        Ok(heartbeat(directory.path(), "control-heartbeat"))
    })?;
    require(
        contains(group.directory(), leaf.0)? && !contains(group.directory(), control_writer.0)?,
        "combined fixture membership mismatch",
    )?;
    until(deadline, || {
        Ok(heartbeat(directory.path(), "heartbeat").filter(|value| value.2 > leaf.2 + 3))
    })?;
    assert_locked(directory.path())?;
    if guardian_loss {
        publish(
            directory.path(),
            "kill-guardian",
            "parent must kill its owned helper",
        )?;
        await_marker(directory.path(), "parent-empty", deadline)?;
        require(
            parent.0.try_wait()?.is_none(),
            "parent exited before cleanup was retired",
        )?;
    } else {
        // Owned and unreaped group leader: no metadata PID is signalled.
        kill_process_group(Pid::from_child(&parent.0), Signal::KILL)?;
        require(
            until(deadline, || parent.0.try_wait())?.signal() == Some(9),
            "fixture parent did not die from SIGKILL",
        )?;
        await_marker(directory.path(), "guardian-empty", deadline)?;
    }
    // This is checked BEFORE the controller invokes any kill/retirement backstop.
    require(
        !populated(group.directory())?,
        "surviving supervisor reported empty while target scope remained populated",
    )?;
    assert_locked(directory.path())?;
    require(
        reap(middle, deadline)?.exit_status() == Some(0),
        "combined middle fixture failed",
    )?;
    require(
        reap(leaf.0, deadline)?.terminating_signal() == Some(9),
        "surviving supervisor did not kill detached writer",
    )?;
    require(
        !directory.path().join("writer-exited").exists(),
        "combined writer exited voluntarily",
    )?;
    let after = until(deadline, || {
        Ok(heartbeat(directory.path(), "control-heartbeat"))
    })?;
    until(deadline, || {
        Ok(heartbeat(directory.path(), "control-heartbeat").filter(|value| value.2 > after.2 + 3))
    })?;
    group.retire(deadline)?;
    require(!group.path().exists(), "combined scope was not retired")?;
    if guardian_loss {
        publish(
            directory.path(),
            "release-parent",
            "independent retirement complete",
        )?;
        await_marker(directory.path(), "parent-finished", deadline)?;
        require(
            until(deadline, || parent.0.try_wait())?.success(),
            "surviving parent failed",
        )?;
    } else {
        publish(
            directory.path(),
            "release-guardian",
            "independent retirement complete",
        )?;
        await_marker(directory.path(), "guardian-finished", deadline)?;
        require(
            reap(guardian, deadline)?.exit_status() == Some(0),
            "combined guardian failed",
        )?;
    }
    File::open(directory.path().join("lease"))?
        .try_lock()
        .map_err(io::Error::other)?;
    outside.0.kill()?;
    require(
        until(deadline, || outside.0.try_wait())?.signal() == Some(9),
        "outside control cleanup failed",
    )?;
    println!(
        "::notice title=Linux guardian cgroup::lost {}; detached writer killed by surviving supervisor; independent population zero before controller retirement; lease held through cleanup; outside writer survives",
        if guardian_loss {
            "guardian"
        } else {
            "parent process group"
        }
    );
    Ok(())
}
