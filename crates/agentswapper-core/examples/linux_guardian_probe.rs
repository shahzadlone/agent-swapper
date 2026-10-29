//! Provider-free guardian/lease experiment; does not establish process containment.
#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
#[path = "../src/supervision/linux_admission_transport.rs"]
mod admission_transport;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("Linux-only guardian probe; no provider launched.");
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = probe::run() {
        let text = error
            .to_string()
            .replace('%', "%25")
            .replace('\r', "%0D")
            .replace('\n', "%0A");
        println!("::error title=Linux guardian probe::{text}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod probe {
    use super::admission_transport::{GO, pair, receive, send};
    use rustix::{
        fd::AsFd,
        net::{RecvFlags, recv},
        process::{
            Pid, Signal, WaitOptions, getpgid, getpgrp, getpid, kill_process_group,
            set_child_subreaper, waitpid,
        },
    };
    use std::{
        fs::{self, File, TryLockError},
        io::{self, IsTerminal},
        os::unix::process::{CommandExt, ExitStatusExt},
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };
    use wait_timeout::ChildExt;

    const BUDGET: Duration = Duration::from_secs(10);

    fn require(value: bool, message: &'static str) -> io::Result<()> {
        if value {
            Ok(())
        } else {
            Err(io::Error::other(message))
        }
    }

    fn until<T>(mut check: impl FnMut() -> io::Result<Option<T>>) -> io::Result<T> {
        let deadline = Instant::now() + BUDGET;
        loop {
            if let Some(value) = check()? {
                return Ok(value);
            }
            require(Instant::now() < deadline, "fixture deadline expired")?;
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn publish(dir: &Path, name: &str, value: &str) -> io::Result<()> {
        let temporary = dir.join(format!("{name}.tmp"));
        fs::write(&temporary, value)?;
        fs::rename(temporary, dir.join(name))
    }

    fn await_marker(dir: &Path, name: &str) -> io::Result<String> {
        until(|| {
            for role in ["parent", "guardian"] {
                if let Ok(error) = fs::read_to_string(dir.join(format!("{role}-error"))) {
                    return Err(io::Error::other(format!("{role}: {error}")));
                }
            }
            match fs::read_to_string(dir.join(name)) {
                Ok(value) => Ok(Some(value)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            }
        })
    }

    fn command(role: &str, dir: &Path) -> io::Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .env_clear()
            .arg(role)
            .arg(dir)
            .current_dir(dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        Ok(command)
    }

    struct ChildGuard(Child);
    impl ChildGuard {
        fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
            self.0
                .wait_timeout(BUDGET)?
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "child did not exit"))
        }
    }
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait_timeout(BUDGET);
        }
    }

    // Cleanup uses only the owned Child. Adopted PIDs are waited on, never signalled.
    struct Fixture {
        parent: ChildGuard,
        dir: PathBuf,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = publish(&self.dir, "release", "fixture cleanup permitted");
            let _ = self.parent.0.kill();
            let _ = self.parent.0.wait_timeout(BUDGET);
            let _ = until(|| match waitpid(None, WaitOptions::NOHANG) {
                Ok(_) => Ok(None),
                Err(rustix::io::Errno::CHILD) => Ok(Some(())),
                Err(error) => Err(error.into()),
            });
        }
    }

    fn guardian(dir: &Path) -> io::Result<()> {
        require(
            !io::stdin().is_terminal()
                && !io::stdout().is_terminal()
                && !io::stderr().is_terminal(),
            "guardian inherited terminal I/O",
        )?;
        require(
            getpgrp() == getpid(),
            "guardian is not its own process group",
        )?;
        let lease = File::from(receive(io::stdin())?);
        publish(dir, "ready", &getpid().to_string())?;
        let mut unexpected = [0_u8; 1];
        // The inherited socket has a bounded receive timeout. Only EOF is accepted.
        require(
            recv(io::stdin(), &mut unexpected, RecvFlags::empty())?.0 == 0,
            "expected parent channel EOF",
        )?;
        publish(dir, "parent-gone", "EOF observed; lease retained")?;
        await_marker(dir, "release")?;
        drop(lease);
        publish(dir, "finished", "lease released after simulated cleanup")
    }

    fn parent(dir: &Path) -> io::Result<()> {
        let lease = File::create_new(dir.join("lease"))?;
        lease.try_lock().map_err(io::Error::other)?;
        let (parent, child) = pair()?;
        let mut helper = ChildGuard(
            command("guardian", dir)?
                .stdin(Stdio::from(child))
                .spawn()?,
        );
        send(&parent, GO, &[lease.as_fd()])?;
        await_marker(dir, "close-parent")?;
        drop(lease);
        drop(parent);
        publish(
            dir,
            "parent-closed",
            "parent stays alive without lease or channel",
        )?;
        require(helper.wait()?.success(), "guardian failed")
    }

    fn assert_locked(dir: &Path) -> io::Result<()> {
        require(
            matches!(
                File::open(dir.join("lease"))?.try_lock(),
                Err(TryLockError::WouldBlock)
            ),
            "independent opener acquired guardian-held lease",
        )
    }

    fn scenario(kill_group: bool) -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let mut fixture = Fixture {
            parent: ChildGuard(command("parent", dir.path())?.spawn()?),
            dir: dir.path().to_owned(),
        };
        let guardian_pid: i32 = await_marker(dir.path(), "ready")?
            .parse()
            .map_err(io::Error::other)?;
        require(guardian_pid > 1, "invalid guardian PID")?;
        let guardian_pid =
            Pid::from_raw(guardian_pid).ok_or_else(|| io::Error::other("missing guardian PID"))?;
        let parent_pid = Pid::from_child(&fixture.parent.0);
        require(
            getpgid(Some(parent_pid))? == parent_pid,
            "parent group mismatch",
        )?;
        require(
            getpgid(Some(guardian_pid))? == guardian_pid,
            "guardian group mismatch",
        )?;
        require(guardian_pid != parent_pid, "guardian shares parent group")?;
        assert_locked(dir.path())?;

        if kill_group {
            // Root remains an unreaped owned child: its PID cannot be reused here.
            kill_process_group(parent_pid, Signal::KILL)?;
            require(
                fixture.parent.wait()?.signal() == Some(9),
                "parent was not killed",
            )?;
        } else {
            publish(dir.path(), "close-parent", "close original descriptors")?;
            await_marker(dir.path(), "parent-closed")?;
            require(
                fixture.parent.0.try_wait()?.is_none(),
                "parent exited early",
            )?;
        }
        await_marker(dir.path(), "parent-gone")?;
        assert_locked(dir.path())?;
        require(
            !dir.path().join("finished").exists(),
            "guardian released lease early",
        )?;
        publish(dir.path(), "release", "simulated cleanup finished")?;
        await_marker(dir.path(), "finished")?;
        File::open(dir.path().join("lease"))?
            .try_lock()
            .map_err(io::Error::other)?;
        if kill_group {
            let (_, status) = until(|| Ok(waitpid(Some(guardian_pid), WaitOptions::NOHANG)?))?;
            require(status.exit_status() == Some(0), "adopted guardian failed")?;
        } else {
            require(fixture.parent.wait()?.success(), "parent failed")?;
        }
        println!(
            "{}: guardian observed EOF in a separate group; lease excluded independent openers until release",
            if kill_group {
                "SIGKILL to parent group"
            } else {
                "parent closes descriptors"
            }
        );
        Ok(())
    }

    pub(super) fn run() -> io::Result<()> {
        let mut args = std::env::args_os().skip(1);
        if let Some(role) = args.next() {
            let dir = PathBuf::from(
                args.next()
                    .ok_or_else(|| io::Error::other("missing fixture directory"))?,
            );
            let role = role
                .to_str()
                .ok_or_else(|| io::Error::other("invalid fixture role"))?;
            let result = match role {
                "parent" => parent(&dir),
                "guardian" => guardian(&dir),
                _ => Err(io::Error::other("unknown fixture role")),
            };
            if let Err(error) = &result {
                let _ = publish(&dir, &format!("{role}-error"), &error.to_string());
            }
            return result;
        }
        set_child_subreaper(Some(getpid()))?;
        scenario(false)?;
        scenario(true)
    }
}
