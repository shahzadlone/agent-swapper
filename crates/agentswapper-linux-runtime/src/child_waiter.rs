//! Exclusive raw waiting for a direct child in a fresh Linux helper.
//! No process-group ownership, ptrace policy or process-scope retirement proof.
use rustix::process::{Pid, WaitOptions, WaitStatus};
use std::{
    io,
    marker::PhantomData,
    process::Child,
    rc::Rc,
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

/// Owns the only wait path for a child. The caller must not install a competing
/// waiter or SIGCHLD auto-reaper elsewhere in the process. Moving a `Child` here
/// prevents reuse of its std exit cache; Linux stops use the raw wait syscall.
/// This is deliberately neither Send nor Sync, and exposes no child handle.
///
/// ```compile_fail
/// use agentswapper_linux_runtime::child_waiter::ChildWaiter;
/// fn send<T: Send>() {}
/// send::<ChildWaiter>();
/// ```
/// ```compile_fail
/// use agentswapper_linux_runtime::child_waiter::ChildWaiter;
/// fn sync<T: Sync>() {}
/// sync::<ChildWaiter>();
/// ```
pub struct ChildWaiter {
    child: Child,
    pid: Pid,
    reaped: bool,
    _thread: PhantomData<Rc<()>>,
}
impl ChildWaiter {
    pub fn new(child: Child) -> io::Result<Self> {
        let pid = Pid::from_raw(i32::try_from(child.id()).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("invalid owned child PID"))?;
        Ok(Self {
            child,
            pid,
            reaped: false,
            _thread: PhantomData,
        })
    }
    /// Original numeric identity for decoding wait events. Once reaped this is
    /// diagnostic only; it never identifies a live process or authorizes a signal.
    pub fn pid(&self) -> Pid {
        self.pid
    }
    pub fn is_reaped(&self) -> bool {
        self.reaped
    }

    /// Poll one raw event, revoking ownership before any fallible higher-level
    /// decoding. In particular, real-time signal exits remain representable.
    pub fn poll(&mut self) -> io::Result<Option<WaitStatus>> {
        require(!self.reaped, "wait ownership already released")?;
        let (observed, raw) = match rustix::process::waitpid(
            Some(self.pid),
            WaitOptions::NOHANG | WaitOptions::UNTRACED | WaitOptions::CONTINUED,
        ) {
            Ok(Some(event)) => event,
            Ok(None) | Err(rustix::io::Errno::INTR) => return Ok(None),
            Err(rustix::io::Errno::CHILD) => {
                self.reaped = true;
                return Err(io::Error::other("lost direct-child wait ownership"));
            }
            Err(error) => return Err(error.into()),
        };
        if raw.exited() || raw.signaled() {
            self.reaped = true;
        }
        require(observed == self.pid, "wait returned another child")?;
        Ok(Some(raw))
    }
    pub fn next(&mut self, until: Instant) -> io::Result<WaitStatus> {
        while Instant::now() < until {
            if let Some(state) = self.poll()? {
                return Ok(state);
            }
            thread::sleep(Duration::from_millis(5));
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "owned-child event expired",
        ))
    }
}
impl Drop for ChildWaiter {
    fn drop(&mut self) {
        if !self.reaped {
            // Exclusive ownership keeps this direct child's PID reserved until
            // reaping. No signal is sent after poll observes exit or ECHILD.
            let _ = self.child.kill();
            let until = Instant::now() + Duration::from_secs(5);
            while Instant::now() < until {
                match self.next(until) {
                    Ok(raw) if raw.exited() || raw.signaled() => break,
                    Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    #[test]
    fn raw_wait_preserves_realtime_termination_and_revokes_child_ownership() -> io::Result<()> {
        use std::{io::Read, os::unix::process::ExitStatusExt};
        let mut child = Command::new("/usr/bin/python3")
            .args(["-I", "-S", "-c", "import os,signal; print(int(signal.SIGRTMIN), flush=True); os.kill(os.getpid(), signal.SIGRTMIN)"])
            .env_clear().stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()?;
        let mut output = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("fixture stdout absent"))?;
        let mut child = ChildWaiter::new(child)?;
        let until = Instant::now() + Duration::from_secs(5);
        let raw = loop {
            if let Some(status) = child.poll()? {
                break status;
            }
            require(Instant::now() < until, "realtime child did not terminate")?;
            thread::sleep(Duration::from_millis(5));
        };
        let mut text = String::new();
        output.read_to_string(&mut text)?;
        let signal: i32 = text.trim().parse().map_err(io::Error::other)?;
        assert!((34..=64).contains(&signal));
        assert!(raw.signaled() && child.is_reaped());
        let status = std::process::ExitStatus::from_raw(raw.as_raw());
        assert_eq!(status.signal(), Some(signal));
        assert!(!status.core_dumped());
        assert!(child.poll().is_err());
        Ok(())
    }

    #[test]
    fn lost_wait_ownership_revokes_later_operations() -> io::Result<()> {
        let child = Command::new("/usr/bin/true")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut child = ChildWaiter::new(child)?;
        // Deliberately violate the sole-waiter contract for this owned child;
        // the next poll must observe ECHILD, revoke and never signal on Drop.
        rustix::process::waitpid(Some(child.pid()), WaitOptions::empty())?;
        assert!(child.poll().is_err());
        assert!(child.is_reaped());
        assert!(child.next(Instant::now() + Duration::from_secs(1)).is_err());
        Ok(())
    }

    #[test]
    fn drop_retires_and_reaps_its_unfinished_direct_child() -> io::Result<()> {
        let child = Command::new("/usr/bin/python3")
            .args(["-I", "-S", "-c", "import time; time.sleep(30)"])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let child = ChildWaiter::new(child)?;
        let pid = child.pid();
        let original = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())?;
        drop(child);
        let mut watched = [rustix::event::PollFd::new(
            &original,
            rustix::event::PollFlags::IN,
        )];
        assert_eq!(
            rustix::event::poll(
                &mut watched,
                Some(&rustix::event::Timespec {
                    tv_sec: 0,
                    tv_nsec: 0
                })
            )?,
            1
        );
        assert!(matches!(
            rustix::process::waitpid(Some(pid), WaitOptions::NOHANG),
            Err(rustix::io::Errno::CHILD)
        ));
        Ok(())
    }
}
