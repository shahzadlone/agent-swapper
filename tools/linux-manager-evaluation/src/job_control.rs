//! Single-threaded, fixed-child job-control owner for Linux qualification.
//! No arbitrary process identifiers or production launch authority.
use crate::require;
use nix::{
    sys::{
        signal::{SigSet, SigmaskHow, Signal, killpg, pthread_sigmask},
        wait::WaitStatus,
    },
    unistd::Pid,
};
use std::{
    fs, io,
    marker::PhantomData,
    process::Child,
    rc::Rc,
    thread,
    time::{Duration, Instant},
};
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

pub(crate) const JOB_SIGNALS: [Signal; 7] = [
    Signal::SIGHUP,
    Signal::SIGINT,
    Signal::SIGQUIT,
    Signal::SIGCHLD,
    Signal::SIGTSTP,
    Signal::SIGTTIN,
    Signal::SIGTTOU,
];

pub(crate) fn dispositions() -> io::Result<()> {
    let status = fs::read_to_string("/proc/self/status")?;
    let bits = JOB_SIGNALS
        .iter()
        .fold(0_u64, |bits, signal| bits | (1 << (*signal as u32 - 1)));
    for field in ["SigIgn:", "SigCgt:"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .ok_or_else(|| io::Error::other("missing signal disposition witness"))?;
        let value = u64::from_str_radix(value.trim(), 16).map_err(io::Error::other)?;
        require(
            value & bits == 0,
            "fixture requires default job-control dispositions",
        )?;
    }
    Ok(())
}
pub(crate) fn blocked_job_signals() -> io::Result<SigSet> {
    let mut mask = SigSet::empty();
    for signal in JOB_SIGNALS {
        mask.add(signal);
    }
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&mask), None)?;
    Ok(mask)
}
pub(crate) fn target_signals() -> io::Result<()> {
    dispositions()?;
    let current = SigSet::thread_get_mask()?;
    require(
        JOB_SIGNALS
            .into_iter()
            .all(|signal| !current.contains(signal)),
        "target inherited a blocked job-control signal",
    )
}

/// The sole waiter. Never use std::Child's exit cache for job-control stops.
pub(crate) struct OwnedChild {
    child: Child,
    pub(crate) pid: Pid,
    reaped: bool,
    _thread: PhantomData<Rc<()>>,
}
impl OwnedChild {
    pub(crate) fn new(child: Child) -> io::Result<Self> {
        Ok(Self {
            pid: Pid::from_raw(i32::try_from(child.id()).map_err(io::Error::other)?),
            child,
            reaped: false,
            _thread: PhantomData,
        })
    }
    pub(crate) fn next(&mut self, until: Instant) -> io::Result<WaitStatus> {
        while Instant::now() < until {
            let state = self.poll()?;
            if state == WaitStatus::StillAlive {
                thread::sleep(Duration::from_millis(5));
                continue;
            }
            return Ok(state);
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "owned-child event expired",
        ))
    }
    pub(crate) fn poll(&mut self) -> io::Result<WaitStatus> {
        require(!self.reaped, "wait ownership already released")?;
        let pid = rustix::process::Pid::from_raw(self.pid.as_raw())
            .ok_or_else(|| io::Error::other("invalid owned child PID"))?;
        let (observed, raw) = match rustix::process::waitpid(
            Some(pid),
            rustix::process::WaitOptions::NOHANG
                | rustix::process::WaitOptions::UNTRACED
                | rustix::process::WaitOptions::CONTINUED,
        ) {
            Ok(Some(event)) => event,
            Ok(None) | Err(rustix::io::Errno::INTR) => return Ok(WaitStatus::StillAlive),
            Err(rustix::io::Errno::CHILD) => {
                self.reaped = true;
                return Err(io::Error::other("lost direct-child wait ownership"));
            }
            Err(error) => return Err(error.into()),
        };
        // The syscall can reap successfully even when nix cannot decode its
        // finite Signal enum (e.g. SIGRTMIN). Revoke PID authority BEFORE that
        // fallible conversion; its EINVAL is not a syscall failure.
        if raw.exited() || raw.signaled() {
            self.reaped = true;
        }
        require(observed == pid, "wait returned another child")?;
        WaitStatus::from_raw(self.pid, raw.as_raw()).map_err(io::Error::from)
    }
    pub(crate) fn resume(&self) -> io::Result<()> {
        require(!self.reaped, "cannot signal a reaped group leader")?;
        require(
            nix::unistd::getpgid(Some(self.pid))? == self.pid,
            "fixed child left its owned process group",
        )?;
        // Only the fixed direct child creates this group and never leaves it.
        // Its unreaped PID reserves the group ID. Not an arbitrary-job API.
        killpg(self.pid, Signal::SIGCONT)?;
        Ok(())
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let until = deadline();
            while Instant::now() < until {
                match self.next(until) {
                    Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) | Err(_) => break,
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
    fn reaped_child_revokes_numeric_operations_even_when_status_decode_fails() -> io::Result<()> {
        // Python sends only its own realtime signal. nix's finite Signal enum
        // cannot decode that termination, even though waitpid already reaped it.
        let child = Command::new("/usr/bin/python3")
            .args([
                "-I",
                "-S",
                "-c",
                "import os,signal; os.kill(os.getpid(), signal.SIGRTMIN)",
            ])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut child = OwnedChild::new(child)?;
        let error = child
            .next(deadline())
            .err()
            .ok_or_else(|| io::Error::other("realtime termination unexpectedly decoded"))?;
        assert_eq!(error.raw_os_error(), Some(nix::libc::EINVAL));
        let revoked = child.reaped;
        // Keep the pre-fix negative control from signalling an already-reaped
        // PID while unwinding its expected assertion failure.
        child.reaped = true;
        assert!(revoked, "decoder failure left a reaped numeric PID owned");
        assert!(child.resume().is_err());
        assert!(child.poll().is_err());
        Ok(())
    }
}
