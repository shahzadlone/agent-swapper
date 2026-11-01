//! Single-threaded, fixed-child job-control owner for Linux qualification.
//! No arbitrary process identifiers or production launch authority.
use crate::require;
use agentswapper_linux_runtime::child_waiter::ChildWaiter;
use nix::{
    sys::{
        ptrace,
        signal::{SigSet, SigmaskHow, Signal, killpg, pthread_sigmask},
        wait::WaitStatus,
    },
    unistd::Pid,
};
use std::{fs, io, process::Child, time::Instant};
#[cfg(test)]
fn deadline() -> Instant {
    Instant::now() + std::time::Duration::from_secs(5)
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
    waiter: ChildWaiter,
    pub(crate) pid: Pid,
    trace: TracePhase,
}
#[derive(PartialEq, Eq)]
enum TracePhase {
    None,
    Armed,
    Held,
    Detached,
}
impl OwnedChild {
    pub(crate) fn new(child: Child) -> io::Result<Self> {
        let waiter = ChildWaiter::new(child)?;
        Ok(Self {
            pid: Pid::from_raw(waiter.pid().as_raw_pid()),
            waiter,
            trace: TracePhase::None,
        })
    }
    pub(crate) fn next(&mut self, until: Instant) -> io::Result<WaitStatus> {
        let raw = self.waiter.next(until)?;
        WaitStatus::from_raw(self.pid, raw.as_raw()).map_err(io::Error::from)
    }
    pub(crate) fn poll(&mut self) -> io::Result<WaitStatus> {
        match self.poll_raw()? {
            Some(raw) => WaitStatus::from_raw(self.pid, raw.as_raw()).map_err(io::Error::from),
            None => Ok(WaitStatus::StillAlive),
        }
    }
    pub(crate) fn poll_raw(&mut self) -> io::Result<Option<rustix::process::WaitStatus>> {
        self.waiter.poll()
    }
    pub(crate) fn resume(&self) -> io::Result<()> {
        require(
            !self.waiter.is_reaped(),
            "cannot signal a reaped group leader",
        )?;
        require(
            matches!(self.trace, TracePhase::None | TracePhase::Detached),
            "job resume cannot release an exec trace",
        )?;
        require(
            nix::unistd::getpgid(Some(self.pid))? == self.pid,
            "fixed child left its owned process group",
        )?;
        // Only the fixed direct child creates this group and never leaves it.
        // Its unreaped PID reserves the group ID. Not an arbitrary-job API.
        killpg(self.pid, Signal::SIGCONT)?;
        Ok(())
    }

    fn next_admission_state(&mut self, until: Instant) -> io::Result<WaitStatus> {
        loop {
            match self.next(until)? {
                WaitStatus::Stopped(pid, Signal::SIGWINCH | Signal::SIGCHLD) if pid == self.pid => {
                    // Only advisory notifications in the trusted pre-exec shim.
                    // These cannot be group stops. Suppress their delivery and
                    // keep waiting under the original absolute admission limit.
                    // Cancellation, job stops and traps are never continued here.
                    ptrace::cont(self.pid, None)?;
                }
                state => return Ok(state),
            }
        }
    }

    #[allow(dead_code, reason = "only the exec-gated guardian uses tracing")]
    pub(crate) fn arm_exec(&mut self, until: Instant) -> io::Result<()> {
        require(
            self.trace == TracePhase::None,
            "exec trace already configured",
        )?;
        require(
            self.next_admission_state(until)? == WaitStatus::Stopped(self.pid, Signal::SIGSTOP),
            "exec shim did not reach its initial trace stop",
        )?;
        ptrace::setoptions(
            self.pid,
            ptrace::Options::PTRACE_O_TRACEEXEC | ptrace::Options::PTRACE_O_EXITKILL,
        )?;
        ptrace::cont(self.pid, None)?;
        self.trace = TracePhase::Armed;
        Ok(())
    }

    #[allow(dead_code, reason = "only the exec-gated guardian uses tracing")]
    pub(crate) fn hold_exec(&mut self, until: Instant) -> io::Result<()> {
        require(self.trace == TracePhase::Armed, "exec trace is not armed")?;
        require(
            self.next_admission_state(until)?
                == WaitStatus::PtraceEvent(self.pid, Signal::SIGTRAP, nix::libc::PTRACE_EVENT_EXEC),
            "original child did not report the exact exec event",
        )?;
        self.trace = TracePhase::Held;
        Ok(())
    }

    #[allow(dead_code, reason = "only the exec-gated guardian uses tracing")]
    pub(crate) fn release_exec(&mut self) -> io::Result<()> {
        require(self.trace == TracePhase::Held, "exec stop is not held")?;
        require(
            self.poll()? == WaitStatus::StillAlive,
            "exec-held child changed state",
        )?;
        ptrace::detach(self.pid, None)?;
        self.trace = TracePhase::Detached;
        Ok(())
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
        let revoked = child.waiter.is_reaped();
        assert!(revoked, "decoder failure left a reaped numeric PID owned");
        let raw = child
            .waiter
            .final_status()
            .ok_or_else(|| io::Error::other("decoder discarded exit"))?;
        assert!(raw.signaled());
        let status = <std::process::ExitStatus as std::os::unix::process::ExitStatusExt>::from_raw(
            raw.as_raw(),
        );
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(nix::libc::SIGRTMIN())
        );
        assert!(child.resume().is_err());
        assert!(child.poll().is_err());
        Ok(())
    }
}
