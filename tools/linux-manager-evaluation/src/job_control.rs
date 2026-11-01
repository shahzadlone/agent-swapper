//! Single-threaded, fixed-child job-control owner for Linux qualification.
//! No arbitrary process identifiers or production launch authority.
use crate::require;
use nix::{
    sys::{
        ptrace,
        signal::{SigSet, SigmaskHow, Signal, killpg, pthread_sigmask},
        wait::{WaitPidFlag, WaitStatus, waitpid},
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
    trace: TracePhase,
    _thread: PhantomData<Rc<()>>,
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
        Ok(Self {
            pid: Pid::from_raw(i32::try_from(child.id()).map_err(io::Error::other)?),
            child,
            reaped: false,
            trace: TracePhase::None,
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
        let state = match waitpid(
            self.pid,
            Some(WaitPidFlag::WNOHANG | WaitPidFlag::WUNTRACED | WaitPidFlag::WCONTINUED),
        ) {
            Ok(state) => state,
            Err(nix::errno::Errno::EINTR) => return Ok(WaitStatus::StillAlive),
            Err(nix::errno::Errno::ECHILD) => {
                self.reaped = true;
                return Err(io::Error::other("lost direct-child wait ownership"));
            }
            Err(error) => return Err(error.into()),
        };
        if state == WaitStatus::StillAlive {
            return Ok(state);
        }
        require(state.pid() == Some(self.pid), "wait returned another child")?;
        if matches!(state, WaitStatus::Exited(..) | WaitStatus::Signaled(..)) {
            self.reaped = true;
        }
        Ok(state)
    }
    pub(crate) fn resume(&self) -> io::Result<()> {
        require(!self.reaped, "cannot signal a reaped group leader")?;
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

    #[allow(dead_code, reason = "only the exec-gated guardian uses tracing")]
    pub(crate) fn arm_exec(&mut self, until: Instant) -> io::Result<()> {
        require(
            self.trace == TracePhase::None,
            "exec trace already configured",
        )?;
        require(
            self.next(until)? == WaitStatus::Stopped(self.pid, Signal::SIGSTOP),
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
            self.next(until)?
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
