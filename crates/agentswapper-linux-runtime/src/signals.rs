//! Fresh-process signal handling shared by Linux terminal helpers.
use nix::sys::{
    signal::{SigSet, SigmaskHow, Signal, raise},
    signalfd::{SfdFlags, SignalFd},
};
use std::{
    fs, io,
    marker::PhantomData,
    os::fd::{AsFd, BorrowedFd},
    rc::Rc,
};

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

const SIGNALS: [Signal; 8] = [
    Signal::SIGINT,
    Signal::SIGTERM,
    Signal::SIGHUP,
    Signal::SIGQUIT,
    Signal::SIGTSTP,
    Signal::SIGCONT,
    Signal::SIGWINCH,
    Signal::SIGCHLD,
];

#[derive(Default)]
pub struct Notices {
    pub terminate: Option<Signal>,
    pub stop: bool,
    pub continued: bool,
    pub resized: bool,
}
/// Signal-mask owner for a fresh helper process.
///
/// Create before starting any runtime or other threads. Its mask must be restored
/// on the same thread, after terminal restoration and child/scope cleanup. This
/// type deliberately cannot move or be shared across threads.
///
/// ```compile_fail
/// use agentswapper_linux_runtime::signals::Signals;
/// fn move_owner(owner: Signals) {
///     std::thread::spawn(move || drop(owner));
/// }
/// ```
/// ```compile_fail
/// use agentswapper_linux_runtime::signals::Signals;
/// fn share_owner(owner: &Signals) {
///     std::thread::scope(|scope| { scope.spawn(|| { owner.drain().ok(); }); });
/// }
/// ```
pub struct Signals {
    file: SignalFd,
    saved: SigSet,
    _thread: PhantomData<Rc<()>>,
}
impl Signals {
    pub fn new() -> io::Result<Self> {
        require(
            fs::read_dir("/proc/self/task")?
                .collect::<io::Result<Vec<_>>>()?
                .len()
                == 1,
            "signal owner must start single-threaded",
        )?;
        let status = fs::read_to_string("/proc/self/status")?;
        let bits = SIGNALS
            .iter()
            .fold(0_u64, |bits, s| bits | (1 << (*s as u32 - 1)));
        for name in ["SigIgn:", "SigCgt:", "SigBlk:"] {
            let field = status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .ok_or_else(|| io::Error::other("missing signal witness"))?;
            require(
                u64::from_str_radix(field.trim(), 16).map_err(io::Error::other)? & bits == 0,
                "signal owner requires default unblocked signal state",
            )?;
        }
        let mut mask = SigSet::empty();
        for signal in SIGNALS {
            mask.add(signal);
        }
        let saved = mask.thread_swap_mask(SigmaskHow::SIG_BLOCK)?;
        match SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK) {
            Ok(file) => Ok(Self {
                file,
                saved,
                _thread: PhantomData,
            }),
            Err(error) => {
                saved.thread_set_mask()?;
                Err(error.into())
            }
        }
    }
    pub fn drain(&self) -> io::Result<Notices> {
        let mut notices = Notices::default();
        for _ in 0..16 {
            let Some(info) = self.file.read_signal()? else {
                break;
            };
            match Signal::try_from(i32::try_from(info.ssi_signo).map_err(io::Error::other)?)? {
                signal @ (Signal::SIGINT | Signal::SIGTERM | Signal::SIGHUP | Signal::SIGQUIT) => {
                    notices.terminate.get_or_insert(signal);
                }
                Signal::SIGTSTP => notices.stop = true,
                Signal::SIGCONT => notices.continued = true,
                Signal::SIGWINCH => notices.resized = true,
                Signal::SIGCHLD => {}
                _ => return Err(io::Error::other("unexpected helper signal")),
            }
        }
        Ok(notices)
    }
    pub fn suspend(&self) -> io::Result<Notices> {
        let before = self.drain()?;
        if before.terminate.is_some() {
            return Ok(before);
        }
        let mut stop = SigSet::empty();
        stop.add(Signal::SIGTSTP);
        let saved = stop.thread_swap_mask(SigmaskHow::SIG_UNBLOCK)?;
        let result = raise(Signal::SIGTSTP);
        let restored = saved.thread_set_mask();
        result?;
        restored?;
        // SIGCONT resumes a process even while blocked. A discarded orphaned
        // SIGTSTP returns without a corresponding continuation notification.
        self.drain()
    }
    pub fn finish(self, termination: Option<Signal>) -> io::Result<()> {
        drop(self);
        if let Some(signal) = termination {
            raise(signal)?;
        }
        Ok(())
    }
}
impl AsFd for Signals {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

impl Drop for Signals {
    fn drop(&mut self) {
        let _ = self.saved.thread_set_mask();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_an_existing_multithreaded_process_without_changing_its_mask() -> io::Result<()> {
        let (hold, release) = std::sync::mpsc::channel::<()>();
        let other = std::thread::spawn(move || release.recv());
        let before = SigSet::thread_get_mask()?;
        let failure = match Signals::new() {
            Err(error) => Some(error),
            Ok(owner) => {
                drop(owner);
                None
            }
        };
        let after = SigSet::thread_get_mask()?;
        drop(hold);
        other
            .join()
            .map_err(|_| io::Error::other("fixture thread panicked"))?
            .ok();
        assert_eq!(before, after);
        assert_eq!(
            failure.map(|error| error.to_string()).as_deref(),
            Some("signal owner must start single-threaded")
        );
        Ok(())
    }
}
