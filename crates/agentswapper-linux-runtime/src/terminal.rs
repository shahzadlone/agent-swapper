//! Terminal restoration tied to the fresh helper's signal-mask lifetime.
use crate::signals::Signals;
use nix::sys::signal::Signal;
use rustix::{
    fs::{self, Mode, OFlags},
    termios,
};
use std::{
    cell::Cell,
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    time::{Duration, Instant},
};

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

/// A foreground terminal guard borrowing its fresh-process signal owner.
///
/// Ordinary cleanup must destroy this guard before restoring that owner's mask.
/// The descriptor, saved attributes and raw-mode tracking are private.
///
/// ```compile_fail
/// use agentswapper_linux_runtime::{signals::Signals, terminal::Terminal};
/// fn wrong_order() -> std::io::Result<()> {
///     let signals = Signals::new()?;
///     let terminal = Terminal::capture(&signals, rustix::process::getpid())?;
///     signals.finish(None)?;
///     drop(terminal);
///     Ok(())
/// }
/// ```
pub struct Terminal<'signals> {
    fd: OwnedFd,
    saved: termios::Termios,
    group: rustix::process::Pid,
    raw: bool,
    signals: &'signals Signals,
}
impl<'signals> Terminal<'signals> {
    /// Admit matching standard terminal streams in this or the direct parent's
    /// original foreground group. Does not enter raw mode or steal foreground.
    pub fn capture(signals: &'signals Signals, owner: rustix::process::Pid) -> io::Result<Self> {
        require(
            owner == rustix::process::getpid() || rustix::process::getppid() == Some(owner),
            "terminal group owner is not this process or its direct parent",
        )?;
        let initial = fs::fstat(io::stdin())?;
        let expected = [initial.st_dev, initial.st_ino, initial.st_rdev];
        for stream in [
            io::stdin().as_fd(),
            io::stdout().as_fd(),
            io::stderr().as_fd(),
        ] {
            let stat = fs::fstat(stream)?;
            require(
                [stat.st_dev, stat.st_ino, stat.st_rdev] == expected,
                "helper requires matching terminal streams",
            )?;
        }
        // A separate open-file description avoids changing flags shared with
        // the parent shell. Recheck identity after reopening verified stdin.
        let original_flags = fs::fcntl_getfl(io::stdin())?;
        let fd = fs::open(
            "/proc/self/fd/0",
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
            Mode::empty(),
        )?;
        let stat = fs::fstat(&fd)?;
        require(
            [stat.st_dev, stat.st_ino, stat.st_rdev] == expected
                && fs::FileType::from_raw_mode(stat.st_mode).is_char_device()
                && termios::isatty(&fd)
                && fs::fcntl_getfl(io::stdin())? == original_flags,
            "reopened terminal identity or caller flags changed",
        )?;
        reject_master(&fd)?;
        let group = rustix::process::getpgrp();
        // nix's signed PID representation can safely decode a zero foreground
        // result. Never interpret zero as our foreground group.
        require(
            group == owner && nix::unistd::tcgetpgrp(&fd)?.as_raw() == group.as_raw_pid(),
            "helper is not its foreground job leader",
        )?;
        Ok(Self {
            saved: termios::tcgetattr(&fd)?,
            fd,
            group,
            raw: false,
            signals,
        })
    }
    pub fn group(&self) -> rustix::process::Pid {
        self.group
    }
    pub fn is_raw(&self) -> bool {
        self.raw
    }
    pub fn foreground(&self) -> io::Result<bool> {
        Ok(
            nix::unistd::tcgetpgrp(&self.fd)?.as_raw() == self.group.as_raw_pid()
                && rustix::process::getpgrp() == self.group,
        )
    }
    /// Wait in cooked mode for foreground ownership without extending the
    /// original admission deadline. A cancellation remains owned by the caller
    /// until it has restored the terminal and attempted independent cleanup.
    pub fn wait_for_admission(
        &self,
        until: Instant,
        cancelled: &Cell<Option<Signal>>,
    ) -> io::Result<()> {
        require(
            !self.raw,
            "admission wait requires cooked terminal ownership",
        )?;
        loop {
            let notices = self.signals.drain()?;
            remember(cancelled, notices.terminate);
            if notices.stop && cancelled.get().is_none() {
                remember(cancelled, self.signals.suspend()?.terminate);
            }
            admission_live(until, cancelled)?;
            if self.foreground()? {
                return Ok(());
            }
            // Background continuation performs no terminal I/O or mode change.
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Enter raw mode immediately before the final target grant. Once ISIG is
    /// disabled, drain any stop generated while the terminal was still cooked.
    /// Return to cooked mode before suspension/cancellation and retry foreground
    /// admission under the same deadline. Later grant delivery remains the
    /// caller's responsibility and is not atomic with signals or foreground loss.
    pub fn enter_for_admission(
        &mut self,
        until: Instant,
        cancelled: &Cell<Option<Signal>>,
    ) -> io::Result<()> {
        loop {
            self.wait_for_admission(until, cancelled)?;
            self.enter()?;
            let pending = match self.signals.drain() {
                Ok(pending) => pending,
                Err(error) => {
                    let _ = self.restore();
                    return Err(error);
                }
            };
            remember(cancelled, pending.terminate);
            if let Err(error) = admission_live(until, cancelled) {
                let _ = self.restore();
                return Err(error);
            }
            if !pending.stop {
                return Ok(());
            }
            self.restore()?;
            remember(cancelled, self.signals.suspend()?.terminate);
        }
    }

    pub fn enter(&mut self) -> io::Result<()> {
        require(
            self.foreground()?,
            "cannot enter raw mode in the background",
        )?;
        let mut raw = self.saved.clone();
        raw.make_raw();
        termios::tcsetattr(&self.fd, termios::OptionalActions::Now, &raw)?;
        self.raw = true;
        Ok(())
    }
    pub fn restore(&mut self) -> io::Result<()> {
        if self.raw {
            self.restore_saved()?;
        }
        Ok(())
    }
    /// The surviving owner calls this only after its exclusive child waiter
    /// observes stop or exit. It never restores another foreground group's mode.
    pub fn restore_saved(&mut self) -> io::Result<()> {
        require(
            self.foreground()?,
            "cannot restore another foreground job's terminal",
        )?;
        termios::tcsetattr(&self.fd, termios::OptionalActions::Now, &self.saved)?;
        self.raw = false;
        Ok(())
    }
}
impl Drop for Terminal<'_> {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

impl AsFd for Terminal<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

fn remember(cancelled: &Cell<Option<Signal>>, signal: Option<Signal>) {
    if cancelled.get().is_none() {
        cancelled.set(signal);
    }
}
fn admission_live(until: Instant, cancelled: &Cell<Option<Signal>>) -> io::Result<()> {
    if cancelled.get().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "terminal admission cancelled",
        ));
    }
    if Instant::now() >= until {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "terminal admission expired before foreground release",
        ));
    }
    Ok(())
}

fn reject_master(fd: impl AsFd) -> io::Result<()> {
    // Pinned rustix ptsname uses TIOCGPTN. Masters accept it even with a locked
    // peer. A non-master must produce ENOTTY; unknown failures refuse admission.
    require(
        matches!(
            rustix::pty::ptsname(fd, Vec::new()),
            Err(rustix::io::Errno::NOTTY)
        ),
        "outer terminal is a PTY master or has unknown type",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_locked_and_unlocked_masters_without_acquiring_a_terminal() -> io::Result<()> {
        use rustix::pty::{self, OpenptFlags};
        let flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC;
        let master = pty::openpt(flags)?;
        assert!(reject_master(&master).is_err());
        pty::grantpt(&master)?;
        pty::unlockpt(&master)?;
        assert!(reject_master(&master).is_err());
        let slave = pty::ioctl_tiocgptpeer(&master, flags)?;
        reject_master(&slave)?;
        Ok(())
    }
}
