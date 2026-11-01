//! Fresh-process terminal ownership shared only by fixed qualification probes.
#![forbid(unsafe_code)]
use rustix::{
    fs::{Mode, OFlags},
    termios,
};
use std::{
    fs, io,
    os::{
        fd::{AsFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};

pub(crate) fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

pub(crate) struct Terminal {
    pub(crate) fd: OwnedFd,
    saved: termios::Termios,
    pub(crate) group: rustix::process::Pid,
    pub(crate) raw: bool,
}
impl Terminal {
    pub(crate) fn capture(directory: &Path) -> io::Result<Self> {
        Self::capture_for_group(directory, rustix::process::getpid())
    }
    pub(crate) fn capture_for_group(
        directory: &Path,
        owner: rustix::process::Pid,
    ) -> io::Result<Self> {
        require(
            owner == rustix::process::getpid() || rustix::process::getppid() == Some(owner),
            "terminal group owner is not this process or its direct parent",
        )?;
        require(
            std::env::var("ASWP_OWNED_OUTER_PTY").as_deref() == Ok("1"),
            "requires owned outer-PTY fixture",
        )?;
        let meta = fs::symlink_metadata(directory)?;
        require(
            directory.is_absolute()
                && meta.is_dir()
                && meta.uid() == rustix::process::getuid().as_raw()
                && meta.mode() & 0o077 == 0,
            "outer fixture directory is not private",
        )?;
        let expected: [u64; 3] =
            serde_json::from_slice(&fs::read(directory.join("terminal.json"))?)
                .map_err(io::Error::other)?;
        for stream in [
            io::stdin().as_fd(),
            io::stdout().as_fd(),
            io::stderr().as_fd(),
        ] {
            let stat = rustix::fs::fstat(stream)?;
            require(
                [stat.st_dev, stat.st_ino, stat.st_rdev] == expected,
                "outer probe requires matching terminal streams",
            )?;
        }
        // Reopen verified stdin into a separate open-file description. Dup
        // would share NONBLOCK changes with the parent shell; /dev/tty's inode
        // is an alias, not the underlying slave inode.
        let original_flags = rustix::fs::fcntl_getfl(io::stdin())?;
        let fd = rustix::fs::open(
            "/proc/self/fd/0",
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
            Mode::empty(),
        )?;
        let stat = rustix::fs::fstat(&fd)?;
        require(
            [stat.st_dev, stat.st_ino, stat.st_rdev] == expected
                && termios::isatty(&fd)
                && rustix::fs::fcntl_getfl(io::stdin())? == original_flags,
            "reopened terminal identity or caller flags changed",
        )?;
        let group = rustix::process::getpgrp();
        require(
            group == owner && termios::tcgetpgrp(&fd)? == group,
            "outer probe is not its foreground job leader",
        )?;
        Ok(Self {
            saved: termios::tcgetattr(&fd)?,
            fd,
            group,
            raw: false,
        })
    }
    pub(crate) fn foreground(&self) -> io::Result<bool> {
        Ok(termios::tcgetpgrp(&self.fd)? == self.group && rustix::process::getpgrp() == self.group)
    }
    pub(crate) fn enter(&mut self) -> io::Result<()> {
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
    pub(crate) fn restore(&mut self) -> io::Result<()> {
        if self.raw {
            self.restore_saved()?;
        }
        Ok(())
    }
    /// The surviving owner calls this only after its exclusive child waiter
    /// observes stop or exit. It never restores another foreground group's mode.
    pub(crate) fn restore_saved(&mut self) -> io::Result<()> {
        require(
            self.foreground()?,
            "cannot restore another foreground job's terminal",
        )?;
        termios::tcsetattr(&self.fd, termios::OptionalActions::Now, &self.saved)?;
        self.raw = false;
        Ok(())
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}
