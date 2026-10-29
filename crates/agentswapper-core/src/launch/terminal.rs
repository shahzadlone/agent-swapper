//! Restore the caller's foreground terminal after an observed child exit.
use std::{
    fs::{File, OpenOptions},
    io::{self, IsTerminal},
    os::fd::AsFd,
    os::unix::fs::OpenOptionsExt,
};

use rustix::{
    process::{Pid, getpgrp},
    termios::{OptionalActions, Termios, tcgetattr, tcgetpgrp, tcsetattr},
};

pub(super) struct ForegroundTerminal {
    terminal: File,
    attributes: Termios,
    group: Pid,
}

impl ForegroundTerminal {
    pub(super) fn capture() -> io::Result<Option<Self>> {
        let group = getpgrp();
        let stdin = io::stdin();
        let stdout = io::stdout();
        let stderr = io::stderr();
        for stream in [
            stdin.is_terminal().then(|| stdin.as_fd()),
            stdout.is_terminal().then(|| stdout.as_fd()),
            stderr.is_terminal().then(|| stderr.as_fd()),
        ]
        .into_iter()
        .flatten()
        {
            let terminal = File::from(rustix::io::fcntl_dupfd_cloexec(stream, 3)?);
            if let Some(captured) = Self::capture_handle(terminal, group)? {
                return Ok(Some(captured));
            }
        }
        // Programs can open /dev/tty even when all standard streams are
        // redirected. Failure to open it simply means no usable tty was found.
        if let Ok(terminal) = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags((rustix::fs::OFlags::NOCTTY | rustix::fs::OFlags::NONBLOCK).bits() as i32)
            .open("/dev/tty")
        {
            return Self::capture_handle(terminal, group);
        }
        Ok(None)
    }

    fn capture_handle(terminal: File, group: Pid) -> io::Result<Option<Self>> {
        let foreground = match tcgetpgrp(&terminal) {
            Ok(foreground) => foreground,
            // A PTY can be attached without being the controlling terminal.
            Err(rustix::io::Errno::NOTTY) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if foreground != group {
            return Ok(None);
        }
        Ok(Some(Self {
            attributes: tcgetattr(&terminal)?,
            terminal,
            group,
        }))
    }

    pub(super) fn restore(self) -> io::Result<()> {
        if !self.terminal.is_terminal()
            || tcgetpgrp(&self.terminal)? != self.group
            || getpgrp() != self.group
        {
            return Err(io::Error::other("terminal foreground changed"));
        }
        tcsetattr(&self.terminal, OptionalActions::Now, &self.attributes)?;
        Ok(())
    }
}
