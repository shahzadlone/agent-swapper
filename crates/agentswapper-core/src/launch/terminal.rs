//! Restore the caller's foreground terminal after an observed child exit.
use std::io::{self, IsTerminal};

use rustix::{
    process::{Pid, getpgrp},
    termios::{OptionalActions, Termios, tcgetattr, tcgetpgrp, tcsetattr},
};

pub(super) struct ForegroundTerminal {
    attributes: Termios,
    group: Pid,
}

impl ForegroundTerminal {
    pub(super) fn capture() -> io::Result<Option<Self>> {
        let stdin = io::stdin();
        if !stdin.is_terminal() {
            return Ok(None);
        }
        let group = getpgrp();
        let foreground = match tcgetpgrp(&stdin) {
            Ok(foreground) => foreground,
            // A PTY can be attached as stdin without being this process's
            // controlling terminal. It has no foreground group we may own.
            Err(rustix::io::Errno::NOTTY) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if foreground != group {
            return Ok(None);
        }
        Ok(Some(Self {
            attributes: tcgetattr(&stdin)?,
            group,
        }))
    }

    pub(super) fn restore(self) -> io::Result<()> {
        let stdin = io::stdin();
        if !stdin.is_terminal() || tcgetpgrp(&stdin)? != self.group || getpgrp() != self.group {
            return Err(io::Error::other("terminal foreground changed"));
        }
        tcsetattr(&stdin, OptionalActions::Now, &self.attributes)?;
        Ok(())
    }
}
