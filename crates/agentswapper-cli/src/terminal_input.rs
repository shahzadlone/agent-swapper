//! Keep incomplete terminal input from blocking signal-aware event loops.
use std::io;

/// The caller must install its restoration guard before invoking this function.
pub(crate) fn enable_raw_mode() -> io::Result<()> {
    crossterm::terminal::enable_raw_mode()?;
    #[cfg(unix)]
    {
        use rustix::termios::{OptionalActions, SpecialCodeIndex, tcgetattr, tcsetattr};
        // The selected crossterm TTY backend checks its poll deadline after a
        // zero-byte read. An incomplete UTF-8/escape sequence must reach that
        // check even without another byte arriving. Its cached pre-raw state
        // restores both fields before returning input to the shell or agent.
        let stdin = io::stdin();
        let mut attributes = tcgetattr(&stdin)?;
        attributes.special_codes[SpecialCodeIndex::VMIN] = 0;
        attributes.special_codes[SpecialCodeIndex::VTIME] = 1;
        tcsetattr(&stdin, OptionalActions::Now, &attributes)?;
    }
    Ok(())
}
