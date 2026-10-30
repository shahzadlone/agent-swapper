//! Keep incomplete terminal input from blocking signal-aware event loops.
use std::io;

/// Crossterm's bounded TTY backend can return an empty poll after hangup.
/// Distinguish that from an idle terminal without consuming any input bytes.
pub(crate) fn poll(timeout: std::time::Duration) -> io::Result<bool> {
    #[cfg(unix)]
    check_connected()?;
    let ready = crossterm::event::poll(timeout)?;
    #[cfg(unix)]
    check_connected()?;
    Ok(ready)
}

#[cfg(unix)]
fn check_connected() -> io::Result<()> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    let stdin = io::stdin();
    let mut descriptors = [PollFd::new(&stdin, PollFlags::IN)];
    match poll(
        &mut descriptors,
        Some(&Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    ) {
        Ok(_) => {}
        // Let the caller's signal guard decide how to handle interruption.
        Err(rustix::io::Errno::INTR) => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    if descriptors[0]
        .revents()
        .intersects(PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL)
    {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "terminal input disconnected",
        ));
    }
    Ok(())
}

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
