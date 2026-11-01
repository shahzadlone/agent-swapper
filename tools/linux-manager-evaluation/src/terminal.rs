//! Owned inner PTY only. This module never changes the caller's terminal.
use crate::require;
use rustix::{fs, pty, termios};
use std::{
    io,
    os::fd::{AsFd, OwnedFd},
};

pub(crate) fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let master =
        pty::openpt(pty::OpenptFlags::RDWR | pty::OpenptFlags::NOCTTY | pty::OpenptFlags::CLOEXEC)?;
    pty::grantpt(&master)?;
    pty::unlockpt(&master)?;
    let slave = pty::ioctl_tiocgptpeer(
        &master,
        pty::OpenptFlags::RDWR | pty::OpenptFlags::NOCTTY | pty::OpenptFlags::CLOEXEC,
    )?;
    fs::fcntl_setfl(&master, fs::fcntl_getfl(&master)? | fs::OFlags::NONBLOCK)?;
    termios::tcsetwinsize(
        &master,
        termios::Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        },
    )?;
    validate_master(&master)?;
    Ok((master, slave))
}

pub(crate) fn validate_master(master: impl AsFd) -> io::Result<()> {
    require(
        fs::FileType::from_raw_mode(fs::fstat(&master)?.st_mode).is_char_device()
            && fs::fcntl_getfl(&master)?.contains(fs::OFlags::NONBLOCK)
            && rustix::io::fcntl_getfd(&master)?.contains(rustix::io::FdFlags::CLOEXEC),
        "terminal capability is not a nonblocking close-on-exec character device",
    )?;
    // TIOCGPTPEER succeeds only on a PTY master. NOCTTY prevents acquisition
    // of a controlling terminal while independently validating the capability.
    let slave = pty::ioctl_tiocgptpeer(
        &master,
        pty::OpenptFlags::RDWR | pty::OpenptFlags::NOCTTY | pty::OpenptFlags::CLOEXEC,
    )?;
    require(termios::isatty(&slave), "terminal peer is not a TTY")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_capability_requires_master_and_descriptor_hygiene() -> io::Result<()> {
        let (master, slave) = pair()?;
        assert!(validate_master(&slave).is_err());
        assert!(validate_master(std::fs::File::open("/dev/null")?).is_err());
        assert!(validate_master(tempfile::tempfile()?).is_err());
        assert_eq!(termios::tcgetwinsize(&slave)?.ws_col, 80);
        fs::fcntl_setfl(&master, fs::fcntl_getfl(&master)? & !fs::OFlags::NONBLOCK)?;
        assert!(validate_master(&master).is_err());
        fs::fcntl_setfl(&master, fs::fcntl_getfl(&master)? | fs::OFlags::NONBLOCK)?;
        rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::empty())?;
        assert!(validate_master(&master).is_err());
        Ok(())
    }
}
