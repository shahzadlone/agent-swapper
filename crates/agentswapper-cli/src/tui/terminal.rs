//! Keep a lost terminal's cursor cleanup from panicking through stderr.
use std::{
    cell::Cell,
    io::{self, Write},
    ops::{Deref, DerefMut},
    rc::Rc,
};

use ratatui::{Terminal, backend::CrosstermBackend};

pub(super) struct CleanupWriter<W> {
    writer: W,
    cleanup: Rc<Cell<bool>>,
}

impl<W: Write> Write for CleanupWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self.writer.write(bytes) {
            Err(_) if self.cleanup.get() => Ok(bytes.len()),
            result => result,
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.writer.flush() {
            Err(_) if self.cleanup.get() => Ok(()),
            result => result,
        }
    }
}

pub(super) struct DashboardTerminal {
    inner: Terminal<CrosstermBackend<CleanupWriter<io::Stdout>>>,
    cleanup: Rc<Cell<bool>>,
}

impl DashboardTerminal {
    pub(super) fn new() -> io::Result<Self> {
        let cleanup = Rc::new(Cell::new(false));
        Ok(Self {
            inner: Terminal::new(CrosstermBackend::new(CleanupWriter {
                writer: io::stdout(),
                cleanup: Rc::clone(&cleanup),
            }))?,
            cleanup,
        })
    }
}

impl Deref for DashboardTerminal {
    type Target = Terminal<CrosstermBackend<CleanupWriter<io::Stdout>>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for DashboardTerminal {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Drop for DashboardTerminal {
    fn drop(&mut self) {
        // Ratatui's Terminal destructor prints a cursor-restoration failure
        // with eprintln!, which itself panics if stderr is also disconnected.
        // Only this destructor's output becomes best-effort. Active rendering
        // still returns its original I/O error, and our independent Restore
        // guard always attempts raw-mode/alternate-screen restoration.
        self.cleanup.set(true);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    struct Disconnected;
    impl Write for Disconnected {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }

    #[test]
    fn active_output_errors_propagate_and_cursor_cleanup_is_best_effort() {
        let mut output = CleanupWriter {
            writer: Disconnected,
            cleanup: Rc::new(Cell::new(false)),
        };
        assert_eq!(
            output.write_all(b"frame").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            output.flush().unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        output.cleanup.set(true);
        output.write_all(b"\x1b[?25h").unwrap();
        output.flush().unwrap();
    }
}
