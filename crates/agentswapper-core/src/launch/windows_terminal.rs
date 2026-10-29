//! Restore console modes through owned handles after an observed child exit.
use std::{
    fs::{File, OpenOptions},
    io::{self, IsTerminal},
    os::windows::io::AsHandle,
};

use winapi_util::console;
use windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE;
use windows_sys::Win32::System::Console::ENABLE_VIRTUAL_TERMINAL_PROCESSING;

struct ConsoleMode {
    handle: File,
    mode: u32,
    output: bool,
}

/// Original modes of owned console handles. This does not establish exclusive
/// console ownership or restore screen-buffer contents.
pub struct ConsoleSnapshot {
    modes: Vec<ConsoleMode>,
}

impl ConsoleSnapshot {
    pub fn capture() -> io::Result<Option<Self>> {
        let mut modes = Vec::new();
        Self::capture_stream(&io::stdin(), false, &mut modes)?;
        Self::capture_stream(&io::stdout(), true, &mut modes)?;
        Self::capture_stream(&io::stderr(), true, &mut modes)?;
        // An attached agent can open its console even with redirected standard
        // streams. Also retain its input/output buffers through owned handles.
        for (name, output) in [(r"\\.\CONIN$", false), (r"\\.\CONOUT$", true)] {
            let handle = match OpenOptions::new().read(true).write(true).open(name) {
                Ok(handle) => handle,
                Err(error)
                    if error.kind() == io::ErrorKind::NotFound
                        || error.raw_os_error() == Some(ERROR_INVALID_HANDLE as i32) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            modes.push(ConsoleMode {
                mode: console::mode(&handle)?,
                handle,
                output,
            });
        }
        Ok((!modes.is_empty()).then_some(Self { modes }))
    }

    fn capture_stream(
        stream: &(impl AsHandle + IsTerminal),
        output: bool,
        modes: &mut Vec<ConsoleMode>,
    ) -> io::Result<()> {
        if stream.is_terminal() {
            let handle = File::from(stream.as_handle().try_clone_to_owned()?);
            modes.push(ConsoleMode {
                mode: console::mode(&handle)?,
                handle,
                output,
            });
        }
        Ok(())
    }

    /// Enable VT parsing for this dashboard phase. Crossterm caches ANSI
    /// support, so a later phase must enable it again after restoring modes.
    /// Native launch consumers do not call this method.
    pub fn enable_ansi_output(&self) -> io::Result<()> {
        for captured in &self.modes {
            if captured.output {
                let mode = console::mode(&captured.handle)?;
                console::set_mode(&captured.handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)?;
            }
        }
        Ok(())
    }

    pub fn restore(self) -> io::Result<()> {
        let mut failure = None;
        for captured in self.modes {
            // Attempt every captured buffer even when one restoration fails.
            let restored = console::set_mode(&captured.handle, captured.mode).and_then(|()| {
                if console::mode(&captured.handle)? != captured.mode {
                    return Err(io::Error::other("console mode restoration did not persist"));
                }
                Ok(())
            });
            if let Err(error) = restored {
                failure.get_or_insert(error);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
