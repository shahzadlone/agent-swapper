//! Signal handlers only set an atomic. Restoration runs in the terminal event loop.
use signal_hook::{
    SigId,
    consts::signal::{SIGHUP, SIGINT, SIGTERM},
    flag, low_level,
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

pub(crate) struct TerminalSignals {
    signal: Arc<AtomicUsize>,
    registrations: Vec<SigId>,
}

impl TerminalSignals {
    pub(crate) fn install() -> io::Result<Self> {
        let mut guard = Self {
            signal: Arc::new(AtomicUsize::new(0)),
            registrations: Vec::new(),
        };
        for signal in [SIGINT, SIGTERM, SIGHUP] {
            guard.registrations.push(flag::register_usize(
                signal,
                Arc::clone(&guard.signal),
                signal as usize,
            )?);
        }
        Ok(guard)
    }

    pub(crate) fn requested(&self) -> bool {
        self.signal.load(Ordering::Relaxed) != 0
    }

    // Called after the terminal and Restore guard have been dropped. Preserve
    // signal termination for shells that distinguish it from an exit code.
    pub(crate) fn finish(self) -> io::Result<()> {
        let signal = self.signal.load(Ordering::Relaxed);
        drop(self);
        if signal != 0 {
            low_level::emulate_default_handler(i32::try_from(signal).map_err(io::Error::other)?)?;
        }
        Ok(())
    }
}

impl Drop for TerminalSignals {
    fn drop(&mut self) {
        for registration in self.registrations.drain(..) {
            low_level::unregister(registration);
        }
    }
}
