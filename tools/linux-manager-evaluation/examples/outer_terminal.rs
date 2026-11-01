//! Fresh-process outer-terminal fixture. Only tools/check_linux_outer_terminal.py
//! creates its owned terminal and admission record. No provider or inner relay.
#![forbid(unsafe_code)]
use nix::sys::{
    signal::{SigSet, SigmaskHow, Signal, raise},
    signalfd::{SfdFlags, SignalFd},
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{Mode, OFlags},
    termios,
};
use std::{
    collections::VecDeque,
    fs, io,
    os::{
        fd::{AsFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    time::{Duration, Instant},
};

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
const SIGNALS: [Signal; 8] = [
    Signal::SIGINT,
    Signal::SIGTERM,
    Signal::SIGHUP,
    Signal::SIGQUIT,
    Signal::SIGTSTP,
    Signal::SIGCONT,
    Signal::SIGWINCH,
    Signal::SIGCHLD,
];

#[derive(Default)]
struct Notices {
    terminate: Option<Signal>,
    stop: bool,
    continued: bool,
    resized: bool,
}
struct Signals {
    file: SignalFd,
    saved: SigSet,
}
impl Signals {
    fn new() -> io::Result<Self> {
        require(
            fs::read_dir("/proc/self/task")?.count() == 1,
            "signal fixture must start single-threaded",
        )?;
        let status = fs::read_to_string("/proc/self/status")?;
        let bits = SIGNALS
            .iter()
            .fold(0_u64, |bits, s| bits | (1 << (*s as u32 - 1)));
        for name in ["SigIgn:", "SigCgt:", "SigBlk:"] {
            let field = status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .ok_or_else(|| io::Error::other("missing signal witness"))?;
            require(
                u64::from_str_radix(field.trim(), 16).map_err(io::Error::other)? & bits == 0,
                "outer fixture requires default unblocked signal state",
            )?;
        }
        let mut mask = SigSet::empty();
        for signal in SIGNALS {
            mask.add(signal);
        }
        let saved = mask.thread_swap_mask(SigmaskHow::SIG_BLOCK)?;
        match SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK) {
            Ok(file) => Ok(Self { file, saved }),
            Err(error) => {
                saved.thread_set_mask()?;
                Err(error.into())
            }
        }
    }
    fn drain(&self) -> io::Result<Notices> {
        let mut notices = Notices::default();
        for _ in 0..16 {
            let Some(info) = self.file.read_signal()? else {
                break;
            };
            match Signal::try_from(i32::try_from(info.ssi_signo).map_err(io::Error::other)?)? {
                signal @ (Signal::SIGINT | Signal::SIGTERM | Signal::SIGHUP | Signal::SIGQUIT) => {
                    notices.terminate.get_or_insert(signal);
                }
                Signal::SIGTSTP => notices.stop = true,
                Signal::SIGCONT => notices.continued = true,
                Signal::SIGWINCH => notices.resized = true,
                Signal::SIGCHLD => {}
                _ => return Err(io::Error::other("unexpected outer fixture signal")),
            }
        }
        Ok(notices)
    }
    fn suspend(&self) -> io::Result<Notices> {
        let before = self.drain()?;
        if before.terminate.is_some() {
            return Ok(before);
        }
        let mut stop = SigSet::empty();
        stop.add(Signal::SIGTSTP);
        let saved = stop.thread_swap_mask(SigmaskHow::SIG_UNBLOCK)?;
        let result = raise(Signal::SIGTSTP);
        let restored = saved.thread_set_mask();
        result?;
        restored?;
        // SIGCONT resumes a process even while blocked. A discarded orphaned
        // SIGTSTP returns without a corresponding continuation notification.
        self.drain()
    }
    fn finish(self, termination: Option<Signal>) -> io::Result<()> {
        drop(self);
        if let Some(signal) = termination {
            raise(signal)?;
        }
        Ok(())
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        let _ = self.saved.thread_set_mask();
    }
}

struct Terminal {
    fd: OwnedFd,
    saved: termios::Termios,
    group: rustix::process::Pid,
    raw: bool,
}
impl Terminal {
    fn capture(directory: &Path) -> io::Result<Self> {
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
            group == rustix::process::getpid() && termios::tcgetpgrp(&fd)? == group,
            "outer probe is not its foreground job leader",
        )?;
        Ok(Self {
            saved: termios::tcgetattr(&fd)?,
            fd,
            group,
            raw: false,
        })
    }
    fn foreground(&self) -> io::Result<bool> {
        Ok(termios::tcgetpgrp(&self.fd)? == self.group && rustix::process::getpgrp() == self.group)
    }
    fn enter(&mut self) -> io::Result<()> {
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
    fn restore(&mut self) -> io::Result<()> {
        if self.raw {
            require(
                self.foreground()?,
                "cannot restore another foreground job's terminal",
            )?;
            termios::tcsetattr(&self.fd, termios::OptionalActions::Now, &self.saved)?;
            self.raw = false;
        }
        Ok(())
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

fn marker(directory: &Path, name: &str, value: &str) -> io::Result<()> {
    fs::write(directory.join(format!("{name}.tmp")), value)?;
    fs::rename(directory.join(format!("{name}.tmp")), directory.join(name))
}
fn run(directory: &Path) -> io::Result<()> {
    // Declaration order ensures terminal restoration before the signal mask
    // is restored on every error path, including pending fatal signals.
    let signals = Signals::new()?;
    let mut terminal = Terminal::capture(directory)?;
    let status = serde_json::json!({"pid": std::process::id(), "group": terminal.group.as_raw_pid(), "session": rustix::process::getsid(None)?.as_raw_pid()});
    marker(directory, "ready", &status.to_string())?;
    terminal.enter()?;
    let mut output: VecDeque<u8> = b"OUTER-READY\r\n".iter().copied().collect();
    let mut input = Vec::new();
    let mut flood = 0_usize;
    let mut backpressured = false;
    let mut suspended = false;
    let mut want_stop = false;
    let mut terminated = None;
    let until = Instant::now() + Duration::from_secs(40);
    'relay: loop {
        require(
            Instant::now() < until,
            "outer fixture exceeded its lifetime",
        )?;
        let notices = signals.drain()?;
        if let Some(signal) = notices.terminate {
            terminated = Some(signal);
            break;
        }
        want_stop |= notices.stop;
        if notices.resized {
            let size = termios::tcgetwinsize(&terminal.fd)?;
            marker(
                directory,
                "size",
                &format!("{}:{}", size.ws_row, size.ws_col),
            )?;
        }
        if terminal.raw && terminal.foreground()? {
            while let Some(index) = input.iter().position(|byte| *byte == b'\n') {
                let command: Vec<_> = input.drain(..=index).collect();
                match &command[..command.len() - 1] {
                    b"exit" => break 'relay,
                    b"stop" => {
                        want_stop = true;
                        break;
                    }
                    b"flood" => {
                        flood = 1024 * 1024;
                        marker(directory, "flood", "started")?;
                    }
                    b"fail" => return Err(io::Error::other("intentional owned terminal failure")),
                    bytes => {
                        let encoded: String =
                            bytes.iter().map(|byte| format!("{byte:02x}")).collect();
                        let response = format!("DATA:{encoded}\r\n");
                        require(
                            output.len() + response.len() <= 17_000,
                            "outer output budget exhausted",
                        )?;
                        output.extend(response.as_bytes());
                    }
                }
            }
        }
        if want_stop && terminal.foreground()? {
            terminal.restore()?;
            marker(directory, "restored-before-stop", "restored")?;
            let resumed = signals.suspend()?;
            if let Some(signal) = resumed.terminate {
                terminated = Some(signal);
                break;
            }
            suspended = true;
            want_stop = false;
            marker(
                directory,
                if resumed.continued {
                    "continued"
                } else {
                    "discarded-stop"
                },
                "observed",
            )?;
        }
        if suspended && terminal.foreground()? {
            terminal.enter()?;
            suspended = false;
            output.extend(b"OUTER-RESUMED\r\n");
            marker(directory, "resumed-foreground", "raw")?;
        }
        let foreground = terminal.foreground()?;
        require(
            !terminal.raw || foreground,
            "outer foreground changed during raw mode",
        )?;
        if foreground && terminal.raw {
            let count = flood.min(16_384_usize.saturating_sub(output.len()));
            output.extend(std::iter::repeat_n(b'x', count));
            flood -= count;
        }
        require(
            output.len() <= 17_000 && input.len() <= 256,
            "outer fixture buffering exceeded bounds",
        )?;
        let mut events = PollFlags::empty();
        if foreground && terminal.raw {
            if input.len() < 256 {
                events |= PollFlags::IN;
            }
            if !output.is_empty() {
                events |= PollFlags::OUT;
            }
        }
        let mut watched = [
            PollFd::new(&terminal.fd, events),
            PollFd::new(&signals.file, PollFlags::IN),
        ];
        let count = match poll(
            &mut watched,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 50_000_000,
            }),
        ) {
            Err(rustix::io::Errno::INTR) => continue,
            value => value?,
        };
        if count == 0
            && !backpressured
            && flood > 0
            && !output.is_empty()
            && foreground
            && terminal.raw
        {
            marker(directory, "backpressure", &output.len().to_string())?;
            backpressured = true;
        }
        let revents = watched[0].revents();
        require(
            !revents.intersects(PollFlags::ERR | PollFlags::NVAL),
            "outer terminal polling failed",
        )?;
        if revents.contains(PollFlags::HUP) {
            break;
        }
        if revents.contains(PollFlags::OUT) {
            match rustix::io::write(&terminal.fd, output.make_contiguous()) {
                Ok(count) => {
                    require(count > 0, "zero-byte terminal write")?;
                    output.drain(..count);
                }
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            }
        }
        if revents.contains(PollFlags::IN) {
            let mut bytes = [0_u8; 128];
            let capacity = bytes.len().min(256 - input.len());
            let count = match rustix::io::read(&terminal.fd, &mut bytes[..capacity]) {
                Ok(0) => break,
                Ok(count) => count,
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => continue,
                Err(error) => return Err(error.into()),
            };
            input.extend_from_slice(&bytes[..count]);
            require(
                input.len() < 256 || input.contains(&b'\n'),
                "outer input budget exhausted",
            )?;
        }
    }
    terminal.restore()?;
    marker(directory, "restored", "complete")?;
    drop(terminal);
    signals.finish(terminated)
}
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    let result = match args.as_slice() {
        [_, path] => run(Path::new(path)),
        _ => Err(io::Error::other(
            "requires the owned outer-terminal harness",
        )),
    };
    if let Err(error) = result {
        eprintln!("outer terminal fixture: {error}");
        std::process::exit(125);
    }
}
