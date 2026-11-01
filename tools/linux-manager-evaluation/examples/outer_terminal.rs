//! Fixed command probe; only the owned-PTY Python harness may run it.
#![forbid(unsafe_code)]
#[path = "../src/outer_terminal.rs"]
mod outer_terminal;
use outer_terminal::{Signals, Terminal, require};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    termios,
};
use std::{
    collections::VecDeque,
    fs, io,
    path::Path,
    time::{Duration, Instant},
};

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
