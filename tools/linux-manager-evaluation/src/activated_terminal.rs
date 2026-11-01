//! Fixed final-exec target and gated shim for inner-PTY qualification.
//! No provider command, user environment or arbitrary executable is accepted.
use crate::{
    activated_guardian, activated_journal, admission_transport as transport, journal_protocol,
    require,
};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    termios,
};
use std::{
    fs,
    io::{self, Write},
    os::{fd::AsFd, unix::process::CommandExt},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub(crate) fn shim(prefix: &str, directory: &Path) -> io::Result<()> {
    activated_journal::gated_ready(prefix, directory)?;
    let deadline = Instant::now() + Duration::from_secs(18);
    let slave = transport::receive_until(io::stdin().as_fd(), deadline)?;
    let nonce = journal_protocol::receive_start(io::stdin().as_fd(), deadline)?;
    require(termios::isatty(&slave), "shim descriptor is not a terminal")?;
    rustix::process::setsid()?;
    // The safe ioctl uses argument zero: never steal a controlling terminal.
    rustix::process::ioctl_tiocsctty(&slave)?;
    termios::tcsetpgrp(&slave, rustix::process::getpgrp())?;
    fuxix::io::cloexec_from(3, fuxix::io::Listed::now()).map_err(io::Error::from)?;
    let mut command = Command::new("/proc/self/exe");
    command
        .args(["--activation-terminal-target", prefix])
        .arg(directory)
        .arg(journal_protocol::encoded(&nonce))
        .env_clear()
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave));
    activated_journal::fixture_environment(&mut command)?;
    // exec preserves the PID already bound by the client's retained pidfd.
    Err(command.exec())
}

fn line(deadline: Instant) -> io::Result<Vec<u8>> {
    let mut result = Vec::new();
    while result.len() < 256 {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "terminal input expired"))?;
        let timeout = Timespec::try_from(remaining).map_err(io::Error::other)?;
        let stdin = io::stdin();
        let mut ready = [PollFd::new(&stdin, PollFlags::IN)];
        require(
            poll(&mut ready, Some(&timeout))? == 1,
            "terminal input deadline expired",
        )?;
        let mut byte = [0_u8];
        require(
            rustix::io::read(&stdin, &mut byte)? == 1,
            "terminal input ended",
        )?;
        if byte[0] == b'\n' {
            return Ok(result);
        }
        result.push(byte[0]);
    }
    Err(io::Error::other("terminal fixture input exceeds bounds"))
}

pub(crate) fn target(prefix: &str, directory: &Path, nonce: &str) -> io::Result<()> {
    activated_guardian::writer_check(prefix, directory)?;
    require(
        nonce.len() == 32
            && nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid terminal nonce",
    )?;
    let pid = rustix::process::getpid();
    for stream in [
        io::stdin().as_fd(),
        io::stdout().as_fd(),
        io::stderr().as_fd(),
    ] {
        require(
            termios::isatty(stream)
                && termios::tcgetsid(stream)? == pid
                && termios::tcgetpgrp(stream)? == pid,
            "target does not own its controlling terminal",
        )?;
    }
    require(
        rustix::process::getsid(None)? == pid && rustix::process::getpgrp() == pid,
        "target session identity changed",
    )?;
    let saved = termios::tcgetattr(io::stdin())?;
    fs::write(
        directory.join("final-exec.tmp"),
        format!("{}:{nonce}", std::process::id()),
    )?;
    fs::rename(
        directory.join("final-exec.tmp"),
        directory.join("final-exec"),
    )?;
    let mut output = io::stdout().lock();
    writeln!(
        output,
        "\x1b[32mREADY:{}:{nonce}:→\x1b[0m",
        std::process::id()
    )?;
    output.flush()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match line(deadline)?.as_slice() {
            b"size" => {
                let size = termios::tcgetwinsize(io::stdin())?;
                writeln!(output, "SIZE:{}:{}", size.ws_row, size.ws_col)?;
            }
            b"secret" => {
                let mut hidden = saved.clone();
                hidden
                    .local_modes
                    .remove(termios::LocalModes::ECHO | termios::LocalModes::ECHONL);
                termios::tcsetattr(io::stdin(), termios::OptionalActions::Now, &hidden)?;
                write!(output, "SECRET>")?;
                output.flush()?;
                let input = line(deadline);
                termios::tcsetattr(io::stdin(), termios::OptionalActions::Now, &saved)?;
                require(!input?.is_empty(), "empty fixture secret")?;
                writeln!(output, "SECRET-OK")?;
            }
            b"raw" => {
                let mut raw = saved.clone();
                raw.make_raw();
                termios::tcsetattr(io::stdin(), termios::OptionalActions::Now, &raw)?;
                write!(output, "RAW>")?;
                output.flush()?;
                let input = line(deadline);
                termios::tcsetattr(io::stdin(), termios::OptionalActions::Now, &saved)?;
                let encoded: String = input?.iter().map(|b| format!("{b:02x}")).collect();
                writeln!(output, "RAW:{encoded}")?;
            }
            _ => return Err(io::Error::other("unknown fixed terminal command")),
        }
        output.flush()?;
    }
}
