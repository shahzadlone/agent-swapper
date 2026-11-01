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
    os::{
        fd::{AsFd, BorrowedFd},
        unix::process::CommandExt,
    },
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub(crate) fn shim(prefix: &str, directory: &Path, guardian_session: bool) -> io::Result<()> {
    if guardian_session {
        crate::job_control::dispositions()?;
        let mask = nix::sys::signal::SigSet::thread_get_mask()?;
        require(
            crate::job_control::JOB_SIGNALS
                .into_iter()
                .all(|signal| mask.contains(signal)),
            "job shim did not inherit the blocked guardian mask",
        )?;
    }
    activated_journal::gated_ready(prefix, directory)?;
    let deadline = Instant::now() + Duration::from_secs(18);
    let slave = transport::receive_until(io::stdin().as_fd(), deadline)?;
    let nonce = journal_protocol::receive_start(io::stdin().as_fd(), deadline)?;
    crate::terminal::validate_slave(&slave)?;
    if guardian_session {
        let parent =
            rustix::process::getppid().ok_or_else(|| io::Error::other("guardian absent"))?;
        let own = rustix::process::getpid();
        require(
            rustix::process::getsid(None)? == parent
                && rustix::process::getpgrp() == own
                && termios::tcgetsid(&slave)? == parent
                && termios::tcgetpgrp(&slave)? == own,
            "job shim did not receive its foreground terminal",
        )?;
    } else {
        rustix::process::setsid()?;
        // The safe ioctl uses argument zero: never steal a controlling terminal.
        rustix::process::ioctl_tiocsctty(&slave)?;
        termios::tcsetpgrp(&slave, rustix::process::getpgrp())?;
    }
    fuxix::io::cloexec_from(3, fuxix::io::Listed::now()).map_err(io::Error::from)?;
    let mut command = Command::new("/proc/self/exe");
    command
        .args([
            if guardian_session {
                "--activation-job-target"
            } else {
                "--activation-terminal-target"
            },
            prefix,
        ])
        .arg(directory)
        .arg(journal_protocol::encoded(&nonce))
        .env_clear()
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave));
    activated_journal::fixture_environment(&mut command)?;
    if guardian_session {
        use nix::sys::signal::{SigSet, SigmaskHow, pthread_sigmask};
        pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&SigSet::empty()), None)?;
    }
    // exec preserves the PID already bound by the client's retained pidfd.
    Err(command.exec())
}

pub(crate) fn line(input: BorrowedFd<'_>, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut result = Vec::new();
    while result.len() < 256 {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "terminal input expired"))?;
        let timeout = Timespec::try_from(remaining).map_err(io::Error::other)?;
        let mut ready = [PollFd::new(&input, PollFlags::IN)];
        let polled = match poll(&mut ready, Some(&timeout)) {
            Err(rustix::io::Errno::INTR) => continue,
            value => value?,
        };
        if polled != 1 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "terminal input deadline expired",
            ));
        }
        let mut byte = [0_u8];
        let count = match rustix::io::read(input, &mut byte) {
            Err(rustix::io::Errno::INTR) => continue,
            value => value?,
        };
        if count != 1 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "terminal input ended",
            ));
        }
        if byte[0] == b'\n' {
            return Ok(result);
        }
        result.push(byte[0]);
    }
    Err(io::Error::other("terminal fixture input exceeds bounds"))
}

struct ModeGuard<'a> {
    input: BorrowedFd<'a>,
    saved: Option<termios::Termios>,
}
impl<'a> ModeGuard<'a> {
    fn apply(input: BorrowedFd<'a>, mode: &termios::Termios) -> io::Result<Self> {
        let saved = termios::tcgetattr(input)?;
        termios::tcsetattr(input, termios::OptionalActions::Now, mode)?;
        Ok(Self {
            input,
            saved: Some(saved),
        })
    }
    fn restore(mut self) -> io::Result<()> {
        if let Some(saved) = &self.saved {
            termios::tcsetattr(self.input, termios::OptionalActions::Now, saved)?;
        }
        self.saved = None;
        Ok(())
    }
}
impl Drop for ModeGuard<'_> {
    fn drop(&mut self) {
        if let Some(saved) = &self.saved {
            let _ = termios::tcsetattr(self.input, termios::OptionalActions::Now, saved);
        }
    }
}

fn mode_line(
    input: BorrowedFd<'_>,
    output: &mut impl Write,
    mode: &termios::Termios,
    prompt: &[u8],
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    let guard = ModeGuard::apply(input, mode)?;
    output.write_all(prompt)?;
    output.flush()?;
    let result = line(input, deadline);
    guard.restore()?;
    result
}

pub(crate) fn target(
    prefix: &str,
    directory: &Path,
    nonce: &str,
    guardian_session: bool,
) -> io::Result<()> {
    activated_guardian::writer_check(prefix, directory)?;
    require(
        nonce.len() == 32
            && nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid terminal nonce",
    )?;
    let pid = rustix::process::getpid();
    let session = if guardian_session {
        crate::job_control::target_signals()?;
        rustix::process::getppid().ok_or_else(|| io::Error::other("guardian absent"))?
    } else {
        pid
    };
    let input_stat = rustix::fs::fstat(io::stdin())?;
    for stream in [
        io::stdin().as_fd(),
        io::stdout().as_fd(),
        io::stderr().as_fd(),
    ] {
        crate::terminal::validate_slave(stream)?;
        let stat = rustix::fs::fstat(stream)?;
        require(
            stat.st_dev == input_stat.st_dev
                && stat.st_ino == input_stat.st_ino
                && stat.st_rdev == input_stat.st_rdev
                && termios::tcgetsid(stream)? == session
                && termios::tcgetpgrp(stream)? == pid,
            "target does not own its controlling terminal",
        )?;
    }
    require(
        rustix::process::getsid(None)? == session && rustix::process::getpgrp() == pid,
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
    let mut descendant = None;
    loop {
        match line(io::stdin().as_fd(), deadline)?.as_slice() {
            b"finish" if guardian_session => {
                output.write_all("FINAL:\u{1b}[34m→\u{1b}[0m\n".as_bytes())?;
                output.flush()?;
                return Ok(());
            }
            b"flood" if guardian_session => {
                fs::write(directory.join("flood-started"), "fixed 1 MiB")?;
                for _ in 0..256 {
                    output.write_all(&[b'x'; 4096])?;
                }
            }
            b"nested" if guardian_session => {
                crate::activated_nested_terminal::run(prefix, directory, &mut output)?;
            }
            b"spawn" if guardian_session => {
                require(descendant.is_none(), "fixed descendant already exists")?;
                let mut command = Command::new("/proc/self/exe");
                command
                    .args(["--activation-job-descendant", prefix])
                    .arg(directory)
                    .env_clear();
                activated_journal::fixture_environment(&mut command)?;
                let mut child = command.spawn()?;
                drop(command);
                activated_guardian::wait_until(Instant::now() + Duration::from_secs(3), || {
                    require(
                        child.try_wait()?.is_none(),
                        "fixed descendant exited before readiness",
                    )?;
                    match fs::read_to_string(directory.join("descendant-ready")) {
                        Ok(pid) => {
                            require(
                                pid == child.id().to_string(),
                                "descendant readiness PID differs",
                            )?;
                            Ok(true)
                        }
                        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
                        Err(error) => Err(error),
                    }
                })?;
                writeln!(output, "CHILD:{}", child.id())?;
                // Never signal or reap this descendant after readiness. The
                // hosted case must observe manager-owned scope retirement.
                descendant = Some(child);
            }
            b"suspend" if guardian_session => {
                let mut raw = saved.clone();
                raw.make_raw();
                let input = io::stdin();
                let guard = ModeGuard::apply(input.as_fd(), &raw)?;
                output.write_all(b"SUSPEND>")?;
                output.flush()?;
                nix::sys::signal::raise(nix::sys::signal::Signal::SIGTSTP)?;
                guard.restore()?;
                writeln!(output, "RESUMED")?;
            }
            b"size" => {
                let size = termios::tcgetwinsize(io::stdin())?;
                writeln!(output, "SIZE:{}:{}", size.ws_row, size.ws_col)?;
            }
            b"secret" => {
                let mut hidden = saved.clone();
                hidden
                    .local_modes
                    .remove(termios::LocalModes::ECHO | termios::LocalModes::ECHONL);
                let input = mode_line(
                    io::stdin().as_fd(),
                    &mut output,
                    &hidden,
                    b"SECRET>",
                    deadline,
                )?;
                require(!input.is_empty(), "empty fixture secret")?;
                writeln!(output, "SECRET-OK")?;
            }
            b"raw" => {
                let mut raw = saved.clone();
                raw.make_raw();
                let input = mode_line(io::stdin().as_fd(), &mut output, &raw, b"RAW>", deadline)?;
                let encoded: String = input.iter().map(|b| format!("{b:02x}")).collect();
                writeln!(output, "RAW:{encoded}")?;
            }
            _ => return Err(io::Error::other("unknown fixed terminal command")),
        }
        output.flush()?;
    }
}

pub(crate) fn descendant(prefix: &str, directory: &Path) -> io::Result<()> {
    use nix::sys::signal::{SigSet, Signal};
    activated_guardian::writer_check(prefix, directory)?;
    crate::job_control::target_signals()?;
    require(
        nix::sys::prctl::get_pdeathsig()?.is_none(),
        "descendant inherited a parent-death signal",
    )?;
    let parent =
        rustix::process::getppid().ok_or_else(|| io::Error::other("target parent absent"))?;
    let group = rustix::process::getpgrp();
    let session = rustix::process::getsid(None)?;
    require(
        group == parent && session != parent && session != rustix::process::getpid(),
        "descendant is outside its target group",
    )?;
    for stream in [
        io::stdin().as_fd(),
        io::stdout().as_fd(),
        io::stderr().as_fd(),
    ] {
        crate::terminal::validate_slave(stream)?;
        require(
            termios::tcgetsid(stream)? == session && termios::tcgetpgrp(stream)? == group,
            "descendant did not inherit the inner terminal",
        )?;
    }
    // A blocked SIGHUP prevents terminal/session loss from being an alternate
    // explanation for descendant death. No parent-death signal or destructor
    // cleanup is installed; the root manager must retire this writer.
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGHUP);
    mask.thread_block()?;
    fs::write(
        directory.join("descendant-ready.tmp"),
        std::process::id().to_string(),
    )?;
    fs::rename(
        directory.join("descendant-ready.tmp"),
        directory.join("descendant-ready"),
    )?;
    let until = Instant::now() + Duration::from_secs(45);
    let mut counter = 0_u64;
    while Instant::now() < until {
        fs::write(
            directory.join("descendant-heartbeat.tmp"),
            counter.to_string(),
        )?;
        fs::rename(
            directory.join("descendant-heartbeat.tmp"),
            directory.join("descendant-heartbeat"),
        )?;
        counter += 1;
        std::thread::sleep(Duration::from_millis(20));
    }
    fs::write(directory.join("descendant-voluntary-exit"), "deadline")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn same_mode(actual: termios::Termios, expected: &termios::Termios) {
        assert_eq!(actual.input_modes, expected.input_modes);
        assert_eq!(actual.output_modes, expected.output_modes);
        assert_eq!(actual.control_modes, expected.control_modes);
        assert_eq!(actual.local_modes, expected.local_modes);
        assert_eq!(
            format!("{:?}", actual.special_codes),
            format!("{:?}", expected.special_codes)
        );
        assert_eq!(actual.input_speed(), expected.input_speed());
        assert_eq!(actual.output_speed(), expected.output_speed());
    }
    #[test]
    fn bounded_input_restores_modes_on_timeout_overflow_and_prompt_failure() -> io::Result<()> {
        let (master, slave) = crate::terminal::pair()?;
        let original = termios::tcgetattr(&slave)?;
        let mut raw = original.clone();
        raw.make_raw();
        let error = mode_line(
            slave.as_fd(),
            &mut Vec::new(),
            &raw,
            b"RAW>",
            Instant::now() + Duration::from_millis(20),
        )
        .err()
        .ok_or_else(|| io::Error::other("timeout accepted"))?;
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        same_mode(termios::tcgetattr(&slave)?, &original);
        // A read-only regular file fails the prompt write after mode entry.
        let path = tempfile::NamedTempFile::new()?;
        let error = mode_line(
            slave.as_fd(),
            &mut fs::File::open(path.path())?,
            &raw,
            b"RAW>",
            Instant::now() + Duration::from_secs(1),
        )
        .err()
        .ok_or_else(|| io::Error::other("prompt write unexpectedly succeeded"))?;
        assert_eq!(
            error.raw_os_error(),
            Some(rustix::io::Errno::BADF.raw_os_error())
        );
        same_mode(termios::tcgetattr(&slave)?, &original);
        rustix::io::write(&master, &[b'x'; 256])?;
        let error = mode_line(
            slave.as_fd(),
            &mut Vec::new(),
            &raw,
            b"RAW>",
            Instant::now() + Duration::from_secs(1),
        )
        .err()
        .ok_or_else(|| io::Error::other("oversized input accepted"))?;
        assert_eq!(error.to_string(), "terminal fixture input exceeds bounds");
        same_mode(termios::tcgetattr(&slave)?, &original);
        drop(master);
        let error = line(slave.as_fd(), Instant::now() + Duration::from_secs(1))
            .err()
            .ok_or_else(|| io::Error::other("hangup accepted as input"))?;
        assert!(
            error.kind() == io::ErrorKind::UnexpectedEof
                || error.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error())
        );
        Ok(())
    }
}
