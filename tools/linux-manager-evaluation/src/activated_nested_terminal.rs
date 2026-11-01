//! Fixed nested foreground job: its parent target handles its stop locally.
use crate::{
    activated_guardian, activated_journal, activated_terminal, job_control::OwnedChild, require,
};
use nix::sys::{
    signal::{SigSet, SigmaskHow, Signal},
    wait::WaitStatus,
};
use std::{
    fs,
    io::{self, Write},
    os::{fd::AsFd, unix::process::CommandExt},
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};

struct OutputSignalMask(Option<SigSet>);
impl OutputSignalMask {
    fn block() -> io::Result<Self> {
        let mut mask = SigSet::empty();
        mask.add(Signal::SIGTTOU);
        Ok(Self(Some(mask.thread_swap_mask(SigmaskHow::SIG_BLOCK)?)))
    }
    fn restore(mut self) -> io::Result<()> {
        if let Some(mask) = &self.0 {
            mask.thread_set_mask()?;
        }
        self.0 = None;
        Ok(())
    }
}
impl Drop for OutputSignalMask {
    fn drop(&mut self) {
        if let Some(mask) = &self.0 {
            let _ = mask.thread_set_mask();
        }
    }
}

pub(crate) fn run(prefix: &str, directory: &Path, output: &mut impl Write) -> io::Result<()> {
    require(
        !directory.join("nested-ready").try_exists()?,
        "nested fixture already ran",
    )?;
    let mut command = Command::new("/proc/self/exe");
    command
        .args(["--activation-nested-child", prefix])
        .arg(directory)
        .env_clear()
        .process_group(0);
    activated_journal::fixture_environment(&mut command)?;
    let mut child = OwnedChild::new(command.spawn()?)?;
    drop(command);
    activated_guardian::wait_until(Instant::now() + Duration::from_secs(3), || {
        require(
            child.poll()? == WaitStatus::StillAlive,
            "nested child changed state before readiness",
        )?;
        match fs::read_to_string(directory.join("nested-ready")) {
            Ok(pid) => {
                require(pid == child.pid.to_string(), "nested readiness PID differs")?;
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    })?;
    let own = rustix::process::getpgrp();
    let nested = rustix::process::Pid::from_raw(child.pid.as_raw())
        .ok_or_else(|| io::Error::other("invalid nested group"))?;
    let mask = OutputSignalMask::block()?;
    rustix::termios::tcsetpgrp(io::stdin(), nested)?;
    writeln!(output, "NESTED-RUNNING:{}", child.pid)?;
    output.flush()?;
    mask.restore()?;
    require(
        child.next(Instant::now() + Duration::from_secs(8))?
            == WaitStatus::Stopped(child.pid, Signal::SIGTSTP),
        "nested foreground job did not stop",
    )?;
    let mask = OutputSignalMask::block()?;
    rustix::termios::tcsetpgrp(io::stdin(), own)?;
    mask.restore()?;
    writeln!(output, "NESTED-STOPPED:{}", child.pid)?;
    output.flush()?;
    require(
        activated_terminal::line(io::stdin().as_fd(), Instant::now() + Duration::from_secs(8))?
            == b"resume-nested",
        "unknown fixed nested resume command",
    )?;
    let mask = OutputSignalMask::block()?;
    rustix::termios::tcsetpgrp(io::stdin(), nested)?;
    child.resume()?;
    mask.restore()?;
    fs::write(directory.join("nested-exit"), "resume")?;
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        match child.next(until)? {
            WaitStatus::Continued(_) => {}
            WaitStatus::Exited(_, 0) => break,
            _ => return Err(io::Error::other("nested job did not exit normally")),
        }
    }
    let mask = OutputSignalMask::block()?;
    rustix::termios::tcsetpgrp(io::stdin(), own)?;
    mask.restore()?;
    writeln!(output, "NESTED-DONE")?;
    output.flush()
}

pub(crate) fn child(prefix: &str, directory: &Path) -> io::Result<()> {
    activated_guardian::writer_check(prefix, directory)?;
    crate::job_control::target_signals()?;
    let own = rustix::process::getpid();
    let parent =
        rustix::process::getppid().ok_or_else(|| io::Error::other("nested parent absent"))?;
    let session = rustix::process::getsid(None)?;
    require(
        rustix::process::getpgrp() == own && session != own && session != parent,
        "nested child is outside its guardian session",
    )?;
    for stream in [
        io::stdin().as_fd(),
        io::stdout().as_fd(),
        io::stderr().as_fd(),
    ] {
        crate::terminal::validate_slave(stream)?;
        require(
            rustix::termios::tcgetsid(stream)? == session
                && rustix::termios::tcgetpgrp(stream)? == parent,
            "nested child did not inherit the inner terminal",
        )?;
    }
    fs::write(directory.join("nested-ready.tmp"), own.to_string())?;
    fs::rename(
        directory.join("nested-ready.tmp"),
        directory.join("nested-ready"),
    )?;
    let until = Instant::now() + Duration::from_secs(25);
    while !directory.join("nested-exit").try_exists()? {
        require(
            Instant::now() < until,
            "nested job exceeded its fixture lifetime",
        )?;
        thread::sleep(Duration::from_millis(10));
    }
    require(
        rustix::termios::tcgetpgrp(io::stdin())? == own,
        "nested job was not resumed in foreground",
    )
}
