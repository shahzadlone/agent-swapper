//! Provider-free exec-event spike. Only this executable's fixed child is traced.
//! No installed service, external PID, arbitrary target or custody receipt.
#![forbid(unsafe_code)]
use agentswapper_linux_runtime::admission_transport as transport;

use nix::{
    sys::{
        ptrace,
        signal::{Signal, raise},
        wait::WaitStatus,
    },
    unistd::Pid,
};
use std::{
    fs, io,
    marker::PhantomData,
    os::{
        fd::{AsFd, OwnedFd},
        unix::process::CommandExt,
    },
    path::Path,
    process::{Child, Command, Stdio},
    rc::Rc,
    thread,
    time::{Duration, Instant},
};

const READY: &[u8] = b"ASWP-TRACE-READY-1";

fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

struct TraceChild {
    child: Child,
    pid: Pid,
    reaped: bool,
    _same_thread: PhantomData<Rc<()>>,
}
impl TraceChild {
    fn owned(child: Child) -> io::Result<Self> {
        let pid = Pid::from_raw(i32::try_from(child.id()).map_err(io::Error::other)?);
        Ok(Self {
            child,
            pid,
            reaped: false,
            _same_thread: PhantomData,
        })
    }
    fn spawn(mode: &str, directory: &Path) -> io::Result<(Self, OwnedFd)> {
        let (control, input) = transport::pair()?;
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args(["--shim", mode])
            .arg(directory)
            .env_clear()
            .stdin(Stdio::from(input))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command.spawn()?;
        drop(command);
        Ok((Self::owned(child)?, control))
    }
    fn next(&mut self, deadline: Instant) -> io::Result<WaitStatus> {
        require(!self.reaped, "cannot wait on a reaped tracee")?;
        loop {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "exec-event wait expired",
                ));
            }
            let pid = rustix::process::Pid::from_raw(self.pid.as_raw())
                .ok_or_else(|| io::Error::other("invalid tracee PID"))?;
            let (observed, raw) =
                match rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG) {
                    Ok(Some(event)) => event,
                    Ok(None) | Err(rustix::io::Errno::INTR) => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(rustix::io::Errno::CHILD) => {
                        // Ownership was lost; never signal this numeric PID again.
                        self.reaped = true;
                        return Err(io::Error::other("tracee wait ownership was lost"));
                    }
                    Err(error) => return Err(error.into()),
                };
            // Record reaping before fallible signal-enum decoding. Unsupported
            // realtime statuses must never leave numeric PID authority alive.
            if raw.exited() || raw.signaled() {
                self.reaped = true;
            }
            require(observed == pid, "wait returned a different child")?;
            return WaitStatus::from_raw(self.pid, raw.as_raw()).map_err(io::Error::from);
        }
    }
    fn prepare(&mut self, control: &OwnedFd, deadline: Instant) -> io::Result<()> {
        require(
            self.next(deadline)? == WaitStatus::Stopped(self.pid, Signal::SIGSTOP),
            "tracee did not reach its initial stop",
        )?;
        ptrace::setoptions(
            self.pid,
            ptrace::Options::PTRACE_O_TRACEEXEC | ptrace::Options::PTRACE_O_EXITKILL,
        )?;
        ptrace::cont(self.pid, None)?;
        transport::receive_control_until(control, READY, deadline)
    }
    fn confirmed(status: WaitStatus, pid: Pid) -> bool {
        matches!(status, WaitStatus::PtraceEvent(observed, Signal::SIGTRAP, event)
            if observed == pid && event == nix::libc::PTRACE_EVENT_EXEC)
    }
    fn retire(&mut self) -> io::Result<()> {
        if !self.reaped {
            self.kill()?;
            require(
                matches!(
                    self.next(Instant::now() + Duration::from_secs(3))?,
                    WaitStatus::Signaled(_, Signal::SIGKILL, false)
                ),
                "fault tracee did not retire after owned-child kill",
            )?;
        }
        Ok(())
    }
    fn kill(&mut self) -> io::Result<()> {
        require(!self.reaped, "cannot signal a reaped tracee")?;
        self.child.kill()
    }
}
impl Drop for TraceChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // Only the directly spawned, unreaped child; its PID cannot be reused.
        let _ = self.kill();
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            // A single wait implementation owns every state, including ptrace
            // stops. Never let std::Child cache a stop as an exit status.
            match self.next(deadline) {
                Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) => break,
                Err(_) => break,
                Ok(_) => {}
            }
        }
    }
}

fn parent_gate() -> io::Result<OwnedFd> {
    let channel = io::stdin().as_fd().try_clone_to_owned()?;
    require(
        rustix::net::sockopt::socket_type(&channel)? == rustix::net::SocketType::SEQPACKET,
        "shim requires private sequenced-packet gate",
    )?;
    let peer = nix::sys::socket::getsockopt(&channel, nix::sys::socket::sockopt::PeerCredentials)?;
    require(
        peer.pid() == nix::unistd::getppid().as_raw()
            && peer.uid() == rustix::process::getuid().as_raw(),
        "shim gate is not owned by its parent",
    )?;
    Ok(channel)
}

fn shim(mode: &str, directory: &Path) -> io::Result<()> {
    let channel = parent_gate()?;
    require(
        matches!(
            mode,
            "exec-125" | "exec-error" | "pre-exit-125" | "pre-kill" | "plain-trap" | "timeout"
        ),
        "unknown fixed spike mode",
    )?;
    ptrace::traceme()?;
    raise(Signal::SIGSTOP)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    transport::send_until(&channel, READY, &[], deadline)?;
    transport::receive_control_until(&channel, transport::GO, deadline)?;
    match mode {
        "pre-exit-125" => std::process::exit(125),
        "plain-trap" => {
            raise(Signal::SIGTRAP)?;
            Err(io::Error::other("plain trap was incorrectly resumed"))
        }
        "exec-125" | "exec-error" => {
            fuxix::io::cloexec_from(3, fuxix::io::Listed::now()).map_err(io::Error::from)?;
            let image = if mode == "exec-125" {
                std::env::current_exe()?
            } else {
                "/proc/self/fd/-1".into()
            };
            let error = Command::new(image)
                .arg("--target")
                .arg(directory)
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .exec();
            fs::write(
                directory.join("exec-error"),
                error.raw_os_error().unwrap_or(0).to_string(),
            )?;
            Err(error)
        }
        _ => Err(io::Error::other("unexpected GO in fault mode")),
    }
}

fn target(directory: &Path) -> io::Result<()> {
    let status = fs::read_to_string("/proc/self/status")?;
    require(
        status.lines().any(|line| line == "TracerPid:\t0"),
        "target remained traced",
    )?;
    let names = fs::read_dir("/proc/self/fd")?
        .map(|entry| entry.map(|e| e.file_name()))
        .collect::<io::Result<Vec<_>>>()?;
    for name in names {
        let number = name
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
            .ok_or_else(|| io::Error::other("invalid descriptor name"))?;
        if number > 2 {
            match fs::symlink_metadata(Path::new("/proc/self/fd").join(name)) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
                Ok(_) => {
                    return Err(io::Error::other(
                        "target inherited a nonstandard descriptor",
                    ));
                }
            }
        }
    }
    fs::write(
        directory.join("target-executed"),
        "untraced; standard streams only",
    )?;
    std::process::exit(125);
}

fn require_wait_ownership() -> io::Result<()> {
    // This fresh, single-threaded executable has no competing waiters. An
    // inherited ignored SIGCHLD would invalidate unreaped-child ownership.
    let status = fs::read_to_string("/proc/self/status")?;
    let ignored = status
        .lines()
        .find_map(|line| line.strip_prefix("SigIgn:\t"))
        .ok_or_else(|| io::Error::other("signal disposition unavailable"))?;
    let ignored = u64::from_str_radix(ignored, 16).map_err(io::Error::other)?;
    require(
        ignored & (1 << (Signal::SIGCHLD as u32 - 1)) == 0,
        "exec-event spike refuses ignored SIGCHLD",
    )
}

fn tracer(stage: &str, directory: &Path) -> io::Result<()> {
    require_wait_ownership()?;
    let controller = parent_gate()?;
    require(
        matches!(stage, "before-go" | "exec-stop"),
        "unknown tracer loss stage",
    )?;
    let (mut child, control) = TraceChild::spawn("exec-125", directory)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    child.prepare(&control, deadline)?;
    let pid = rustix::process::Pid::from_raw(child.pid.as_raw())
        .ok_or_else(|| io::Error::other("invalid owned child PID"))?;
    let witness = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())?;
    if stage == "exec-stop" {
        transport::send_until(&control, transport::GO, &[], deadline)?;
        require(
            TraceChild::confirmed(child.next(deadline)?, child.pid),
            "tracer never observed exec stop",
        )?;
    }
    require(
        !directory.join("target-executed").exists(),
        "target ran before tracer-loss barrier",
    )?;
    transport::send_until(&controller, transport::GO, &[witness.as_fd()], deadline)?;
    // The controller kills this process after receiving the original pidfd.
    // A lost controller or missing fault reaches bounded checked cleanup.
    transport::receive_control_until(&controller, b"NO-RELEASE", deadline)?;
    Err(io::Error::other("tracer loss fault was not injected"))
}

struct Witness {
    fd: OwnedFd,
    retired: bool,
}
impl Drop for Witness {
    fn drop(&mut self) {
        if !self.retired {
            // Failure cleanup uses only the capability from the fixed tracer,
            // never a PID claim. This is not counted as fault-retirement proof.
            let _ = rustix::process::pidfd_send_signal(&self.fd, rustix::process::Signal::KILL);
        }
    }
}
fn tracer_loss() -> io::Result<()> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    for stage in ["before-go", "exec-stop"] {
        let directory = tempfile::tempdir()?;
        let (controller, input) = transport::pair()?;
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args(["--tracer", stage])
            .arg(directory.path())
            .env_clear()
            .stdin(Stdio::from(input))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut tracer = TraceChild::owned(command.spawn()?)?;
        drop(command);
        let mut witness = Witness {
            fd: transport::receive_until(&controller, Instant::now() + Duration::from_secs(5))?,
            retired: false,
        };
        let mut ready = [PollFd::new(&witness.fd, PollFlags::IN)];
        let zero = Timespec::default();
        require(
            poll(&mut ready, Some(&zero))? == 0,
            "tracee exited before tracer loss",
        )?;
        require(
            !directory.path().join("target-executed").exists(),
            "target ran before tracer loss",
        )?;
        // Only the owned, unreaped tracer is killed. This cannot execute its
        // TraceChild destructor, so tracee exit must occur without that cleanup.
        tracer.retire()?;
        let timeout = Timespec::try_from(Duration::from_secs(3)).map_err(io::Error::other)?;
        require(
            poll(&mut ready, Some(&timeout))? == 1 && ready[0].revents().contains(PollFlags::IN),
            "original tracee did not exit after tracer SIGKILL",
        )?;
        witness.retired = true;
        require(
            !directory.path().join("target-executed").exists(),
            "target executed after tracer loss",
        )?;
        println!("exec-event tracer loss: {stage}: passed");
    }
    Ok(())
}

fn experiment() -> io::Result<()> {
    require_wait_ownership()?;
    let child = Command::new("/usr/bin/python3")
        .args([
            "-I",
            "-S",
            "-c",
            "import os,signal; os.kill(os.getpid(), signal.SIGRTMIN)",
        ])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let mut child = TraceChild::owned(child)?;
    let error = child
        .next(Instant::now() + Duration::from_secs(3))
        .err()
        .ok_or_else(|| io::Error::other("realtime termination unexpectedly decoded"))?;
    let revoked = child.reaped;
    child.reaped = true; // Also keep a failing negative control safe on Drop.
    require(
        error.raw_os_error() == Some(nix::libc::EINVAL) && revoked,
        "status decoding failure retained a reaped tracee PID",
    )?;
    require(
        child.kill().is_err(),
        "tracee signal allowed after decoding failure",
    )?;
    require(
        child.next(Instant::now() + Duration::from_secs(1)).is_err(),
        "tracee wait allowed after decoding failure",
    )?;
    drop(child);
    println!(
        "exec-event wait ownership: realtime decode failure revokes numeric operations: passed"
    );
    for mode in [
        "exec-125",
        "exec-error",
        "pre-exit-125",
        "pre-kill",
        "plain-trap",
        "timeout",
    ] {
        let directory = tempfile::tempdir()?;
        let (mut child, control) = TraceChild::spawn(mode, directory.path())?;
        let deadline = Instant::now() + Duration::from_secs(5);
        child.prepare(&control, deadline)?;
        require(
            !directory.path().join("target-executed").exists(),
            "target ran before GO",
        )?;
        if mode == "timeout" {
            let error = child
                .next(Instant::now() + Duration::from_millis(50))
                .err()
                .ok_or_else(|| io::Error::other("gated tracee unexpectedly changed state"))?;
            require(
                error.kind() == io::ErrorKind::TimedOut,
                "wrong timeout failure",
            )?;
        } else {
            if mode == "pre-kill" {
                child.kill()?;
            } else {
                transport::send_until(&control, transport::GO, &[], deadline)?;
            }
            let observed = child.next(deadline)?;
            let confirmed = TraceChild::confirmed(observed, child.pid);
            require(
                confirmed == (mode == "exec-125"),
                "exec-event attribution differs",
            )?;
            if confirmed {
                require(
                    !directory.path().join("target-executed").exists(),
                    "target ran before tracer detached",
                )?;
                ptrace::detach(child.pid, None)?;
                require(
                    child.next(deadline)? == WaitStatus::Exited(child.pid, 125),
                    "executed target status differs",
                )?;
                require(
                    fs::read_to_string(directory.path().join("target-executed"))?
                        == "untraced; standard streams only",
                    "target did not acknowledge detached execution",
                )?;
            } else {
                match mode {
                    "exec-error" => {
                        require(
                            observed == WaitStatus::Exited(child.pid, 125),
                            "exec failure status differs",
                        )?;
                        require(
                            fs::read_to_string(directory.path().join("exec-error"))? == "2",
                            "expected ENOENT exec failure",
                        )?;
                    }
                    "pre-exit-125" => require(
                        observed == WaitStatus::Exited(child.pid, 125),
                        "pre-exec status differs",
                    )?,
                    "pre-kill" => require(
                        observed == WaitStatus::Signaled(child.pid, Signal::SIGKILL, false),
                        "pre-exec kill differs",
                    )?,
                    "plain-trap" => require(
                        observed == WaitStatus::Stopped(child.pid, Signal::SIGTRAP),
                        "ordinary trap differs",
                    )?,
                    _ => unreachable!(),
                }
            }
        }
        child.retire()?;
        drop(child);
        if mode != "exec-125" {
            require(
                !directory.path().join("target-executed").exists(),
                "fault case executed the target",
            )?;
        }
        println!("exec-event spike: {mode}: passed");
    }
    tracer_loss()?;
    println!(
        "::notice title=Linux exec-event tracer loss::original child pidfd exited after owned tracer SIGKILL before GO and at the exec stop; target marker absent; no tracer destructor ran"
    );
    println!(
        "::notice title=Linux exec-event spike::six fixed-child cases passed; exec event distinguishes target exit 125 from pre-exec exit, ENOENT, SIGKILL, plain SIGTRAP and deadline; target untraced after detach; no production qualification"
    );
    Ok(())
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [] => experiment(),
        [role, mode, directory] if role == "--shim" => shim(mode, Path::new(directory)),
        [role, directory] if role == "--target" => target(Path::new(directory)),
        [role, stage, directory] if role == "--tracer" => tracer(stage, Path::new(directory)),
        _ => Err(io::Error::other("unknown fixed spike role")),
    };
    if let Err(error) = result {
        eprintln!("exec-event spike refused: {error}");
        std::process::exit(125);
    }
}
