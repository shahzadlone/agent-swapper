//! Private fixture topology for tools/check_linux_terminal_guardian.py.
//! No cgroup, journal receipt or real provider; this does not establish containment.
#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
#[path = "support/linux_admission_transport.rs"]
mod admission_transport;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("Linux-only terminal guardian fixture; no provider launched.");
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = fixture::run() {
        eprintln!("terminal guardian fixture: {error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod fixture {
    use super::admission_transport::{GO, pair, receive, send};
    use rustix::{
        fd::AsFd,
        net::{RecvFlags, recv},
        process::{Pid, Signal, getpgid, getpgrp, getpid, getppid, kill_process},
        termios::{tcgetpgrp, tcgetwinsize},
    };
    use serde_json::json;
    use std::{
        fs::{self, File},
        io::{self, BufRead, IsTerminal},
        os::unix::process::{CommandExt, ExitStatusExt},
        path::{Path, PathBuf},
        process::{Child, Command, ExitStatus, Stdio},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        time::{Duration, Instant},
    };
    use wait_timeout::ChildExt;

    const BUDGET: Duration = Duration::from_secs(30);

    fn require(value: bool, message: &'static str) -> io::Result<()> {
        if value {
            Ok(())
        } else {
            Err(io::Error::other(message))
        }
    }

    fn publish(dir: &Path, name: &str, value: serde_json::Value) -> io::Result<()> {
        let temporary = dir.join(format!("{name}.tmp"));
        fs::write(&temporary, serde_json::to_vec(&value)?)?;
        fs::rename(temporary, dir.join(name))
    }

    fn command(role: &str, dir: &Path) -> io::Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .env_clear()
            .arg(role)
            .arg(dir)
            .current_dir(dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        Ok(command)
    }

    struct Target(Child);
    impl Drop for Target {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait_timeout(Duration::from_secs(3));
        }
    }

    fn parent(dir: &Path) -> io::Result<()> {
        require(
            getpgrp() == getpid(),
            "shell did not create the foreground group",
        )?;
        require(
            tcgetpgrp(io::stdin())? == getpgrp(),
            "parent is not foreground",
        )?;
        publish(
            dir,
            "parent",
            json!({"pid":getpid().as_raw_pid(),"group":getpgrp().as_raw_pid()}),
        )?;
        let (channel, gate) = pair()?;
        // The guardian must survive an abrupt parent exit. Dropping Child must
        // not kill it; channel EOF, rather than a parent destructor, triggers cleanup.
        let mut helper = command("guardian", dir)?
            .arg(getpgrp().to_string())
            .stdin(Stdio::from(gate))
            .process_group(0)
            .spawn()?;
        send(&channel, GO, &[io::stdin().as_fd()])?;
        let deadline = Instant::now() + BUDGET;
        let status = loop {
            if dir.join("kill-parent").exists() {
                // Kill only this fixture. The guardian must stop its still-live
                // target. No PID from fixture metadata is used for signalling.
                kill_process(getpid(), Signal::KILL)?;
                return Err(io::Error::other("fixture self-kill returned"));
            }
            if let Some(status) = helper.try_wait()? {
                break status;
            }
            require(Instant::now() < deadline, "guardian did not finish")?;
            std::thread::sleep(Duration::from_millis(10));
        };
        drop(channel);
        require(status.success(), "guardian failed")
    }

    fn guardian(dir: &Path, foreground: Pid) -> io::Result<()> {
        require(
            getpgrp() == getpid() && getpgrp() != foreground,
            "guardian group mismatch",
        )?;
        require(
            getpgid(getppid())? == foreground,
            "guardian parent group mismatch",
        )?;
        require(
            !io::stdin().is_terminal()
                && !io::stdout().is_terminal()
                && !io::stderr().is_terminal(),
            "guardian has terminal standard streams",
        )?;
        let terminal = File::from(receive(io::stdin())?);
        // This fixture uses one read/write PTY for all three target streams.
        // Separate output/error descriptor transfer remains a production gate.
        let mut target = Target(
            command("target", dir)?
                .stdin(terminal.try_clone()?)
                .stdout(terminal.try_clone()?)
                .stderr(terminal)
                .process_group(foreground.as_raw_pid())
                .spawn()?,
        );
        publish(
            dir,
            "guardian",
            json!({"pid":getpid().as_raw_pid(),"group":getpgrp().as_raw_pid()}),
        )?;
        let deadline = Instant::now() + BUDGET;
        let mut parent_eof = false;
        let status = loop {
            let mut unexpected = [0_u8; 1];
            match recv(io::stdin(), &mut unexpected, RecvFlags::DONTWAIT) {
                Ok((0, _)) => {
                    parent_eof = true;
                    target.0.kill()?;
                    break target
                        .0
                        .wait_timeout(Duration::from_secs(3))?
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::TimedOut, "target did not stop")
                        })?;
                }
                Ok(_) => return Err(io::Error::other("unexpected control packet")),
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            }
            if let Some(status) = target.0.try_wait()? {
                break status;
            }
            require(Instant::now() < deadline, "guardian deadline expired")?;
            std::thread::sleep(Duration::from_millis(10));
        };
        finished(dir, status, parent_eof)
    }

    fn finished(dir: &Path, status: ExitStatus, parent_eof: bool) -> io::Result<()> {
        publish(
            dir,
            "finished",
            json!({"exit":status.code(),"signal":status.signal(),"parentEof":parent_eof}),
        )
    }

    fn ignored_signals() -> io::Result<u64> {
        let status = fs::read_to_string("/proc/self/status")?;
        let mask = status
            .lines()
            .find_map(|line| line.strip_prefix("SigIgn:\t"))
            .ok_or_else(|| io::Error::other("missing signal mask"))?;
        u64::from_str_radix(mask.trim(), 16).map_err(io::Error::other)
    }

    fn target(dir: &Path) -> io::Result<()> {
        require(
            io::stdin().is_terminal() && io::stdout().is_terminal() && io::stderr().is_terminal(),
            "target lost terminal streams",
        )?;
        let group = getpgrp();
        require(tcgetpgrp(io::stdin())? == group, "target is not foreground")?;
        let ignored = ignored_signals()?;
        let resized = Arc::new(AtomicBool::new(false));
        // Observe WINCH without overriding an explicitly inherited SIG_IGN.
        if ignored & (1 << (signal_hook::consts::SIGWINCH - 1)) == 0 {
            signal_hook::flag::register(signal_hook::consts::SIGWINCH, Arc::clone(&resized))?;
        }
        let (sender, commands) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut line = String::new();
            let result = io::stdin().lock().read_line(&mut line).map(|_| line);
            let _ = sender.send(result);
        });
        publish(
            dir,
            "target",
            json!({"pid":getpid().as_raw_pid(),"group":group.as_raw_pid(),"ignored":ignored}),
        )?;
        let deadline = Instant::now() + BUDGET;
        loop {
            if resized.swap(false, Ordering::Relaxed) {
                let size = tcgetwinsize(io::stdin())?;
                publish(
                    dir,
                    "resize",
                    json!({"rows":size.ws_row,"cols":size.ws_col}),
                )?;
            }
            match commands.recv_timeout(Duration::from_millis(10)) {
                Ok(Ok(line)) if line.is_empty() => {
                    return publish(dir, "input", json!({"closed":"eof"}));
                }
                Ok(Ok(line)) => {
                    require(line == "exit\n", "target input changed")?;
                    return publish(dir, "input", json!({"line":line}));
                }
                Ok(Err(error))
                    if error.raw_os_error() == Some(rustix::io::Errno::IO.raw_os_error()) =>
                {
                    return publish(dir, "input", json!({"closed":"eio"}));
                }
                Ok(Err(error)) => return Err(error),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(error) => return Err(io::Error::other(error)),
            }
            require(Instant::now() < deadline, "target deadline expired")?;
        }
    }

    pub(super) fn run() -> io::Result<()> {
        let mut args = std::env::args_os().skip(1);
        let role = args
            .next()
            .ok_or_else(|| io::Error::other("use tools/check_linux_terminal_guardian.py"))?;
        let dir = PathBuf::from(
            args.next()
                .ok_or_else(|| io::Error::other("missing fixture directory"))?,
        );
        let result = match role.to_str() {
            Some("parent") => parent(&dir),
            Some("target") => target(&dir),
            Some("guardian") => {
                let raw: i32 = args
                    .next()
                    .and_then(|value| value.to_str().and_then(|s| s.parse().ok()))
                    .filter(|pid| *pid > 1)
                    .ok_or_else(|| io::Error::other("invalid foreground group"))?;
                guardian(
                    &dir,
                    Pid::from_raw(raw)
                        .ok_or_else(|| io::Error::other("missing foreground group"))?,
                )
            }
            _ => Err(io::Error::other("unknown fixture role")),
        };
        if let Err(error) = &result {
            let _ = publish(
                &dir,
                "failure",
                json!({"role":role.to_string_lossy(),"error":error.to_string()}),
            );
        }
        result
    }
}
