//! Private fixture topology for tools/check_linux_terminal_guardian.py.
//! Optional explicit delegation exercises cgroup admission; no production receipt/provider.
#![forbid(unsafe_code)]
#[cfg(target_os = "linux")]
#[path = "../src/supervision/linux_admission_transport.rs"]
mod admission_transport;
#[cfg(target_os = "linux")]
#[path = "../src/supervision/linux_cgroup.rs"]
mod cgroup;

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
    use super::{
        admission_transport::{GO, pair, receive, receive_control, send},
        cgroup,
    };
    use rustix::{
        fd::AsFd,
        net::{RecvFlags, recv},
        process::{
            Pid, Signal, WaitOptions, getpgid, getpgrp, getpid, getppid, kill_process,
            set_child_subreaper, setsid, waitpid,
        },
        termios::{OptionalActions, tcgetattr, tcgetpgrp, tcgetwinsize, tcsetattr},
    };
    use serde_json::json;
    use std::{
        ffi::OsString,
        fs::{self, File},
        io::{self, BufRead, IsTerminal, Write},
        os::unix::{
            ffi::{OsStrExt, OsStringExt},
            process::{CommandExt, ExitStatusExt},
        },
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
    const READY: &[u8] = b"ASWP-READY-1";
    const DIAGNOSTIC: &[u8] = b"target diagnostic stays on stderr\n";

    fn encode_flags(flags: [bool; 3]) -> String {
        flags
            .into_iter()
            .map(|flag| if flag { '1' } else { '0' })
            .collect()
    }

    fn decode_flags(value: Option<OsString>) -> io::Result<[bool; 3]> {
        let value = value
            .and_then(|value| value.into_string().ok())
            .filter(|value| {
                value.len() == 3 && value.bytes().all(|byte| byte == b'0' || byte == b'1')
            })
            .ok_or_else(|| io::Error::other("invalid terminal flags"))?;
        let bytes = value.as_bytes();
        Ok([bytes[0] == b'1', bytes[1] == b'1', bytes[2] == b'1'])
    }

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

    struct FallbackScope {
        parent: File,
        leaf: File,
        path: PathBuf,
        _lease: File,
        retired: bool,
    }

    impl Drop for FallbackScope {
        fn drop(&mut self) {
            if self.retired || cgroup::validate_scope(&self.parent, &self.leaf, &self.path).is_err()
            {
                return;
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            let _ = (|| -> io::Result<()> {
                cgroup::control(&self.leaf, "cgroup.kill", rustix::fs::OFlags::WRONLY)?
                    .write_all(b"1\n")?;
                cgroup::until(deadline, || {
                    Ok((!cgroup::populated(&self.leaf)?).then_some(()))
                })?;
                cgroup::retire_transferred(&self.parent, &self.leaf, &self.path, deadline)
            })();
        }
    }

    fn parent(dir: &Path, delegated: Option<&Path>) -> io::Result<()> {
        require(
            getpgrp() == getpid(),
            "shell did not create the foreground group",
        )?;
        require(
            tcgetpgrp(io::stdin())? == getpgrp(),
            "parent is not foreground",
        )?;
        let original_terminal = if dir.join("with-raw-terminal").exists() {
            Some(tcgetattr(io::stdin())?)
        } else {
            None
        };
        publish(
            dir,
            "parent",
            json!({"pid":getpid().as_raw_pid(),"group":getpgrp().as_raw_pid()}),
        )?;
        let (channel, gate) = pair()?;
        let lease = File::create_new(dir.join("lease"))?;
        lease.try_lock().map_err(io::Error::other)?;
        // The guardian must survive an abrupt parent exit. Dropping Child must
        // not kill it; channel EOF, rather than a parent destructor, triggers cleanup.
        let mut helper = command("guardian", dir)?;
        helper
            .arg(getpgrp().to_string())
            .arg(encode_flags([
                io::stdin().is_terminal(),
                io::stdout().is_terminal(),
                io::stderr().is_terminal(),
            ]))
            .stdin(Stdio::from(gate))
            .process_group(0);
        if let Some(delegated) = delegated {
            helper.arg(delegated);
        }
        let mut helper = helper.spawn()?;
        for fd in [
            io::stdin().as_fd(),
            io::stdout().as_fd(),
            io::stderr().as_fd(),
        ] {
            send(&channel, GO, &[fd])?;
        }
        send(&channel, GO, &[lease.as_fd()])?;
        // Only the guardian's transferred open-file description retains this
        // lock. The observer checks it independently while the parent is alive
        // and after a parent-only kill.
        let guardian_loss = dir.join("with-guardian-loss").exists();
        rustix::net::sockopt::set_socket_timeout(
            &channel,
            rustix::net::sockopt::Timeout::Recv,
            Some(Duration::from_secs(5)),
        )?;
        let fallback = if guardian_loss {
            require(
                delegated.is_some(),
                "guardian-loss fixture requires delegation",
            )?;
            let parent = File::from(receive(&channel)?);
            let leaf = File::from(receive(&channel)?);
            let record: serde_json::Value = serde_json::from_slice(&fs::read(dir.join("scope"))?)?;
            let bytes: Vec<u8> = serde_json::from_value(record["pathBytes"].clone())?;
            let path = PathBuf::from(OsString::from_vec(bytes));
            cgroup::validate_scope(&parent, &leaf, &path)?;
            Some(FallbackScope {
                parent,
                leaf,
                path,
                _lease: lease,
                retired: false,
            })
        } else {
            drop(lease);
            None
        };
        // The admitted shim cannot execute until the parent acknowledges that
        // the guardian reached its prepared state. A lost or timed-out parent
        // closes this channel and leaves the guardian responsible for cleanup.
        receive_control(&channel, READY)?;
        if dir.join("delay-before-go").exists() {
            publish(dir, "parent-ready", json!({"ready":true}))?;
            cgroup::until(Instant::now() + Duration::from_secs(10), || {
                Ok(dir.join("release-go").exists().then_some(()))
            })?;
        }
        send(&channel, GO, &[])?;
        let mut injected = false;
        let status = loop {
            if dir.join("kill-parent").exists() {
                // Kill only this fixture. The guardian must stop its still-live
                // target. No PID from fixture metadata is used for signalling.
                kill_process(getpid(), Signal::KILL)?;
                return Err(io::Error::other("fixture self-kill returned"));
            }
            if fallback.is_some() && dir.join("kill-guardian").exists() && !injected {
                helper.kill()?;
                injected = true;
            }
            if let Some(status) = helper.try_wait()? {
                break status;
            }
            // A live interactive session (including a stopped foreground job)
            // has no lifetime deadline. Startup and cleanup have separate bounds.
            std::thread::sleep(Duration::from_millis(10));
        };
        if let Some(mut fallback) = fallback {
            require(
                injected && status.signal() == Some(9),
                "guardian loss was not observed",
            )?;
            cgroup::validate_scope(&fallback.parent, &fallback.leaf, &fallback.path)?;
            cgroup::control(&fallback.leaf, "cgroup.kill", rustix::fs::OFlags::WRONLY)?
                .write_all(b"1\n")?;
            cgroup::until(Instant::now() + Duration::from_secs(10), || {
                Ok((!cgroup::populated(&fallback.leaf)?).then_some(()))
            })?;
            publish(dir, "parent-empty", json!({"guardianSignal":9}))?;
            cgroup::until(Instant::now() + Duration::from_secs(10), || {
                Ok(dir.join("retire-scope").exists().then_some(()))
            })?;
            cgroup::retire_transferred(
                &fallback.parent,
                &fallback.leaf,
                &fallback.path,
                Instant::now() + Duration::from_secs(10),
            )?;
            fallback.retired = true;
            publish(dir, "scope-finished", json!({"retired":true}))?;
            publish(dir, "cleanup-ready", json!({"leaseHeld":true}))?;
            cgroup::until(Instant::now() + Duration::from_secs(10), || {
                Ok(dir.join("release-lease").exists().then_some(()))
            })?;
            drop(fallback);
            return publish(dir, "finished", json!({"guardianSignal":9}));
        }
        drop(channel);
        require(status.success(), "guardian failed")?;
        if let Some(original) = original_terminal {
            require(
                tcgetpgrp(io::stdin())? == getpgrp(),
                "terminal foreground changed before restoration",
            )?;
            tcsetattr(io::stdin(), OptionalActions::Now, &original)?;
            publish(dir, "terminal-restored", json!({"foreground":true}))?;
        }
        Ok(())
    }

    fn guardian(
        dir: &Path,
        foreground: Pid,
        flags: [bool; 3],
        delegated: Option<&Path>,
    ) -> io::Result<()> {
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
        set_child_subreaper(Some(getpid()))?;
        let input = File::from(receive(io::stdin())?);
        let output = File::from(receive(io::stdin())?);
        let diagnostic = File::from(receive(io::stdin())?);
        let lease = File::from(receive(io::stdin())?);
        let domain = delegated.map(cgroup::Domain::open).transpose()?;
        let mut scope = domain.as_ref().map(cgroup::Domain::create).transpose()?;
        require(
            scope.is_some() || !dir.join("with-writer").exists(),
            "detached fixture requires a delegated scope",
        )?;
        if let (Some(scope), Some(domain)) = (&scope, &domain) {
            require(
                cgroup::contains(scope.parent(), std::process::id())?
                    && !cgroup::contains(scope.directory(), std::process::id())?,
                "guardian entered target scope",
            )?;
            publish(
                dir,
                "scope",
                json!({"parentBytes":domain.path().as_os_str().as_bytes(),"pathBytes":scope.path().as_os_str().as_bytes()}),
            )?;
            if dir.join("with-guardian-loss").exists() {
                let channel = rustix::io::dup(io::stdin())?;
                send(&channel, GO, &[scope.parent().as_fd()])?;
                send(&channel, GO, &[scope.directory().as_fd()])?;
            }
        }
        let (grant, gate) = pair()?;
        let mut shim = command("shim", dir)?;
        shim.arg(encode_flags(flags))
            .stdin(Stdio::from(gate))
            .process_group(foreground.as_raw_pid());
        if let Some(scope) = &scope {
            shim.arg(scope.path());
        }
        let mut target = Target(shim.spawn()?);
        if let Some(scope) = &scope {
            cgroup::control(
                scope.directory(),
                "cgroup.procs",
                rustix::fs::OFlags::WRONLY,
            )?
            .write_all(format!("{}\n", target.0.id()).as_bytes())?;
            require(
                cgroup::contains(scope.directory(), target.0.id())?,
                "terminal shim admission did not match owned child",
            )?;
            publish(dir, "admitted", json!({"pid":target.0.id()}))?;
        }
        if dir.join("delay-before-ready").exists() {
            cgroup::until(Instant::now() + Duration::from_secs(10), || {
                Ok(dir.join("release-startup").exists().then_some(()))
            })?;
        }
        let channel = rustix::io::dup(io::stdin())?;
        rustix::net::sockopt::set_socket_timeout(
            &channel,
            rustix::net::sockopt::Timeout::Recv,
            Some(Duration::from_secs(5)),
        )?;
        send(&channel, READY, &[])?;
        receive_control(&channel, GO)?;
        rustix::net::sockopt::set_socket_timeout(
            &channel,
            rustix::net::sockopt::Timeout::Recv,
            None,
        )?;
        drop(channel);
        for fd in [input.as_fd(), output.as_fd(), diagnostic.as_fd()] {
            send(&grant, GO, &[fd])?;
        }
        drop(grant);
        drop([input, output, diagnostic]);
        publish(
            dir,
            "guardian",
            json!({"pid":getpid().as_raw_pid(),"group":getpgrp().as_raw_pid()}),
        )?;
        let mut parent_eof = false;
        let mut retired = false;
        let status = loop {
            let mut unexpected = [0_u8; 1];
            match recv(io::stdin(), &mut unexpected, RecvFlags::DONTWAIT) {
                Ok((0, _)) => {
                    parent_eof = true;
                    if let Some(scope) = &mut scope {
                        scope.retire(Instant::now() + Duration::from_secs(10))?;
                        retired = true;
                    } else {
                        target.0.kill()?;
                    }
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
            std::thread::sleep(Duration::from_millis(10));
        };
        if let Some(scope) = &mut scope {
            if !retired {
                scope.retire(Instant::now() + Duration::from_secs(10))?;
            }
            publish(dir, "scope-finished", json!({"retired":true}))?;
        }
        if dir.join("with-writer").exists() {
            let heartbeat: serde_json::Value =
                serde_json::from_slice(&fs::read(dir.join("writer-heartbeat"))?)?;
            let raw = heartbeat["pid"]
                .as_i64()
                .and_then(|pid| i32::try_from(pid).ok())
                .filter(|pid| *pid > 1)
                .ok_or_else(|| io::Error::other("invalid fixture writer PID"))?;
            let pid = Pid::from_raw(raw).ok_or_else(|| io::Error::other("missing writer PID"))?;
            // Wait only after the owned root Child has been reaped. Never signal
            // a metadata PID or reap an owned Child behind its handle's back.
            let (_, status) = cgroup::until(Instant::now() + Duration::from_secs(3), || {
                Ok(waitpid(Some(pid), WaitOptions::NOHANG)?)
            })?;
            require(
                status.terminating_signal() == Some(9),
                "detached writer was not killed",
            )?;
            publish(dir, "writer-stopped", json!({"signal":9}))?;
        }
        publish(dir, "cleanup-ready", json!({"leaseHeld":true}))?;
        cgroup::until(Instant::now() + Duration::from_secs(10), || {
            Ok(dir.join("release-lease").exists().then_some(()))
        })?;
        drop(lease);
        finished(dir, status, parent_eof)
    }

    fn shim(dir: &Path, flags: [bool; 3], scope: Option<&Path>) -> io::Result<()> {
        let input = receive(io::stdin())?;
        let output = receive(io::stdin())?;
        let diagnostic = receive(io::stdin())?;
        if let Some(scope) = scope {
            let directory = cgroup::checked_directory(scope)?;
            require(
                cgroup::contains(&directory, std::process::id())?,
                "terminal shim was not admitted before GO",
            )?;
        }
        Err(command("target", dir)?
            .arg(encode_flags(flags))
            .stdin(Stdio::from(input))
            .stdout(Stdio::from(output))
            .stderr(Stdio::from(diagnostic))
            .exec())
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

    fn writer(dir: &Path) -> io::Result<()> {
        setsid()?;
        let deadline = Instant::now() + BUDGET;
        let mut tick = 0_u64;
        while Instant::now() < deadline {
            tick += 1;
            publish(
                dir,
                "writer-heartbeat",
                json!({"pid":getpid().as_raw_pid(),"group":getpgrp().as_raw_pid(),"tick":tick}),
            )?;
            std::thread::sleep(Duration::from_millis(10));
        }
        publish(dir, "writer-exited", json!({"voluntary":true}))
    }

    fn target(dir: &Path, expected: [bool; 3]) -> io::Result<()> {
        let actual = [
            io::stdin().is_terminal(),
            io::stdout().is_terminal(),
            io::stderr().is_terminal(),
        ];
        require(
            actual == expected,
            "target standard-stream terminal identities changed",
        )?;
        let group = getpgrp();
        require(tcgetpgrp(io::stdin())? == group, "target is not foreground")?;
        if dir.join("with-raw-terminal").exists() {
            let mut attributes = tcgetattr(io::stdin())?;
            attributes.make_raw();
            tcsetattr(io::stdin(), OptionalActions::Now, &attributes)?;
            publish(dir, "raw-entered", json!({"raw":true}))?;
        }
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
        io::stdout().write_all(b"target stdout stays in terminal\n")?;
        io::stderr().write_all(DIAGNOSTIC)?;
        if dir.join("with-writer").exists() {
            // The Child handle deliberately drops without killing its process:
            // the writer must outlive this initial CLI and be stopped by scope.
            let _writer = command("writer", dir)?.spawn()?;
        }
        publish(
            dir,
            "target",
            json!({"pid":getpid().as_raw_pid(),"group":group.as_raw_pid(),"ignored":ignored,"terminals":actual}),
        )?;
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
            Some("parent") => parent(&dir, args.next().map(PathBuf::from).as_deref()),
            Some("target") => target(&dir, decode_flags(args.next())?),
            Some("writer") => writer(&dir),
            Some("shim") => {
                let flags = decode_flags(args.next())?;
                shim(&dir, flags, args.next().map(PathBuf::from).as_deref())
            }
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
                    decode_flags(args.next())?,
                    args.next().map(PathBuf::from).as_deref(),
                )
            }
            _ => Err(io::Error::other("unknown fixture role")),
        };
        if let Err(error) = &result {
            if let Some(name @ ("parent" | "guardian" | "shim" | "target" | "writer")) =
                role.to_str()
            {
                let _ = publish(
                    &dir,
                    &format!("failure-{name}"),
                    json!({"role":name,"error":error.to_string(),"errno":error.raw_os_error()}),
                );
            }
            let _ = publish(
                &dir,
                "failure",
                json!({"role":role.to_string_lossy(),"error":error.to_string()}),
            );
        }
        result
    }
}
