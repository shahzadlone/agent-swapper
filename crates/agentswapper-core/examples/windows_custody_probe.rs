//! Provider-free Windows Job spike. This is not the native launch path.
#![forbid(unsafe_code)]
#[cfg(not(windows))]
fn main() {
    println!("Windows-only custody probe; no native agent was started.");
}

#[cfg(windows)]
fn main() {
    if let Err(error) = windows_probe::run() {
        let message = error
            .to_string()
            .replace('%', "%25")
            .replace('\r', "%0D")
            .replace('\n', "%0A");
        println!("::error title=Windows custody probe::{message}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod windows_probe {
    use process_wrap::std::{ChildWrapper, CommandWrap, CreationFlags, JobObject};
    use std::{
        fs, io,
        os::windows::process::CommandExt,
        path::{Path, PathBuf},
        process::{Child, Command, ExitStatus, Stdio},
        sync::OnceLock,
        time::{Duration, Instant},
    };
    use win32job::{ExtendedLimitInfo, Job};
    use windows::Win32::System::Threading::CREATE_NO_WINDOW;
    use windows_sys::Win32::{
        Foundation::ERROR_ACCESS_DENIED, System::Threading::CREATE_BREAKAWAY_FROM_JOB,
    };

    static ROOT: OnceLock<Result<Job, String>> = OnceLock::new();
    const BUDGET: Duration = Duration::from_secs(15);
    const FIXTURE_LIFETIME: Duration = Duration::from_secs(45);

    fn require(value: bool, message: &'static str) -> io::Result<()> {
        if value {
            Ok(())
        } else {
            Err(io::Error::other(message))
        }
    }

    fn command(role: &str, directory: &Path) -> io::Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        command.env_clear();
        for name in [
            "SystemRoot",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "LLVM_PROFILE_FILE",
            "ASAN_OPTIONS",
            "UBSAN_OPTIONS",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command
            .arg(role)
            .arg(directory)
            .current_dir(directory)
            .creation_flags(CREATE_NO_WINDOW.0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        Ok(command)
    }

    fn publish(directory: &Path, name: &str, contents: &str) -> io::Result<()> {
        let temporary = directory.join(format!("{name}.tmp"));
        fs::write(&temporary, contents)?;
        fs::rename(temporary, directory.join(name))
    }

    fn heartbeat(directory: &Path) -> Option<(u32, u64)> {
        let text = fs::read_to_string(directory.join("heartbeat")).ok()?;
        let (pid, tick) = text.trim().split_once(' ')?;
        Some((pid.parse().ok()?, tick.parse().ok()?))
    }

    fn until<T>(
        deadline: Instant,
        mut check: impl FnMut() -> io::Result<Option<T>>,
    ) -> io::Result<T> {
        loop {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "custody probe deadline exceeded",
                ));
            }
            if let Some(value) = check()? {
                return Ok(value);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn members(job: &Job) -> io::Result<Vec<usize>> {
        job.query_process_id_list()
            .map_err(|error| io::Error::other(error.to_string()))
    }

    fn only_self(ids: &[usize]) -> bool {
        ids == [std::process::id() as usize]
    }

    fn root_job() -> io::Result<&'static Job> {
        // Never drop a Job containing this supervisor. Its non-inherited handle
        // lives until process exit; kernel handle closure performs crash cleanup.
        ROOT.get_or_init(|| {
            let install = || -> io::Result<Job> {
                // Construct fresh zeroed limits. The audited safe API has no
                // flag getter; behavioral probes below check both properties.
                let mut limits = ExtendedLimitInfo::new();
                limits.limit_kill_on_job_close();
                let job = Job::create_with_limit_info(&limits)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                job.assign_current_process()
                    .map_err(|error| io::Error::other(error.to_string()))?;
                Ok(job)
            };
            install().map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| io::Error::other(error.clone()))
    }

    fn stop_and_observe(
        job: &Job,
        worker: &mut dyn ChildWrapper,
        deadline: Instant,
    ) -> io::Result<()> {
        let mut issued_kill = false;
        loop {
            let ids = members(job)?;
            require(
                ids.contains(&(std::process::id() as usize)),
                "supervisor absent from root Job",
            )?;
            if only_self(&ids) {
                require(issued_kill, "no targeted Job termination was issued")?;
                return Ok(());
            }
            // Termination is asynchronous. Repeat while members remain, using
            // the owned Job handle rather than any PID read from a file.
            let killed = worker.start_kill();
            issued_kill |= killed.is_ok();
            if only_self(&members(job)?) {
                require(issued_kill, "no targeted Job termination succeeded")?;
                return Ok(());
            }
            killed?;
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Job remained populated after termination",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn supervisor(directory: &Path, terminate: bool) -> io::Result<()> {
        let root = root_job()?;
        require(
            only_self(&members(root)?),
            "root Job not initially exclusive",
        )?;
        check_breakaway(directory, "root")?;
        let mut wrapped = CommandWrap::from(command("worker", directory)?);
        wrapped
            .wrap(CreationFlags(CREATE_NO_WINDOW))
            .wrap(JobObject);
        let mut worker = wrapped.spawn()?;
        require(
            members(root)?.contains(&(worker.id() as usize)),
            "worker absent from root Job",
        )?;
        publish(directory, "admitted", "admitted")?;
        let deadline = Instant::now() + BUDGET;
        // Bypass the library's Job completion queue. Its notification is not an
        // empty-Job proof and its wait helper can block after a drained queue.
        let status = until(deadline, || worker.inner_mut().try_wait())?;
        require(status.success(), "fixture worker failed")?;
        let (leaf, _) = until(deadline, || Ok(heartbeat(directory)))?;
        require(
            members(root)?.contains(&(leaf as usize)),
            "reparented writer absent from root Job",
        )?;
        publish(directory, "orphaned", "worker exited; descendant remains")?;
        if terminate {
            until(deadline, || {
                Ok(directory.join("request-stop").exists().then_some(()))
            })?;
            require(
                members(root)?.contains(&(leaf as usize)),
                "writer exited before targeted termination",
            )?;
            stop_and_observe(root, worker.as_mut(), deadline)?;
            require(
                only_self(&members(root)?),
                "root Job contains unexpected members after stop",
            )?;
            publish(
                directory,
                "observed-empty-workers",
                "only supervisor remains",
            )?;
        } else {
            // The controller kills this owned supervisor to test kernel cleanup.
            until::<()>(Instant::now() + FIXTURE_LIFETIME, || Ok(None))?;
        }
        Ok(())
    }

    fn wait_native(child: &mut Child, deadline: Instant) -> io::Result<ExitStatus> {
        until(deadline, || child.try_wait())
    }

    fn check_breakaway(directory: &Path, scope: &str) -> io::Result<()> {
        let deadline = Instant::now() + BUDGET;
        let mut normal = command("mark", directory)?.spawn()?;
        require(
            wait_native(&mut normal, deadline)?.success(),
            "normal child creation failed",
        )?;
        let attempt = command("mark", directory)?
            .creation_flags(CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW.0)
            .spawn();
        match attempt {
            Ok(mut escaped) => {
                let _ = escaped.kill();
                let _ = escaped.wait();
                Err(io::Error::other(
                    "CREATE_BREAKAWAY_FROM_JOB unexpectedly succeeded",
                ))
            }
            Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => publish(
                directory,
                &format!("breakaway-{scope}-refused"),
                "access denied",
            ),
            Err(error) => Err(io::Error::other(format!(
                "breakaway failed for an unexpected reason: {error}"
            ))),
        }
    }

    fn worker(directory: &Path) -> io::Result<()> {
        // Spawn immediately, before any cooperative admission handshake. If
        // assignment ever races target execution, the inner Job kill test fails.
        let leaf = command("heartbeat", directory)?.spawn()?;
        publish(directory, "leaf-pid", &leaf.id().to_string())?;
        let deadline = Instant::now() + BUDGET;
        check_breakaway(directory, "inner")?;
        until(deadline, || {
            Ok(directory.join("admitted").exists().then_some(()))
        })?;
        Ok(())
    }

    fn writer(directory: &Path) -> io::Result<()> {
        let lease = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(directory.join("writer-lock"))?;
        lease
            .try_lock()
            .map_err(|error| io::Error::other(error.to_string()))?;
        let started = Instant::now();
        let mut tick = 0_u64;
        while started.elapsed() < FIXTURE_LIFETIME && !directory.join("stop-all").exists() {
            tick += 1;
            // An incidental sharing violation must not make a stopped writer
            // look like successful Job termination. Keep the lifetime lock.
            let _ = publish(
                directory,
                "heartbeat",
                &format!("{} {tick}", std::process::id()),
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = publish(directory, "writer-exited", "voluntary exit");
        drop(lease);
        Ok(())
    }

    struct Probe {
        child: Child,
        directory: tempfile::TempDir,
    }
    impl Drop for Probe {
        fn drop(&mut self) {
            let _ = fs::write(self.directory.path().join("stop-all"), "stop");
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
    impl Probe {
        fn new(role: &str) -> io::Result<Self> {
            let directory = tempfile::tempdir()?;
            let child = command(role, directory.path())?.spawn()?;
            Ok(Self { child, directory })
        }
        fn alive(&mut self) -> io::Result<()> {
            if let Some(status) = self.child.try_wait()? {
                let details = fs::read_to_string(self.directory.path().join("supervisor-failure"))
                    .unwrap_or_default();
                return Err(io::Error::other(format!(
                    "supervisor exited unexpectedly: {status}; {details}"
                )));
            }
            Ok(())
        }
        fn ready(&mut self, deadline: Instant) -> io::Result<(u32, u64)> {
            until(deadline, || {
                self.alive()?;
                Ok(heartbeat(self.directory.path())
                    .filter(|_| self.directory.path().join("orphaned").exists()))
            })
        }
    }

    fn require_stable(directory: &Path, expected_pid: u32, deadline: Instant) -> io::Result<()> {
        let (_, baseline) = until(deadline, || {
            Ok(heartbeat(directory).filter(|(pid, _)| *pid == expected_pid))
        })?;
        let started = Instant::now();
        while started.elapsed() < Duration::from_millis(150) {
            if let Some((pid, tick)) = heartbeat(directory) {
                require(
                    pid == expected_pid && tick == baseline,
                    "writer continued after containment stop",
                )?;
            }
            require(
                Instant::now() < deadline,
                "stability observation exceeded deadline",
            )?;
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }

    fn controller() -> io::Result<()> {
        for (role, force_exit) in [("supervisor-stop", false), ("supervisor-crash", true)] {
            let deadline = Instant::now() + BUDGET;
            let mut probe = Probe::new(role)?;
            let (leaf, before) = probe.ready(deadline)?;
            let observer = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(probe.directory.path().join("writer-lock"))?;
            match observer.try_lock() {
                Err(std::fs::TryLockError::WouldBlock) => {}
                Err(std::fs::TryLockError::Error(error)) => return Err(error),
                Ok(()) => {
                    return Err(io::Error::other(
                        "writer fixture did not retain its lifetime lock",
                    ));
                }
            }
            until(deadline, || {
                probe.alive()?;
                Ok(heartbeat(probe.directory.path())
                    .filter(|(pid, tick)| *pid == leaf && *tick > before + 3))
            })?;
            require(
                probe
                    .directory
                    .path()
                    .join("breakaway-root-refused")
                    .exists()
                    && probe
                        .directory
                        .path()
                        .join("breakaway-inner-refused")
                        .exists(),
                "missing breakaway refusal",
            )?;
            require(
                !probe.directory.path().join("supervisor-failure").exists(),
                "fixture failed before the stop request",
            )?;
            require(
                matches!(observer.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
                "fixture ended before the stop request",
            )?;
            if force_exit {
                probe.alive()?;
                probe.child.kill()?;
                require(
                    !wait_native(&mut probe.child, deadline)?.success(),
                    "hard-killed supervisor exited successfully",
                )?;
            } else {
                publish(probe.directory.path(), "request-stop", "stop")?;
                require(
                    wait_native(&mut probe.child, deadline)?.success(),
                    "supervisor stop failed",
                )?;
                require(
                    probe
                        .directory
                        .path()
                        .join("observed-empty-workers")
                        .exists(),
                    "missing Job membership observation",
                )?;
            }
            // A kill request is asynchronous. Wait for this controlled fixture's
            // lifetime lock to close before observing stable output. This is a
            // fixture control, never a general process-custody certificate.
            until(deadline, || match observer.try_lock() {
                Ok(()) => Ok(Some(())),
                Err(std::fs::TryLockError::WouldBlock) => Ok(None),
                Err(std::fs::TryLockError::Error(error)) => Err(error),
            })?;
            require_stable(probe.directory.path(), leaf, deadline)?;
            require(
                !probe.directory.path().join("writer-exited").exists(),
                "writer exited voluntarily instead of being terminated",
            )?;
            require(
                !probe.directory.path().join("supervisor-failure").exists(),
                "fixture failed during the stop observation",
            )?;
            println!(
                "::notice title=Windows custody probe::{role}: pass; breakaway refused; scope=cooperating owned processes"
            );
        }
        Ok(())
    }

    pub fn run() -> io::Result<()> {
        let mut args = std::env::args_os().skip(1);
        let Some(role) = args.next() else {
            return controller();
        };
        let directory = PathBuf::from(
            args.next()
                .ok_or_else(|| io::Error::other("fixture directory required"))?,
        );
        let result = match role.to_str() {
            Some("supervisor-stop") => supervisor(&directory, true),
            Some("supervisor-crash") => supervisor(&directory, false),
            Some("worker") => worker(&directory),
            Some("heartbeat") => writer(&directory),
            Some("mark") => publish(&directory, "normal-child", "started"),
            _ => Err(io::Error::other("unknown probe role")),
        };
        if let Err(error) = &result {
            let _ = publish(&directory, "supervisor-failure", &error.to_string());
        }
        result
    }
}
