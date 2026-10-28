//! Exercise the reusable per-run backend with cooperating fixture processes only.
#![forbid(unsafe_code)]

#[cfg(not(windows))]
fn main() {
    println!("Windows-only supervision probe; no provider was launched.");
}

#[cfg(windows)]
fn main() {
    if let Err(error) = probe::run() {
        let text = error
            .to_string()
            .replace('%', "%25")
            .replace('\r', "%0D")
            .replace('\n', "%0A");
        println!("::error title=Windows per-run supervision::{text}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
mod probe {
    use agentswapper_core::supervision::windows_job::{JobChild, WindowsJob};
    use std::{
        fs::{self, File, TryLockError},
        io,
        os::windows::process::CommandExt,
        path::Path,
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Foundation::ERROR_ACCESS_DENIED, System::Threading::CREATE_BREAKAWAY_FROM_JOB,
    };

    const BUDGET: Duration = Duration::from_secs(15);
    const LIFETIME: Duration = Duration::from_secs(45);

    fn require(ok: bool, message: &str) -> io::Result<()> {
        if ok {
            Ok(())
        } else {
            Err(io::Error::other(message.to_owned()))
        }
    }

    fn until<T>(mut check: impl FnMut() -> io::Result<Option<T>>) -> io::Result<T> {
        let deadline = Instant::now() + BUDGET;
        loop {
            if let Some(value) = check()? {
                return Ok(value);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "fixture deadline exceeded",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn command(role: &str, dir: &Path) -> io::Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        command.env_clear();
        for key in ["SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        command
            .arg(role)
            .arg(dir)
            .current_dir(dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        Ok(command)
    }

    fn publish(dir: &Path, name: &str) -> io::Result<()> {
        fs::write(dir.join(name), b"ready")
    }

    fn writer(dir: &Path) -> io::Result<()> {
        let lease = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.join("writer-lock"))?;
        lease
            .try_lock()
            .map_err(|error| io::Error::other(error.to_string()))?;
        publish(dir, "writer-ready")?;
        let started = Instant::now();
        while started.elapsed() < LIFETIME && !dir.join("stop").exists() {
            std::thread::sleep(Duration::from_millis(10));
        }
        publish(dir, "voluntary-exit")?;
        drop(lease);
        Ok(())
    }

    fn observe_writer(dir: &Path) -> io::Result<File> {
        until(|| Ok(dir.join("writer-ready").exists().then_some(())))?;
        let file = File::options()
            .read(true)
            .write(true)
            .open(dir.join("writer-lock"))?;
        require(
            matches!(file.try_lock(), Err(TryLockError::WouldBlock)),
            "writer not alive before stop",
        )?;
        Ok(file)
    }

    fn observed_stopped(dir: &Path, file: &File) -> io::Result<()> {
        until(|| match file.try_lock() {
            Ok(()) => Ok(Some(())),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(error)) => Err(error),
        })?;
        require(
            !dir.join("voluntary-exit").exists(),
            "writer exited voluntarily; cleanup evidence invalid",
        )
    }

    struct NativeGuard(Child);
    impl Drop for NativeGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = until(|| self.0.try_wait());
        }
    }

    fn worker(dir: &Path) -> io::Result<()> {
        // First target instruction must observe callback completion. Then spawn
        // a descendant immediately, without a cooperative admission handshake.
        require(
            dir.join("admitted").exists(),
            "target ran before admission callback",
        )?;
        publish(dir, "executed")?;
        let _leaf = command("writer", dir)?.spawn()?;
        let mut normal = NativeGuard(command("mark", dir)?.spawn()?);
        require(
            until(|| normal.0.try_wait())?.success(),
            "normal child spawn failed",
        )?;
        match command("mark", dir)?
            .creation_flags(CREATE_BREAKAWAY_FROM_JOB)
            .spawn()
        {
            Ok(child) => {
                drop(NativeGuard(child));
                return Err(io::Error::other("breakaway unexpectedly succeeded"));
            }
            Err(error) if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {}
            Err(error) => {
                return Err(io::Error::other(format!(
                    "unexpected breakaway error: {error}"
                )));
            }
        }
        publish(dir, "breakaway-refused")
    }

    fn launch(dir: &Path) -> io::Result<JobChild> {
        WindowsJob::create()?.spawn(command("worker", dir)?, |_| {
            std::thread::sleep(Duration::from_millis(500));
            require(!dir.join("executed").exists(), "target escaped suspension")?;
            publish(dir, "admitted")
        })
    }

    fn orphan_ready(child: &mut JobChild, dir: &Path) -> io::Result<File> {
        require(until(|| child.try_wait())?.success(), "worker failed")?;
        require(
            dir.join("breakaway-refused").exists(),
            "missing breakaway evidence",
        )?;
        observe_writer(dir)
    }

    fn controller() -> io::Result<()> {
        let first = tempfile::tempdir()?;
        let second = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let mut unrelated = NativeGuard(command("writer", outside.path())?.spawn()?);
        let outside_lock = observe_writer(outside.path())?;
        let mut a = launch(first.path())?;
        let mut b = launch(second.path())?;
        let a_lock = orphan_ready(&mut a, first.path())?;
        let b_lock = orphan_ready(&mut b, second.path())?;
        require(a.scope_id() != b.scope_id(), "scope IDs reused")?;

        let failed = WindowsJob::create()?
            .spawn(Command::new(first.path().join("missing.exe")), |_| {
                Err(io::Error::other("callback for failed spawn should not run"))
            });
        require(failed.is_err(), "missing executable unexpectedly launched")?;
        let expected = a.scope_id();
        require(
            a.stop_and_observe()?.id() == expected,
            "receipt does not match scope",
        )?;
        observed_stopped(first.path(), &a_lock)?;
        require(
            matches!(b_lock.try_lock(), Err(TryLockError::WouldBlock)),
            "sibling Job was killed",
        )?;
        require(
            unrelated.0.try_wait()?.is_none(),
            "unrelated child was killed",
        )?;
        require(
            matches!(outside_lock.try_lock(), Err(TryLockError::WouldBlock)),
            "outside writer stopped",
        )?;
        b.stop_and_observe()?;
        observed_stopped(second.path(), &b_lock)?;
        println!(
            "independent Jobs, orphan cleanup, failed spawn isolation, breakaway refusal: pass"
        );

        let empty = tempfile::tempdir()?;
        let mut child = WindowsJob::create()?.spawn(command("mark", empty.path())?, |_| Ok(()))?;
        require(
            until(|| child.try_wait())?.success(),
            "empty-scope control failed",
        )?;
        child.stop_and_observe()?;

        for panic in [false, true] {
            let dir = tempfile::tempdir()?;
            let scope = WindowsJob::create()?;
            let target = command("mark", dir.path())?;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                scope.spawn(target, |_| {
                    if panic {
                        panic!("intentional admission unwind");
                    }
                    Err(io::Error::other("intentional admission rejection"))
                })
            }));
            match result {
                Ok(result) => require(!panic && result.is_err(), "admission rejection failed")?,
                Err(_) => require(panic, "unexpected admission panic")?,
            }
            std::thread::sleep(Duration::from_millis(200));
            require(
                !dir.path().join("mark").exists(),
                "rejected target executed",
            )?;
        }
        println!("admission ordering, rejection and unwind: pass");

        let dropped = tempfile::tempdir()?;
        let sibling = tempfile::tempdir()?;
        let mut child = launch(dropped.path())?;
        // Spawn B after A's Job exists: B must not inherit A's ownership handle.
        let mut other = launch(sibling.path())?;
        let lock = orphan_ready(&mut child, dropped.path())?;
        let sibling_lock = orphan_ready(&mut other, sibling.path())?;
        drop(child);
        observed_stopped(dropped.path(), &lock)?;
        require(
            matches!(sibling_lock.try_lock(), Err(TryLockError::WouldBlock)),
            "drop killed sibling scope",
        )?;
        other.stop_and_observe()?;
        observed_stopped(sibling.path(), &sibling_lock)?;

        let crashed = tempfile::tempdir()?;
        let mut supervisor = NativeGuard(command("supervisor", crashed.path())?.spawn()?);
        until(|| {
            require(
                supervisor.0.try_wait()?.is_none(),
                "supervisor exited before crash test",
            )?;
            Ok(crashed.path().join("orphaned").exists().then_some(()))
        })?;
        let lock = observe_writer(crashed.path())?;
        supervisor.0.kill()?;
        require(
            !until(|| supervisor.0.try_wait())?.success(),
            "supervisor wasn't hard-killed",
        )?;
        observed_stopped(crashed.path(), &lock)?;
        require(
            unrelated.0.try_wait()?.is_none(),
            "supervisor crash affected outside child",
        )?;
        println!(
            "drop and supervisor crash cleanup: pass (fixture observation, no durable stop receipt)"
        );
        drop(unrelated);
        Ok(())
    }

    pub fn run() -> io::Result<()> {
        let args: Vec<_> = std::env::args_os().collect();
        if args.len() == 1 {
            return controller();
        }
        let dir = Path::new(
            args.get(2)
                .ok_or_else(|| io::Error::other("missing fixture directory"))?,
        );
        let result = match args[1].to_str() {
            Some("mark") => publish(dir, "mark"),
            Some("writer") => writer(dir),
            Some("worker") => worker(dir),
            Some("supervisor") => {
                let mut child = launch(dir)?;
                let _lock = orphan_ready(&mut child, dir)?;
                publish(dir, "orphaned")?;
                std::thread::sleep(LIFETIME);
                Err(io::Error::other(
                    "supervisor was not killed before deadline",
                ))
            }
            _ => Err(io::Error::other("unknown fixture role")),
        };
        if let Err(error) = &result {
            let _ = fs::write(dir.join("failure"), error.to_string());
        }
        result
    }
}
