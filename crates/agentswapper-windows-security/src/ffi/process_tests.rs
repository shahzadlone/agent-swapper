//! Disposable alternate-parent measurement. Never selects an existing process.
//!
//! The outer production Job owns the controller and its fresh peer. The
//! controller installs a nested root only AFTER starting that peer, then uses
//! the production per-run backend to start the target. All fixture roles have
//! deadlines and an authentication-free environment. No Job handles are shared.

use agentswapper_core::supervision::windows_job::{JobChild, WindowsJob, install_process_root};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::{self, File, TryLockError},
    io,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    ptr::{null, null_mut},
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, FILETIME, HANDLE},
    System::Threading::{
        CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetProcessTimes, InitializeProcThreadAttributeList,
        OpenProcess, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, PROCESS_CREATE_PROCESS,
        PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, STARTUPINFOEXW,
        UpdateProcThreadAttribute,
    },
};

const ENTRY: &str = "ffi::process_tests::fixture_entry";
const STEP: Duration = Duration::from_secs(10);
const TOTAL: Duration = Duration::from_secs(45);
const LIFETIME: Duration = Duration::from_secs(90);

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

fn until<T>(budget: Duration, mut check: impl FnMut() -> io::Result<Option<T>>) -> io::Result<T> {
    let deadline = Instant::now() + budget;
    loop {
        if let Some(value) = check()? {
            return Ok(value);
        }
        require(
            Instant::now() < deadline,
            "process fixture deadline exceeded",
        )?;
        thread::sleep(Duration::from_millis(10));
    }
}

fn environment(dir: &Path, role: &str) -> BTreeMap<OsString, OsString> {
    let mut env = BTreeMap::new();
    for key in ["SYSTEMROOT", "WINDIR", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(key) {
            env.insert(key.into(), value);
        }
    }
    env.insert("ASWP_PARENT_DIR".into(), dir.as_os_str().to_owned());
    env.insert("ASWP_PARENT_ROLE".into(), role.into());
    env
}

fn command(dir: &Path, role: &str) -> io::Result<Command> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--exact", ENTRY, "--ignored", "--nocapture"])
        .env_clear()
        .envs(environment(dir, role))
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    Ok(command)
}

struct Peer(Child);
impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = until(STEP, || self.0.try_wait());
    }
}

struct Backstop(Option<JobChild>);
impl Backstop {
    fn finish(&mut self) -> io::Result<()> {
        self.0
            .take()
            .ok_or_else(|| io::Error::other("backstop already consumed"))?
            .stop_and_observe()
            .map(|_| ())
    }
}
impl Drop for Backstop {
    fn drop(&mut self) {
        // Attempt bounded termination AND the empty query on unwinding too.
        // Failure cannot create evidence: only explicit finish can succeed.
        if let Some(scope) = self.0.take() {
            let _ = scope.stop_and_observe();
        }
    }
}

fn marker(dir: &Path, role: &str, suffix: &str) -> PathBuf {
    dir.join(format!("{role}-{suffix}"))
}

fn writer(dir: &Path, role: &str) -> io::Result<()> {
    let lease = File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(marker(dir, role, "lock"))?;
    lease.try_lock().map_err(io::Error::other)?;
    fs::write(marker(dir, role, "ready"), b"ready")?;
    let started = Instant::now();
    let mut answered_before = false;
    let mut answered_after = false;
    while started.elapsed() < LIFETIME {
        if !answered_before && marker(dir, role, "before-challenge").exists() {
            fs::write(marker(dir, role, "before-response"), b"alive before stop")?;
            answered_before = true;
        }
        if !answered_after && marker(dir, role, "challenge").exists() {
            // Challenge is created only after the inner stop receipt. This
            // establishes new execution, rather than a stale buffered heartbeat.
            fs::write(marker(dir, role, "response"), b"alive after receipt")?;
            answered_after = true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    fs::write(marker(dir, role, "voluntary"), b"expired")
}

fn observe(dir: &Path, role: &str) -> io::Result<File> {
    until(STEP, || {
        Ok(marker(dir, role, "ready").exists().then_some(()))
    })?;
    let file = File::options()
        .read(true)
        .write(true)
        .open(marker(dir, role, "lock"))?;
    require(alive(&file)?, "writer was not alive before stop")?;
    Ok(file)
}

fn alive(file: &File) -> io::Result<bool> {
    match file.try_lock() {
        Ok(()) => {
            file.unlock()?;
            Ok(false)
        }
        Err(TryLockError::WouldBlock) => Ok(true),
        Err(TryLockError::Error(error)) => Err(error),
    }
}

fn stopped(dir: &Path, role: &str, file: &File) -> io::Result<()> {
    until(STEP, || Ok((!alive(file)?).then_some(())))?;
    require(
        !marker(dir, role, "voluntary").exists(),
        "writer expired voluntarily",
    )
}

fn creation_time(handle: HANDLE) -> io::Result<u64> {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: caller retains a live process handle; all output FILETIMEs are
    // initialized, writable and exclusive for this synchronous call.
    if unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut value: Vec<u16> = value.encode_wide().collect();
    require(!value.contains(&0), "embedded NUL in fixture argument")?;
    value.push(0);
    Ok(value)
}

struct Attributes(Vec<usize>);
impl Attributes {
    fn new() -> io::Result<Self> {
        let mut bytes = 0;
        // SAFETY: the documented sizing call accepts a null list and writes size.
        let result = unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut bytes) };
        let error = io::Error::last_os_error();
        require(
            result == 0 && error.raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER as i32),
            "unexpected attribute-list sizing result",
        )?;
        require(
            bytes > 0 && bytes <= 65536,
            "unexpected attribute-list size",
        )?;
        let mut buffer = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        // SAFETY: this aligned allocation is at least the requested size; it
        // remains owned and unmoved through DeleteProcThreadAttributeList.
        if unsafe {
            InitializeProcThreadAttributeList(buffer.as_mut_ptr().cast(), 1, 0, &mut bytes)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(buffer))
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: exactly one successful initialization owns this allocation;
        // deletion runs before its Vec storage is freed.
        unsafe { DeleteProcThreadAttributeList(self.0.as_mut_ptr().cast()) };
    }
}

fn alternate_writer(dir: &Path, peer_pid: u32, expected_created: u64) -> io::Result<OwnedHandle> {
    // SAFETY: PID identifies only our live fixture peer. OpenProcess does not
    // mutate it. Identity is checked below before using it as a selected parent.
    let raw = unsafe {
        OpenProcess(
            PROCESS_CREATE_PROCESS | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            peer_pid,
        )
    };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful OpenProcess returns a fresh owned, non-inherited handle.
    let peer = unsafe { OwnedHandle::from_raw_handle(raw) };
    require(
        creation_time(peer.as_raw_handle())? == expected_created,
        "fixture peer identity changed",
    )?;
    let peer_handle = peer.as_raw_handle();
    let mut attributes = Attributes::new()?;
    // SAFETY: the parent handle value and its owning handle outlive attributes;
    // the list is initialized and stores one correctly sized HANDLE attribute.
    if unsafe {
        UpdateProcThreadAttribute(
            attributes.0.as_mut_ptr().cast(),
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
            (&peer_handle as *const HANDLE).cast(),
            size_of::<HANDLE>(),
            null_mut(),
            null(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let exe = std::env::current_exe()?;
    let executable = wide(exe.as_os_str())?;
    require(
        !executable.contains(&u16::from(b'"')),
        "quote in executable path",
    )?;
    let mut line = OsString::from("\"");
    line.push(exe.as_os_str());
    line.push(format!("\" --exact {ENTRY} --ignored --nocapture"));
    let mut line = wide(&line)?;
    let cwd = wide(dir.as_os_str())?;
    let mut env = Vec::new();
    for (key, value) in environment(dir, "alternate") {
        let mut entry = key;
        entry.push("=");
        entry.push(value);
        env.extend(wide(&entry)?);
    }
    env.push(0);
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.lpAttributeList = attributes.0.as_mut_ptr().cast();
    let mut process = PROCESS_INFORMATION::default();
    // SAFETY: all UTF-16 inputs are terminated (environment twice), writable
    // command line and outputs are exclusive, and the initialized attribute
    // list/peer live through this synchronous call. No handles are inherited.
    // Only this exact fixture binary, fixed test entry and clean env are used.
    if unsafe {
        CreateProcessW(
            executable.as_ptr(),
            line.as_mut_ptr(),
            null(),
            null(),
            0,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            env.as_ptr().cast(),
            cwd.as_ptr(),
            &startup.StartupInfo,
            &mut process,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful CreateProcessW transferred two fresh owned handles.
    let child = unsafe { OwnedHandle::from_raw_handle(process.hProcess) };
    // SAFETY: this is the separate primary-thread handle from that success.
    drop(unsafe { OwnedHandle::from_raw_handle(process.hThread) });
    Ok(child)
}

fn target(dir: &Path) -> io::Result<()> {
    let pid: u32 = std::env::var("ASWP_PARENT_PID")
        .map_err(io::Error::other)?
        .parse()
        .map_err(io::Error::other)?;
    let created: u64 = std::env::var("ASWP_PARENT_CREATED")
        .map_err(io::Error::other)?
        .parse()
        .map_err(io::Error::other)?;
    let _normal = command(dir, "normal")?.spawn()?;
    let _alternate = alternate_writer(dir, pid, created)?;
    // The inner Job kills the target. Its children are intentionally not killed
    // by Rust Drop, so the fixture measures the kernel's actual Job membership.
    thread::sleep(LIFETIME);
    Err(io::Error::other("target reached its lifetime deadline"))
}

fn controller(dir: &Path) -> io::Result<()> {
    let peer = Peer(command(dir, "peer")?.spawn()?);
    let peer_lock = observe(dir, "peer")?;
    let created = creation_time(peer.0.as_raw_handle())?;
    install_process_root()?;
    let mut target_command = command(dir, "target")?;
    target_command
        .env("ASWP_PARENT_PID", peer.0.id().to_string())
        .env("ASWP_PARENT_CREATED", created.to_string());
    let target = WindowsJob::create()?.spawn(target_command, |_| Ok(()))?;
    let normal = observe(dir, "normal")?;
    let alternate = observe(dir, "alternate")?;
    // Establish execution after both ready markers, before issuing any stop.
    // A failed spawn or stalled startup is inconclusive, never a stopped result.
    for (role, file) in [("normal", &normal), ("alternate", &alternate)] {
        fs::write(marker(dir, role, "before-challenge"), b"before stop")?;
        until(STEP, || {
            Ok(marker(dir, role, "before-response").exists().then_some(()))
        })?;
        require(alive(file)?, "writer stopped before the inner stop request")?;
    }
    target.stop_and_observe()?;
    stopped(dir, "normal", &normal)?;
    fs::write(marker(dir, "peer", "challenge"), b"after inner receipt")?;
    fs::write(
        marker(dir, "alternate", "challenge"),
        b"after inner receipt",
    )?;
    until(STEP, || {
        Ok(marker(dir, "peer", "response").exists().then_some(()))
    })?;
    require(
        alive(&peer_lock)?,
        "outside peer stopped with the target Job",
    )?;
    let survived = until(STEP, || {
        if marker(dir, "alternate", "response").exists() {
            require(
                alive(&alternate)?,
                "alternate answered but is no longer alive",
            )?;
            Ok(Some(true))
        } else if !alive(&alternate)? {
            stopped(dir, "alternate", &alternate)?;
            Ok(Some(false))
        } else {
            Ok(None)
        }
    })?;
    fs::write(
        dir.join("observation"),
        if survived {
            b"survived".as_slice()
        } else {
            b"stopped".as_slice()
        },
    )?;
    Ok(())
}

#[test]
#[ignore = "owned subprocess entry for alternate-parent qualification"]
fn fixture_entry() -> io::Result<()> {
    let dir = PathBuf::from(
        std::env::var_os("ASWP_PARENT_DIR")
            .ok_or_else(|| io::Error::other("fixture directory absent"))?,
    );
    require(dir.is_absolute(), "fixture directory must be absolute")?;
    match std::env::var("ASWP_PARENT_ROLE").as_deref() {
        Ok("controller") => controller(&dir),
        Ok("target") => target(&dir),
        Ok(role @ ("normal" | "alternate" | "peer")) => writer(&dir, role),
        _ => Err(io::Error::other("unknown fixture role")),
    }
}

#[test]
#[ignore = "dedicated process: installs a lifetime root Job; invoked explicitly in Windows CI"]
fn alternate_parent_custody() -> io::Result<()> {
    let result = measure();
    if result.is_err() {
        println!(
            "::error title=Windows alternate-parent custody::qualification failed; no custody conclusion"
        );
    }
    result
}

fn measure() -> io::Result<()> {
    // Run only with nextest's exact per-test filter (as CI does). Do not run
    // this alongside other tests in a shared cargo-test harness process.
    let dir = tempfile::tempdir()?;
    install_process_root()?;
    let mut outer = Backstop(Some(
        WindowsJob::create()?.spawn(command(dir.path(), "controller")?, |_| Ok(()))?,
    ));
    let result = until(TOTAL, || {
        outer
            .0
            .as_mut()
            .ok_or_else(|| io::Error::other("backstop absent"))?
            .try_wait()
    });
    // Consume and retire the outer Job even when the controller failed/timed
    // out. Its peer is the alternate writer's selected parent, so this backstop
    // also owns that writer independently of the controller's inner root.
    outer.finish()?;
    for role in ["normal", "alternate", "peer"] {
        let path = marker(dir.path(), role, "lock");
        if path.exists() {
            let file = File::options().read(true).write(true).open(path)?;
            stopped(dir.path(), role, &file)?;
        }
    }
    require(result?.success(), "fixture controller failed")?;
    match fs::read(dir.path().join("observation"))?.as_slice() {
        b"survived" => println!(
            "::notice title=Windows alternate-parent custody::owned alternate-parent writer executed after inner Job empty receipt; normal writer stopped; outside peer continued; all fixture writers observed stopped; outer Job observed empty"
        ),
        b"stopped" => println!(
            "::notice title=Windows alternate-parent custody::owned alternate-parent and normal writers stopped with inner Job; outside peer continued; all fixture writers observed stopped; outer Job observed empty"
        ),
        _ => return Err(io::Error::other("missing bounded custody observation")),
    }
    Ok(())
}
