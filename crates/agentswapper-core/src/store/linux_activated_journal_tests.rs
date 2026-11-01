//! Real journal/lease integration with the opted-in, root-installed CI fixture.
#![allow(clippy::unwrap_used)]
use super::*;
use aswp_linux_manager_evaluation::journal_client::{Bound, Identity, Prepared, StartCause};
use std::{fs, os::fd::AsFd, thread};

fn environment() -> (String, PathBuf) {
    assert_eq!(
        std::env::var("ASWP_CI_ACTIVATED_JOURNAL").as_deref(),
        Ok("1")
    );
    let prefix = std::env::var("ASWP_ACTIVATION_PREFIX").unwrap();
    let directory = PathBuf::from(std::env::var_os("ASWP_ACTIVATION_DIRECTORY").unwrap());
    assert!(directory.is_absolute());
    (prefix, directory)
}

fn prepare(store: &mut Store, alias: &str, prefix: &str) -> (ProfileId, String, Prepared) {
    prepare_mode(store, alias, prefix, false)
}

fn prepare_mode(
    store: &mut Store,
    alias: &str,
    prefix: &str,
    terminal: bool,
) -> (ProfileId, String, Prepared) {
    let profile = store
        .register(Harness::Claude, alias.parse().unwrap())
        .unwrap();
    let lease = store.lease(profile.id).unwrap();
    let bound = if terminal {
        Bound::connect_terminal(prefix)
    } else {
        Bound::connect(prefix)
    }
    .unwrap();
    let logical = Uuid::new_v4();
    assert_ne!(logical.simple().to_string(), bound.identity().invocation);
    let run = store
        .begin_run_with_scope(
            &lease,
            "run",
            None,
            Some(LocalScope::LinuxCgroup { id: logical }),
        )
        .unwrap();
    let prepared = bound.prepare(lease.as_fd()).unwrap();
    // Only the guardian's received copy now retains this lock.
    drop(lease);
    assert!(matches!(store.acquire_lease(profile.id), Err(Error::Busy)));
    (profile.id, run, prepared)
}

fn heartbeat(
    directory: &Path,
    id: &Identity,
    pid: u32,
    nonce: &[u8; 16],
    previous: Option<&str>,
) -> String {
    let prefix: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let value = fs::read_to_string(directory.join(&id.invocation).join("heartbeat"));
        if let Ok(value) = value
            && value.starts_with(&format!("{pid}:{prefix}:"))
            && previous != Some(value.as_str())
        {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "writer did not acknowledge the journaled GO nonce"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn quiescent(prepared: &Prepared, directory: &Path) {
    let run = directory.join(prepared.identity().invocation);
    assert_eq!(
        fs::read_to_string(run.join("ready")).unwrap(),
        prepared.pid().to_string()
    );
    prepared.observe_ready().unwrap();
    thread::sleep(Duration::from_millis(200));
    assert!(!run.join("heartbeat").exists());
    prepared.observe_ready().unwrap();
}

fn journal_while_gated(
    store: &mut Store,
    run: &str,
    pid: u32,
    directory: &Path,
    id: &Identity,
) -> Result<()> {
    store.observe_spawn(run, pid)?;
    thread::sleep(Duration::from_millis(200));
    assert_eq!(store.run(run)?.observed_pid, Some(pid));
    assert_eq!(
        fs::read_to_string(directory.join(&id.invocation).join("ready"))?,
        pid.to_string()
    );
    assert!(!directory.join(&id.invocation).join("heartbeat").exists());
    Ok(())
}

fn unresolved(store: &Store, profile: ProfileId, run: &str) {
    drop(store.acquire_lease(profile).unwrap());
    assert!(matches!(store.lease(profile), Err(Error::Busy)));
    let record = store.run(run).unwrap();
    assert_eq!(record.custody, ProcessCustody::Unknown);
    assert!(record.exit_code.is_none());
}

fn terminal_output(master: impl AsFd, suffix: &[u8]) -> Vec<u8> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut output = Vec::new();
    while !output.ends_with(suffix) {
        assert!(output.len() < 4096, "terminal output exceeds fixture bound");
        let timeout =
            Timespec::try_from(deadline.checked_duration_since(Instant::now()).unwrap()).unwrap();
        let mut ready = [PollFd::new(&master, PollFlags::IN)];
        assert_eq!(
            poll(&mut ready, Some(&timeout)).unwrap(),
            1,
            "terminal output timed out: {output:?}"
        );
        let mut bytes = [0; 512];
        let read = rustix::io::read(&master, &mut bytes).unwrap();
        assert!(
            read > 0,
            "terminal closed before expected output: {output:?}"
        );
        output.extend_from_slice(&bytes[..read]);
    }
    output
}

fn terminal_input(master: impl AsFd, input: &[u8]) {
    assert_eq!(rustix::io::write(master, input).unwrap(), input.len());
}

#[test]
#[ignore = "requires the opted-in root-owned activation fixture on a hosted runner"]
fn inner_terminal_exec_is_journal_gated_and_retires_with_master_open() {
    let (prefix, directory) = environment();
    for finish in ["disconnect", "interrupt", "journal"] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("state");
        let mut store = Store::open(&root).unwrap();
        let (profile, run, prepared) = prepare_mode(&mut store, "terminal", &prefix, true);
        let id = prepared.identity();
        let pid = prepared.pid();
        let scope = directory.join(&id.invocation);
        // Retain an independent master even across retirement, so a PTY hangup
        // cannot masquerade as successful control-channel cleanup.
        let master = prepared.terminal().unwrap().try_clone_to_owned().unwrap();
        quiescent(&prepared, &directory);
        assert!(!scope.join("final-exec").exists());
        let blocker = Connection::open(root.join("registry.sqlite3")).unwrap();
        if finish == "journal" {
            store.db.busy_timeout(Duration::from_millis(20)).unwrap();
            blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
        }
        let nonce = *Uuid::new_v4().as_bytes();
        let start = prepared.start_after(nonce, |child| {
            assert_eq!(child, pid);
            journal_while_gated(&mut store, &run, child, &directory, &id)?;
            assert!(!scope.join("final-exec").exists());
            Ok::<(), Error>(())
        });
        if finish == "journal" {
            let failure = match start {
                Err(failure) => failure,
                Ok(_) => panic!("SQLite failure released terminal GO"),
            };
            assert!(matches!(failure.live_at_refusal, Some(Ok(()))));
            assert!(matches!(failure.cause,
                StartCause::Journal(Error::Database(rusqlite::Error::SqliteFailure(ref error, _)))
                if error.code == rusqlite::ErrorCode::DatabaseBusy));
            assert!(
                failure
                    .closed
                    .retire()
                    .unwrap()
                    .connection_close_error
                    .is_none()
            );
            assert_eq!(
                fs::read_to_string(scope.join("guardian-withdrawn-before-go")).unwrap(),
                id.invocation
            );
            assert!(!scope.join("final-exec").exists());
            blocker.execute_batch("ROLLBACK").unwrap();
        } else {
            let running = start.unwrap();
            let nonce: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
            let output = terminal_output(&master, b"\x1b[0m\r\n");
            assert_eq!(
                output,
                format!("\x1b[32mREADY:{pid}:{nonce}:→\x1b[0m\r\n").as_bytes()
            );
            assert_eq!(
                fs::read_to_string(scope.join("final-exec")).unwrap(),
                format!("{pid}:{nonce}")
            );
            rustix::termios::tcsetwinsize(
                &master,
                rustix::termios::Winsize {
                    ws_row: 41,
                    ws_col: 113,
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                },
            )
            .unwrap();
            terminal_input(&master, b"size\n");
            terminal_output(&master, b"SIZE:41:113\r\n");
            terminal_input(&master, b"secret\n");
            terminal_output(&master, b"SECRET>");
            terminal_input(&master, b"fake-password-123\n");
            assert_eq!(terminal_output(&master, b"SECRET-OK\r\n"), b"SECRET-OK\r\n");
            terminal_input(&master, b"raw\n");
            terminal_output(&master, b"RAW>");
            let bytes = "é→\x1b[A\x03".as_bytes();
            terminal_input(&master, &[bytes, b"\n"].concat());
            let encoded: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(
                terminal_output(&master, b"\r\n"),
                format!("RAW:{encoded}\r\n").as_bytes()
            );
            assert!(matches!(store.acquire_lease(profile), Err(Error::Busy)));
            if finish == "interrupt" {
                terminal_input(&master, b"\x03");
                let deadline = Instant::now() + Duration::from_secs(4);
                while !scope.join("target-exit").exists() {
                    assert!(
                        Instant::now() < deadline,
                        "Ctrl-C did not terminate the foreground target"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                assert_eq!(
                    fs::read_to_string(scope.join("target-exit")).unwrap(),
                    "None:Some(2)"
                );
            }
            assert!(
                running
                    .close()
                    .retire()
                    .unwrap()
                    .connection_close_error
                    .is_none()
            );
            if finish == "disconnect" {
                assert_eq!(
                    fs::read_to_string(scope.join("guardian-clean-eof")).unwrap(),
                    id.invocation
                );
                assert!(!scope.join("target-exit").exists());
            }
        }
        unresolved(&store, profile, &run);
        drop(blocker);
        drop(store);
        let reopened = Store::open(&root).unwrap();
        unresolved(&reopened, profile, &run);
        assert_eq!(
            reopened.run(&run).unwrap().observed_pid,
            if finish == "journal" { None } else { Some(pid) }
        );
        assert!(reopened.verify().unwrap().consistent);
        drop(master);
    }
}

#[test]
#[ignore = "requires the opted-in root-owned activation fixture on a hosted runner"]
fn actual_lease_and_journal_gate_two_independent_activations() {
    let (prefix, directory) = environment();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    let mut store = Store::open(&root).unwrap();
    let started = Instant::now();
    let (profile_a, run_a, a) = prepare(&mut store, "activation-a", &prefix);
    let id_a = a.identity();
    assert!(!directory.join(&id_a.invocation).join("heartbeat").exists());
    let pid_a = a.pid();
    quiescent(&a, &directory);
    let nonce_a = *Uuid::new_v4().as_bytes();
    let a = a
        .start_after(nonce_a, |pid| {
            journal_while_gated(&mut store, &run_a, pid, &directory, &id_a)
        })
        .unwrap();
    heartbeat(&directory, &id_a, pid_a, &nonce_a, None);
    let (profile_b, run_b, b) = prepare(&mut store, "activation-b", &prefix);
    let id_b = b.identity();
    assert_ne!(id_a.invocation, id_b.invocation);
    assert_ne!(id_a.unit, id_b.unit);
    assert_ne!(
        (id_a.directory_device, id_a.directory_inode),
        (id_b.directory_device, id_b.directory_inode)
    );
    assert!(!directory.join(&id_b.invocation).join("heartbeat").exists());
    let pid_b = b.pid();
    quiescent(&b, &directory);
    let nonce_b = *Uuid::new_v4().as_bytes();
    let b = b
        .start_after(nonce_b, |pid| {
            journal_while_gated(&mut store, &run_b, pid, &directory, &id_b)
        })
        .unwrap();
    heartbeat(&directory, &id_b, pid_b, &nonce_b, None);
    assert!(started.elapsed() < Duration::from_secs(20));
    assert!(a.close().retire().unwrap().connection_close_error.is_none());
    unresolved(&store, profile_a, &run_a);
    let before = heartbeat(&directory, &id_b, pid_b, &nonce_b, None);
    heartbeat(&directory, &id_b, pid_b, &nonce_b, Some(&before));
    assert!(matches!(store.acquire_lease(profile_b), Err(Error::Busy)));
    assert!(b.close().retire().unwrap().connection_close_error.is_none());
    unresolved(&store, profile_b, &run_b);
    for id in [&id_a, &id_b] {
        assert!(
            !directory
                .join(&id.invocation)
                .join("voluntary-exit")
                .exists()
        );
        assert_eq!(
            fs::read_to_string(directory.join(&id.invocation).join("guardian-clean-eof")).unwrap(),
            id.invocation
        );
    }
    drop(store);
    let reopened = Store::open(&root).unwrap();
    unresolved(&reopened, profile_a, &run_a);
    unresolved(&reopened, profile_b, &run_b);
    assert_eq!(reopened.run(&run_a).unwrap().observed_pid, Some(pid_a));
    assert_eq!(reopened.run(&run_b).unwrap().observed_pid, Some(pid_b));
    assert!(reopened.verify().unwrap().consistent);
    println!(
        "::notice title=Linux activated journal::two distinct invocations kept real leases, journaled PID before nonce-bound GO, retired independently and retained unresolved intent after reopening"
    );
}

#[test]
#[ignore = "requires the opted-in root-owned activation fixture on a hosted runner"]
fn sqlite_write_failure_withholds_go_and_keeps_unresolved_intent() {
    let (prefix, directory) = environment();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    let mut store = Store::open(&root).unwrap();
    let (profile, run, prepared) = prepare(&mut store, "activation-busy", &prefix);
    let id = prepared.identity();
    quiescent(&prepared, &directory);
    store.db.busy_timeout(Duration::from_millis(20)).unwrap();
    let blocker = Connection::open(root.join("registry.sqlite3")).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let failure = match prepared.start_after(*Uuid::new_v4().as_bytes(), |pid| {
        store.observe_spawn(&run, pid)
    }) {
        Err(failure) => failure,
        Ok(_) => panic!("journal failure unexpectedly released GO"),
    };
    assert!(matches!(failure.live_at_refusal, Some(Ok(()))));
    let result = failure.cause;
    assert!(
        matches!(result, StartCause::Journal(Error::Database(rusqlite::Error::SqliteFailure(ref error, _)))
        if error.code == rusqlite::ErrorCode::DatabaseBusy),
        "unexpected journal failure: {result:?}"
    );
    assert!(!directory.join(&id.invocation).join("heartbeat").exists());
    assert!(
        failure
            .closed
            .retire()
            .unwrap()
            .connection_close_error
            .is_none()
    );
    assert_eq!(
        fs::read_to_string(
            directory
                .join(&id.invocation)
                .join("guardian-withdrawn-before-go")
        )
        .unwrap(),
        id.invocation
    );
    unresolved(&store, profile, &run);
    assert!(!directory.join(&id.invocation).join("heartbeat").exists());
    blocker.execute_batch("ROLLBACK").unwrap();
    drop(blocker);
    drop(store);
    let reopened = Store::open(&root).unwrap();
    unresolved(&reopened, profile, &run);
    assert_eq!(reopened.run(&run).unwrap().observed_pid, None);
    assert!(reopened.verify().unwrap().consistent);
    println!(
        "::notice title=Linux activated journal refusal::actual SQLite BUSY withheld GO; gated child retired without heartbeat and unresolved intent survived reopening"
    );
}

#[test]
#[ignore = "requires the opted-in root-owned activation fixture on a hosted runner"]
fn invalid_or_independently_locked_lease_never_spawns_writer() {
    use std::os::unix::fs::PermissionsExt;
    let (prefix, directory) = environment();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    let mut store = Store::open(&root).unwrap();
    for reason in ["metadata", "locked"] {
        let profile = store
            .register(Harness::Claude, format!("lease-{reason}").parse().unwrap())
            .unwrap();
        let lease = store.lease(profile.id).unwrap();
        let bound = Bound::connect(&prefix).unwrap();
        let id = bound.identity();
        let run = store
            .begin_run_with_scope(
                &lease,
                "run",
                None,
                Some(LocalScope::LinuxCgroup { id: Uuid::new_v4() }),
            )
            .unwrap();
        let wrong = tempfile::NamedTempFile::new_in(temp.path()).unwrap();
        if reason == "metadata" {
            wrong
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o644))
                .unwrap();
        } else {
            wrong.as_file().try_lock().unwrap();
        }
        let independent = File::open(wrong.path()).unwrap();
        let failure = match bound.prepare(independent.as_fd()) {
            Err(failure) => failure,
            Ok(_) => panic!("invalid lease spawned a writer"),
        };
        assert!(!directory.join(&id.invocation).exists());
        assert_eq!(
            fs::read_to_string(directory.join(format!("{}.lease-refused", id.invocation))).unwrap(),
            reason
        );
        drop(lease);
        assert!(
            failure
                .closed
                .retire()
                .unwrap()
                .connection_close_error
                .is_none()
        );
        unresolved(&store, profile.id, &run);
        let reopened = Store::open(&root).unwrap();
        unresolved(&reopened, profile.id, &run);
        assert_eq!(reopened.run(&run).unwrap().observed_pid, None);
        assert!(reopened.verify().unwrap().consistent);
    }
    println!(
        "::notice title=Linux activated lease refusal::invalid metadata and independently locked lease refused before writer creation; real planned runs remain unresolved"
    );
}

#[test]
#[ignore = "requires the opted-in root-owned activation fixture on a hosted runner"]
fn guardian_sigkill_retires_writer_without_clearing_journal() {
    let (prefix, directory) = environment();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    let mut store = Store::open(&root).unwrap();
    let (profile, run, prepared) = prepare(&mut store, "guardian-crash", &prefix);
    let id = prepared.identity();
    let writer = prepared.pid();
    let nonce = *Uuid::new_v4().as_bytes();
    let running = prepared
        .start_after(nonce, |pid| store.observe_spawn(&run, pid))
        .unwrap();
    let before = heartbeat(&directory, &id, writer, &nonce, None);
    heartbeat(&directory, &id, writer, &nonce, Some(&before));
    assert!(matches!(store.acquire_lease(profile), Err(Error::Busy)));
    // This signal is sent before the sole client channel is closed. No
    // guardian destructor or cooperative EOF path can be responsible.
    let closed = match running.crash_guardian() {
        Ok(closed) => closed,
        Err(failure) => {
            let reason = failure.error.to_string();
            let retirement = failure.closed.retire();
            panic!(
                "guardian fault refused: {reason}; retirement error: {:?}",
                retirement.err()
            );
        }
    };
    assert!(closed.retire().unwrap().connection_close_error.is_none());
    unresolved(&store, profile, &run);
    assert!(
        !directory
            .join(&id.invocation)
            .join("guardian-clean-eof")
            .exists()
    );
    assert!(
        !directory
            .join(&id.invocation)
            .join("voluntary-exit")
            .exists()
    );
    drop(store);
    let reopened = Store::open(&root).unwrap();
    unresolved(&reopened, profile, &run);
    assert!(reopened.verify().unwrap().consistent);
    println!(
        "::notice title=Linux activated guardian loss::SIGKILL requested through retained pidfd; original scope and writer retired; raw lock released but reopened journal still refuses launch"
    );
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientReport {
    profile: ProfileId,
    run: String,
    unit: String,
    invocation: String,
    guardian: u32,
    writer: u32,
    device: u64,
    inode: u64,
    nonce: [u8; 16],
}

const CLIENT_ROLE: &str = "store::linux_activated_journal_tests::client_crash_role";

#[test]
#[ignore = "private subprocess role for hosted activation client-loss fixture"]
fn client_crash_role() {
    let (prefix, directory) = environment();
    let root = PathBuf::from(std::env::var_os("ASWP_ACTIVATION_CLIENT_ROOT").unwrap());
    let reports = PathBuf::from(std::env::var_os("ASWP_ACTIVATION_REPORTS").unwrap());
    let mut store = Store::open(&root).unwrap();
    let (profile, run, prepared) = prepare(&mut store, "client-crash", &prefix);
    let id = prepared.identity();
    let writer = prepared.pid();

    let nonce = *Uuid::new_v4().as_bytes();
    let _running = prepared
        .start_after(nonce, |pid| store.observe_spawn(&run, pid))
        .unwrap();
    heartbeat(&directory, &id, writer, &nonce, None);
    let report = ClientReport {
        profile,
        run,
        unit: id.unit,
        invocation: id.invocation,
        guardian: id.guardian_pid,
        writer,
        device: id.directory_device,
        inode: id.directory_inode,
        nonce,
    };
    fs::write(
        reports.join("client-ready.tmp"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    fs::rename(
        reports.join("client-ready.tmp"),
        reports.join("client-ready"),
    )
    .unwrap();
    thread::sleep(Duration::from_secs(60));
    fs::write(reports.join("client-voluntary"), "deadline").unwrap();
    panic!("client fault controller did not kill its owned child");
}

#[test]
#[ignore = "requires the opted-in root-owned activation fixture on a hosted runner"]
fn client_sigkill_retires_writer_without_running_client_cleanup() {
    use aswp_linux_manager_evaluation::journal_client::Witness;
    use std::{
        os::unix::process::ExitStatusExt,
        process::{Child, Command, Stdio},
    };
    use wait_timeout::ChildExt;
    struct Owned(Child);
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait_timeout(Duration::from_secs(3));
        }
    }
    let (prefix, directory) = environment();
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("state");
    let reports = temporary.path().join("reports");
    private_fs::directory(&reports, true).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", CLIENT_ROLE, "--ignored", "--nocapture"])
        .env_clear()
        .env("ASWP_ACTIVATION_CLIENT_ROOT", &root)
        .env("ASWP_ACTIVATION_REPORTS", &reports)
        .env("RUST_BACKTRACE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            File::create(temporary.path().join("client.stderr")).unwrap(),
        ));
    for key in [
        "GITHUB_ACTIONS",
        "RUNNER_ENVIRONMENT",
        "ASWP_CI_SOCKET_ACTIVATION",
        "ASWP_CI_ACTIVATED_JOURNAL",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "ASWP_ACTIVATION_PREFIX",
        "ASWP_ACTIVATION_DIRECTORY",
    ] {
        command.env(key, std::env::var_os(key).unwrap());
    }
    let mut client = Owned(command.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(15);
    while !reports.join("client-ready").exists() {
        assert!(
            client.0.try_wait().unwrap().is_none(),
            "client failed: {}",
            fs::read_to_string(temporary.path().join("client.stderr")).unwrap()
        );
        assert!(Instant::now() < deadline, "client readiness expired");
        thread::sleep(Duration::from_millis(10));
    }
    let bytes = fs::read(reports.join("client-ready")).unwrap();
    assert!(bytes.len() <= 4096);
    let report: ClientReport = serde_json::from_slice(&bytes).unwrap();
    let id = Identity {
        unit: report.unit.clone(),
        invocation: report.invocation.clone(),
        guardian_pid: report.guardian,
        directory_device: report.device,
        directory_inode: report.inode,
    };
    // No activation socket is duplicated into this controller. Its independent
    // witness corroborates every claim before the client is killed.
    let mut wrong = id.clone();
    wrong.invocation = Uuid::new_v4().simple().to_string();
    assert_eq!(
        Witness::bind(&prefix, &wrong, report.writer)
            .err()
            .unwrap()
            .to_string(),
        "invocation changed"
    );
    wrong = id.clone();
    wrong.directory_inode ^= 1;
    assert_eq!(
        Witness::bind(&prefix, &wrong, report.writer)
            .err()
            .unwrap()
            .to_string(),
        "independent manager/kernel facts differ from claims"
    );
    assert_eq!(
        Witness::bind(&prefix, &id, std::process::id())
            .err()
            .unwrap()
            .to_string(),
        "main process is outside the bound cgroup"
    );
    assert_eq!(
        Witness::bind(&prefix, &id, report.guardian)
            .err()
            .unwrap()
            .to_string(),
        "writer is not the bound guardian's direct child"
    );
    let witness = Witness::bind(&prefix, &id, report.writer).unwrap();
    let store = Store::open(&root).unwrap();
    assert_eq!(
        store.run(&report.run).unwrap().observed_pid,
        Some(report.writer)
    );
    assert!(matches!(
        store.acquire_lease(report.profile),
        Err(Error::Busy)
    ));
    let before = heartbeat(&directory, &id, report.writer, &report.nonce, None);
    heartbeat(&directory, &id, report.writer, &report.nonce, Some(&before));
    assert!(
        !directory
            .join(&id.invocation)
            .join("guardian-clean-eof")
            .exists()
    );
    client.0.kill().unwrap();
    let status = client
        .0
        .wait_timeout(Duration::from_secs(3))
        .unwrap()
        .unwrap();
    assert_eq!(status.signal(), Some(9));
    assert!(witness.retire().unwrap().connection_close_error.is_none());
    assert_eq!(
        fs::read_to_string(directory.join(&id.invocation).join("guardian-clean-eof")).unwrap(),
        id.invocation
    );
    assert!(
        !directory
            .join(&id.invocation)
            .join("voluntary-exit")
            .exists()
    );
    assert!(!reports.join("client-voluntary").exists());
    drop(store);
    let reopened = Store::open(&root).unwrap();
    unresolved(&reopened, report.profile, &report.run);
    assert!(reopened.verify().unwrap().consistent);
    println!(
        "::notice title=Linux activated client loss::owned client SIGKILL ran no client cleanup; independent witnesses observed writer retirement and reopened unresolved journal still refuses launch"
    );
}
