//! Real journal/lease integration with the opted-in, root-installed CI fixture.
#![allow(clippy::unwrap_used)]
use super::*;
use aswp_linux_manager_evaluation::journal_client::{Bound, Identity, Prepared};
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
    let profile = store
        .register(Harness::Claude, alias.parse().unwrap())
        .unwrap();
    let lease = store.lease(profile.id).unwrap();
    let bound = Bound::connect(prefix).unwrap();
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

fn heartbeat(directory: &Path, id: &Identity, nonce: &[u8; 16], previous: Option<&str>) -> String {
    let prefix: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let value = fs::read_to_string(directory.join(&id.invocation).join("heartbeat"));
        if let Ok(value) = value
            && value.starts_with(&format!("{prefix}:"))
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

fn unresolved(store: &Store, profile: ProfileId, run: &str) {
    drop(store.acquire_lease(profile).unwrap());
    assert!(matches!(store.lease(profile), Err(Error::Busy)));
    let record = store.run(run).unwrap();
    assert_eq!(record.custody, ProcessCustody::Unknown);
    assert!(record.exit_code.is_none());
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
    store.observe_spawn(&run_a, a.pid()).unwrap();
    assert_eq!(store.run(&run_a).unwrap().observed_pid, Some(a.pid()));
    let nonce_a = *Uuid::new_v4().as_bytes();
    let a = a.start(nonce_a).unwrap();
    heartbeat(&directory, &id_a, &nonce_a, None);
    let (profile_b, run_b, b) = prepare(&mut store, "activation-b", &prefix);
    let id_b = b.identity();
    assert_ne!(id_a.invocation, id_b.invocation);
    assert_ne!(id_a.unit, id_b.unit);
    assert_ne!(
        (id_a.directory_device, id_a.directory_inode),
        (id_b.directory_device, id_b.directory_inode)
    );
    assert!(!directory.join(&id_b.invocation).join("heartbeat").exists());
    store.observe_spawn(&run_b, b.pid()).unwrap();
    let nonce_b = *Uuid::new_v4().as_bytes();
    let b = b.start(nonce_b).unwrap();
    heartbeat(&directory, &id_b, &nonce_b, None);
    assert!(started.elapsed() < Duration::from_secs(20));
    assert_eq!(a.close().retire().unwrap(), id_a);
    let before = heartbeat(&directory, &id_b, &nonce_b, None);
    heartbeat(&directory, &id_b, &nonce_b, Some(&before));
    assert!(matches!(store.acquire_lease(profile_b), Err(Error::Busy)));
    assert_eq!(b.close().retire().unwrap(), id_b);
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
    store.db.busy_timeout(Duration::from_millis(20)).unwrap();
    let blocker = Connection::open(root.join("registry.sqlite3")).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let result = store.observe_spawn(&run, prepared.pid());
    assert!(
        matches!(result, Err(Error::Database(rusqlite::Error::SqliteFailure(ref error, _)))
        if error.code == rusqlite::ErrorCode::DatabaseBusy),
        "unexpected journal failure: {result:?}"
    );
    assert!(!directory.join(&id.invocation).join("heartbeat").exists());
    assert_eq!(prepared.close().retire().unwrap(), id);
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
fn guardian_sigkill_retires_writer_without_clearing_journal() {
    let (prefix, directory) = environment();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    let mut store = Store::open(&root).unwrap();
    let (profile, run, prepared) = prepare(&mut store, "guardian-crash", &prefix);
    let id = prepared.identity();
    store.observe_spawn(&run, prepared.pid()).unwrap();
    let nonce = *Uuid::new_v4().as_bytes();
    let running = prepared.start(nonce).unwrap();
    let before = heartbeat(&directory, &id, &nonce, None);
    heartbeat(&directory, &id, &nonce, Some(&before));
    assert!(matches!(store.acquire_lease(profile), Err(Error::Busy)));
    // This signal is sent before the sole client channel is closed. No
    // guardian destructor or cooperative EOF path can be responsible.
    assert_eq!(running.crash_guardian().unwrap().retire().unwrap(), id);
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
        "::notice title=Linux activated guardian loss::retained-pidfd SIGKILL stopped the live writer through manager cleanup; raw lock released but reopened journal still refuses launch"
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
    let mut store = Store::open(&root).unwrap();
    let (profile, run, prepared) = prepare(&mut store, "client-crash", &prefix);
    let id = prepared.identity();
    let writer = prepared.pid();
    store.observe_spawn(&run, writer).unwrap();
    let nonce = *Uuid::new_v4().as_bytes();
    let _running = prepared.start(nonce).unwrap();
    heartbeat(&directory, &id, &nonce, None);
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
        root.join("client-ready.tmp"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    fs::rename(root.join("client-ready.tmp"), root.join("client-ready")).unwrap();
    thread::sleep(Duration::from_secs(60));
    fs::write(root.join("client-voluntary"), "deadline").unwrap();
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
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", CLIENT_ROLE, "--ignored", "--nocapture"])
        .env_clear()
        .env("ASWP_ACTIVATION_CLIENT_ROOT", &root)
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
    while !root.join("client-ready").exists() {
        assert!(
            client.0.try_wait().unwrap().is_none(),
            "client failed: {}",
            fs::read_to_string(temporary.path().join("client.stderr")).unwrap()
        );
        assert!(Instant::now() < deadline, "client readiness expired");
        thread::sleep(Duration::from_millis(10));
    }
    let bytes = fs::read(root.join("client-ready")).unwrap();
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
    assert!(Witness::bind(&prefix, &wrong, report.writer).is_err());
    wrong = id.clone();
    wrong.directory_inode ^= 1;
    assert!(Witness::bind(&prefix, &wrong, report.writer).is_err());
    assert!(Witness::bind(&prefix, &id, std::process::id()).is_err());
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
    let before = heartbeat(&directory, &id, &report.nonce, None);
    heartbeat(&directory, &id, &report.nonce, Some(&before));
    client.0.kill().unwrap();
    let status = client
        .0
        .wait_timeout(Duration::from_secs(3))
        .unwrap()
        .unwrap();
    assert_eq!(status.signal(), Some(9));
    assert_eq!(witness.retire().unwrap(), id);
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
    assert!(!root.join("client-voluntary").exists());
    drop(store);
    let reopened = Store::open(&root).unwrap();
    unresolved(&reopened, report.profile, &report.run);
    assert!(reopened.verify().unwrap().consistent);
    println!(
        "::notice title=Linux activated client loss::owned client SIGKILL ran no client cleanup; independent witnesses observed writer retirement and reopened unresolved journal still refuses launch"
    );
}
