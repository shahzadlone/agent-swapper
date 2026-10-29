//! Linux lease transfer with real journal state; no provider is launched.
#![allow(clippy::unwrap_used)]
use super::*;
use rustix::io::fcntl_dupfd_cloexec;
use std::{
    fs,
    process::{Child, Command, Stdio},
    thread,
};
use wait_timeout::ChildExt;

const SUPERVISOR: &str = "store::lease_transfer_tests::supervisor_fixture";
const GUARDIAN: &str = "store::lease_transfer_tests::guardian_fixture";
const BUDGET: Duration = Duration::from_secs(15);

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait_timeout(Duration::from_secs(2));
    }
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + BUDGET;
    while !path.exists() {
        assert!(Instant::now() < deadline, "fixture marker timed out");
        thread::sleep(Duration::from_millis(10));
    }
}

fn child_command(name: &str, dir: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", name, "--ignored"])
        .env("ASWP_LEASE_TEST_DIR", dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

#[test]
#[ignore = "guardian role invoked by the profile lease transfer test"]
fn guardian_fixture() {
    let dir = PathBuf::from(std::env::var_os("ASWP_LEASE_TEST_DIR").unwrap());
    // Descriptor 0 is the duplicated locked lease; keeping it open retains
    // the same open-file description after the supervisor is killed.
    fs::write(dir.join("guardian-ready"), b"ready").unwrap();
    let deadline = Instant::now() + BUDGET;
    while !dir.join("release-guardian").exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[ignore = "supervisor role invoked by the profile lease transfer test"]
fn supervisor_fixture() {
    let dir = PathBuf::from(std::env::var_os("ASWP_LEASE_TEST_DIR").unwrap());
    let mut store = Store::open(&dir.join("state")).unwrap();
    let profile = store.profiles().unwrap().pop().unwrap();
    let lease = store.lease(profile.id).unwrap();
    let run = store.begin_run(&lease, "run").unwrap();
    let duplicate = File::from(fcntl_dupfd_cloexec(&lease, 3).unwrap());
    // The child gets only the lease in stdin, never a pathname-based lock.
    let mut guardian = OwnedChild(
        child_command(GUARDIAN, &dir)
            .stdin(Stdio::from(duplicate))
            .spawn()
            .unwrap(),
    );
    wait_for(&dir.join("guardian-ready"));
    fs::write(dir.join("run-id.tmp"), run).unwrap();
    fs::rename(dir.join("run-id.tmp"), dir.join("run-id")).unwrap();
    // This process is killed by its parent. If it is not, clean up the owned
    // guardian after a bounded interval rather than leaving a fixture behind.
    let deadline = Instant::now() + BUDGET;
    while Instant::now() < deadline && guardian.0.try_wait().unwrap().is_none() {
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn transferred_real_lease_and_intent_fence_reuse_after_supervisor_death() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    let mut store = Store::open(&root).unwrap();
    let profile = store
        .register(Harness::Claude, "work".parse().unwrap())
        .unwrap();
    drop(store);
    let mut supervisor = OwnedChild(
        child_command(SUPERVISOR, temp.path())
            .stdin(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for(&temp.path().join("run-id"));
    let run = fs::read_to_string(temp.path().join("run-id")).unwrap();
    supervisor.0.kill().unwrap();
    supervisor.0.wait().unwrap();

    let mut store = Store::open(&root).unwrap();
    assert!(matches!(store.attest_stopped(&run), Err(Error::Busy)));
    assert!(matches!(store.lease(profile.id), Err(Error::Busy)));
    assert_eq!(store.run(&run).unwrap().custody, ProcessCustody::Unknown);
    fs::write(temp.path().join("release-guardian"), b"release").unwrap();
    let deadline = Instant::now() + BUDGET;
    loop {
        match store.acquire_lease(profile.id) {
            Ok(lease) => {
                drop(lease);
                break;
            }
            Err(Error::Busy) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10))
            }
            Err(error) => panic!("guardian lease did not release: {error:?}"),
        }
    }
    assert!(matches!(store.lease(profile.id), Err(Error::Busy)));
    store.attest_stopped(&run).unwrap();
    assert_eq!(
        store.run(&run).unwrap().custody,
        ProcessCustody::AttestedStopped
    );
    assert!(store.lease(profile.id).is_ok());
    assert!(store.verify().unwrap().consistent);
}
