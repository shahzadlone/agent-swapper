//! Delegated cgroup fixture with the real profile lease and durable journal.
#![allow(clippy::unwrap_used)]
use crate::supervision::linux_admission_transport as transport;
use crate::supervision::linux_cgroup as cgroup;
use crate::supervision::linux_launch_envelope::LaunchEnvelope;

use super::*;
use rustix::{
    fd::AsFd,
    fs::OFlags,
    net::{
        RecvFlags, SendFlags, recv, send,
        sockopt::{self, Timeout},
    },
    process::setsid,
};
use std::{
    fs,
    io::{self, BufRead, Write},
    os::unix::process::CommandExt,
    process::{Child, Command, Stdio},
    thread,
};
use wait_timeout::ChildExt;

const SUPERVISOR: &str = "store::linux_journal_guardian_tests::supervisor_fixture";
const GUARDIAN: &str = "store::linux_journal_guardian_tests::guardian_fixture";
const TARGET: &str = "store::linux_journal_guardian_tests::target_fixture";
const BUDGET: Duration = Duration::from_secs(20);
const ACK: &[u8] = b"ASWP-JOURNALED-1";

fn command(role: &str, dir: &Path, scope: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    let name = role.rsplit("::").next().unwrap();
    command
        .args(["--exact", role, "--ignored"])
        .env("ASWP_JOURNAL_FIXTURE_DIR", dir)
        .env("ASWP_JOURNAL_FIXTURE_SCOPE", scope)
        .stdout(Stdio::from(
            File::create(dir.join(format!("{name}.stdout"))).unwrap(),
        ))
        .stderr(Stdio::from(
            File::create(dir.join(format!("{name}.stderr"))).unwrap(),
        ));
    command
}

fn controller_wait(dir: &Path, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + BUDGET;
    while !check() {
        if Instant::now() >= deadline {
            for role in ["supervisor_fixture", "guardian_fixture", "target_fixture"] {
                for stream in ["stdout", "stderr"] {
                    if let Ok(text) = fs::read_to_string(dir.join(format!("{role}.{stream}"))) {
                        eprintln!(
                            "{role} {stream}: {}",
                            text.chars().take(3000).collect::<String>()
                        );
                    }
                }
            }
            panic!("delegated journal fixture timed out");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn fixture_paths() -> (PathBuf, PathBuf) {
    (
        PathBuf::from(std::env::var_os("ASWP_JOURNAL_FIXTURE_DIR").unwrap()),
        PathBuf::from(std::env::var_os("ASWP_JOURNAL_FIXTURE_SCOPE").unwrap()),
    )
}

fn until(mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + BUDGET;
    while !check() {
        assert!(
            Instant::now() < deadline,
            "journal guardian fixture timed out"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait_timeout(Duration::from_secs(3));
    }
}

#[test]
#[ignore = "target role for the delegated journal guardian fixture"]
fn target_fixture() {
    let (dir, _) = fixture_paths();
    let mut grant = String::new();
    io::stdin().lock().read_line(&mut grant).unwrap();
    assert_eq!(grant, "GO\n");
    fs::write(dir.join("target-started"), b"started").unwrap();
    if let Some(canary) = std::env::var_os("ASWP_JOURNAL_TARGET_CANARY") {
        fs::write(dir.join("target-envelope"), canary.as_encoded_bytes()).unwrap();
    }
    setsid().unwrap();
    let deadline = Instant::now() + BUDGET * 4;
    let mut tick = 0_u64;
    while Instant::now() < deadline {
        tick += 1;
        fs::write(dir.join("heartbeat.tmp"), tick.to_string()).unwrap();
        fs::rename(dir.join("heartbeat.tmp"), dir.join("heartbeat")).unwrap();
        thread::sleep(Duration::from_millis(20));
    }
    fs::write(dir.join("target-voluntary"), b"fixture deadline").unwrap();
}

#[test]
#[ignore = "guardian role for the delegated journal guardian fixture"]
fn guardian_fixture() {
    let (dir, scope) = fixture_paths();
    let parent = File::from(transport::receive(io::stdin()).unwrap());
    let leaf = File::from(transport::receive(io::stdin()).unwrap());
    let lease = File::from(transport::receive(io::stdin()).unwrap());
    cgroup::validate_scope(&parent, &leaf, &scope).unwrap();
    let launch = LaunchEnvelope::receive_from(io::stdin()).unwrap();
    let mut target = OwnedChild(
        launch
            .command()
            .stdin(Stdio::piped())
            .stdout(Stdio::from(
                File::create(dir.join("target_fixture.stdout")).unwrap(),
            ))
            .stderr(Stdio::from(
                File::create(dir.join("target_fixture.stderr")).unwrap(),
            ))
            .spawn()
            .unwrap(),
    );
    cgroup::control(&leaf, "cgroup.procs", OFlags::WRONLY)
        .unwrap()
        .write_all(format!("{}\n", target.0.id()).as_bytes())
        .unwrap();
    assert!(cgroup::contains(&leaf, target.0.id()).unwrap());
    let pid = target.0.id().to_string();
    fs::write(dir.join("target-pid"), &pid).unwrap();
    assert_eq!(
        send(io::stdin(), pid.as_bytes(), SendFlags::NOSIGNAL).unwrap(),
        pid.len()
    );
    if transport::receive_control(io::stdin(), ACK).is_err() {
        cgroup::control(&leaf, "cgroup.kill", OFlags::WRONLY)
            .unwrap()
            .write_all(b"1\n")
            .unwrap();
        until(|| !cgroup::populated(&leaf).unwrap());
        cgroup::retire_transferred(&parent, &leaf, &scope, Instant::now() + BUDGET).unwrap();
        drop(lease);
        fs::write(dir.join("guardian-pre-go-cleaned"), b"cleaned").unwrap();
        return;
    }
    target.0.stdin.take().unwrap().write_all(b"GO\n").unwrap();
    until(|| dir.join("heartbeat").exists());
    fs::write(dir.join("guardian-ready"), b"ready").unwrap();
    until(|| {
        let mut buf = [0_u8; 1];
        match recv(io::stdin(), &mut buf, RecvFlags::DONTWAIT) {
            Ok((0, _)) => true,
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => false,
            other => panic!("unexpected supervisor channel result: {other:?}"),
        }
    });
    cgroup::control(&leaf, "cgroup.kill", OFlags::WRONLY)
        .unwrap()
        .write_all(b"1\n")
        .unwrap();
    until(|| !cgroup::populated(&leaf).unwrap());
    fs::write(dir.join("guardian-empty"), b"empty").unwrap();
    until(|| dir.join("retire").exists());
    cgroup::retire_transferred(&parent, &leaf, &scope, Instant::now() + BUDGET).unwrap();
    fs::write(dir.join("guardian-retired"), b"retired").unwrap();
    until(|| dir.join("release").exists());
    drop(lease);
}

#[test]
#[ignore = "supervisor role for the delegated journal guardian fixture"]
fn supervisor_fixture() {
    let (dir, scope) = fixture_paths();
    let parent = cgroup::checked_directory(scope.parent().unwrap()).unwrap();
    let leaf = cgroup::checked_directory(&scope).unwrap();
    cgroup::validate_scope(&parent, &leaf, &scope).unwrap();
    let mut store = Store::open(&dir.join("state")).unwrap();
    let profile = store.profiles().unwrap().pop().unwrap();
    let lease = store.lease(profile.id).unwrap();
    let run = store.begin_run(&lease, "run").unwrap();
    let (channel, gate) = transport::pair().unwrap();
    let canary = uuid::Uuid::new_v4().to_string();
    fs::write(dir.join("canary-expected"), &canary).unwrap();
    let mut guardian = OwnedChild(
        command(GUARDIAN, &dir, &scope)
            .env_clear()
            .env("ASWP_JOURNAL_FIXTURE_DIR", &dir)
            .env("ASWP_JOURNAL_FIXTURE_SCOPE", &scope)
            .stdin(Stdio::from(gate))
            .process_group(0)
            .spawn()
            .unwrap(),
    );
    for name in ["cmdline", "environ"] {
        let bytes = fs::read(format!("/proc/{}/{name}", guardian.0.id())).unwrap();
        assert!(
            !bytes
                .windows(canary.len())
                .any(|window| window == canary.as_bytes())
        );
    }
    for fd in [parent.as_fd(), leaf.as_fd(), lease.as_fd()] {
        transport::send(&channel, transport::GO, &[fd]).unwrap();
    }
    let executable = std::env::current_exe().unwrap();
    let launch = LaunchEnvelope::capture(
        executable.as_os_str(),
        &dir,
        ["--exact".into(), TARGET.into(), "--ignored".into()],
        [],
        [
            (
                "ASWP_JOURNAL_FIXTURE_DIR".into(),
                Some(dir.as_os_str().to_owned()),
            ),
            (
                "ASWP_JOURNAL_FIXTURE_SCOPE".into(),
                Some(scope.as_os_str().to_owned()),
            ),
            ("ASWP_JOURNAL_TARGET_CANARY".into(), Some(canary.into())),
        ],
    )
    .unwrap();
    launch.send_to(&channel).unwrap();
    drop(launch);
    sockopt::set_socket_timeout(&channel, Timeout::Recv, Some(Duration::from_secs(5))).unwrap();
    let mut pid = [0_u8; 32];
    let (count, length) = recv(&channel, &mut pid, RecvFlags::TRUNC).unwrap();
    assert_eq!(count, length);
    let pid: u32 = std::str::from_utf8(&pid[..count]).unwrap().parse().unwrap();
    store.observe_spawn(&run, pid).unwrap();
    if dir.join("pause-before-go").exists() {
        fs::write(dir.join("run-id.tmp"), &run).unwrap();
        fs::rename(dir.join("run-id.tmp"), dir.join("run-id")).unwrap();
        until(|| false);
    }
    transport::send(&channel, ACK, &[]).unwrap();
    until(|| dir.join("guardian-ready").exists());
    fs::write(dir.join("run-id.tmp"), run).unwrap();
    fs::rename(dir.join("run-id.tmp"), dir.join("run-id")).unwrap();
    let deadline = Instant::now() + BUDGET;
    while Instant::now() < deadline && guardian.0.try_wait().unwrap().is_none() {
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[ignore = "requires the disposable delegated CI cgroup"]
fn supervisor_loss_before_go_keeps_journal_unresolved() {
    let delegated = PathBuf::from(std::env::var_os("ASWP_DELEGATED_CGROUP").unwrap());
    let domain = cgroup::Domain::open(&delegated).unwrap();
    let scope = domain.create().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    let mut store = Store::open(&root).unwrap();
    let profile = store
        .register(Harness::Claude, "work".parse().unwrap())
        .unwrap();
    drop(store);
    fs::write(temp.path().join("pause-before-go"), b"pause").unwrap();
    let mut supervisor = OwnedChild(
        command(SUPERVISOR, temp.path(), scope.path())
            .stdin(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap(),
    );
    controller_wait(temp.path(), || temp.path().join("run-id").exists());
    assert!(!temp.path().join("target-envelope").exists());
    let run = fs::read_to_string(temp.path().join("run-id")).unwrap();
    let mut store = Store::open(&root).unwrap();
    assert!(matches!(store.attest_stopped(&run), Err(Error::Busy)));
    supervisor.0.kill().unwrap();
    supervisor.0.wait().unwrap();
    controller_wait(temp.path(), || {
        temp.path().join("guardian-pre-go-cleaned").exists()
    });
    assert!(!scope.path().exists());
    assert!(!temp.path().join("target-started").exists());
    let pid: u32 = fs::read_to_string(temp.path().join("target-pid"))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(store.run(&run).unwrap().observed_pid, Some(pid));
    drop(store.acquire_lease(profile.id).unwrap());
    assert!(matches!(store.lease(profile.id), Err(Error::Busy)));
    assert_eq!(store.run(&run).unwrap().custody, ProcessCustody::Unknown);
    store.attest_stopped(&run).unwrap();
    assert!(store.verify().unwrap().consistent);
    println!(
        "::notice title=Linux pre-GO guardian::supervisor loss before GO preserved unresolved intent and stopped the gated target"
    );
}

#[test]
#[ignore = "requires the disposable delegated CI cgroup"]
fn real_journal_lease_survives_supervisor_loss_through_cgroup_cleanup() {
    struct Release(PathBuf);
    impl Drop for Release {
        fn drop(&mut self) {
            let _ = fs::write(self.0.join("retire"), b"cleanup");
            let _ = fs::write(self.0.join("release"), b"cleanup");
        }
    }
    let delegated = PathBuf::from(std::env::var_os("ASWP_DELEGATED_CGROUP").unwrap());
    let domain = cgroup::Domain::open(&delegated).unwrap();
    let scope = domain.create().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let _release = Release(temp.path().to_owned());
    let root = temp.path().join("state");
    let mut store = Store::open(&root).unwrap();
    let profile = store
        .register(Harness::Claude, "work".parse().unwrap())
        .unwrap();
    drop(store);
    let outside_dir = temp.path().join("outside");
    fs::create_dir(&outside_dir).unwrap();
    let mut outside = OwnedChild(
        command(TARGET, &outside_dir, scope.path())
            .stdin(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    outside.0.stdin.take().unwrap().write_all(b"GO\n").unwrap();
    controller_wait(temp.path(), || outside_dir.join("heartbeat").exists());
    let mut supervisor = OwnedChild(
        command(SUPERVISOR, temp.path(), scope.path())
            .stdin(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap(),
    );
    controller_wait(temp.path(), || temp.path().join("run-id").exists());
    assert!(temp.path().join("target-envelope").exists());
    assert_eq!(
        fs::read(temp.path().join("target-envelope")).unwrap(),
        fs::read(temp.path().join("canary-expected")).unwrap()
    );
    let run = fs::read_to_string(temp.path().join("run-id")).unwrap();
    let expected_pid: u32 = fs::read_to_string(temp.path().join("target-pid"))
        .unwrap()
        .parse()
        .unwrap();
    let before: u64 = fs::read_to_string(outside_dir.join("heartbeat"))
        .unwrap()
        .parse()
        .unwrap();
    assert!(cgroup::populated(scope.directory()).unwrap());
    supervisor.0.kill().unwrap();
    supervisor.0.wait().unwrap();
    controller_wait(temp.path(), || temp.path().join("guardian-empty").exists());
    assert!(!cgroup::populated(scope.directory()).unwrap());
    assert!(!temp.path().join("target-voluntary").exists());
    controller_wait(temp.path(), || {
        fs::read_to_string(outside_dir.join("heartbeat"))
            .ok()
            .and_then(|text| text.parse::<u64>().ok())
            .is_some_and(|tick| tick > before + 2)
    });
    let mut store = Store::open(&root).unwrap();
    assert_eq!(store.run(&run).unwrap().observed_pid, Some(expected_pid));
    assert!(matches!(store.attest_stopped(&run), Err(Error::Busy)));
    fs::write(temp.path().join("retire"), b"retire").unwrap();
    controller_wait(temp.path(), || {
        temp.path().join("guardian-retired").exists()
    });
    assert!(!scope.path().exists());
    assert!(matches!(store.attest_stopped(&run), Err(Error::Busy)));
    fs::write(temp.path().join("release"), b"release").unwrap();
    controller_wait(temp.path(), || match store.acquire_lease(profile.id) {
        Ok(lease) => {
            drop(lease);
            true
        }
        Err(Error::Busy) => false,
        Err(error) => panic!("lease observation failed: {error:?}"),
    });
    assert!(matches!(store.lease(profile.id), Err(Error::Busy)));
    assert_eq!(store.run(&run).unwrap().custody, ProcessCustody::Unknown);
    store.attest_stopped(&run).unwrap();
    assert!(store.verify().unwrap().consistent);
    println!(
        "::notice title=Linux journal guardian::real lease and pending intent survived supervisor loss through detached cgroup cleanup"
    );
}
