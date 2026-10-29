//! Delegated cgroup fixture with the real profile lease and durable journal.
#![allow(clippy::unwrap_used)]
use crate::supervision::linux_admission_transport as transport;
use crate::supervision::linux_cgroup as cgroup;
use crate::supervision::{linux_launch_envelope::LaunchEnvelope, linux_shim};

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
    io::{self, BufRead, Seek, SeekFrom, Write},
    os::unix::process::CommandExt,
    process::{Child, Command, Stdio},
    thread,
};
use wait_timeout::ChildExt;

const SUPERVISOR: &str = "store::linux_journal_guardian_tests::supervisor_fixture";
const GUARDIAN: &str = "store::linux_journal_guardian_tests::guardian_fixture";
const SHIM: &str = "store::linux_journal_guardian_tests::shim_fixture";
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
            for role in [
                "supervisor_fixture",
                "guardian_fixture",
                "shim_fixture",
                "target_fixture",
            ] {
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

fn scope_id(path: &Path) -> uuid::Uuid {
    let name = path.file_name().unwrap().to_str().unwrap();
    uuid::Uuid::parse_str(name.strip_prefix("aswp-probe-").unwrap()).unwrap()
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
#[ignore = "shim role for the delegated journal guardian fixture"]
fn shim_fixture() {
    let (_, scope) = fixture_paths();
    linux_shim::exec_until(io::stdin(), &scope, Instant::now() + BUDGET).unwrap();
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
    let (grant, gate) = transport::pair().unwrap();
    let mut shim = if let Some(executable) = std::env::var_os("ASWP_TEST_CLI_SHIM") {
        assert!(Path::new(&executable).is_absolute());
        let mut command = Command::new(executable);
        command
            .arg(linux_shim::INTERNAL_ARG)
            .arg(&scope)
            .stdout(Stdio::from(
                File::create(dir.join("shim_fixture.stdout")).unwrap(),
            ))
            .stderr(Stdio::from(
                File::create(dir.join("shim_fixture.stderr")).unwrap(),
            ));
        fs::write(dir.join("cli-shim"), b"selected").unwrap();
        command
    } else {
        command(SHIM, &dir, &scope)
    };
    let fixture_shim = std::env::var_os("ASWP_TEST_CLI_SHIM").is_none();
    shim.env_clear();
    if fixture_shim {
        shim.env("ASWP_JOURNAL_FIXTURE_DIR", &dir)
            .env("ASWP_JOURNAL_FIXTURE_SCOPE", &scope);
    }
    let target = OwnedChild(shim.stdin(Stdio::from(gate)).spawn().unwrap());
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
    for fd in [parent.as_fd(), leaf.as_fd()] {
        transport::send(&grant, transport::GO, &[fd]).unwrap();
    }
    launch.send_to(&grant).unwrap();
    let mut input = tempfile::tempfile().unwrap();
    input.write_all(b"GO\n").unwrap();
    input.seek(SeekFrom::Start(0)).unwrap();
    let output = File::create(dir.join("target_fixture.stdout")).unwrap();
    let diagnostic = File::create(dir.join("target_fixture.stderr")).unwrap();
    for fd in [input.as_fd(), output.as_fd(), diagnostic.as_fd()] {
        transport::send(&grant, transport::GO, &[fd]).unwrap();
    }
    transport::send(&grant, transport::GO, &[]).unwrap();
    drop(grant);
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
    let run = store
        .begin_run_with_scope(
            &lease,
            "run",
            None,
            Some(LocalScope::LinuxCgroup {
                id: scope_id(&scope),
            }),
        )
        .unwrap();
    let (channel, gate) = transport::pair().unwrap();
    let canary = uuid::Uuid::new_v4().to_string();
    fs::write(dir.join("canary-expected"), &canary).unwrap();
    let mut guardian_command = command(GUARDIAN, &dir, &scope);
    guardian_command
        .env_clear()
        .env("ASWP_JOURNAL_FIXTURE_DIR", &dir)
        .env("ASWP_JOURNAL_FIXTURE_SCOPE", &scope);
    if let Some(executable) = std::env::var_os("ASWP_TEST_CLI_SHIM") {
        guardian_command.env("ASWP_TEST_CLI_SHIM", executable);
    }
    let mut guardian = OwnedChild(
        guardian_command
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
    if std::env::var_os("ASWP_TEST_CLI_SHIM").is_some() {
        assert!(temp.path().join("cli-shim").exists());
    }
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
    assert_eq!(
        store.run(&run).unwrap().local_scope,
        Some(LocalScope::LinuxCgroup {
            id: scope_id(scope.path())
        })
    );
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
    if std::env::var_os("ASWP_TEST_CLI_SHIM").is_some() {
        assert!(temp.path().join("cli-shim").exists());
    }
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
    assert_eq!(
        store.run(&run).unwrap().local_scope,
        Some(LocalScope::LinuxCgroup {
            id: scope_id(scope.path())
        })
    );
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

const GUARDIAN_EXIT_TARGET: &str = "store::linux_journal_guardian_tests::guardian_exit_target";

#[test]
#[ignore = "exit-status role for the internal guardian fixture"]
fn guardian_exit_target() {
    let mut grant = String::new();
    io::stdin().lock().read_line(&mut grant).unwrap();
    assert_eq!(grant, "GO\n");
    std::process::exit(7);
}

fn internal_guardian_case(parent_loss: bool, loss_after_empty: bool) {
    use crate::supervision::linux_guardian;
    let delegated = PathBuf::from(std::env::var_os("ASWP_DELEGATED_CGROUP").unwrap());
    let executable = PathBuf::from(std::env::var_os("ASWP_TEST_CLI_SHIM").unwrap());
    let domain = cgroup::Domain::open(&delegated).unwrap();
    let scope = domain.create().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    let mut store = Store::open(&root).unwrap();
    let profile = store
        .register(Harness::Claude, "work".parse().unwrap())
        .unwrap();
    let lease = store.lease(profile.id).unwrap();
    let run = store
        .begin_run_with_scope(
            &lease,
            "run",
            None,
            Some(LocalScope::LinuxCgroup {
                id: scope_id(scope.path()),
            }),
        )
        .unwrap();
    let (channel, gate) = transport::pair().unwrap();
    let foreground = rustix::process::getpgrp().as_raw_pid().to_string();
    let mut guardian = OwnedChild(
        Command::new(executable)
            .arg(linux_guardian::INTERNAL_ARG)
            .arg(scope.path())
            .arg(foreground)
            .env_clear()
            .stdin(Stdio::from(gate))
            .stdout(Stdio::from(
                File::create(temp.path().join("guardian_fixture.stdout")).unwrap(),
            ))
            .stderr(Stdio::from(
                File::create(temp.path().join("guardian_fixture.stderr")).unwrap(),
            ))
            .process_group(0)
            .spawn()
            .unwrap(),
    );
    for fd in [
        scope.parent().as_fd(),
        scope.directory().as_fd(),
        lease.as_fd(),
    ] {
        transport::send(&channel, transport::GO, &[fd]).unwrap();
    }
    let target = if parent_loss {
        TARGET
    } else {
        GUARDIAN_EXIT_TARGET
    };
    let test_executable = std::env::current_exe().unwrap();
    let launch = LaunchEnvelope::capture(
        test_executable.as_os_str(),
        temp.path(),
        ["--exact".into(), target.into(), "--ignored".into()],
        [],
        [
            (
                "ASWP_JOURNAL_FIXTURE_DIR".into(),
                Some(temp.path().as_os_str().to_owned()),
            ),
            (
                "ASWP_JOURNAL_FIXTURE_SCOPE".into(),
                Some(scope.path().as_os_str().to_owned()),
            ),
        ],
    )
    .unwrap();
    launch.send_to(&channel).unwrap();
    let mut input = tempfile::tempfile().unwrap();
    input.write_all(b"GO\n").unwrap();
    input.seek(SeekFrom::Start(0)).unwrap();
    let output = File::create(temp.path().join("target_fixture.stdout")).unwrap();
    let diagnostic = File::create(temp.path().join("target_fixture.stderr")).unwrap();
    for fd in [input.as_fd(), output.as_fd(), diagnostic.as_fd()] {
        transport::send(&channel, transport::GO, &[fd]).unwrap();
    }
    let pid = linux_guardian::receive_pid(&channel, Instant::now() + BUDGET).unwrap();
    store.observe_spawn(&run, pid).unwrap();
    transport::send(&channel, transport::GO, &[]).unwrap();
    drop(lease);
    if parent_loss {
        controller_wait(temp.path(), || temp.path().join("heartbeat").exists());
        assert!(matches!(store.attest_stopped(&run), Err(Error::Busy)));
        drop(channel);
    } else {
        assert_eq!(
            linux_guardian::receive_empty(&channel, Instant::now() + BUDGET).unwrap(),
            7
        );
        assert!(!cgroup::populated(scope.directory()).unwrap());
        assert!(scope.path().exists());
        assert!(matches!(store.attest_stopped(&run), Err(Error::Busy)));
        if !loss_after_empty {
            transport::send(&channel, linux_guardian::RETIRE, &[]).unwrap();
            linux_guardian::receive_retired(&channel, Instant::now() + BUDGET).unwrap();
        }
        drop(channel);
    }
    let Some(status) = guardian.0.wait_timeout(BUDGET).unwrap() else {
        panic!("guardian timed out");
    };
    assert_eq!(status.code(), Some(if loss_after_empty { 125 } else { 0 }));
    assert!(!scope.path().exists());
    assert_eq!(store.run(&run).unwrap().observed_pid, Some(pid));
    assert_eq!(store.run(&run).unwrap().custody, ProcessCustody::Unknown);
    assert!(matches!(store.lease(profile.id), Err(Error::Busy)));
    store.attest_stopped(&run).unwrap();
    assert!(store.verify().unwrap().consistent);
}

#[test]
#[ignore = "requires the disposable delegated CI cgroup and actual CLI guardian"]
fn internal_guardian_reports_exit_after_cleanup() {
    internal_guardian_case(false, false);
    println!(
        "::notice title=Linux internal guardian exit::actual CLI guardian observed exit and retired the scope; journal remains pending"
    );
}

#[test]
#[ignore = "requires the disposable delegated CI cgroup and actual CLI guardian"]
fn internal_guardian_cleans_up_on_supervisor_channel_loss() {
    internal_guardian_case(true, false);
    println!(
        "::notice title=Linux internal guardian EOF::actual CLI guardian retired target scope on channel loss; journal remains pending"
    );
}

#[test]
#[ignore = "requires the disposable delegated CI cgroup and actual CLI guardian"]
fn internal_guardian_cleans_up_if_parent_disappears_before_retirement() {
    internal_guardian_case(false, true);
    println!(
        "::notice title=Linux internal guardian pre-retirement EOF::actual CLI guardian retained lease through empty-scope cleanup after channel loss"
    );
}
