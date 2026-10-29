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
    os::{fd::AsRawFd, unix::process::CommandExt},
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
#[allow(
    clippy::zombie_processes,
    reason = "the bounded escape probe deliberately outlives its parent"
)]
fn guardian_exit_target() {
    let mut grant = String::new();
    io::stdin().lock().read_line(&mut grant).unwrap();
    assert_eq!(grant, "GO\n");
    if let Some(fd) = std::env::var_os("ASWP_JOURNAL_AMBIENT_FD") {
        let (dir, scope) = fixture_paths();
        let target = scope.parent().unwrap().join("cgroup.procs");
        let observed = fs::read_link(format!("/proc/self/fd/{}", fd.to_string_lossy())).ok();
        assert_ne!(observed.as_deref(), Some(target.as_path()));
        fs::write(dir.join("ambient-fd-closed"), b"closed").unwrap();
    }
    if std::env::var_os("ASWP_JOURNAL_ESCAPE_PROBE").is_some() {
        if std::env::var_os("ASWP_JOURNAL_NAMESPACE_PROBE").is_some() {
            assert!(
                fs::read_to_string("/proc/self/cgroup")
                    .unwrap()
                    .lines()
                    .any(|line| line == "0::/")
            );
        }
        let (dir, scope) = fixture_paths();
        let inherited = std::env::var_os("ASWP_JOURNAL_INHERITED_FD_PROBE").is_some();
        let received = std::env::var_os("ASWP_JOURNAL_RECEIVED_FD_PROBE").is_some();
        let received_file = if received {
            fs::write(dir.join("capability-requested"), b"ready").unwrap();
            Some(File::from(
                transport::receive_until(io::stdin(), Instant::now() + BUDGET).unwrap(),
            ))
        } else {
            None
        };
        let parent = if inherited || received {
            None
        } else {
            match cgroup::checked_directory(scope.parent().unwrap()) {
                Ok(parent) => Some(parent),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
                    ) =>
                {
                    fs::write(dir.join("escape-result"), b"denied").unwrap();
                    std::process::exit(7);
                }
                Err(error) => panic!("unexpected parent access error: {error}"),
            }
        };
        let pid = format!("{}\n", std::process::id());
        let result = if let Some(parent) = &parent {
            cgroup::control(parent, "cgroup.procs", OFlags::WRONLY)
                .and_then(|mut file| file.write_all(pid.as_bytes()))
        } else if let Some(mut file) = received_file {
            file.write_all(pid.as_bytes())
        } else {
            io::stderr().write_all(pid.as_bytes())
        };
        match result {
            Ok(()) => {
                if let Some(parent) = &parent {
                    assert!(cgroup::contains(parent, std::process::id()).unwrap());
                } else {
                    assert!(
                        !fs::read_to_string("/proc/self/cgroup")
                            .unwrap()
                            .lines()
                            .any(|line| line == "0::/")
                    );
                }
                fs::write(dir.join("escape-result"), b"escaped").unwrap();
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "store::linux_journal_guardian_tests::escaped_writer",
                        "--ignored",
                    ])
                    .env("ASWP_JOURNAL_FIXTURE_DIR", &dir)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                until(|| dir.join("escaped-heartbeat").exists());
            }
            Err(error)
                if error.kind() == io::ErrorKind::PermissionDenied
                    || error.kind() == io::ErrorKind::NotFound =>
            {
                fs::write(dir.join("escape-result"), b"denied").unwrap();
            }
            Err(error) => panic!("unexpected migration error: {error}"),
        }
    }
    std::process::exit(7);
}

#[test]
#[ignore = "bounded escaped-writer role for the delegated migration probe"]
fn escaped_writer() {
    let dir = PathBuf::from(std::env::var_os("ASWP_JOURNAL_FIXTURE_DIR").unwrap());
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut tick = 0_u64;
    while Instant::now() < deadline && !dir.join("escaped-stop").exists() {
        fs::write(dir.join("escaped-heartbeat.tmp"), tick.to_string()).unwrap();
        fs::rename(
            dir.join("escaped-heartbeat.tmp"),
            dir.join("escaped-heartbeat"),
        )
        .unwrap();
        tick += 1;
        thread::sleep(Duration::from_millis(20));
    }
    fs::write(dir.join("escaped-done"), b"done").unwrap();
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MigrationProbe {
    None,
    Direct,
    Namespace,
    InheritedFd,
    AmbientFd,
    ReceivedFd,
}

fn internal_guardian_case(
    parent_loss: bool,
    loss_after_empty: bool,
    guardian_loss: bool,
    probe: MigrationProbe,
) {
    use crate::supervision::linux_guardian;
    let escape_probe = matches!(
        probe,
        MigrationProbe::Direct
            | MigrationProbe::Namespace
            | MigrationProbe::InheritedFd
            | MigrationProbe::ReceivedFd
    );
    let namespace_probe = matches!(
        probe,
        MigrationProbe::Namespace | MigrationProbe::InheritedFd | MigrationProbe::ReceivedFd
    );
    let inherited_probe = probe == MigrationProbe::InheritedFd;
    let ambient_probe = probe == MigrationProbe::AmbientFd;
    let received_probe = probe == MigrationProbe::ReceivedFd;
    let delegated = PathBuf::from(std::env::var_os("ASWP_DELEGATED_CGROUP").unwrap());
    let executable = PathBuf::from(std::env::var_os("ASWP_TEST_CLI_SHIM").unwrap());
    let domain = cgroup::Domain::open(&delegated).unwrap();
    let mut scope = domain.create().unwrap();
    let ambient = ambient_probe.then(|| {
        let file = cgroup::control(scope.parent(), "cgroup.procs", OFlags::WRONLY).unwrap();
        fuxix::io::duplicate_inheritable(&file).unwrap()
    });
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
    let startup_deadline = Instant::now() + BUDGET;
    let (guardian, channel) = linux_guardian::spawn_guardian(
        &executable,
        scope.path(),
        Stdio::from(File::create(temp.path().join("guardian_fixture.stdout")).unwrap()),
        Stdio::from(File::create(temp.path().join("guardian_fixture.stderr")).unwrap()),
    )
    .unwrap();
    let mut guardian = OwnedChild(guardian);
    if let Some(fd) = &ambient {
        let observed = format!("/proc/{}/fd/{}", guardian.0.id(), fd.as_raw_fd());
        let expected = scope.path().parent().unwrap().join("cgroup.procs");
        until(|| fs::read_link(&observed).ok().as_deref() == Some(expected.as_path()));
    }
    let target = if parent_loss || guardian_loss {
        TARGET
    } else {
        GUARDIAN_EXIT_TARGET
    };
    let test_executable = std::env::current_exe().unwrap();
    let mut arguments = Vec::new();
    // The shim should reject inherited cgroup streams before executing even
    // the namespace setup command, so that case does not require unshare.
    let program = if namespace_probe && !inherited_probe {
        arguments.extend([
            "--user".into(),
            "--map-current-user".into(),
            "--cgroup".into(),
            test_executable.as_os_str().to_owned(),
        ]);
        PathBuf::from(std::env::var_os("ASWP_TEST_UNSHARE").unwrap())
    } else {
        test_executable
    };
    arguments.extend(["--exact".into(), target.into(), "--ignored".into()]);
    let launch = LaunchEnvelope::capture(
        program.as_os_str(),
        temp.path(),
        arguments,
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
            (
                "ASWP_JOURNAL_ESCAPE_PROBE".into(),
                escape_probe.then(|| "1".into()),
            ),
            (
                "ASWP_JOURNAL_NAMESPACE_PROBE".into(),
                namespace_probe.then(|| "1".into()),
            ),
            (
                "ASWP_JOURNAL_INHERITED_FD_PROBE".into(),
                inherited_probe.then(|| "1".into()),
            ),
            (
                "ASWP_JOURNAL_AMBIENT_FD".into(),
                ambient.as_ref().map(|fd| fd.as_raw_fd().to_string().into()),
            ),
            (
                "ASWP_JOURNAL_RECEIVED_FD_PROBE".into(),
                received_probe.then(|| "1".into()),
            ),
        ],
    )
    .unwrap();
    let (input, sender) = if received_probe {
        let (sender, receiver) = transport::pair().unwrap();
        transport::send(&sender, b"GO\n", &[]).unwrap();
        (File::from(receiver), Some(sender))
    } else {
        let mut input = tempfile::tempfile().unwrap();
        input.write_all(b"GO\n").unwrap();
        input.seek(SeekFrom::Start(0)).unwrap();
        (input, None)
    };
    let output = File::create(temp.path().join("target_fixture.stdout")).unwrap();
    let diagnostic = if inherited_probe {
        cgroup::control(scope.parent(), "cgroup.procs", OFlags::WRONLY).unwrap()
    } else {
        File::create(temp.path().join("target_fixture.stderr")).unwrap()
    };
    let pid = linux_guardian::prepare(
        &channel,
        [
            scope.parent().as_fd(),
            scope.directory().as_fd(),
            lease.as_fd(),
        ],
        &launch,
        [input.as_fd(), output.as_fd(), diagnostic.as_fd()],
        startup_deadline,
    )
    .unwrap();
    linux_guardian::record_and_go(&mut store, &run, pid, &channel, startup_deadline).unwrap();
    let transfer = sender.map(|sender| {
        let dir = temp.path().to_owned();
        let file = cgroup::control(scope.parent(), "cgroup.procs", OFlags::WRONLY).unwrap();
        thread::spawn(move || {
            until(|| dir.join("capability-requested").exists());
            transport::send(&sender, transport::GO, &[file.as_fd()]).unwrap();
        })
    });
    if guardian_loss {
        controller_wait(temp.path(), || temp.path().join("heartbeat").exists());
        assert!(cgroup::populated(scope.directory()).unwrap());
        guardian.0.kill().unwrap();
        assert!(linux_guardian::wait_for_empty(&channel, &mut guardian.0).is_err());
        assert!(matches!(store.attest_stopped(&run), Err(Error::Busy)));
        linux_guardian::recover_scope(&mut scope, Instant::now() + BUDGET).unwrap();
        assert!(cgroup::events_missing(scope.directory()).unwrap());
        assert!(matches!(store.attest_stopped(&run), Err(Error::Busy)));
        drop(lease);
        assert_eq!(store.run(&run).unwrap().observed_pid, Some(pid));
        assert_eq!(store.run(&run).unwrap().custody, ProcessCustody::Unknown);
        assert!(matches!(store.lease(profile.id), Err(Error::Busy)));
        store.attest_stopped(&run).unwrap();
        assert!(store.verify().unwrap().consistent);
        return;
    }
    drop(lease);
    if inherited_probe {
        assert!(linux_guardian::wait_for_empty(&channel, &mut guardian.0).is_err());
        drop(channel);
        let Some(status) = guardian.0.wait_timeout(BUDGET).unwrap() else {
            panic!("guardian timed out");
        };
        assert_eq!(status.code(), Some(125));
        assert!(!scope.path().exists());
        assert!(cgroup::events_missing(scope.directory()).unwrap());
        assert!(!temp.path().join("escape-result").exists());
        assert!(!temp.path().join("escaped-heartbeat").exists());
        assert_eq!(store.run(&run).unwrap().observed_pid, Some(pid));
        assert_eq!(store.run(&run).unwrap().custody, ProcessCustody::Unknown);
        assert!(matches!(store.lease(profile.id), Err(Error::Busy)));
        store.attest_stopped(&run).unwrap();
        assert!(store.verify().unwrap().consistent);
        println!(
            "::notice title=Linux inherited cgroup capability::shim refused the cgroup-backed standard stream and the ambiguous exit remained unresolved"
        );
        return;
    }
    if parent_loss {
        controller_wait(temp.path(), || temp.path().join("heartbeat").exists());
        assert!(matches!(store.attest_stopped(&run), Err(Error::Busy)));
        drop(channel);
    } else {
        assert_eq!(
            linux_guardian::wait_for_empty(&channel, &mut guardian.0).unwrap(),
            7
        );
        assert!(!cgroup::populated(scope.directory()).unwrap());
        assert!(!cgroup::events_missing(scope.directory()).unwrap());
        assert!(scope.path().exists());
        assert!(matches!(store.attest_stopped(&run), Err(Error::Busy)));
        if !loss_after_empty {
            linux_guardian::retire_observed(
                &channel,
                scope.parent(),
                scope.directory(),
                scope.path(),
                Instant::now() + BUDGET,
            )
            .unwrap();
        }
        drop(channel);
    }
    let Some(status) = guardian.0.wait_timeout(BUDGET).unwrap() else {
        panic!("guardian timed out");
    };
    if let Some(transfer) = transfer {
        transfer.join().unwrap();
    }
    assert_eq!(status.code(), Some(if loss_after_empty { 125 } else { 0 }));
    assert!(!scope.path().exists());
    assert!(cgroup::events_missing(scope.directory()).unwrap());
    if ambient_probe {
        assert!(temp.path().join("ambient-fd-closed").exists());
        println!(
            "::notice title=Linux ambient descriptor cleanup::the guardian inherited a cgroup capability that was closed before target exec"
        );
    }
    if escape_probe {
        let result = fs::read_to_string(temp.path().join("escape-result")).unwrap();
        match result.as_str() {
            "escaped" => {
                let heartbeat = temp.path().join("escaped-heartbeat");
                let first = fs::read_to_string(&heartbeat).unwrap();
                until(|| fs::read_to_string(&heartbeat).is_ok_and(|value| value != first));
                assert!(!temp.path().join("escaped-done").exists());
                println!(
                    "::warning title=Linux containment escape::an admitted same-user process escaped to the delegated parent and its writer survived scope retirement"
                );
                fs::write(temp.path().join("escaped-stop"), b"stop").unwrap();
                until(|| temp.path().join("escaped-done").exists());
                let title = if received_probe {
                    "Linux post-exec cgroup capability"
                } else if namespace_probe {
                    "Linux cgroup namespace migration"
                } else {
                    "Linux cgroup migration"
                };
                println!("::notice title={title}::escaped writer survived retirement");
            }
            "denied" => {
                let title = if received_probe {
                    "Linux post-exec cgroup capability"
                } else if namespace_probe {
                    "Linux cgroup namespace migration"
                } else {
                    "Linux cgroup migration"
                };
                println!("::notice title={title}::migration was denied on this runner");
            }
            _ => panic!("unexpected migration observation"),
        }
    }
    if !parent_loss && !loss_after_empty {
        fs::create_dir(scope.path()).unwrap();
        let replacement = cgroup::checked_directory(scope.path()).unwrap();
        assert!(!cgroup::events_missing(&replacement).unwrap());
        assert!(cgroup::events_missing(scope.directory()).unwrap());
        assert!(
            cgroup::retire_transferred(
                scope.parent(),
                scope.directory(),
                scope.path(),
                Instant::now() + BUDGET,
            )
            .is_err()
        );
        assert!(scope.path().exists());
        assert!(!cgroup::events_missing(&replacement).unwrap());
        cgroup::retire_transferred(
            scope.parent(),
            &replacement,
            scope.path(),
            Instant::now() + BUDGET,
        )
        .unwrap();
    }
    assert_eq!(store.run(&run).unwrap().observed_pid, Some(pid));
    assert_eq!(store.run(&run).unwrap().custody, ProcessCustody::Unknown);
    assert!(matches!(store.lease(profile.id), Err(Error::Busy)));
    store.attest_stopped(&run).unwrap();
    assert!(store.verify().unwrap().consistent);
}

#[test]
#[ignore = "requires the disposable delegated CI cgroup and actual CLI guardian"]
fn internal_guardian_cleans_up_on_incomplete_startup() {
    use crate::supervision::linux_guardian;
    let delegated = PathBuf::from(std::env::var_os("ASWP_DELEGATED_CGROUP").unwrap());
    let executable = PathBuf::from(std::env::var_os("ASWP_TEST_CLI_SHIM").unwrap());
    let scope = cgroup::Domain::open(&delegated).unwrap().create().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(&temp.path().join("state")).unwrap();
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
    let mut guardian = OwnedChild(
        Command::new(executable)
            .arg(linux_guardian::INTERNAL_ARG)
            .arg(scope.path())
            .arg(rustix::process::getpgrp().as_raw_pid().to_string())
            .env_clear()
            .stdin(Stdio::from(gate))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
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
    drop(lease);
    // Close after transferring custody, but before sending any launch data.
    drop(channel);
    let Some(status) = guardian.0.wait_timeout(BUDGET).unwrap() else {
        panic!("guardian timed out");
    };
    assert_eq!(status.code(), Some(125));
    assert!(!scope.path().exists());
    assert!(cgroup::events_missing(scope.directory()).unwrap());
    assert_eq!(store.run(&run).unwrap().observed_pid, None);
    assert_eq!(store.run(&run).unwrap().custody, ProcessCustody::Unknown);
    assert!(matches!(store.lease(profile.id), Err(Error::Busy)));
    store.attest_stopped(&run).unwrap();
    assert!(store.verify().unwrap().consistent);
    println!(
        "::notice title=Linux internal guardian incomplete startup::cleanup retained unresolved journal intent"
    );
}

#[test]
#[ignore = "requires the disposable delegated CI cgroup and actual CLI guardian"]
fn internal_guardian_reports_exit_after_cleanup() {
    internal_guardian_case(false, false, false, MigrationProbe::None);
    println!(
        "::notice title=Linux internal guardian exit::actual CLI guardian observed exit and retired the scope; journal remains pending"
    );
}

#[test]
#[ignore = "requires the disposable delegated CI cgroup and actual CLI guardian"]
fn internal_guardian_cleans_up_on_supervisor_channel_loss() {
    internal_guardian_case(true, false, false, MigrationProbe::None);
    println!(
        "::notice title=Linux internal guardian EOF::actual CLI guardian retired target scope on channel loss; journal remains pending"
    );
}

#[test]
#[ignore = "requires the disposable delegated CI cgroup and actual CLI guardian"]
fn internal_guardian_cleans_up_if_parent_disappears_before_retirement() {
    internal_guardian_case(false, true, false, MigrationProbe::None);
    println!(
        "::notice title=Linux internal guardian pre-retirement EOF::actual CLI guardian retained lease through empty-scope cleanup after channel loss"
    );
}

#[test]
#[ignore = "requires the disposable delegated CI cgroup and actual CLI guardian"]
fn internal_guardian_loss_preserves_unresolved_run_through_cleanup() {
    internal_guardian_case(false, false, true, MigrationProbe::None);
    println!(
        "::notice title=Linux internal guardian loss::owned guardian loss leaves the run unresolved while the supervisor retains custody through cleanup"
    );
}

#[test]
#[ignore = "requires the disposable delegated CI cgroup and actual CLI guardian"]
fn internal_guardian_checks_same_user_cgroup_migration() {
    internal_guardian_case(false, false, false, MigrationProbe::Direct);
}

#[test]
#[ignore = "requires delegated cgroup, unprivileged namespaces and the actual CLI guardian"]
fn internal_guardian_checks_namespaced_cgroup_migration() {
    internal_guardian_case(false, false, false, MigrationProbe::Namespace);
}

#[test]
#[ignore = "requires the disposable delegated CI cgroup and actual CLI guardian"]
fn internal_guardian_checks_inherited_cgroup_capability() {
    internal_guardian_case(false, false, false, MigrationProbe::InheritedFd);
}

#[test]
#[ignore = "requires the disposable delegated CI cgroup and actual CLI guardian"]
fn internal_guardian_closes_ambient_cgroup_capability() {
    internal_guardian_case(false, false, false, MigrationProbe::AmbientFd);
}

#[test]
#[ignore = "requires delegated cgroup, unprivileged namespaces and the actual CLI guardian"]
fn internal_guardian_checks_post_exec_cgroup_capability() {
    internal_guardian_case(false, false, false, MigrationProbe::ReceivedFd);
}
