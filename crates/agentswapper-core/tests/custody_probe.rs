//! Provider-free evidence that process groups cannot contain a detached writer.
#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use rustix::process::{Pid, Signal, getpgrp, getsid, kill_process_group, setsid};
use std::{
    fs,
    os::unix::process::{CommandExt, ExitStatusExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn command(role: &str, directory: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.env_clear();
    // Preserve instrumentation and runtime-library lookup without auth variables.
    for name in [
        "LLVM_PROFILE_FILE",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "ASAN_OPTIONS",
        "UBSAN_OPTIONS",
        "LSAN_OPTIONS",
        "TSAN_OPTIONS",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .env("ASWP_PROBE_ROLE", role)
        .env("ASWP_PROBE_DIRECTORY", directory)
        .args([
            "--ignored",
            "--exact",
            "custody_fixture_entry",
            "--test-threads=1",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn publish(directory: &Path, name: &str, value: &str) {
    let temporary = directory.join(format!("{name}.tmp"));
    fs::write(&temporary, value).unwrap();
    fs::rename(temporary, directory.join(name)).unwrap();
}

#[derive(Clone, Copy)]
struct Heartbeat {
    pid: u32,
    group: u32,
    session: u32,
    tick: u64,
}
fn heartbeat(directory: &Path, name: &str) -> Option<Heartbeat> {
    let text = fs::read_to_string(directory.join(name)).ok()?;
    let mut fields = text.split_whitespace();
    let result = Heartbeat {
        pid: fields.next()?.parse().ok()?,
        group: fields.next()?.parse().ok()?,
        session: fields.next()?.parse().ok()?,
        tick: fields.next()?.parse().ok()?,
    };
    fields.next().is_none().then_some(result)
}

struct Deadline(Instant);
impl Deadline {
    fn new() -> Self {
        Self(Instant::now() + Duration::from_secs(8))
    }
    fn until<T>(&self, mut condition: impl FnMut() -> Option<T>) -> T {
        loop {
            if let Some(value) = condition() {
                return value;
            }
            assert!(Instant::now() < self.0, "custody fixture timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(target_os = "linux")]
fn reaped(pid: u32) -> Option<rustix::process::WaitStatus> {
    let pid = Pid::from_raw(pid.try_into().unwrap()).unwrap();
    rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG)
        .unwrap()
        .map(|(actual, status)| {
            assert_eq!(actual, pid);
            status
        })
}

struct Probe {
    root: Child,
    directory: tempfile::TempDir,
}
impl Drop for Probe {
    fn drop(&mut self) {
        let _ = fs::write(self.directory.path().join("stop"), "stop");
        // Child::kill is a no-op after wait. Never signal a PID read from a file.
        let _ = self.root.kill();
        let _ = self.root.wait();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !self.directory.path().join("leaf-stopped").exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        #[cfg(target_os = "linux")]
        for name in ["control-pid", "leaf-pid"] {
            let pid = fs::read_to_string(self.directory.path().join(name))
                .ok()
                .and_then(|s| s.parse::<i32>().ok())
                .and_then(Pid::from_raw);
            if let Some(pid) = pid {
                while Instant::now() < deadline {
                    match rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::NOHANG)
                    {
                        Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                        _ => break,
                    }
                }
            }
        }
    }
}

#[test]
fn process_groups_do_not_contain_a_reparented_setsid_writer() {
    #[cfg(target_os = "linux")]
    rustix::process::set_child_subreaper(Some(rustix::process::getpid())).unwrap();
    let deadline = Deadline::new();
    let directory = tempfile::tempdir().unwrap();
    let root = command("root", directory.path())
        .process_group(0)
        .spawn()
        .unwrap();
    let mut probe = Probe { root, directory };
    let escaped = deadline.until(|| heartbeat(probe.directory.path(), "heartbeat"));
    let control = deadline.until(|| heartbeat(probe.directory.path(), "control-heartbeat"));
    deadline.until(|| {
        probe
            .directory
            .path()
            .join("middle-reaped")
            .exists()
            .then_some(())
    });
    assert_eq!(control.group, probe.root.id());
    assert_ne!(escaped.group, probe.root.id());
    assert_ne!(escaped.session, control.session);
    // Reserve the root PID by leaving it unreaped until after killpg.
    kill_process_group(Pid::from_child(&probe.root), Signal::KILL).unwrap();
    assert_eq!(probe.root.wait().unwrap().signal(), Some(9));
    let after_kill = deadline.until(|| {
        heartbeat(probe.directory.path(), "heartbeat").filter(|value| value.pid == escaped.pid)
    });
    let stopped_control = deadline.until(|| heartbeat(probe.directory.path(), "control-heartbeat"));
    deadline.until(|| {
        heartbeat(probe.directory.path(), "heartbeat")
            .filter(|value| value.pid == escaped.pid && value.tick > after_kill.tick + 4)
    });
    assert_eq!(
        heartbeat(probe.directory.path(), "control-heartbeat")
            .unwrap()
            .tick,
        stopped_control.tick
    );
    #[cfg(target_os = "linux")]
    assert_eq!(
        deadline.until(|| reaped(control.pid)).terminating_signal(),
        Some(9)
    );
    fs::write(probe.directory.path().join("stop"), "stop").unwrap();
    deadline.until(|| {
        probe
            .directory
            .path()
            .join("leaf-stopped")
            .exists()
            .then_some(())
    });
    #[cfg(target_os = "linux")]
    assert_eq!(
        deadline.until(|| reaped(escaped.pid)).exit_status(),
        Some(0)
    );
}

#[test]
#[ignore = "fixture entry point; invoked explicitly by the custody probe"]
fn custody_fixture_entry() {
    let Ok(role) = std::env::var("ASWP_PROBE_ROLE") else {
        return;
    };
    let directory = PathBuf::from(
        std::env::var_os("ASWP_PROBE_DIRECTORY").expect("fixture directory required"),
    );
    match role.as_str() {
        "root" => {
            let mut control = command("control", &directory).spawn().unwrap();
            publish(&directory, "control-pid", &control.id().to_string());
            let mut middle = command("middle", &directory).spawn().unwrap();
            assert!(middle.wait().unwrap().success());
            publish(&directory, "middle-reaped", "reaped");
            let started = Instant::now();
            while !directory.join("stop").exists() && started.elapsed() < Duration::from_secs(20) {
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = control.wait();
        }
        "middle" => {
            setsid().unwrap();
            // Intentionally reparent the writer. Linux's probe subreaper (or
            // macOS init) reaps it; waiting here would defeat the fixture.
            #[expect(
                clippy::zombie_processes,
                reason = "intentional reparenting; fixture reaped by probe or OS init"
            )]
            let leaf = command("leaf", &directory).spawn().unwrap();
            publish(&directory, "leaf-pid", &leaf.id().to_string());
        }
        "leaf" | "control" => {
            let started = Instant::now();
            let mut tick = 0_u64;
            let group = getpgrp().as_raw_nonzero().get();
            let session = getsid(None).unwrap().as_raw_nonzero().get();
            let name = if role == "leaf" {
                "heartbeat"
            } else {
                "control-heartbeat"
            };
            while !directory.join("stop").exists() && started.elapsed() < Duration::from_secs(20) {
                tick += 1;
                publish(
                    &directory,
                    name,
                    &format!("{} {group} {session} {tick}", std::process::id()),
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            publish(&directory, &format!("{role}-stopped"), "stopped");
        }
        _ => panic!("unknown fixture role"),
    }
}
