#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::OnceLock,
    time::{Duration, Instant},
};

use assert_cmd::{Command as AssertCommand, cargo::cargo_bin_cmd};
use predicates::prelude::*;
use serde_json::Value;
use tempfile::TempDir;

fn fixture() -> &'static Path {
    static BUILT: OnceLock<TempDir> = OnceLock::new();
    let dir = BUILT.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native_agent.rs");
        let result = Command::new("rustc")
            .args(["--edition=2024"])
            .arg(source)
            .arg("-o")
            .arg(
                dir.path()
                    .join(format!("native-agent{}", std::env::consts::EXE_SUFFIX)),
            )
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        dir
    });
    // The backing TempDir lives for the duration of this test process.
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        dir.path()
            .join(format!("native-agent{}", std::env::consts::EXE_SUFFIX))
    })
}

struct Sandbox {
    temp: TempDir,
}
impl Sandbox {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("home")).unwrap();
        Self { temp }
    }
    fn state(&self) -> PathBuf {
        self.temp.path().join("state")
    }
    fn command(&self) -> AssertCommand {
        AssertCommand::from_std(self.native_command())
    }
    fn native_command(&self) -> Command {
        let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("aswp"));
        cmd.env_clear();
        // Windows needs these for loading native binaries. No credential variables.
        for name in ["SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"] {
            if let Some(value) = std::env::var_os(name) {
                cmd.env(name, value);
            }
        }
        cmd.env("HOME", self.temp.path().join("home"))
            .env("USERPROFILE", self.temp.path().join("home"))
            .current_dir(self.temp.path())
            .arg("--state-dir")
            .arg(self.state());
        cmd
    }
    fn add(&self, harness: &str, alias: &str) {
        self.command()
            .args(["profile", "add", harness, "--alias", alias])
            .assert()
            .success();
    }
    fn run(&self, alias: &str) -> AssertCommand {
        let mut cmd = self.command();
        cmd.args(["run", alias, "--experimental-native", "--executable"])
            .arg(fixture());
        cmd
    }
}

fn hex(value: &OsStr) -> String {
    value
        .as_encoded_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn help_and_alias_work_without_opening_storage() {
    let s = Sandbox::new();
    s.command()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Switch agents. Keep your place."));
    assert!(!s.state().exists());
    cargo_bin_cmd!("agentswapper")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage: agentswapper"));
}

#[test]
fn profile_lifecycle_and_json_contract() {
    let s = Sandbox::new();
    s.add("claude", "work");
    let first = s.command().args(["list", "--json"]).output().unwrap();
    let first: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(first["schemaVersion"], 0);
    assert_eq!(first["data"][0]["quota"], "unknown");
    let id = first["data"][0]["profile"]["id"].clone();
    s.command()
        .args(["profile", "alias", "work", "personal"])
        .assert()
        .success();
    s.command()
        .args(["profile", "disable", "personal"])
        .assert()
        .success();
    let output = s
        .command()
        .args(["profile", "show", "personal", "--json"])
        .output()
        .unwrap();
    let after: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(after["data"]["profile"]["id"], id);
    assert_eq!(after["data"]["profile"]["enabled"], false);
    s.command()
        .args(["profile", "remove", "personal"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Vendor files retained"));
    assert!(
        s.state()
            .join("profiles")
            .join(id.as_str().unwrap())
            .exists()
    );
}

#[test]
fn duplicate_alias_fails_with_a_structured_error() {
    let s = Sandbox::new();
    s.add("claude", "work");
    s.command()
        .args(["profile", "add", "codex", "--alias", "work", "--json"])
        .assert()
        .code(125)
        .stdout(predicate::str::contains("duplicate_alias"));
    s.command()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("work").count(1));
}

#[test]
fn all_harnesses_forward_argv_without_a_shell_and_write_only_selected_home() {
    let s = Sandbox::new();
    for (harness, variable) in [
        ("claude", "CLAUDE_CONFIG_DIR"),
        ("codex", "CODEX_HOME"),
        ("kimi", "KIMI_CODE_HOME"),
    ] {
        s.add(harness, harness);
        let values = [
            "",
            "a b",
            "$(touch SHOULD_NOT_EXIST)",
            "`whoami`",
            "a'\"b",
            "--",
            "--help",
        ];
        let output = s.run(harness).arg("--").args(values).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        for value in values {
            assert!(text.contains(&format!("arg={}\n", hex(OsStr::new(value)))));
        }
        assert!(text.contains(&format!("{variable}=")));
        let preview = s
            .command()
            .args(["run", harness, "--dry-run", "--json", "--executable"])
            .arg(fixture())
            .output()
            .unwrap();
        let preview: Value = serde_json::from_slice(&preview.stdout).unwrap();
        let expected_home = preview["data"]["plan"]["profile_home"].as_str().unwrap();
        assert!(text.contains(&format!("{variable}={}\n", hex(OsStr::new(expected_home)))));
        assert!(Path::new(expected_home).join("fixture-owned.txt").exists());
        for other in ["CLAUDE_CONFIG_DIR", "CODEX_HOME", "KIMI_CODE_HOME"] {
            if other != variable {
                assert!(!text.contains(&format!("{other}=")));
            }
        }
    }
    assert!(!s.temp.path().join("SHOULD_NOT_EXIST").exists());
    assert_eq!(
        std::fs::read_dir(s.temp.path().join("home"))
            .unwrap()
            .count(),
        0
    );
}

#[cfg(unix)]
#[test]
fn non_utf8_native_arguments_survive() {
    use std::os::unix::ffi::OsStringExt;
    let s = Sandbox::new();
    s.add("codex", "work");
    let arg = std::ffi::OsString::from_vec(vec![0xff, 0xfe, b'a']);
    s.run("work")
        .arg("--")
        .arg(arg)
        .assert()
        .success()
        .stdout(predicate::str::contains("arg=fffe61"));
}

#[test]
fn dry_run_redacts_secret_arguments_and_never_spawns() {
    let s = Sandbox::new();
    s.add("claude", "work");
    let output = s
        .command()
        .args(["run", "work", "--dry-run", "--json", "--executable"])
        .arg(fixture())
        .args(["--", "secret-argument-canary"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("secret-argument-canary"));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["data"]["plan"]["argument_count"], 1);
    let home = value["data"]["plan"]["profile_home"].as_str().unwrap();
    assert!(!Path::new(home).join("fixture-owned.txt").exists());
}

#[test]
fn conflicting_authentication_never_exposes_secret() {
    let s = Sandbox::new();
    s.add("claude", "work");
    let output = s
        .run("work")
        .env("ANTHROPIC_API_KEY", "credential-canary")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&output.stderr).contains("ANTHROPIC_API_KEY"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("credential-canary"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("credential-canary"));
    let database = std::fs::read(s.state().join("registry.sqlite3")).unwrap();
    assert!(!database.windows(17).any(|w| w == b"credential-canary"));
}

#[test]
fn native_exit_status_is_preserved_and_completed_runs_can_relaunch() {
    let s = Sandbox::new();
    s.add("kimi", "work");
    s.run("work").args(["--", "--exit"]).assert().code(42);
    s.run("work").assert().success();
    s.command()
        .args(["status", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"unfinishedRuns\":[]"));
}

#[test]
fn launch_requires_explicit_experimental_opt_in() {
    let s = Sandbox::new();
    s.add("claude", "work");
    s.command()
        .args(["run", "work", "--executable"])
        .arg(fixture())
        .assert()
        .code(125)
        .stderr(predicate::str::contains("--experimental-native"));
}

#[test]
fn other_harness_home_variables_do_not_leak_to_the_child() {
    let s = Sandbox::new();
    s.add("codex", "work");
    s.run("work")
        .env("CLAUDE_CONFIG_DIR", s.temp.path().join("other-identity"))
        .assert()
        .success()
        .stdout(predicate::str::contains("CLAUDE_CONFIG_DIR=").not());
    assert!(!s.temp.path().join("other-identity").exists());
}

#[test]
fn doctor_reports_a_missing_home_and_metadata_can_still_be_removed() {
    let s = Sandbox::new();
    s.add("claude", "work");
    let output = s
        .command()
        .args(["profile", "show", "work", "--json"])
        .output()
        .unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let home = s
        .state()
        .join("profiles")
        .join(value["data"]["profile"]["id"].as_str().unwrap());
    std::fs::remove_dir(home).unwrap();
    let output = s.command().args(["doctor", "--json"]).output().unwrap();
    assert_eq!(output.status.code(), Some(125));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["data"]["storage"], "needs_attention");
    assert_eq!(value["data"]["issue"]["code"], "profile_dir_missing");
    assert_eq!(value["data"]["executables"].as_array().unwrap().len(), 3);
    s.command()
        .args(["profile", "remove", "work"])
        .assert()
        .success();
}

#[cfg(unix)]
#[test]
fn symlinked_native_shim_keeps_its_invocation_name() {
    let s = Sandbox::new();
    s.add("claude", "work");
    let shim = s.temp.path().join("my-claude-shim");
    std::os::unix::fs::symlink(fixture(), &shim).unwrap();
    s.command()
        .args(["run", "work", "--experimental-native", "--executable"])
        .arg(&shim)
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "argv0={}\n",
            hex(shim.as_os_str())
        )));
}

#[test]
fn supervisor_crash_leaves_a_durable_block_even_after_lock_release() {
    let s = Sandbox::new();
    s.add("claude", "work");
    let ready = s.temp.path().join("ready");
    let stop = s.temp.path().join("stop");
    struct StopOnDrop(PathBuf);
    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::write(&self.0, "stop");
        }
    }
    let _cleanup = StopOnDrop(stop.clone());
    let mut command = s.native_command();
    command
        .args(["run", "work", "--experimental-native", "--executable"])
        .arg(fixture())
        .arg("--")
        .arg("--wait")
        .arg(&ready)
        .arg(&stop);
    let mut child = command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let started = Instant::now();
    while !ready.exists() {
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "fixture did not start"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    s.run("work")
        .assert()
        .code(125)
        .stderr(predicate::str::contains("busy"));
    let pending = s.command().args(["status", "--json"]).output().unwrap();
    let pending: Value = serde_json::from_slice(&pending.stdout).unwrap();
    let run_id = pending["data"]["unfinishedRuns"][0]["id"].as_str().unwrap();
    s.command().args(["recover", run_id]).assert().code(2);
    s.command()
        .args(["recover", run_id, "--confirm-stopped"])
        .assert()
        .code(125);
    child.kill().unwrap();
    child.wait().unwrap();
    s.run("work")
        .assert()
        .code(125)
        .stderr(predicate::str::contains("unfinished run"));
    s.command()
        .args(["profile", "remove", "work"])
        .assert()
        .code(125);
    s.command()
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("custody is unknown"));
    std::fs::write(&stop, "stop").unwrap();
    // The controlled fixture polls the stop file. This attestation is explicit;
    // the production command never interprets a released lock as stopped custody.
    std::thread::sleep(Duration::from_millis(100));
    s.command()
        .args(["recover", run_id, "--confirm-stopped"])
        .assert()
        .success();
    s.run("work").assert().success();
}
