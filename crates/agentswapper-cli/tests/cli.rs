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

#[path = "cli/supervision.rs"]
mod supervision;

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
fn bare_command_in_pipes_preserves_help_and_json_without_opening_state() {
    let s = Sandbox::new();
    s.command()
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage: aswp"));
    s.command()
        .arg("--json")
        .assert()
        .success()
        .stdout(predicate::str::contains("developer_preview"));
    assert!(!s.state().exists());
}

#[test]
fn run_history_records_pid_and_custody_without_argument_contents() {
    let s = Sandbox::new();
    s.command()
        .arg("runs")
        .assert()
        .success()
        .stdout(predicate::str::contains("No runs recorded"));
    s.add("claude", "work");
    s.run("work")
        .args(["--", "private-argument-canary"])
        .assert()
        .success();
    let output = s
        .command()
        .args(["runs", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    let record = &value["data"][0];
    assert_eq!(record["custody"], "exited_uncontained");
    assert_eq!(record["exitCode"], 0);
    assert!(record["observedPid"].as_u64().unwrap() > 0);
    assert!(record["spawnedAt"].is_string());
    let id = record["id"].as_str().unwrap();
    s.command()
        .args(["profile", "remove", "work"])
        .assert()
        .success();
    s.command()
        .args(["runs", id, "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("exited_uncontained"))
        .stdout(predicate::str::contains("private-argument-canary").not());
    s.command().args(["runs", "--limit", "0"]).assert().code(2);
    s.command()
        .args(["runs", "missing", "--json"])
        .assert()
        .code(125)
        .stdout(predicate::str::contains("run_not_found"));
}

#[test]
fn registry_verify_reports_full_replay_in_json() {
    let s = Sandbox::new();
    let output = s
        .command()
        .args(["registry", "verify", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["schemaVersion"], 0);
    assert_eq!(value["data"]["schemaVersion"], 6);
    assert_eq!(value["data"]["events"], 0);
    assert_eq!(value["data"]["consistent"], true);
    s.add("claude", "work");
    s.run("work").assert().success();
    let output = s
        .command()
        .args(["registry", "verify", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["data"]["events"], 4);
    assert_eq!(value["data"]["consistent"], true);
    assert_eq!(value["data"]["mismatchedTables"], serde_json::json!([]));
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
fn kimi_routing_overrides_are_reported_without_values_and_refused_before_spawn() {
    let s = Sandbox::new();
    s.add("kimi", "work");
    // Independent examples from the reviewed upstream contract: managed auth,
    // header credentials, temporary models, legacy migration and SDK auth.
    for key in [
        "KIMI_CODE_BASE_URL",
        "KIMI_CODE_OAUTH_HOST",
        "KIMI_OAUTH_HOST",
        "KIMI_CODE_CUSTOM_HEADERS",
        "KIMI_CODE_PASSWORD",
        "KIMI_MODEL_NAME",
        "KIMI_MODEL_API_KEY",
        "KIMI_MODEL_BASE_URL",
        "KIMI_SHARE_DIR",
        "GOOGLE_APPLICATION_CREDENTIALS",
    ] {
        let output = s
            .command()
            .args(["run", "work", "--dry-run", "--json", "--executable"])
            .arg(fixture())
            .env(key, "routing-secret-canary")
            .output()
            .unwrap();
        assert!(output.status.success());
        let preview: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            preview["data"]["environmentConflict"]
                .as_str()
                .unwrap()
                .contains(key)
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("routing-secret-canary"));
        let run = s
            .run("work")
            .env(key, "routing-secret-canary")
            .output()
            .unwrap();
        assert_eq!(run.status.code(), Some(125));
        let error = String::from_utf8_lossy(&run.stderr);
        assert!(error.contains(key));
        assert!(!error.contains("routing-secret-canary"));
        assert!(!String::from_utf8_lossy(&run.stdout).contains("routing-secret-canary"));
        let home = Path::new(preview["data"]["plan"]["profile_home"].as_str().unwrap());
        assert!(!home.join("fixture-owned.txt").exists());
    }
    // Even an empty override is refused, while unrelated runtime preferences
    // remain usable. No policy depends on inspecting an override's contents.
    s.run("work").env("KIMI_MODEL_NAME", "").assert().code(125);
    let history = s.command().args(["runs", "--json"]).output().unwrap();
    let history: Value = serde_json::from_slice(&history.stdout).unwrap();
    assert_eq!(history["data"].as_array().unwrap().len(), 0);
    s.run("work")
        .env("KIMI_DISABLE_TELEMETRY", "1")
        .assert()
        .success();
    let database = std::fs::read(s.state().join("registry.sqlite3")).unwrap();
    assert!(
        !database
            .windows(b"routing-secret-canary".len())
            .any(|w| w == b"routing-secret-canary")
    );
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
    assert_eq!(value["data"]["executables"].as_array().unwrap().len(), 4);
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

#[cfg(unix)]
#[test]
fn executable_unix_script_preserves_literal_arguments_and_exit_status() {
    use std::{
        ffi::OsString,
        os::unix::{
            ffi::OsStringExt,
            fs::{PermissionsExt, symlink},
        },
    };
    let s = Sandbox::new();
    s.add("codex", "work");
    let script = s.temp.path().join("agent script");
    std::fs::write(
        &script,
        "#!/bin/sh\nprintf '%s\\000' \"$0\" \"$@\"\nexit 37\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let entry = s.temp.path().join("entry script");
    symlink("agent script", &entry).unwrap();
    let mut values: Vec<OsString> = [
        "",
        "a b",
        "$(touch SHOULD_NOT_EXIST)",
        "`whoami`",
        "a'\"b",
        "*",
        "a\nb",
        "--help",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    values.push(OsString::from_vec(vec![0xff, 0xfe, b'a']));
    let output = s
        .command()
        .args(["run", "work", "--experimental-native", "--executable"])
        .arg(&entry)
        .arg("--")
        .args(&values)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(37),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut expected = Vec::new();
    for value in std::iter::once(entry.as_os_str()).chain(values.iter().map(OsString::as_os_str)) {
        expected.extend_from_slice(value.as_encoded_bytes());
        expected.push(0);
    }
    assert_eq!(output.stdout, expected);
    assert!(!s.temp.path().join("SHOULD_NOT_EXIST").exists());
    let history = s.command().args(["runs", "--json"]).output().unwrap();
    let history: Value = serde_json::from_slice(&history.stdout).unwrap();
    assert!(!history.to_string().contains("SHOULD_NOT_EXIST"));
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

#[cfg(unix)]
#[test]
fn foreground_sigint_reaches_child_while_supervisor_records_exit() {
    use rustix::process::{Pid, Signal, kill_process_group};
    use std::os::unix::process::CommandExt;
    let s = Sandbox::new();
    s.add("claude", "work");
    let ready = s.temp.path().join("ready");
    let stop = s.temp.path().join("stop");
    let mut command = s.native_command();
    command
        .args(["run", "work", "--experimental-native", "--executable"])
        .arg(fixture())
        .args(["--", "--wait"])
        .arg(&ready)
        .arg(&stop)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn().unwrap();
    let started = Instant::now();
    while !ready.exists() {
        if started.elapsed() >= Duration::from_secs(8) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("signal fixture failed to start");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    // Only this owned, unreaped child's group is signalled. No stored PID is used.
    kill_process_group(Pid::from_child(&child), Signal::INT).unwrap();
    let result = child.wait().unwrap();
    assert_eq!(result.code(), Some(130));
    let output = s
        .command()
        .args(["runs", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["data"][0]["custody"], "exited_uncontained");
    assert_eq!(value["data"][0]["exitCode"], 130);
}

fn gents_profile(s: &Sandbox, address: &str, agent: &str) -> PathBuf {
    let output = s
        .command()
        .args([
            "profile",
            "add",
            "--engine",
            "gents",
            "--alias",
            "relay",
            "--address",
            address,
            "--agent",
            agent,
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["data"]["engine"], "gents");
    PathBuf::from(value["data"]["profileHome"].as_str().unwrap())
}

fn runtime_state(home: &Path, address: &str) {
    let path = home.join("runtime.json");
    std::fs::write(
        &path,
        serde_json::to_vec(
            &serde_json::json!({"home":home,"graphql":format!("http://{address}/api/v0/graphql")}),
        )
        .unwrap(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn gents_run(s: &Sandbox) -> AssertCommand {
    let mut cmd = s.command();
    cmd.args(["run", "relay", "--experimental-gents", "--executable"])
        .arg(fixture());
    cmd
}

#[test]
fn engine_comparison_never_opens_storage() {
    let s = Sandbox::new();
    let out = s
        .command()
        .args(["engines", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(value["data"][0]["engine"], "native");
    assert_eq!(value["data"][1]["engine"], "gents");
    assert!(value["data"][1]["limitations"].as_array().unwrap().len() >= 5);
    assert!(!s.state().exists());
    s.command()
        .arg("engines")
        .assert()
        .success()
        .stdout(predicate::str::contains("Listener identity is unverified"));
    assert!(!s.state().exists());
}

#[test]
fn gents_launch_binds_argv_isolates_environment_and_records_external_custody() {
    let s = Sandbox::new();
    let home = gents_profile(&s, "[::1]:9192", "web_persona");
    runtime_state(&home, "::1:9192"); // Exact unbracketed form written by reviewed upstream.
    let session = "cafe0000-0000-4000-8000-000000000004";
    let out = gents_run(&s)
        .args(["--engine", "gents", "--session", session])
        .env("GENTS_HOME", "private-canary")
        .env("GENTS_GRAPHQL", "private-canary")
        .env("GENTS_FUTURE_OVERRIDE", "private-canary")
        .env("HTTP_PROXY", "private-canary")
        .env("http_proxy", "private-canary")
        .env("HTTPS_PROXY", "private-canary")
        .env("ALL_PROXY", "private-canary")
        .env("UNRELATED_SECRET", "private-canary")
        .env("OPENAI_API_KEY", "private-canary")
        .env("ANTHROPIC_API_KEY", "private-canary")
        .env("TERM", "xterm-256color")
        .assert()
        .success()
        .stdout(predicate::str::contains("leaked=").not())
        .stdout(predicate::str::contains("terminal=xterm-256color"))
        .stdout(predicate::str::contains("private-canary").not())
        .stderr(predicate::str::contains(
            "External runtime work may continue",
        ))
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(out).unwrap();
    let actual: Vec<_> = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("arg="))
        .collect();
    let expected = [
        OsStr::new("chat"),
        OsStr::new("--home"),
        home.as_os_str(),
        OsStr::new("--graphql"),
        OsStr::new("http://[::1]:9192/api/v0/graphql"),
        OsStr::new("--agent-id=web_persona"),
        OsStr::new("--session-id"),
        OsStr::new(session),
    ]
    .map(hex);
    assert_eq!(actual, expected);
    assert!(home.join("fixture-owned.txt").is_file());
    for key in ["CLAUDE_CONFIG_DIR=", "CODEX_HOME=", "KIMI_CODE_HOME="] {
        assert!(!stdout.contains(key));
    }
    let out = s
        .command()
        .args(["runs", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(value["data"][0]["outcome"], "external_client_exited");
    assert_eq!(value["data"][0]["custody"], "external_runtime_unknown");
    assert_eq!(value["data"][0]["harness"], "gents");
    gents_run(&s).assert().success(); // Explicit manual reuse, not runtime cleanup proof.
    s.command().args(["registry", "verify"]).assert().success();
}

#[test]
fn gents_scope_overrides_wrong_opt_in_and_native_login_are_rejected_before_spawn() {
    let s = Sandbox::new();
    let home = gents_profile(&s, "127.0.0.1:9191", "worker");
    runtime_state(&home, "127.0.0.1:9191");
    for (args, message) in [
        (
            vec!["run", "relay", "--experimental-native"],
            "--experimental-gents",
        ),
        (
            vec!["run", "relay", "--experimental-gents", "--engine", "native"],
            "does not match",
        ),
        (
            vec!["login", "relay", "--experimental-gents"],
            "no forwarded arguments or native login",
        ),
    ] {
        s.command()
            .args(args)
            .arg("--executable")
            .arg(fixture())
            .assert()
            .code(125)
            .stderr(predicate::str::contains(message));
    }
    for args in [
        vec!["--home", "private-canary"],
        vec!["--graphql", "https://remote.invalid"],
        vec!["--agent-id=other"],
        vec!["private-message-canary"],
    ] {
        gents_run(&s)
            .arg("--")
            .args(args)
            .assert()
            .code(125)
            .stderr(predicate::str::contains("no forwarded arguments"))
            .stderr(predicate::str::contains("canary").not());
    }
    assert!(!home.join("fixture-owned.txt").exists());
    s.command()
        .args(["runs", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"data\":[]"));
    s.add("codex", "native");
    s.command()
        .args(["run", "native", "--experimental-gents", "--executable"])
        .arg(fixture())
        .assert()
        .code(125)
        .stderr(predicate::str::contains("--experimental-native"));
    s.run("native")
        .args(["--session", "cafe0000-0000-4000-8000-000000000004"])
        .assert()
        .code(125)
        .stderr(predicate::str::contains("only for the gents engine"));
    s.command()
        .args([
            "profile",
            "bind",
            "native",
            "--address",
            "127.0.0.1:9192",
            "--agent",
            "worker",
            "--json",
        ])
        .assert()
        .code(125)
        .stdout(predicate::str::contains("engine_mismatch"));
    s.command()
        .args(["profile", "remove", "relay"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Keychain items retained"))
        .stdout(predicate::str::contains(
            "External runtimes are not stopped",
        ));
    assert!(home.is_dir());
}

#[test]
fn runtime_record_is_checked_and_previews_disclose_listener_and_workspace_scope() {
    let s = Sandbox::new();
    let home = gents_profile(&s, "127.0.0.1:9191", "worker");
    gents_run(&s)
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains("runtime.json missing"))
        .stdout(predicate::str::contains("Listener unverified"))
        .stdout(predicate::str::contains(
            "Workspace and permissions belong to the gents agent configuration",
        ));
    gents_run(&s)
        .assert()
        .code(125)
        .stderr(predicate::str::contains("runtime.json"));
    runtime_state(&home, "127.0.0.1:9192");
    gents_run(&s)
        .assert()
        .code(125)
        .stderr(predicate::str::contains("matching this profile"));
    for invalid in ["private-canary".to_owned(), " ".repeat(65537)] {
        std::fs::write(home.join("runtime.json"), invalid).unwrap();
        gents_run(&s)
            .assert()
            .code(125)
            .stderr(predicate::str::contains("private-canary").not());
    }
    // A copied runtime record from another home must not authorize launch.
    runtime_state(&home, "127.0.0.1:9191");
    let mut state: Value =
        serde_json::from_slice(&std::fs::read(home.join("runtime.json")).unwrap()).unwrap();
    state["home"] = s.temp.path().to_str().unwrap().into();
    std::fs::write(
        home.join("runtime.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();
    gents_run(&s).assert().code(125);
    assert!(!home.join("fixture-owned.txt").exists());
    s.command()
        .args([
            "profile",
            "bind",
            "relay",
            "--address",
            "127.0.0.1:9192",
            "--agent",
            "--leading-id",
        ])
        .assert()
        .code(2); // Use = for a leading hyphen, just as clap documents.
    s.command()
        .args([
            "profile",
            "bind",
            "relay",
            "--address",
            "127.0.0.1:9192",
            "--agent=-leading_id",
        ])
        .assert()
        .success();
    runtime_state(&home, "127.0.0.1:9192");
    gents_run(&s)
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "arg={}",
            hex(OsStr::new("--agent-id=-leading_id"))
        )));
    assert!(home.join("fixture-owned.txt").exists());
}

#[test]
fn engine_registration_refuses_ambiguous_or_nonlocal_bindings() {
    let s = Sandbox::new();
    for args in [
        vec!["--engine", "gents"],
        vec![
            "claude",
            "--engine",
            "gents",
            "--address",
            "127.0.0.1:9191",
            "--agent",
            "worker",
        ],
        vec!["gents", "--engine", "native"],
        vec!["codex", "--address", "127.0.0.1:9191", "--agent", "worker"],
        vec!["gents", "--address", "192.0.2.1:9191", "--agent", "worker"],
    ] {
        s.command()
            .args(["profile", "add", "--alias", "invalid"])
            .args(args)
            .assert()
            .code(125);
    }
    for address in ["localhost:9191", "http://127.0.0.1:9191", "[::1]:0"] {
        s.command()
            .args([
                "profile",
                "add",
                "gents",
                "--alias",
                "invalid",
                "--address",
                address,
                "--agent",
                "worker",
            ])
            .assert()
            .failure();
    }
    s.command()
        .args(["list", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"data\":[]"));
}

fn run_history(s: &Sandbox) -> Vec<Value> {
    let output = s
        .command()
        .args(["runs", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice::<Value>(&output).unwrap()["data"]
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn gents_new_explicit_and_resumed_sessions_match_argv_and_durable_history() {
    let s = Sandbox::new();
    let home = gents_profile(&s, "127.0.0.1:9191", "worker");
    runtime_state(&home, "127.0.0.1:9191");
    gents_run(&s)
        .arg("--resume")
        .arg("--json")
        .arg("--dry-run")
        .assert()
        .code(125)
        .stdout(predicate::str::contains("no_recorded_session"));
    let output = gents_run(&s)
        .args(["--dry-run", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let preview: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(preview["data"]["plan"]["session_selection"], "new");
    assert!(preview["data"]["plan"]["session"].as_str().is_some());
    assert_eq!(preview["data"]["plan"]["session_reserved"], false);
    assert!(run_history(&s).is_empty());
    assert!(!home.join("fixture-owned.txt").exists());

    let output = gents_run(&s).assert().success().get_output().clone();
    let first = run_history(&s).remove(0);
    let session = first["gentsSession"]["id"].as_str().unwrap();
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains(&format!("arg={}", hex(OsStr::new(session))))
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains(session));
    assert!(first["gentsSession"]["resumedFrom"].is_null());
    assert_eq!(first["gentsSession"]["binding"]["agent"], "worker");
    gents_run(&s)
        .args(["--resume", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Preview only; no session is reserved.",
        ));
    let resumed = gents_run(&s)
        .arg("--resume")
        .assert()
        .success()
        .stderr(predicate::str::contains("(resume)"))
        .get_output()
        .stdout
        .clone();
    let actual: Vec<_> = String::from_utf8(resumed)
        .unwrap()
        .lines()
        .filter_map(|line| line.strip_prefix("arg=").map(str::to_owned))
        .collect();
    let expected = [
        OsStr::new("chat"),
        OsStr::new("--home"),
        home.as_os_str(),
        OsStr::new("--graphql"),
        OsStr::new("http://127.0.0.1:9191/api/v0/graphql"),
        OsStr::new("--agent-id=worker"),
        OsStr::new("--session-id"),
        OsStr::new(session),
    ]
    .map(hex);
    assert_eq!(actual, expected);
    let second = run_history(&s).remove(0);
    assert_eq!(second["gentsSession"]["id"], session);
    assert_eq!(second["gentsSession"]["resumedFrom"], first["id"]);
    gents_run(&s).assert().success();
    let fresh = run_history(&s).remove(0);
    assert_ne!(fresh["gentsSession"]["id"], session);
    assert!(fresh["gentsSession"]["resumedFrom"].is_null());
    gents_run(&s)
        .args(["--session", session])
        .assert()
        .success();
    let explicit = run_history(&s).remove(0);
    assert_eq!(explicit["gentsSession"]["id"], session);
    assert!(explicit["gentsSession"]["resumedFrom"].is_null());
    s.command()
        .args(["runs"])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!("Gents session={session}")));
    s.command().args(["registry", "verify"]).assert().success();
}

#[test]
fn resume_rejects_rebinding_and_conflicts_but_native_forwarding_is_untouched() {
    let s = Sandbox::new();
    let home = gents_profile(&s, "127.0.0.1:9191", "worker");
    runtime_state(&home, "127.0.0.1:9191");
    gents_run(&s).assert().success();
    let history = run_history(&s);
    let session = history[0]["gentsSession"]["id"].as_str().unwrap();
    gents_run(&s)
        .args(["--resume", "--session", session])
        .assert()
        .code(2);
    s.command()
        .args([
            "profile",
            "bind",
            "relay",
            "--address",
            "127.0.0.1:9191",
            "--agent",
            "different_worker",
        ])
        .assert()
        .success();
    gents_run(&s)
        .args(["--resume", "--dry-run", "--json"])
        .assert()
        .code(125)
        .stdout(predicate::str::contains("session_binding_changed"));
    assert_eq!(run_history(&s), history);
    // Explicit UUID is a conscious create-or-continue choice under the new binding.
    gents_run(&s)
        .args(["--session", session])
        .assert()
        .success();
    assert_eq!(
        run_history(&s)[0]["gentsSession"]["binding"]["agent"],
        "different_worker"
    );
    s.add("claude", "native");
    s.run("native")
        .arg("--resume")
        .assert()
        .code(125)
        .stderr(predicate::str::contains("only for the gents engine"));
    s.run("native")
        .args(["--", "--resume"])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "arg={}",
            hex(OsStr::new("--resume"))
        )));
    assert!(run_history(&s)[0]["gentsSession"].is_null());
}

#[test]
fn config_read_commands_leave_missing_state_untouched_and_report_defaults() {
    let s = Sandbox::new();
    for args in [
        vec!["config"],
        vec!["config", "list"],
        vec!["config", "get", "history.limit"],
        vec!["config", "path"],
    ] {
        s.command().args(args).arg("--json").assert().success();
        assert!(!s.state().exists());
    }
    s.command()
        .args(["config", "get", "ui.mask", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"value\":false"))
        .stdout(predicate::str::contains("\"source\":\"default\""));
    for args in [
        vec!["config", "set", "auth.token", "private-canary"],
        vec!["config", "set", "history.limit", "private-canary"],
        vec!["config", "set", "ui.mask", "private-canary"],
    ] {
        s.command()
            .args(args)
            .arg("--json")
            .assert()
            .code(125)
            .stdout(predicate::str::contains("private-canary").not())
            .stderr(predicate::str::contains("private-canary").not());
        assert!(!s.state().exists());
    }
}

#[test]
fn config_writes_are_independent_of_registry_and_unset_restores_defaults() {
    let s = Sandbox::new();
    s.command()
        .args(["config", "set", "history.limit", "5", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"source\":\"config\""));
    s.command()
        .args(["config", "set", "ui.mask", "true"])
        .assert()
        .success();
    assert!(!s.state().join("registry.sqlite3").exists());
    assert!(s.state().join("config.json").is_file());
    s.command()
        .args(["config", "get", "history.limit", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"value\":5"));
    s.command()
        .args(["config", "unset", "history.limit", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"value\":20"))
        .stdout(predicate::str::contains("\"source\":\"default\""));
    s.command()
        .args(["config", "get", "ui.mask", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"value\":true"));
    // Path inspection remains usable when the preferences need manual repair.
    let malformed = b"private-canary";
    std::fs::write(s.state().join("config.json"), malformed).unwrap();
    s.command().args(["config", "path"]).assert().success();
    s.command()
        .args(["config", "set", "ui.mask", "false", "--json"])
        .assert()
        .code(125)
        .stdout(predicate::str::contains("invalid_config"))
        .stdout(predicate::str::contains("private-canary").not());
    assert_eq!(
        std::fs::read(s.state().join("config.json")).unwrap(),
        malformed
    );
}

#[test]
fn config_history_preference_is_applied_with_explicit_limit_precedence() {
    let s = Sandbox::new();
    s.add("claude", "work");
    for _ in 0..3 {
        s.run("work").assert().success();
    }
    assert_eq!(run_history(&s).len(), 3);
    s.command()
        .args(["config", "set", "history.limit", "2"])
        .assert()
        .success();
    assert_eq!(run_history(&s).len(), 2);
    let explicit_default = s
        .command()
        .args(["runs", "--limit", "20", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        serde_json::from_slice::<Value>(&explicit_default).unwrap()["data"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let run_id = run_history(&s)[0]["id"].as_str().unwrap().to_owned();
    let out = s
        .command()
        .args(["runs", "--limit", "1", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        serde_json::from_slice::<Value>(&out).unwrap()["data"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    std::fs::write(s.state().join("config.json"), b"invalid").unwrap();
    s.command()
        .args(["runs", "--json"])
        .assert()
        .code(125)
        .stdout(predicate::str::contains("invalid_config"));
    s.command()
        .args(["runs", "--limit", "1"])
        .assert()
        .success();
    s.command().args(["runs", &run_id]).assert().success();
    s.command()
        .args(["doctor", "--json"])
        .assert()
        .code(125)
        .stdout(predicate::str::contains("invalid_config"))
        .stdout(predicate::str::contains("\"storage\":\"ok\""));
    s.run("work").arg("--dry-run").assert().success();
    s.command().args(["registry", "verify"]).assert().success();
    s.command()
        .args(["tui", "--mask", "--show-aliases"])
        .assert()
        .code(2);
}

#[cfg(unix)]
#[test]
fn config_non_utf8_and_hyphen_values_are_rejected_without_echoing_them() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    let s = Sandbox::new();
    for value in [
        OsString::from_vec(b"private-canary-\xff".to_vec()),
        OsString::from("--private-canary"),
    ] {
        s.command()
            .args(["--json", "config", "set", "ui.mask"])
            .arg(value)
            .assert()
            .code(125)
            .stdout(predicate::str::contains("private-canary").not())
            .stderr(predicate::str::contains("private-canary").not());
    }
    assert!(!s.state().exists());
}

#[test]
fn config_setters_in_separate_processes_preserve_both_preferences() {
    let s = Sandbox::new();
    let mut first = s
        .native_command()
        .args(["config", "set", "history.limit", "31"])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let mut second = s
        .native_command()
        .args(["config", "set", "ui.mask", "true"])
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    assert!(first.wait().unwrap().success());
    assert!(second.wait().unwrap().success());
    s.command()
        .args(["config", "get", "history.limit", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"value\":31"));
    s.command()
        .args(["config", "get", "ui.mask", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"value\":true"));
}
