use super::*;

#[test]
fn gents_and_unknown_containment_backends_are_refused_without_launch() {
    let s = Sandbox::new();
    gents_profile(&s, "127.0.0.1:9191", "agent");
    s.command()
        .args([
            "run",
            "relay",
            "--experimental-containment",
            "windows-job",
            "--executable",
        ])
        .arg(fixture())
        .arg("--dry-run")
        .assert()
        .code(125)
        .stderr(predicate::str::contains("externally owned"));
    s.add("codex", "native");
    s.run("native")
        .args(["--experimental-containment", "imaginary"])
        .assert()
        .code(2);
    s.command()
        .args(["runs", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"data\":[]"));
}

#[cfg(not(windows))]
#[test]
fn windows_containment_refuses_other_platforms_without_fallback() {
    let s = Sandbox::new();
    s.add("claude", "work");
    for preview in [false, true] {
        let mut command = s.run("work");
        command.args(["--experimental-containment", "windows-job"]);
        if preview {
            command.arg("--dry-run");
        }
        command
            .assert()
            .code(125)
            .stderr(predicate::str::contains("requires Windows"));
    }
    s.command()
        .args(["runs", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"data\":[]"));
}

#[cfg(windows)]
fn history(s: &Sandbox) -> Value {
    let result = s
        .command()
        .args(["runs", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    serde_json::from_slice(&result).unwrap()
}

#[cfg(windows)]
fn assert_leaf_stopped(dir: &Path) {
    let file = std::fs::File::options()
        .read(true)
        .write(true)
        .open(dir.join("leaf-lock"))
        .unwrap();
    let start = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) => {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "descendant survived cleanup"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("lock observer failed: {error}"),
        }
    }
    assert!(!dir.join("leaf-voluntary-exit").exists());
}

#[cfg(windows)]
#[test]
fn windows_job_preview_and_root_exit_preserve_status_and_record_empty_scope() {
    let s = Sandbox::new();
    s.add("codex", "work");
    let preview = s
        .run("work")
        .args([
            "--experimental-containment",
            "windows-job",
            "--dry-run",
            "--json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let preview: Value = serde_json::from_slice(&preview).unwrap();
    assert_eq!(preview["data"]["plan"]["containment"], "windows_job");
    assert!(history(&s)["data"].as_array().unwrap().is_empty());
    s.run("work")
        .args([
            "--experimental-containment",
            "windows-job",
            "--",
            "--job-orphan",
        ])
        .arg(s.temp.path())
        .timeout(Duration::from_secs(20))
        .assert()
        .code(42)
        .stderr(predicate::str::contains("descendants will be terminated"));
    assert_leaf_stopped(s.temp.path());
    let runs = history(&s);
    let run = &runs["data"][0];
    assert_eq!(run["exitCode"], 42);
    assert_eq!(run["custody"], "local_scope_empty");
    assert_eq!(run["outcome"], "local_scope_empty");
    assert_eq!(run["localScope"]["backend"], "windows_job");
    assert!(run["localScope"]["id"].as_str().is_some());
    assert!(run["observedPid"].as_u64().is_some());
    s.run("work")
        .args(["--experimental-containment", "windows-job"])
        .assert()
        .success();
    s.command().args(["registry", "verify"]).assert().success();
}

#[cfg(windows)]
#[test]
fn windows_supervisor_crash_kills_owned_tree_but_keeps_durable_run_unresolved() {
    let s = Sandbox::new();
    s.add("claude", "work");
    let mut command = s.native_command();
    command
        .args([
            "run",
            "work",
            "--experimental-native",
            "--experimental-containment",
            "windows-job",
            "--executable",
        ])
        .arg(fixture())
        .args(["--", "--job-wait"])
        .arg(s.temp.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    struct Guard(std::process::Child);
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = self.0.kill();
        }
    }
    let mut child = Guard(command.spawn().unwrap());
    let start = Instant::now();
    while !s.temp.path().join("root-ready").exists() {
        assert!(child.0.try_wait().unwrap().is_none());
        assert!(start.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(10));
    }
    let before = history(&s);
    let run = &before["data"][0];
    assert_eq!(run["custody"], "unknown");
    let root: u64 = std::fs::read_to_string(s.temp.path().join("root-ready"))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(run["observedPid"], root);
    assert_eq!(run["localScope"]["backend"], "windows_job");
    child.0.kill().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.0.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_leaf_stopped(s.temp.path());
    assert_eq!(history(&s)["data"][0]["custody"], "unknown");
    s.run("work")
        .args(["--experimental-containment", "windows-job"])
        .assert()
        .code(125);
    let id = run["id"].as_str().unwrap();
    s.command()
        .args(["recover", id, "--confirm-stopped"])
        .assert()
        .success();
    assert_eq!(history(&s)["data"][0]["custody"], "attested_stopped");
}
