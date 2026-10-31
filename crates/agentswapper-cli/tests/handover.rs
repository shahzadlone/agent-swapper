#![allow(clippy::unwrap_used)]

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use assert_cmd::{Command as AssertCommand, cargo::cargo_bin};
use predicates::prelude::*;
use serde_json::Value;

const PASSPHRASE: &str = "synthetic-unique-test-passphrase";

struct Sandbox {
    temp: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("home")).unwrap();
        fs::create_dir(temp.path().join("project")).unwrap();
        let this = Self { temp };
        this.cmd()
            .args(["profile", "add", "claude", "--alias", "work"])
            .assert()
            .success();
        this
    }
    fn project(&self) -> PathBuf {
        self.temp.path().join("project")
    }
    fn state(&self) -> PathBuf {
        self.temp.path().join("state")
    }
    fn native(&self) -> Command {
        self.native_with_state(&self.state())
    }
    fn native_with_state(&self, state: &Path) -> Command {
        let mut cmd = Command::new(cargo_bin!("aswp"));
        cmd.env_clear()
            .env("HOME", self.temp.path().join("home"))
            .env("USERPROFILE", self.temp.path().join("home"));
        for name in ["PATH", "SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"] {
            if let Some(value) = std::env::var_os(name) {
                cmd.env(name, value);
            }
        }
        cmd.current_dir(self.project())
            .arg("--state-dir")
            .arg(state);
        cmd
    }
    fn cmd(&self) -> AssertCommand {
        AssertCommand::from_std(self.native())
    }
    fn git(&self, args: &[&str]) {
        let hooks = self.temp.path().join("empty-hooks");
        fs::create_dir_all(&hooks).unwrap();
        let mut command = Command::new("git");
        for (key, _) in std::env::vars_os() {
            if key.to_str().is_some_and(|name| name.starts_with("GIT_")) {
                command.env_remove(key);
            }
        }
        let status = command
            .arg("-C")
            .arg(self.project())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env(
                "GIT_CONFIG_GLOBAL",
                self.temp.path().join("missing-global-config"),
            )
            .env("HOME", self.temp.path().join("home"))
            .args([
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
            ])
            .arg(format!("core.hooksPath={}", hooks.display()))
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    }
    fn pack(&self, note: &Path, output: &Path) -> std::process::Output {
        self.cmd()
            .args(["handover", "pack", "--from", "work", "--input"])
            .arg(note)
            .arg("--output")
            .arg(output)
            .args(["--passphrase-stdin", "--json"])
            .write_stdin(format!("{PASSPHRASE}\n"))
            .output()
            .unwrap()
    }
}

#[test]
fn handover_roundtrip_reports_drift_and_never_executes_imported_commands() {
    let s = Sandbox::new();
    s.git(&["init", "--quiet"]);
    s.git(&[
        "commit",
        "--quiet",
        "--allow-empty",
        "-m",
        "fixture initial",
    ]);
    let note = s.project().join("HANDOVER.md");
    let text = "# HANDOVER - fixture\n\n## 2. THE GOAL AND THE GOVERNING INSTRUCTIONS\nPreserve the user's exact task.\n\n## 3. HARD CONSTRAINTS\nNever touch production.\n\n## 4. CURRENT STATE\nCLAIMED: context-canary-27491\n\n## 7. NEXT STEPS\n```sh\ntouch DONT_EXECUTE\n```\n\n## 12. OPEN DECISIONS\nVerify assumptions before continuing.\n";
    fs::write(&note, text).unwrap();
    let encrypted = s.temp.path().join("task.age");
    let result = s.pack(&note, &encrypted);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let metadata: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(metadata["data"]["pack"]["trust"], "imported_unverified");
    assert_eq!(
        metadata["data"]["pack"]["workspace"]["head"]
            .as_str()
            .unwrap()
            .len(),
        40
    );
    assert!(!String::from_utf8_lossy(&result.stdout).contains("context-canary"));
    let bytes = fs::read(&encrypted).unwrap();
    assert!(bytes.starts_with(b"age-encryption.org/v1\n"));
    assert!(
        !bytes
            .windows(20)
            .any(|part| part == b"context-canary-27491")
    );
    for entry in fs::read_dir(s.state()).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let data = fs::read(path).unwrap();
            assert!(
                !data
                    .windows(PASSPHRASE.len())
                    .any(|part| part == PASSPHRASE.as_bytes())
            );
            assert!(!data.windows(20).any(|part| part == b"context-canary-27491"));
        }
    }
    let receiver = s.temp.path().join("receiver-must-not-be-created");
    let inspected = AssertCommand::from_std(s.native_with_state(&receiver))
        .args(["handover", "inspect"])
        .arg(&encrypted)
        .args(["--passphrase-stdin", "--json"])
        .write_stdin(PASSPHRASE)
        .output()
        .unwrap();
    assert!(inspected.status.success());
    assert!(!receiver.exists());
    assert!(!String::from_utf8_lossy(&inspected.stdout).contains("context-canary"));
    let picked = s
        .cmd()
        .args(["handover", "pickup"])
        .arg(&encrypted)
        .args(["--target", "codex", "--passphrase-stdin", "--json"])
        .write_stdin(PASSPHRASE)
        .output()
        .unwrap();
    assert!(picked.status.success());
    let value: Value = serde_json::from_slice(&picked.stdout).unwrap();
    assert_eq!(value["data"]["report"]["head"], "unchanged");
    assert_eq!(value["data"]["report"]["worktree"], "not_checked");
    let rendered = value["data"]["handover"].as_str().unwrap();
    for section in [
        "THE GOAL",
        "HARD CONSTRAINTS",
        "CURRENT STATE",
        "NEXT STEPS",
        "OPEN DECISIONS",
        "context-canary-27491",
    ] {
        assert!(rendered.contains(section));
    }
    assert!(rendered.contains("````markdown"));
    assert!(!s.project().join("DONT_EXECUTE").exists());
    let pickup = s.temp.path().join("HANDOVER_PICKUP.md");
    let exported = AssertCommand::from_std(s.native_with_state(&receiver))
        .args(["handover", "pickup"])
        .arg(&encrypted)
        .arg("--output")
        .arg(&pickup)
        .args(["--target", "codex", "--passphrase-stdin", "--json"])
        .write_stdin(PASSPHRASE)
        .output()
        .unwrap();
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    assert!(
        !receiver.exists(),
        "pickup export must not initialize receiver state"
    );
    assert!(!String::from_utf8_lossy(&exported.stdout).contains("context-canary"));
    assert!(!String::from_utf8_lossy(&exported.stderr).contains("context-canary"));
    let exported: Value = serde_json::from_slice(&exported.stdout).unwrap();
    assert_eq!(exported["data"]["plaintext"], true);
    assert!(exported["data"]["handover"].is_null());
    assert_eq!(fs::read_to_string(&pickup).unwrap(), rendered);
    s.cmd()
        .args(["handover", "pickup"])
        .arg(&encrypted)
        .arg("--output")
        .arg(&pickup)
        .args(["--target", "codex"])
        .assert()
        .code(125)
        .stderr(predicate::str::contains("output already exists"));
    assert_eq!(fs::read_to_string(&pickup).unwrap(), rendered);
    s.git(&[
        "commit",
        "--quiet",
        "--allow-empty",
        "-m",
        "fixture changed",
    ]);
    let changed = s
        .cmd()
        .args(["handover", "pickup"])
        .arg(&encrypted)
        .args(["--target", "kimi", "--passphrase-stdin", "--json"])
        .write_stdin(PASSPHRASE)
        .output()
        .unwrap();
    let changed: Value = serde_json::from_slice(&changed.stdout).unwrap();
    assert_eq!(changed["data"]["report"]["head"], "changed");
    s.cmd()
        .args(["handover", "inspect"])
        .arg(&encrypted)
        .args(["--passphrase-stdin", "--json"])
        .write_stdin("wrong-test-passphrase")
        .assert()
        .code(125)
        .stdout(
            predicate::str::contains("handover_decryption_failed")
                .and(predicate::str::contains("context-canary").not()),
        );
    let mut corrupt = bytes;
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    let bad = s.temp.path().join("tampered.age");
    fs::write(&bad, corrupt).unwrap();
    let refused = s.temp.path().join("PICKUP_TAMPERED.md");
    s.cmd()
        .args(["handover", "pickup"])
        .arg(&bad)
        .arg("--output")
        .arg(&refused)
        .args(["--target", "codex", "--passphrase-stdin", "--json"])
        .write_stdin(PASSPHRASE)
        .assert()
        .code(125)
        .stdout(predicate::str::contains("handover_decryption_failed"));
    assert!(!refused.exists());
    s.cmd()
        .args(["handover", "inspect"])
        .arg(&bad)
        .args(["--passphrase-stdin", "--json"])
        .write_stdin(PASSPHRASE)
        .assert()
        .code(125)
        .stdout(predicate::str::contains("context-canary").not());
    s.cmd()
        .args(["handover", "pack", "--from", "work", "--input"])
        .arg(&note)
        .arg("--output")
        .arg(&encrypted)
        .assert()
        .code(125)
        .stderr(predicate::str::contains("output already exists"));
    // A truncated context stream or export acknowledgement is an error. A
    // file already published before the acknowledgement fails is retained.
    for output in [None, Some(s.temp.path().join("PICKUP_BROKEN_PIPE.md"))] {
        let mut native = s.native();
        native
            .args(["handover", "pickup"])
            .arg(&encrypted)
            .args(["--target", "codex", "--passphrase-stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(path) = &output {
            native.arg("--output").arg(path);
        }
        let mut child = native.spawn().unwrap();
        drop(child.stdout.take());
        child
            .stdin
            .take()
            .unwrap()
            .write_all(PASSPHRASE.as_bytes())
            .unwrap();
        assert_eq!(child.wait().unwrap().code(), Some(125));
        if let Some(path) = output {
            assert!(
                fs::read_to_string(path)
                    .unwrap()
                    .contains("context-canary-27491")
            );
        }
    }
}

#[test]
fn handover_refuses_credential_locations_and_linked_source_notes_before_prompting() {
    let s = Sandbox::new();
    let profile = s
        .cmd()
        .args(["profile", "show", "work", "--json"])
        .output()
        .unwrap();
    let profile: Value = serde_json::from_slice(&profile.stdout).unwrap();
    let home = s
        .state()
        .join("profiles")
        .join(profile["data"]["profile"]["id"].as_str().unwrap());
    let secret = home.join("HANDOVER.md");
    fs::write(&secret, "credential-location-canary").unwrap();
    let output = s.temp.path().join("refused.age");
    s.cmd()
        .args(["handover", "pack", "--from", "work", "--input"])
        .arg(&secret)
        .arg("--output")
        .arg(&output)
        .assert()
        .code(125)
        .stderr(predicate::str::contains("outside authentication"));
    let linked = s.project().join("linked.md");
    fs::hard_link(&secret, &linked).unwrap();
    s.cmd()
        .args(["handover", "pack", "--from", "work", "--input"])
        .arg(&linked)
        .arg("--output")
        .arg(&output)
        .assert()
        .code(125)
        .stderr(predicate::str::contains("outside authentication"));
    assert!(!output.exists());
    assert_eq!(
        fs::read_to_string(&secret).unwrap(),
        "credential-location-canary"
    );
}

#[test]
fn handover_requires_explicit_password_input_and_rejects_multiline_passwords() {
    let s = Sandbox::new();
    let note = s.project().join("HANDOVER.md");
    fs::write(&note, "Task notes").unwrap();
    let output = s.temp.path().join("task.age");
    s.cmd()
        .args(["handover", "pack", "--from", "work", "--input"])
        .arg(&note)
        .arg("--output")
        .arg(&output)
        .assert()
        .code(125)
        .stderr(predicate::str::contains("--passphrase-stdin"));
    s.cmd()
        .args(["handover", "pack", "--from", "work", "--input"])
        .arg(&note)
        .arg("--output")
        .arg(&output)
        .arg("--passphrase-stdin")
        .write_stdin(format!("{PASSPHRASE}\nextra-data\n"))
        .assert()
        .code(125)
        .stderr(predicate::str::contains(PASSPHRASE).not());
    assert!(!output.exists());
}

#[test]
fn pickup_refuses_unsafe_plaintext_destinations_before_reading_password_or_pack() {
    let s = Sandbox::new();
    let missing = s.temp.path().join("missing.age");
    let native = s.temp.path().join("home").join(".claude");
    fs::create_dir(&native).unwrap();
    for output in [
        s.project().join("AGENTS.md"),
        s.project().join("CLAUDE.md"),
        s.project().join("pickup.json"),
        s.state().join("HANDOVER.md"),
        native.join("HANDOVER.md"),
    ] {
        s.cmd()
            .args(["handover", "pickup"])
            .arg(&missing)
            .arg("--output")
            .arg(&output)
            .args(["--target", "codex", "--json"])
            .assert()
            .code(125)
            .stdout(predicate::str::contains("unsafe_handover_output"));
        assert!(!output.exists());
    }
    let overridden = s.temp.path().join("overridden-profile");
    let credentials = overridden.join(".codex");
    fs::create_dir_all(&credentials).unwrap();
    let output = credentials.join("HANDOVER.md");
    s.cmd()
        .env("USERPROFILE", &overridden)
        .args(["handover", "pickup"])
        .arg(&missing)
        .arg("--output")
        .arg(&output)
        .args(["--target", "codex", "--json"])
        .assert()
        .code(125)
        .stdout(predicate::str::contains("unsafe_handover_output"));
    let source = credentials.join("HANDOVER_SOURCE.md");
    fs::write(&source, "credential-directory-canary").unwrap();
    s.cmd()
        .env("USERPROFILE", &overridden)
        .args(["handover", "pack", "--from", "work", "--input"])
        .arg(&source)
        .arg("--output")
        .arg(s.temp.path().join("must-not-exist.age"))
        .assert()
        .code(125)
        .stderr(predicate::str::contains("outside authentication"));
}

#[cfg(windows)]
#[test]
fn pickup_reports_invalid_windows_filenames_before_reading_password_or_pack() {
    let s = Sandbox::new();
    let missing = s.temp.path().join("missing.age");
    for name in ["HANDOVER.md:stream.md", "HANDOVER.md ", "NUL.age"] {
        let output = s.project().join(name);
        s.cmd()
            .args(["handover", "pickup"])
            .arg(&missing)
            .arg("--output")
            .arg(&output)
            .args(["--target", "codex", "--json"])
            .assert()
            .code(125)
            .stdout(predicate::str::contains("handover_output_path"));
    }
}
