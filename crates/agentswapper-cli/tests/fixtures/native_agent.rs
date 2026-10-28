//! Standalone native test fixture, compiled into a temporary directory by tests.
use std::{ffi::OsStr, path::PathBuf, time::{Duration, Instant}};

fn hex(value: &OsStr) -> String {
    value.as_encoded_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    println!("argv0={}", hex(&std::env::args_os().next().unwrap()));
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    #[cfg(windows)]
    if args.first().is_some_and(|arg| arg == "--job-leaf") {
        let dir = PathBuf::from(&args[1]);
        let lock = std::fs::File::options().read(true).write(true).create_new(true).open(dir.join("leaf-lock")).unwrap();
        lock.try_lock().unwrap();
        std::fs::write(dir.join("leaf-ready"), "ready").unwrap();
        std::thread::sleep(Duration::from_secs(45));
        std::fs::write(dir.join("leaf-voluntary-exit"), "expired").unwrap();
        return;
    }
    #[cfg(windows)]
    if args.first().is_some_and(|arg| arg == "--job-orphan" || arg == "--job-wait") {
        let dir = PathBuf::from(&args[1]);
        let _leaf = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--job-leaf").arg(&dir).stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
        let started = Instant::now();
        while !dir.join("leaf-ready").exists() {
            assert!(started.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(10));
        }
        std::fs::write(dir.join("root-ready"), std::process::id().to_string()).unwrap();
        if args[0] == "--job-wait" { std::thread::sleep(Duration::from_secs(45)); }
        std::process::exit(42);
    }
    if args.first().is_some_and(|arg| arg == "--wait") {
        let ready = PathBuf::from(&args[1]);
        let stop = PathBuf::from(&args[2]);
        std::fs::write(ready, std::process::id().to_string()).unwrap();
        let started = Instant::now();
        while !stop.exists() && started.elapsed() < Duration::from_secs(15) {
            std::thread::sleep(Duration::from_millis(10));
        }
        return;
    }
    for arg in &args { println!("arg={}", hex(arg)); }
    println!("cwd={}", hex(std::env::current_dir().unwrap().as_os_str()));
    for key in ["CLAUDE_CONFIG_DIR", "CODEX_HOME", "KIMI_CODE_HOME"] {
        if let Some(value) = std::env::var_os(key) {
            println!("{key}={}", hex(&value));
            std::fs::write(PathBuf::from(value).join("fixture-owned.txt"), "fixture").unwrap();
        }
    }
    if args.first().is_some_and(|arg| arg == "chat") {
        let home = args.windows(2).find(|pair| pair[0] == "--home").unwrap();
        std::fs::write(PathBuf::from(&home[1]).join("fixture-owned.txt"), "gents fixture").unwrap();
        for key in ["GENTS_HOME", "GENTS_GRAPHQL", "GENTS_FUTURE_OVERRIDE", "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "ALL_PROXY", "UNRELATED_SECRET", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"] {
            if std::env::var_os(key).is_some() { println!("leaked={key}"); }
        }
        println!("terminal={}", std::env::var("TERM").unwrap_or_default());
    }
    if args.first().is_some_and(|arg| arg == "--exit") { std::process::exit(42); }
}
