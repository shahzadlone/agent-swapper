//! Standalone native test fixture, compiled into a temporary directory by tests.
use std::{ffi::OsStr, path::PathBuf, time::{Duration, Instant}};

fn hex(value: &OsStr) -> String {
    value.as_encoded_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    println!("argv0={}", hex(&std::env::args_os().next().unwrap()));
    let args: Vec<_> = std::env::args_os().skip(1).collect();
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
    if args.first().is_some_and(|arg| arg == "--exit") { std::process::exit(42); }
}
