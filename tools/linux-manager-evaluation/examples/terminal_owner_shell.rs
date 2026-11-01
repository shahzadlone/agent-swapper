//! Owned-PTY shell bootstrap; makes parent-loss tests independent of orphan CONT.
#![forbid(unsafe_code)]
#[allow(
    dead_code,
    reason = "shell bootstrap uses only owned-terminal admission"
)]
#[path = "../src/outer_terminal.rs"]
mod outer_terminal;
use std::{fs, io, os::unix::process::CommandExt, path::Path, process::Command};

fn run(directory: &Path) -> io::Result<()> {
    let terminal = outer_terminal::Terminal::capture(directory)?;
    drop(terminal);
    nix::sys::prctl::set_child_subreaper(true)?;
    outer_terminal::require(
        nix::sys::prctl::get_child_subreaper()?,
        "subreaper setup failed",
    )?;
    fs::write(
        directory.join("subreaper-shell"),
        std::process::id().to_string(),
    )?;
    Err(Command::new("/bin/bash")
        .args(["--noprofile", "--norc", "-i"])
        .exec())
}
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    let result = match args.as_slice() {
        [_, directory] => run(Path::new(directory)),
        _ => Err(io::Error::other("requires owned shell fixture")),
    };
    if result.is_err() {
        std::process::exit(125);
    }
}
