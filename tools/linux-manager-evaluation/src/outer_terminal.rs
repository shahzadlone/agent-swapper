//! Owned-fixture policy around the shared terminal guard.
use agentswapper_linux_runtime::signals::Signals;
pub(crate) use agentswapper_linux_runtime::terminal::Terminal;
use std::{
    fs, io,
    os::{fd::AsFd, unix::fs::MetadataExt},
    path::Path,
};
pub(crate) fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
pub(crate) fn capture<'a>(directory: &Path, signals: &'a Signals) -> io::Result<Terminal<'a>> {
    capture_for_group(directory, signals, rustix::process::getpid())
}
pub(crate) fn capture_for_group<'a>(
    directory: &Path,
    signals: &'a Signals,
    owner: rustix::process::Pid,
) -> io::Result<Terminal<'a>> {
    require(
        std::env::var("ASWP_OWNED_OUTER_PTY").as_deref() == Ok("1"),
        "requires owned outer-PTY fixture",
    )?;
    let meta = fs::symlink_metadata(directory)?;
    require(
        directory.is_absolute()
            && meta.is_dir()
            && meta.uid() == rustix::process::getuid().as_raw()
            && meta.mode() & 0o077 == 0,
        "outer fixture directory is not private",
    )?;
    let expected: [u64; 3] = serde_json::from_slice(&fs::read(directory.join("terminal.json"))?)
        .map_err(io::Error::other)?;
    for stream in [
        io::stdin().as_fd(),
        io::stdout().as_fd(),
        io::stderr().as_fd(),
    ] {
        let stat = rustix::fs::fstat(stream)?;
        require(
            [stat.st_dev, stat.st_ino, stat.st_rdev] == expected,
            "outer probe requires matching terminal streams",
        )?;
    }
    Terminal::capture(signals, owner)
}
