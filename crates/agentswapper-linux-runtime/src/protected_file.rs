//! Root-owned, non-writable ancestry shared by installed assets.
//! The caller must establish a trusted namespace and fixed installation path.
use rustix::fs::{FileType, Mode, OFlags, fstat, open as fs_open, openat};
use std::{
    io,
    os::fd::{AsFd, OwnedFd},
    path::{Component, Path},
};
const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);
const FILE: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NOCTTY)
    .union(OFlags::NONBLOCK);
fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
fn protected_directory(fd: impl AsFd) -> io::Result<()> {
    let stat = fstat(fd)?;
    require(
        FileType::from_raw_mode(stat.st_mode) == FileType::Directory
            && stat.st_uid == 0
            && stat.st_mode & 0o022 == 0,
        "installed file ancestor is not root-owned and protected",
    )
}
pub(crate) fn open(path: &Path) -> io::Result<OwnedFd> {
    require(
        path.is_absolute() && path.as_os_str().len() <= 4096,
        "installed file path must be bounded and absolute",
    )?;
    let mut components = path.components();
    require(
        components.next() == Some(Component::RootDir),
        "installed file path lacks a root",
    )?;
    let components = components.collect::<Vec<_>>();
    require(
        !components.is_empty()
            && components
                .iter()
                .all(|part| matches!(part, Component::Normal(_))),
        "installed file path must contain only normal components",
    )?;
    let (leaf, parents) = components
        .split_last()
        .ok_or_else(|| io::Error::other("installed file path lacks a filename"))?;
    let mut directory = fs_open("/", DIRECTORY, Mode::empty())?;
    protected_directory(&directory)?;
    for part in parents {
        directory = openat(&directory, part.as_os_str(), DIRECTORY, Mode::empty())?;
        protected_directory(&directory)?;
    }
    // Resolve each component from an already validated directory handle.
    // NONBLOCK prevents a FIFO from blocking before fstat. NOCTTY prevents
    // opening a terminal device from acquiring process-wide terminal ownership.
    let file = openat(&directory, leaf.as_os_str(), FILE, Mode::empty())?;
    let stat = fstat(&file)?;
    require(
        FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
            && stat.st_uid == 0
            && stat.st_mode & 0o022 == 0,
        "installed file is not a root-owned protected regular file",
    )?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read,
        os::unix::ffi::OsStrExt,
        process::{Command, Stdio},
        time::Duration,
    };
    use wait_timeout::ChildExt;

    fn no_controlling_terminal() -> io::Result<()> {
        let stat = std::fs::read_to_string("/proc/self/stat")?;
        let tty = stat
            .rsplit_once(") ")
            .and_then(|(_, rest)| rest.split_whitespace().nth(4));
        require(
            tty == Some("0"),
            "installed-file refusal acquired a controlling terminal",
        )
    }

    #[test]
    #[ignore = "fresh session role invoked by refuses_device_without_acquiring_terminal"]
    fn terminal_refusal_process() -> io::Result<()> {
        require(
            std::env::var("ASWP_TEST_INSTALLED_FILE_SESSION").as_deref() == Ok("1"),
            "missing isolated test role",
        )?;
        rustix::process::setsid()?;
        no_controlling_terminal()?;
        let master = rustix::pty::openpt(
            rustix::pty::OpenptFlags::RDWR
                | rustix::pty::OpenptFlags::NOCTTY
                | rustix::pty::OpenptFlags::CLOEXEC,
        )?;
        rustix::pty::grantpt(&master)?;
        rustix::pty::unlockpt(&master)?;
        let name = rustix::pty::ptsname(&master, Vec::new())?;
        let path = Path::new(std::ffi::OsStr::from_bytes(name.as_bytes()));
        let error = crate::installed_config::ProtectedConfig::open(path)
            .err()
            .ok_or_else(|| io::Error::other("terminal was accepted as installed data"))?;
        require(
            error.to_string() == "installed file is not a root-owned protected regular file",
            "terminal test did not reach the leaf type refusal",
        )?;
        // Keep the master alive while checking: closing it would obscure the
        // unwanted acquisition by hanging up the newly acquired terminal.
        no_controlling_terminal()
    }

    #[test]
    fn refuses_device_without_acquiring_terminal() -> io::Result<()> {
        let role = format!(
            "{}::terminal_refusal_process",
            module_path!()
                .split_once("::")
                .map_or(module_path!(), |(_, path)| path)
        );
        let mut child = Command::new(std::env::current_exe()?)
            .args(["--exact", &role, "--ignored"])
            .env_clear()
            .env("ASWP_TEST_INSTALLED_FILE_SESSION", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let status = child.wait_timeout(Duration::from_secs(5))?;
        if status.is_none() {
            child.kill()?;
            child.wait()?;
        }
        let mut report = String::new();
        child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("isolated role output absent"))?
            .take(8192)
            .read_to_string(&mut report)?;
        require(
            status.is_some_and(|status| status.success())
                && report.contains("test result: ok. 1 passed; 0 failed;"),
            "isolated terminal refusal failed",
        )
    }
}
