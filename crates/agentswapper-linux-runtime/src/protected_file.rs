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
    // NONBLOCK prevents a substituted FIFO from blocking before fstat.
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
