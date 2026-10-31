//! Kernel corroboration for one live, manager-owned fixture invocation.
//! These retained descriptors are observations, not authority to stop a unit.
use crate::require;
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{FileType, Mode, OFlags, openat},
    process::{Pid, PidfdFlags, pidfd_open},
};
use serde::Serialize;
use std::{
    fs::File,
    io::{self, Read},
    os::fd::OwnedFd,
};

const CGROUP2: rustix::fs::FsWord = 0x6367_7270;
const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);
const READ: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK);

fn read_at(parent: &OwnedFd, name: &str, limit: usize) -> io::Result<Vec<u8>> {
    let fd = openat(parent, name, READ, Mode::empty())?;
    require(
        FileType::from_raw_mode(rustix::fs::fstat(&fd)?.st_mode) == FileType::RegularFile,
        "kernel metadata is not a regular file",
    )?;
    let mut bytes = Vec::new();
    File::from(fd)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    require(bytes.len() <= limit, "kernel metadata exceeds bounds")?;
    Ok(bytes)
}

fn root_directory(fd: &OwnedFd) -> io::Result<()> {
    let stat = rustix::fs::fstat(fd)?;
    require(
        FileType::from_raw_mode(stat.st_mode) == FileType::Directory
            && stat.st_uid == 0
            && stat.st_mode & 0o022 == 0,
        "kernel path is mutable or not a root-owned directory",
    )
}

fn check_scope_controls(fd: &OwnedFd) -> io::Result<()> {
    root_directory(fd)?;
    require(
        rustix::fs::fstatfs(fd)?.f_type == CGROUP2,
        "scope is not on cgroup v2",
    )?;
    let control = openat(fd, "cgroup.procs", READ, Mode::empty())?;
    let stat = rustix::fs::fstat(&control)?;
    require(
        FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
            && stat.st_uid == 0
            && stat.st_mode & 0o022 == 0,
        "migration control is not root-owned and protected",
    )?;
    match openat(
        fd,
        "cgroup.procs",
        OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Err(rustix::io::Errno::ACCESS | rustix::io::Errno::PERM) => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(io::Error::other(
            "ordinary observer can open a migration control for writing",
        )),
    }
}

fn populated(bytes: &[u8]) -> io::Result<bool> {
    let text = std::str::from_utf8(bytes).map_err(io::Error::other)?;
    let mut value = None;
    let mut frozen = false;
    for line in text.lines() {
        match line {
            "populated 0" | "populated 1" if value.is_none() => value = Some(line == "populated 1"),
            "frozen 0" | "frozen 1" if !frozen => frozen = true,
            _ => return Err(io::Error::other("unknown or duplicate cgroup event")),
        }
    }
    value.ok_or_else(|| io::Error::other("missing cgroup population event"))
}

fn check_user(bytes: &[u8], user: u32) -> io::Result<()> {
    let text = std::str::from_utf8(bytes).map_err(io::Error::other)?;
    let rows = text
        .lines()
        .filter_map(|line| line.strip_prefix("Uid:"))
        .collect::<Vec<_>>();
    require(rows.len() == 1, "process identity is absent or ambiguous")?;
    let values = rows[0].split_whitespace().collect::<Vec<_>>();
    require(
        values.len() == 4 && values.iter().all(|v| *v == user.to_string()),
        "process user differs from managed invocation",
    )
}

struct Process {
    pidfd: OwnedFd,
    proc_dir: OwnedFd,
    user: u32,
    group: String,
}

impl Process {
    fn bind(pid: u32, user: u32, group: &str) -> io::Result<Self> {
        let pid = i32::try_from(pid)
            .ok()
            .and_then(Pid::from_raw)
            .ok_or_else(|| io::Error::other("invalid process identity"))?;
        // Open before /proc reads, and require it to remain live afterwards.
        // This prevents a PID reused during those reads from passing admission.
        let pidfd = pidfd_open(pid, PidfdFlags::empty())?;
        let proc_root = rustix::fs::open("/proc", DIRECTORY, Mode::empty())?;
        root_directory(&proc_root)?;
        require(
            rustix::fs::fstatfs(&proc_root)?.f_type == rustix::fs::PROC_SUPER_MAGIC,
            "process metadata is not procfs",
        )?;
        let proc_dir = openat(
            &proc_root,
            pid.as_raw_nonzero().get().to_string(),
            DIRECTORY,
            Mode::empty(),
        )?;
        require(
            rustix::fs::fstatfs(&proc_dir)?.f_type == rustix::fs::PROC_SUPER_MAGIC,
            "process directory is not procfs",
        )?;
        let result = Self {
            pidfd,
            proc_dir,
            user,
            group: group.into(),
        };
        result.check()?;
        Ok(result)
    }

    fn check(&self) -> io::Result<()> {
        require(
            read_at(&self.proc_dir, "cgroup", 4096)? == format!("0::{}\n", self.group).as_bytes(),
            "main process is outside the bound cgroup",
        )?;
        check_user(&read_at(&self.proc_dir, "status", 65536)?, self.user)?;
        self.live()
    }

    fn live(&self) -> io::Result<()> {
        require(
            !self.exited()?,
            "bound main process exited during observation",
        )
    }

    fn exited(&self) -> io::Result<bool> {
        let mut watched = [PollFd::new(&self.pidfd, PollFlags::IN)];
        let count = poll(
            &mut watched,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )?;
        let events = watched[0].revents();
        require(
            !events.intersects(PollFlags::ERR | PollFlags::NVAL),
            "pidfd polling failed",
        )?;
        if count == 0 && events.is_empty() {
            return Ok(false);
        }
        require(
            count == 1 && events.intersects(PollFlags::IN | PollFlags::HUP),
            "unexpected pidfd event",
        )?;
        Ok(true)
    }
}

#[derive(Serialize)]
pub(crate) struct Fact {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    populated: bool,
    main_pidfd_live: bool,
    migration_controls_refused: bool,
}

pub(crate) struct Binding {
    scope: OwnedFd,
    main: Process,
    device: u64,
    inode: u64,
}

#[derive(Serialize)]
pub(crate) struct Retirement {
    device: u64,
    inode: u64,
    original_directory_removed: bool,
    main_pidfd_exited: bool,
}

impl Binding {
    pub(crate) fn bind(unit: &str, user: u32, pid: u32) -> io::Result<Self> {
        // The caller has already restricted the unit to one safe fixture name.
        require(
            !unit.contains('/') && unit.starts_with("aswp-managed-") && unit.ends_with(".service"),
            "invalid scope leaf",
        )?;
        let mut dir = rustix::fs::open("/", DIRECTORY, Mode::empty())?;
        root_directory(&dir)?;
        for component in ["sys", "fs", "cgroup"] {
            dir = openat(&dir, component, DIRECTORY, Mode::empty())?;
            root_directory(&dir)?;
        }
        check_scope_controls(&dir)?;
        for component in ["system.slice", unit] {
            dir = openat(&dir, component, DIRECTORY, Mode::empty())?;
            check_scope_controls(&dir)?;
        }
        let stat = rustix::fs::fstat(&dir)?;
        let main = Process::bind(pid, user, &format!("/system.slice/{unit}"))?;
        let result = Self {
            scope: dir,
            main,
            device: stat.st_dev,
            inode: stat.st_ino,
        };
        result.observe()?;
        Ok(result)
    }

    pub(crate) fn observe(&self) -> io::Result<Fact> {
        self.main.check()?;
        require(
            populated(&read_at(&self.scope, "cgroup.events", 4096)?)?,
            "bound scope is not populated",
        )?;
        self.main.live()?;
        Ok(Fact {
            device: self.device,
            inode: self.inode,
            populated: true,
            main_pidfd_live: true,
            migration_controls_refused: true,
        })
    }

    pub(crate) fn directory(&self) -> &OwnedFd {
        &self.scope
    }

    pub(crate) fn retirement(&self) -> io::Result<Option<Retirement>> {
        match read_at(&self.scope, "cgroup.events", 4096) {
            Ok(bytes) => {
                populated(&bytes)?;
                Ok(None)
            }
            Err(error) if error.raw_os_error() == Some(rustix::io::Errno::NOENT.raw_os_error()) => {
                require(
                    self.main.exited()?,
                    "original scope removed while bound main process remains live",
                )?;
                Ok(Some(Retirement {
                    device: self.device,
                    inode: self.inode,
                    original_directory_removed: true,
                    main_pidfd_exited: true,
                }))
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_and_user_metadata_refuse_ambiguity() -> io::Result<()> {
        assert!(populated(b"populated 1\nfrozen 0\n")?);
        assert!(!populated(b"populated 0\nfrozen 1\n")?);
        for input in [
            b"frozen 0\n".as_slice(),
            b"populated 1\npopulated 0\n",
            b"populated 2\n",
            b"populated 1\nfrozen 0\nfrozen 1\n",
            b"populated 1\nextra 1\n",
        ] {
            assert!(populated(input).is_err());
        }
        check_user(b"Name:\tfixture\nUid:\t1000\t1000\t1000\t1000\n", 1000)?;
        for input in [
            b"Uid: 1000 0 1000 1000\n".as_slice(),
            b"Uid: 1000 1000 1000\n",
            b"Uid: 1000 1000 1000 1000\nUid: 1000 1000 1000 1000\n",
        ] {
            assert!(check_user(input, 1000).is_err());
        }
        Ok(())
    }

    #[test]
    fn live_process_binding_uses_kernel_membership_and_identity() -> io::Result<()> {
        let pid = std::process::id();
        let group = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
        let group = group
            .strip_prefix("0::")
            .and_then(|s| s.strip_suffix('\n'))
            .ok_or_else(|| io::Error::other("test requires unified cgroup v2"))?;
        let user = rustix::process::getuid().as_raw();
        Process::bind(pid, user, group)?.check()?;
        assert!(Process::bind(pid, user.wrapping_add(1), group).is_err());
        assert!(Process::bind(pid, user, "/aswp-nonexistent-fixture").is_err());
        Ok(())
    }

    #[test]
    fn exited_owned_process_never_remains_a_live_witness() -> io::Result<()> {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Child(
            std::process::Command::new("/bin/sleep")
                .arg("30")
                .env_clear()
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()?,
        );
        let group = std::fs::read_to_string(format!("/proc/{}/cgroup", child.0.id()))?;
        let group = group
            .strip_prefix("0::")
            .and_then(|s| s.strip_suffix('\n'))
            .ok_or_else(|| io::Error::other("test requires unified cgroup v2"))?;
        let process = Process::bind(child.0.id(), rustix::process::getuid().as_raw(), group)?;
        child.0.kill()?;
        child.0.wait()?;
        assert!(process.live().is_err());
        Ok(())
    }
}
