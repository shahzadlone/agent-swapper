//! Retained Linux process and cgroup observations for a system-manager service.
//!
//! The caller must separately authenticate its manager, installed policy and
//! invocation before binding, and recheck them afterwards. A unit name or these
//! diagnostic facts alone never establish custody, exec, or journal completion.
//! This module does not install units, contact a manager, send signals or write
//! migration controls. It is not a restart-recovery or provider-isolation API.
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{FileType, Mode, OFlags, ResolveFlags, openat, openat2},
    process::{Pid, PidfdFlags, pidfd_open},
};
use std::{
    fs::File,
    io::{self, Read},
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
fn identity_map(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|s| s.split_whitespace().eq(["0", "0", "4294967295"]))
}
fn service_leaf(unit: &str) -> bool {
    unit.len() <= 255
        && unit
            .strip_suffix(".service")
            .is_some_and(|stem| !stem.is_empty())
        && unit
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:@\\-".contains(&byte))
}

const CGROUP2: rustix::fs::FsWord = 0x6367_7270;
const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);
const READ: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK);

fn same_mount(parent: &OwnedFd, name: &str, flags: OFlags) -> io::Result<OwnedFd> {
    openat2(
        parent,
        name,
        flags,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )
    .map_err(|error| {
        if error == rustix::io::Errno::XDEV {
            io::Error::other("kernel metadata crosses a mount boundary")
        } else {
            error.into()
        }
    })
}

fn read_at(parent: &OwnedFd, name: &str, limit: usize) -> io::Result<Vec<u8>> {
    let fd = same_mount(parent, name, READ)?;
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

fn proc_root() -> io::Result<OwnedFd> {
    let root = rustix::fs::open("/proc", DIRECTORY, Mode::empty())?;
    root_directory(&root)?;
    require(
        rustix::fs::fstatfs(&root)?.f_type == rustix::fs::PROC_SUPER_MAGIC,
        "process metadata is not procfs",
    )?;
    Ok(root)
}

fn own_process(root: &OwnedFd) -> io::Result<OwnedFd> {
    // /proc/self is a kernel-generated ordinary symlink. Resolve it within
    // this procfs mount; overlays and procfs magic links are refused. File
    // reads underneath the resulting directory also refuse mount crossings.
    let own = openat2(
        root,
        "self",
        DIRECTORY & !OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_XDEV,
    )?;
    let status = read_at(&own, "status", 65536)?;
    let status = std::str::from_utf8(&status).map_err(io::Error::other)?;
    let pids = status
        .lines()
        .filter_map(|line| line.strip_prefix("Pid:"))
        .map(str::trim)
        .collect::<Vec<_>>();
    require(
        pids == [std::process::id().to_string()],
        "procfs PID view disagrees with this process",
    )?;
    Ok(own)
}

pub fn initial_namespace() -> io::Result<()> {
    let root = proc_root()?;
    let own = own_process(&root)?;
    for name in ["uid_map", "gid_map"] {
        require(
            identity_map(&read_at(&own, name, 4096)?),
            "non-initial identity map refused",
        )?;
    }
    let init = same_mount(&root, "1", DIRECTORY)?;
    root_directory(&init)?;
    require(
        read_at(&init, "cgroup", 4096)? == b"0::/init.scope\n",
        "initial unified system-manager scope unavailable",
    )
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
    let control = same_mount(fd, "cgroup.procs", READ)?;
    let stat = rustix::fs::fstat(&control)?;
    require(
        FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
            && stat.st_uid == 0
            && stat.st_mode & 0o022 == 0,
        "migration control is not root-owned and protected",
    )?;
    match same_mount(
        fd,
        "cgroup.procs",
        OFlags::WRONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
    ) {
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Ok(()),
        Err(error) => Err(error),
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

fn retirement_events_absent(events: io::Result<Vec<u8>>) -> io::Result<bool> {
    match events {
        Ok(bytes) => {
            populated(&bytes)?;
            Ok(false)
        }
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::NODEV.raw_os_error()) => {
            // kernfs can deactivate the file between open and read. This is
            // unresolved, never removal evidence. The bounded watcher retries
            // via the same retained directory and must still observe absence.
            Ok(false)
        }
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::NOENT.raw_os_error()) => {
            Ok(true)
        }
        Err(error) => Err(error),
    }
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
        // Reuse before this open requires the caller's separate manager binding
        // and recheck, under its direct-child service lifecycle restrictions.
        let pidfd = pidfd_open(pid, PidfdFlags::empty())?;
        let proc_root = proc_root()?;
        let proc_dir = same_mount(
            &proc_root,
            &pid.as_raw_nonzero().get().to_string(),
            DIRECTORY,
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

// A retained child witness; this is not an exec or custody receipt.
pub struct Child {
    process: Process,
    parent: u32,
}

impl Child {
    pub fn check(&self) -> io::Result<()> {
        self.process.check()?;
        let status = read_at(&self.process.proc_dir, "status", 65536)?;
        let status = std::str::from_utf8(&status).map_err(io::Error::other)?;
        let parents = status
            .lines()
            .filter_map(|line| line.strip_prefix("PPid:"))
            .map(str::trim)
            .collect::<Vec<_>>();
        require(
            parents == [self.parent.to_string()],
            "writer is not the bound guardian's direct child",
        )?;
        self.process.live()
    }

    pub fn exited(&self) -> io::Result<bool> {
        self.process.exited()
    }
}

#[derive(Debug)]
pub struct Fact {
    // A directory can survive a failed invocation and be reused. These fields
    // identify that retained directory, never an invocation or a fresh start.
    pub device: u64,
    pub inode: u64,
    pub populated: bool,
    pub main_pidfd_live: bool,
    pub migration_controls_refused: bool,
}

pub struct Binding {
    scope: OwnedFd,
    main: Process,
    device: u64,
    inode: u64,
}

#[derive(Debug)]
// Kernel facts only; the caller must independently observe manager retirement.
pub struct Retirement {
    pub device: u64,
    pub inode: u64,
    pub original_directory_removed: bool,
    pub main_pidfd_exited: bool,
}

impl Binding {
    /// Borrow the original guardian pidfd. This is not a numeric-PID lookup or
    /// manager authorization; the caller remains responsible for its policy.
    pub fn guardian_pidfd(&self) -> BorrowedFd<'_> {
        self.main.pidfd.as_fd()
    }

    pub fn bind(unit: &str, user: u32, pid: u32) -> io::Result<Self> {
        initial_namespace()?;
        // Lexical safety is separate from installation/manager authorization.
        // Each caller must restrict this service to its own accepted policy.
        require(service_leaf(unit), "invalid scope leaf")?;
        let mut dir = rustix::fs::open("/", DIRECTORY, Mode::empty())?;
        root_directory(&dir)?;
        for component in ["sys", "fs", "cgroup"] {
            dir = openat(&dir, component, DIRECTORY, Mode::empty())?;
            root_directory(&dir)?;
        }
        check_scope_controls(&dir)?;
        for component in ["system.slice", unit] {
            dir = same_mount(&dir, component, DIRECTORY)?;
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

    pub fn observe(&self) -> io::Result<Fact> {
        check_scope_controls(&self.scope)?;
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

    pub fn child(&self, pid: u32, parent: u32) -> io::Result<Child> {
        self.observe()?;
        let child = Child {
            process: Process::bind(pid, self.main.user, &self.main.group)?,
            parent,
        };
        child.check()?;
        self.observe()?;
        Ok(child)
    }

    pub fn directory(&self) -> &OwnedFd {
        &self.scope
    }

    pub fn retirement(&self) -> io::Result<Option<Retirement>> {
        if !retirement_events_absent(read_at(&self.scope, "cgroup.events", 4096))? {
            return Ok(None);
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_leaf_cannot_escape_the_retained_system_slice() {
        for unit in [
            "agentswapper-1000@1-42-1000.service",
            "aswp-managed-fixture.service",
            "aswp-activation-1-1@1-42-1000.service",
        ] {
            assert!(service_leaf(unit));
        }
        for unit in [
            "",
            ".service",
            "/etc/a.service",
            "../a.service",
            "system.slice/a.service",
            "a.service/..",
            "a.scope",
            "a.service\0",
            "a\n.service",
            "a service",
            "é.service",
        ] {
            assert!(!service_leaf(unit));
        }
        assert!(!service_leaf(&format!("{}.service", "a".repeat(248))));
    }

    #[test]
    fn namespace_gate_rejects_remapped_and_partial_identity_ranges() {
        assert!(identity_map(b"         0          0 4294967295\n"));
        for bytes in [
            b"0 1000 1".as_slice(),
            b"0 0 65536",
            b"0 0 4294967295\n1 1 1",
            b"0 0 4294967296",
            b"\xff",
        ] {
            assert!(!identity_map(bytes));
        }
    }

    #[test]
    fn deactivated_events_never_count_as_retirement_evidence() -> io::Result<()> {
        assert!(!retirement_events_absent(Ok(
            b"populated 1\nfrozen 0\n".to_vec()
        ))?);
        assert!(!retirement_events_absent(Ok(
            b"populated 0\nfrozen 0\n".to_vec()
        ))?);
        for _ in 0..3 {
            assert!(!retirement_events_absent(Err(
                rustix::io::Errno::NODEV.into()
            ))?);
        }
        assert!(retirement_events_absent(Err(
            rustix::io::Errno::NOENT.into()
        ))?);
        for error in [
            rustix::io::Errno::IO,
            rustix::io::Errno::ACCESS,
            rustix::io::Errno::XDEV,
            rustix::io::Errno::BADF,
        ] {
            assert_eq!(
                retirement_events_absent(Err(error.into()))
                    .err()
                    .and_then(|error| error.raw_os_error()),
                Some(error.raw_os_error())
            );
        }
        assert!(retirement_events_absent(Ok(b"populated 0\nextra 0\n".to_vec())).is_err());
        Ok(())
    }

    #[test]
    fn own_process_metadata_comes_from_one_procfs_mount() -> io::Result<()> {
        let root = proc_root()?;
        let own = own_process(&root)?;
        require(
            identity_map(&read_at(&own, "uid_map", 4096)?),
            "local qualification requires the initial user namespace",
        )?;
        assert!(same_mount(&own, "../1/status", READ).is_err());
        assert!(same_mount(&root, "self/status", READ).is_err());
        Ok(())
    }

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
    fn direct_child_check_rejects_wrong_parent_and_group() -> io::Result<()> {
        struct Owned(std::process::Child);
        impl Drop for Owned {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let child = Owned(std::process::Command::new("/bin/sleep").arg("10").spawn()?);
        let membership = std::fs::read_to_string(format!("/proc/{}/cgroup", child.0.id()))?;
        let group = membership
            .strip_prefix("0::")
            .and_then(|s| s.strip_suffix('\n'))
            .ok_or_else(|| io::Error::other("test requires unified cgroup v2"))?;
        let uid = rustix::process::getuid().as_raw();
        let witness = Child {
            process: Process::bind(child.0.id(), uid, group)?,
            parent: std::process::id(),
        };
        witness.check()?;
        let wrong = Child {
            process: Process::bind(child.0.id(), uid, group)?,
            parent: 1,
        };
        assert!(wrong.check().is_err());
        assert!(Process::bind(child.0.id(), uid, "/aswp-wrong-child-group").is_err());
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
