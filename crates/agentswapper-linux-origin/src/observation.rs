use crate::ffi;
use rustix::{
    fs::{fstat, fstatfs},
    io::{FdFlags, fcntl_getfd},
    process::{Pid, PidfdFlags, getgroups, pidfd_open},
    thread::{CapabilitySets, capabilities, gettid},
};
use std::{
    io,
    marker::PhantomData,
    os::fd::{AsFd, OwnedFd},
    rc::Rc,
};

const NSFS: rustix::fs::FsWord = 0x6e73_6673;
// Linux include/linux/proc_ns.h reserves this initial-user-namespace inode.
// It is an implementation contract requiring native qualification, not a UID.
const INITIAL_USER: u64 = 0xefff_fffd;

#[path = "procfs.rs"]
mod procfs;

/// Diagnostic name of the mechanism that supplied a retained observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Pidfd,
    Procfs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamespaceKind {
    User,
    Mount,
    Pid,
    Cgroup,
}
impl NamespaceKind {
    fn name(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Mount => "mnt",
            Self::Pid => "pid",
            Self::Cgroup => "cgroup",
        }
    }
    fn native(self) -> i32 {
        match self {
            Self::User => libc::CLONE_NEWUSER,
            Self::Mount => libc::CLONE_NEWNS,
            Self::Pid => libc::CLONE_NEWPID,
            Self::Cgroup => libc::CLONE_NEWCGROUP,
        }
    }
}

/// Copyable diagnostics. These fields cannot construct an origin observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamespaceFact {
    pub kind: NamespaceKind,
    pub device: u64,
    pub inode: u64,
    pub owner_inode: u64,
}
struct Namespace {
    _file: OwnedFd,
    _owner: Option<OwnedFd>,
    fact: NamespaceFact,
}
#[derive(PartialEq, Eq)]
struct Credentials {
    users: [u32; 4],
    groups: [u32; 4],
    supplementary: Vec<u32>,
}

fn require(ok: bool, message: &'static str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, message))
    }
}
fn unsupported(error: io::Error) -> io::Error {
    if matches!(
        error.raw_os_error(),
        Some(libc::ENOSYS | libc::EINVAL | libc::ENOTTY | libc::EOPNOTSUPP)
    ) {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "kernel pidfd namespace queries are unavailable",
        )
    } else {
        error
    }
}
fn ordinary(value: &Credentials, caps: CapabilitySets) -> io::Result<()> {
    let ids = |values: &[u32; 4]| {
        values[0] != 0
            && values[0] <= i32::MAX as u32
            && values.iter().all(|value| *value == values[0])
    };
    require(
        ids(&value.users)
            && ids(&value.groups)
            && value.supplementary.len() <= 4096
            && value
                .supplementary
                .iter()
                .all(|id| *id > 0 && *id <= i32::MAX as u32)
            && caps.effective.is_empty()
            && caps.permitted.is_empty()
            && caps.inheritable.is_empty(),
        "origin observation requires an ordinary capability-free identity",
    )
}
fn credentials() -> io::Result<Credentials> {
    let (users, groups) = ffi::ids()?;
    let mut supplementary: Vec<_> = getgroups()?.into_iter().map(|id| id.as_raw()).collect();
    supplementary.sort_unstable();
    let value = Credentials {
        users,
        groups,
        supplementary,
    };
    ordinary(&value, capabilities(None)?)?;
    Ok(value)
}
fn descriptor(file: &OwnedFd, kind: NamespaceKind) -> io::Result<(u64, u64)> {
    require(
        fstatfs(file)?.f_type == NSFS
            && ffi::namespace_type(file.as_fd()).map_err(unsupported)? == kind.native()
            && fcntl_getfd(file)?.contains(FdFlags::CLOEXEC),
        "kernel namespace descriptor failed validation",
    )?;
    let stat = fstat(file)?;
    Ok((stat.st_dev, stat.st_ino))
}
fn observe(pidfd: &OwnedFd, kind: NamespaceKind) -> io::Result<Namespace> {
    let file = ffi::namespace(pidfd.as_fd(), kind).map_err(unsupported)?;
    namespace(file, kind)
}
fn namespace(file: OwnedFd, kind: NamespaceKind) -> io::Result<Namespace> {
    let (device, inode) = descriptor(&file, kind)?;
    let owner = if kind == NamespaceKind::User {
        None
    } else {
        Some(ffi::owner(file.as_fd()).map_err(unsupported)?)
    };
    let owner_inode = match &owner {
        Some(owner) => descriptor(owner, NamespaceKind::User)?.1,
        None => inode,
    };
    require(
        owner_inode == INITIAL_USER,
        if kind == NamespaceKind::User {
            "process is outside the initial user namespace"
        } else {
            "process namespaces are not owned by the initial user namespace"
        },
    )?;
    Ok(Namespace {
        _file: file,
        _owner: owner,
        fact: NamespaceFact {
            kind,
            device,
            inode,
            owner_inode,
        },
    })
}

/// A retained observation of this thread's kernel namespace objects and ordinary
/// credentials. It prefers pidfd queries and uses descriptor-anchored procfs
/// when those queries are unsupported. It does not attest
/// to an installation, manager, executable, process custody or target exit.
///
/// Recheck on the same thread before relying on this snapshot. Each helper must
/// capture its own after exec. Root, kernel and this process's code are trusted;
/// this is not protection from same-UID code injection or hostile root.
///
/// ```compile_fail,E0277
/// use agentswapper_linux_origin::Origin;
/// fn send<T: Send>() {}
/// send::<Origin>();
/// ```
/// ```compile_fail,E0599
/// use agentswapper_linux_origin::Origin;
/// fn duplicate(value: Origin) { let _ = value.clone(); }
/// ```
#[cfg_attr(
    not(feature = "qualification"),
    doc = "\n```compile_fail,E0599\nuse agentswapper_linux_origin::Origin;\nfn force() { let _ = Origin::capture_for_qualification; }\n```"
)]
pub struct Origin {
    thread: Pid,
    backend: Backend,
    credentials: Credentials,
    namespaces: [Namespace; 4],
    _same_thread: PhantomData<Rc<()>>,
}
impl Origin {
    pub fn capture() -> io::Result<Self> {
        match Self::capture_with(Backend::Pidfd) {
            Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                Self::capture_with(Backend::Procfs)
            }
            result => result,
        }
    }
    /// Exercise either real capture algorithm; no caller-supplied paths or facts.
    #[cfg(feature = "qualification")]
    pub fn capture_for_qualification(backend: Backend) -> io::Result<Self> {
        Self::capture_with(backend)
    }
    fn capture_with(backend: Backend) -> io::Result<Self> {
        let credentials = credentials()?;
        let thread = gettid();
        // PIDFD_THREAD is O_EXCL in Linux's pidfd UAPI. Capturing a leader via
        // getpid would inspect the wrong task when called from another thread.
        let namespaces = match backend {
            Backend::Pidfd => {
                let flags = PidfdFlags::from_bits_retain(libc::O_EXCL as u32);
                let pidfd = pidfd_open(thread, flags)
                    .map_err(io::Error::from)
                    .map_err(unsupported)?;
                [
                    observe(&pidfd, NamespaceKind::User)?,
                    observe(&pidfd, NamespaceKind::Mount)?,
                    observe(&pidfd, NamespaceKind::Pid)?,
                    observe(&pidfd, NamespaceKind::Cgroup)?,
                ]
            }
            Backend::Procfs => procfs::capture(thread, &credentials)?,
        };
        let value = Self {
            thread,
            backend,
            credentials,
            namespaces,
            _same_thread: PhantomData,
        };
        require(
            value.thread == gettid() && value.credentials == self::credentials()?,
            "origin credentials changed during observation",
        )?;
        Ok(value)
    }
    pub fn user(&self) -> u32 {
        self.credentials.users[0]
    }
    pub fn group(&self) -> u32 {
        self.credentials.groups[0]
    }
    pub fn backend(&self) -> Backend {
        self.backend
    }
    pub fn facts(&self) -> [NamespaceFact; 4] {
        self.namespaces.each_ref().map(|namespace| namespace.fact)
    }
    pub fn require_current(&self) -> io::Result<()> {
        require(self.thread == gettid(), "origin belongs to another thread")?;
        let current = Self::capture_with(self.backend)?;
        require(
            self.credentials == current.credentials && self.facts() == current.facts(),
            "origin changed since observation",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::thread::CapabilitySet;

    #[test]
    fn privileged_saved_filesystem_or_supplementary_ids_refuse() -> io::Result<()> {
        let clean = || Credentials {
            users: [1000; 4],
            groups: [1001; 4],
            supplementary: vec![20],
        };
        let empty = CapabilitySets {
            effective: CapabilitySet::empty(),
            permitted: CapabilitySet::empty(),
            inheritable: CapabilitySet::empty(),
        };
        ordinary(&clean(), empty)?;
        for index in 0..4 {
            for invalid in [0, 1002, u32::MAX] {
                let mut changed = clean();
                changed.users[index] = invalid;
                assert!(ordinary(&changed, empty).is_err());
                let mut changed = clean();
                changed.groups[index] = invalid;
                assert!(ordinary(&changed, empty).is_err());
            }
        }
        for invalid in [0, i32::MAX as u32 + 1, u32::MAX] {
            let mut changed = clean();
            changed.supplementary.push(invalid);
            assert!(ordinary(&changed, empty).is_err());
        }
        let mut changed = clean();
        changed.supplementary = vec![20; 4097];
        assert!(ordinary(&changed, empty).is_err());
        for field in 0..3 {
            let mut caps = empty;
            match field {
                0 => caps.effective = CapabilitySet::CHOWN,
                1 => caps.permitted = CapabilitySet::CHOWN,
                _ => caps.inheritable = CapabilitySet::CHOWN,
            }
            assert!(ordinary(&clean(), caps).is_err());
        }
        Ok(())
    }
    #[test]
    fn unsupported_queries_are_distinct_from_permission_or_io_failures() {
        for code in [libc::ENOSYS, libc::ENOTTY, libc::EINVAL, libc::EOPNOTSUPP] {
            assert_eq!(
                unsupported(io::Error::from_raw_os_error(code)).kind(),
                io::ErrorKind::Unsupported
            );
        }
        for code in [libc::EPERM, libc::EACCES, libc::EIO, libc::EBADF] {
            assert_eq!(
                unsupported(io::Error::from_raw_os_error(code)).raw_os_error(),
                Some(code)
            );
        }
    }
    #[test]
    fn live_observation_queries_the_calling_nonleader_thread() -> io::Result<()> {
        std::thread::spawn(|| -> io::Result<()> {
            assert_ne!(gettid().as_raw_pid() as u32, std::process::id());
            for backend in [Backend::Pidfd, Backend::Procfs] {
                match Origin::capture_with(backend) {
                    Ok(origin) => {
                        assert_eq!(origin.user(), rustix::process::getuid().as_raw());
                        assert_eq!(origin.group(), rustix::process::getgid().as_raw());
                        assert!(
                            origin
                                .facts()
                                .iter()
                                .all(|fact| fact.owner_inode == INITIAL_USER)
                        );
                        origin.require_current()?;
                    }
                    Err(error)
                        if backend == Backend::Pidfd
                            && error.kind() == io::ErrorKind::Unsupported => {}
                    Err(error) => return Err(error),
                }
            }
            Origin::capture()?.require_current()
        })
        .join()
        .map_err(|_| io::Error::other("origin test thread panicked"))?
    }
    #[test]
    fn independent_capture_backends_agree_on_live_namespace_objects() -> io::Result<()> {
        let procfs = Origin::capture_with(Backend::Procfs)?;
        match Origin::capture_with(Backend::Pidfd) {
            Ok(pidfd) => {
                assert_eq!(procfs.facts(), pidfd.facts());
                assert!(procfs.credentials == pidfd.credentials);
                pidfd.require_current()?;
            }
            Err(error) if error.kind() == io::ErrorKind::Unsupported => {}
            Err(error) => return Err(error),
        }
        procfs.require_current()
    }
}
