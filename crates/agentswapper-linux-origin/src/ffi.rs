//! Sole native boundary: fixed scalar ioctls, owned returned descriptors, and
//! credential queries. No caller supplies an ioctl number or raw descriptor.
use crate::observation::NamespaceKind;
use std::{
    io,
    os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
};

pub(crate) fn namespace_request(kind: NamespaceKind) -> libc::Ioctl {
    // Linux v6.11 include/uapi/linux/pidfd.h. libc 0.2.191 does not expose
    // these names; its architecture-specific _IO encoding is still used.
    libc::_IO(
        0xff,
        match kind {
            NamespaceKind::Cgroup => 1,
            NamespaceKind::Mount => 3,
            NamespaceKind::Pid => 5,
            NamespaceKind::User => 9,
        },
    )
}

fn descriptor_result(result: libc::c_int) -> io::Result<OwnedFd> {
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: The only callers pass successful results of namespace-getter
    // ioctls, which return a new exclusively owned O_CLOEXEC descriptor.
    // They never pass a scalar-result ioctl, borrowed fd, or caller input.
    Ok(unsafe { OwnedFd::from_raw_fd(result) })
}

pub(crate) fn namespace(pidfd: BorrowedFd<'_>, kind: NamespaceKind) -> io::Result<OwnedFd> {
    // SAFETY: pidfd is borrowed for this synchronous call. The fixed getter
    // accepts a zero scalar argument, accesses no userspace pointer, and
    // returns a fresh namespace descriptor on success.
    descriptor_result(unsafe {
        libc::ioctl(
            pidfd.as_raw_fd(),
            namespace_request(kind),
            0 as libc::c_ulong,
        )
    })
}

pub(crate) fn owner(namespace: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    // SAFETY: Only an owned namespace descriptor returned by the kernel reaches
    // this fixed ioctl. Its argument is zero, with no userspace memory access;
    // successful NS_GET_USERNS returns a new owned O_CLOEXEC descriptor.
    descriptor_result(unsafe {
        libc::ioctl(
            namespace.as_raw_fd(),
            libc::NS_GET_USERNS,
            0 as libc::c_ulong,
        )
    })
}

pub(crate) fn namespace_type(namespace: BorrowedFd<'_>) -> io::Result<i32> {
    // SAFETY: This fixed scalar query borrows a live descriptor and passes no
    // pointer. Unlike the getters above, its result is a namespace type.
    let result = unsafe {
        libc::ioctl(
            namespace.as_raw_fd(),
            libc::NS_GET_NSTYPE,
            0 as libc::c_ulong,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

pub(crate) fn ids() -> io::Result<([u32; 4], [u32; 4])> {
    let (mut real, mut effective, mut saved) = (0, 0, 0);
    // SAFETY: Three distinct initialized uid_t values remain writable and live
    // for this synchronous query. Nothing is read on failure.
    if unsafe { libc::getresuid(&mut real, &mut effective, &mut saved) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: uid_t::MAX is Linux's invalid unmappable UID. setfsuid cannot set
    // it and returns the unchanged current fsuid, including for privileged
    // callers. This is the Linux query idiom, not a credential transition.
    let fs = unsafe { libc::setfsuid(libc::uid_t::MAX) } as u32;
    let users = [real, effective, saved, fs];
    let (mut real, mut effective, mut saved) = (0, 0, 0);
    // SAFETY: As above, the three gid_t outputs are distinct, initialized and
    // valid for the synchronous query. Errors return before consuming them.
    if unsafe { libc::getresgid(&mut real, &mut effective, &mut saved) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: gid_t::MAX is Linux's invalid unmappable GID, so this query
    // returns the existing fsgid without changing it.
    let fs = unsafe { libc::setfsgid(libc::gid_t::MAX) } as u32;
    Ok((users, [real, effective, saved, fs]))
}
