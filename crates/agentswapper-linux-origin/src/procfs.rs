//! Older-kernel capture. Authenticate the current thread's procfs links before
//! following the unavoidable procfs-to-nsfs hop; a borrowed namespace is never
//! used as the reference identity. All paths and namespace names are fixed here.
use super::{Credentials, Namespace, NamespaceKind, namespace, require};
use rustix::{
    fs::{self, FileType, Mode, OFlags, ResolveFlags},
    process::{Pid, getpid},
};
use std::{
    fs::File,
    io::{self, Read},
    os::fd::OwnedFd,
};

const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);
const READ: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK);
const SAME_MOUNT: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_XDEV);

fn at(parent: &OwnedFd, name: &str, flags: OFlags) -> io::Result<OwnedFd> {
    fs::openat2(parent, name, flags, Mode::empty(), SAME_MOUNT).map_err(|error| {
        if error == rustix::io::Errno::XDEV {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "origin metadata crosses a mount boundary",
            )
        } else {
            error.into()
        }
    })
}

fn status(own: &OwnedFd) -> io::Result<String> {
    let file = at(own, "status", READ)?;
    require(
        FileType::from_raw_mode(fs::fstat(&file)?.st_mode) == FileType::RegularFile,
        "origin status is not a regular file",
    )?;
    let mut data = Vec::new();
    File::from(file).take(65537).read_to_end(&mut data)?;
    require(data.len() <= 65536, "origin status exceeds bounds")?;
    String::from_utf8(data).map_err(io::Error::other)
}

fn field<'a>(status: &'a str, key: &str) -> io::Result<&'a str> {
    let mut values = status.lines().filter_map(|line| line.strip_prefix(key));
    let value = values.next();
    require(
        value.is_some() && values.next().is_none(),
        "origin status field missing or repeated",
    )?;
    value.ok_or_else(|| io::Error::other("origin status field missing"))
}
fn numbers(status: &str, key: &str) -> io::Result<Vec<u32>> {
    field(status, key)?
        .split_whitespace()
        .map(|value| {
            require(
                value.bytes().all(|byte| byte.is_ascii_digit()),
                "origin status has invalid IDs",
            )?;
            value.parse().map_err(io::Error::other)
        })
        .collect()
}
fn validate_status(status: &str, thread: Pid, credentials: &Credentials) -> io::Result<()> {
    require(
        numbers(status, "Pid:")? == [thread.as_raw_pid() as u32]
            && numbers(status, "Tgid:")? == [getpid().as_raw_pid() as u32],
        "procfs identity disagrees with the calling thread",
    )?;
    let mut groups = numbers(status, "Groups:")?;
    groups.sort_unstable();
    require(
        numbers(status, "Uid:")? == credentials.users
            && numbers(status, "Gid:")? == credentials.groups
            && groups == credentials.supplementary,
        "procfs credentials disagree with kernel queries",
    )?;
    for key in ["CapEff:", "CapPrm:", "CapInh:", "CapAmb:"] {
        let value = field(status, key)?.trim();
        require(
            value.len() == 16 && value.bytes().all(|byte| byte == b'0'),
            "procfs reports nonempty capabilities",
        )?;
    }
    Ok(())
}

fn link_inode(link: &OwnedFd, kind: NamespaceKind) -> io::Result<u64> {
    let mut data = [0_u8; 64];
    let count = fs::readlinkat_raw(link, "", &mut data[..])?;
    require(count < data.len(), "namespace link exceeds bounds")?;
    parse_inode(&data[..count], kind)
}
fn parse_inode(data: &[u8], kind: NamespaceKind) -> io::Result<u64> {
    let text = std::str::from_utf8(data).map_err(io::Error::other)?;
    let number = text
        .strip_prefix(kind.name())
        .and_then(|value| value.strip_prefix(":["))
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| io::Error::other("invalid namespace link"))?;
    require(
        !number.is_empty()
            && number.len() <= 20
            && !number.starts_with('0')
            && number.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid namespace inode",
    )?;
    number.parse().map_err(io::Error::other)
}

fn observe(ns: &OwnedFd, kind: NamespaceKind) -> io::Result<Namespace> {
    // O_PATH|O_NOFOLLOW retains the link itself; NO_SYMLINKS allows this final
    // component because it is not followed. The readlink query uses that fd.
    let link = at(
        ns,
        kind.name(),
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
    )?;
    require(
        FileType::from_raw_mode(fs::fstat(&link)?.st_mode) == FileType::Symlink,
        "namespace metadata is not a procfs link",
    )?;
    let inode = link_inode(&link, kind)?;
    if kind == NamespaceKind::User {
        require(
            inode == super::INITIAL_USER,
            "process is outside the initial user namespace",
        )?;
    }
    // A namespace magic hop crosses into nsfs and cannot use BENEATH, NO_XDEV
    // or NO_MAGICLINKS (Linux namei.c::nd_jump_link). Resolve only this fixed
    // single name relative to the retained ns directory, then authenticate the
    // returned nsfs handle against the independently pinned procfs link above.
    let file = fs::openat(
        ns,
        kind.name(),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    let value = namespace(file, kind)?;
    require(
        value.fact.inode == inode && link_inode(&link, kind)? == inode,
        "namespace handle disagrees with the pinned procfs link",
    )?;
    Ok(value)
}

pub(super) fn capture(thread: Pid, credentials: &Credentials) -> io::Result<[Namespace; 4]> {
    let root = fs::open("/proc", DIRECTORY, Mode::empty())?;
    let metadata = fs::fstat(&root)?;
    require(
        fs::fstatfs(&root)?.f_type == fs::PROC_SUPER_MAGIC
            && metadata.st_ino == 1
            && FileType::from_raw_mode(metadata.st_mode) == FileType::Directory,
        "origin metadata is not a procfs root",
    )?;
    // thread-self is a kernel-generated ordinary symlink, unlike ns/* magic
    // links. NO_XDEV also rejects an overlay on any part of its resolved path.
    let own = fs::openat2(
        &root,
        "thread-self",
        DIRECTORY & !OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_XDEV,
    )?;
    validate_status(&status(&own)?, thread, credentials)?;
    let ns = at(&own, "ns", DIRECTORY)?;
    let result = [
        observe(&ns, NamespaceKind::User)?,
        observe(&ns, NamespaceKind::Mount)?,
        observe(&ns, NamespaceKind::Pid)?,
        observe(&ns, NamespaceKind::Cgroup)?,
    ];
    validate_status(&status(&own)?, thread, credentials)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn namespace_link_parser_refuses_ambiguous_or_foreign_facts() -> io::Result<()> {
        assert_eq!(
            parse_inode(b"user:[4026531837]", NamespaceKind::User)?,
            super::super::INITIAL_USER
        );
        for value in [
            b"user:[0]".as_slice(),
            b"user:[04026531837]",
            b"user:[+4026531837]",
            b"user:[4026531837]\n",
            b"mnt:[4026531837]",
            b"user:[18446744073709551616]",
            b"user:[-1]",
            b"user:[]",
            b"user:[1][2]",
            b"user:[\xff]",
        ] {
            assert!(
                parse_inode(value, NamespaceKind::User).is_err(),
                "{value:?}"
            );
        }
        Ok(())
    }
    #[test]
    fn status_requires_exact_current_thread_and_every_credential_tier() -> io::Result<()> {
        let ids = super::super::credentials()?;
        let thread = rustix::thread::gettid();
        let text = format!(
            "Pid:\t{}\nTgid:\t{}\nUid:\t{}\nGid:\t{}\nGroups:\t{}\nCapEff:\t0000000000000000\nCapPrm:\t0000000000000000\nCapInh:\t0000000000000000\nCapAmb:\t0000000000000000\n",
            thread.as_raw_pid(),
            getpid().as_raw_pid(),
            ids.users.map(|v| v.to_string()).join(" "),
            ids.groups.map(|v| v.to_string()).join(" "),
            ids.supplementary
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        );
        validate_status(&text, thread, &ids)?;
        for key in [
            "Pid:", "Tgid:", "Uid:", "Gid:", "Groups:", "CapEff:", "CapPrm:", "CapInh:", "CapAmb:",
        ] {
            let changed = text
                .lines()
                .filter(|line| !line.starts_with(key))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(validate_status(&changed, thread, &ids).is_err());
            assert!(validate_status(&format!("{text}{key}\t0\n"), thread, &ids).is_err());
        }
        let changed = text.replace("CapAmb:\t0000000000000000", "CapAmb:\t0000000000000001");
        assert!(validate_status(&changed, thread, &ids).is_err());
        let mut changed = ids;
        changed.users[3] += 1;
        assert!(validate_status(&text, thread, &changed).is_err());
        Ok(())
    }
}
