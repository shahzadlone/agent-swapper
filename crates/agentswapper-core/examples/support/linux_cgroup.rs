//! Shared Linux-only cgroup capabilities for provider-free experiments.
//! These types are private to example binaries and cannot issue production receipts.
use rustix::{
    fs::{AtFlags, CWD, Mode, OFlags, ResolveFlags, fstatfs, mkdirat, openat, openat2, unlinkat},
    process::geteuid,
};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use uuid::Uuid;

pub(crate) fn require(value: bool, message: &'static str) -> io::Result<()> {
    if value {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
pub(crate) fn until<T>(
    deadline: Instant,
    mut check: impl FnMut() -> io::Result<Option<T>>,
) -> io::Result<T> {
    loop {
        require(Instant::now() < deadline, "cgroup probe deadline exceeded")?;
        if let Some(value) = check()? {
            return Ok(value);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
pub(crate) fn checked_directory(path: &Path) -> io::Result<File> {
    require(path.is_absolute(), "cgroup path must be absolute")?;
    let fd = openat2(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )?;
    let file = File::from(fd);
    validate_directory(&file)?;
    Ok(file)
}
pub(crate) fn validate_directory(file: &File) -> io::Result<()> {
    // CGROUP2_SUPER_MAGIC from the kernel's cgroup v2 interface contract.
    require(
        fstatfs(file)?.f_type == 0x6367_7270,
        "path is not a cgroup v2 filesystem",
    )?;
    require(
        !geteuid().is_root(),
        "run the probe as an ordinary delegated user",
    )?;
    let metadata = file.metadata()?;
    require(
        metadata.uid() == geteuid().as_raw() && metadata.mode() & 0o022 == 0,
        "cgroup is not privately delegated to this user",
    )?;
    Ok(())
}
pub(crate) fn control(directory: &File, name: &str, flags: OFlags) -> io::Result<File> {
    Ok(File::from(openat(
        directory,
        name,
        flags | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )?))
}
fn text(directory: &File, name: &str) -> io::Result<String> {
    let mut result = String::new();
    control(directory, name, OFlags::RDONLY)?
        .take(64 * 1024 + 1)
        .read_to_string(&mut result)?;
    require(result.len() <= 64 * 1024, "oversized cgroup metadata")?;
    Ok(result)
}
pub(crate) fn contains(directory: &File, pid: u32) -> io::Result<bool> {
    Ok(text(directory, "cgroup.procs")?
        .lines()
        .any(|line| line.parse::<u32>().ok() == Some(pid)))
}
pub(crate) fn populated(directory: &File) -> io::Result<bool> {
    let events = text(directory, "cgroup.events")?;
    let values = events
        .lines()
        .filter_map(|line| line.strip_prefix("populated "))
        .collect::<Vec<_>>();
    match values.as_slice() {
        ["0"] => Ok(false),
        ["1"] => Ok(true),
        _ => Err(io::Error::other("invalid cgroup population observation")),
    }
}

pub(crate) struct Domain {
    directory: File,
    path: PathBuf,
}
impl Domain {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let directory = checked_directory(path)?;
        require(
            text(&directory, "cgroup.type")?.trim() == "domain",
            "threaded cgroups are unsupported",
        )?;
        require(
            contains(&directory, std::process::id())?,
            "probe must already be inside its delegated parent",
        )?;
        let _ = control(&directory, "cgroup.procs", OFlags::WRONLY)?;
        Ok(Self {
            directory,
            path: path.to_owned(),
        })
    }
    pub(crate) fn create(&self) -> io::Result<Group> {
        self.create_with_check(|_| Ok(()))
    }
    pub(crate) fn create_with_check(
        &self,
        check: impl FnOnce(&File) -> io::Result<()>,
    ) -> io::Result<Group> {
        let parent = self.directory.try_clone()?;
        let name = format!("aswp-probe-{}", Uuid::new_v4());
        let mut created = NewDirectory::create(&parent, &name)?;
        let path = self.path.join(&name);
        let result = (|| {
            // Resolve beneath the already-validated parent handle, rather
            // than reopening the absolute delegated-parent path.
            let directory = File::from(openat2(
                &parent,
                name.as_str(),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
            )?);
            validate_directory(&directory)?;
            let _ = control(&directory, "cgroup.kill", OFlags::WRONLY)?;
            check(&directory)?;
            Ok::<_, io::Error>(directory)
        })();
        let directory = match result {
            Ok(directory) => directory,
            Err(error) => {
                return match created.rollback() {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(io::Error::other(format!(
                        "cgroup initialization failed ({error}); empty-child rollback also failed ({cleanup})"
                    ))),
                };
            }
        };
        created.commit();
        Ok(Group {
            directory,
            parent,
            name,
            path,
            retired: false,
        })
    }
}
// Acquired only after mkdirat succeeds. A collision never transfers ownership.
struct NewDirectory<'a> {
    parent: &'a File,
    name: &'a str,
    active: bool,
}
impl<'a> NewDirectory<'a> {
    fn create(parent: &'a File, name: &'a str) -> io::Result<Self> {
        mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR)?;
        Ok(Self {
            parent,
            name,
            active: true,
        })
    }
    fn rollback(&mut self) -> io::Result<()> {
        if self.active {
            unlinkat(self.parent, self.name, AtFlags::REMOVEDIR)?;
            self.active = false;
        }
        Ok(())
    }
    fn commit(mut self) {
        self.active = false;
    }
}
impl Drop for NewDirectory<'_> {
    fn drop(&mut self) {
        let _ = self.rollback();
    }
}
pub(crate) struct Group {
    directory: File,
    parent: File,
    name: String,
    path: PathBuf,
    retired: bool,
}
impl Group {
    pub(crate) fn parent(&self) -> &File {
        &self.parent
    }
    pub(crate) fn directory(&self) -> &File {
        &self.directory
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn retire(&mut self, deadline: Instant) -> io::Result<()> {
        until(deadline, || {
            control(&self.directory, "cgroup.kill", OFlags::WRONLY)?.write_all(b"1\n")?;
            if populated(&self.directory)? {
                return Ok(None);
            }
            match unlinkat(&self.parent, self.name.as_str(), AtFlags::REMOVEDIR) {
                Ok(()) => {
                    self.retired = true;
                    Ok(Some(()))
                }
                Err(rustix::io::Errno::BUSY | rustix::io::Errno::NOTEMPTY) => Ok(None),
                Err(error) => Err(error.into()),
            }
        })
    }
}
impl Drop for Group {
    fn drop(&mut self) {
        if !self.retired {
            // This handle can only describe the unique child we created.
            // The delegated parent never reaches a kill operation here.
            let _ = self.retire(Instant::now() + Duration::from_secs(2));
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::fs;
    #[test]
    fn ordinary_directories_and_links_are_refused_before_any_write() {
        let directory = tempfile::tempdir().unwrap();
        let before = fs::read_dir(directory.path()).unwrap().count();
        assert!(Domain::open(directory.path()).is_err());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), before);
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(directory.path(), &link).unwrap();
        assert!(checked_directory(&link).is_err());
    }

    #[test]
    fn directory_creation_rollback_uses_owned_parent_and_preserves_collisions() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("original");
        fs::create_dir(&original).unwrap();
        let parent = File::open(&original).unwrap();
        let moved = directory.path().join("moved");
        let owned = NewDirectory::create(&parent, "child").unwrap();
        fs::rename(&original, &moved).unwrap();
        fs::create_dir(&original).unwrap();
        fs::create_dir(original.join("child")).unwrap();
        drop(owned);
        assert!(!moved.join("child").exists());
        assert!(original.join("child").is_dir());
        let replacement = File::open(&original).unwrap();
        assert!(NewDirectory::create(&replacement, "child").is_err());
        assert!(original.join("child").is_dir());
    }
}
