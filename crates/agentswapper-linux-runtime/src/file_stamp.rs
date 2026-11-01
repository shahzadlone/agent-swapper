use rustix::fs::fstat;
use std::{io, os::fd::AsFd};

// Exclude access time: reading must not invalidate the observation. These are
// change detectors under a trusted root, not an atomic or cryptographic proof
// of the bytes that a separate process loaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Stamp(pub(crate) [i128; 12]);
impl Stamp {
    pub(crate) fn read(file: impl AsFd) -> io::Result<Self> {
        Ok(Self::from_stat(fstat(file)?))
    }
    pub(crate) fn from_stat(stat: rustix::fs::Stat) -> Self {
        Self([
            stat.st_dev.into(),
            stat.st_ino.into(),
            stat.st_nlink.into(),
            stat.st_size.into(),
            stat.st_mtime.into(),
            stat.st_mtime_nsec.into(),
            stat.st_ctime.into(),
            stat.st_ctime_nsec.into(),
            stat.st_mode.into(),
            stat.st_uid.into(),
            stat.st_gid.into(),
            stat.st_rdev.into(),
        ])
    }
    pub(crate) fn require_config(self, current: Self) -> io::Result<()> {
        if self != current {
            return Err(io::Error::other(
                "installed configuration changed since admission began",
            ));
        }
        Ok(())
    }
}
