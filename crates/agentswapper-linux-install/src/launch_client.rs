//! The ordinary launch client's durable journal seam and flow ordering. The
//! client commits a durable run intent before sending the launch gate, and a
//! durable spawn observation before releasing the held exec; an uncertain
//! write is an error, never a silent success. Production Store integration
//! is a separately reviewed gate; this module defines the mandatory
//! semantics and ships a local fsync'd journal for disposable launches.
use crate::client;
use agentswapper_linux_manager::{RetiredService, ServiceKey};
use std::{
    fs,
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

/// The durable journal boundary the launch client composes on. Implementations
/// must satisfy, and the client enforces:
/// - `confirm_intent` commits the durable run intent synchronously while the
///   exec is held, before the client releases it; its `Ok(())` is the only
///   launch-gate authority the client receives. It receives the launch's
///   one-use `ServiceKey` by value: the adapter moves it into the durable
///   scope association, where it cannot be extracted or serialized. A failed
///   commit consumes the key into the adapter's pending association; the run
///   stays unresolved and is never re-launched.
/// - `observe_spawn` durably records the spawn observation before the client
///   releases the held exec; an uncertain write is an error.
/// - `audit_exit` commits the authenticated target exit together with the
///   one-use retirement value. It runs only after the client has
///   independently observed the original scope's retirement on its retained
///   handles; the retirement value authorizes exactly this commit and no
///   other. A failure is retry-safe: the adapter retains the retirement
///   value for in-place retry, and the run's profile stays blocked until the
///   commit lands.
///
/// An independent review (2026-11-22) fixed these signatures and the client's
/// closure order; a production Store adapter must additionally decide the
/// durable recording of a scoped run's target exit, which today lives only
/// in this journal's records and the client's memory.
pub trait Journal {
    fn confirm_intent(&self, invocation: &str, nonce: &str, key: ServiceKey) -> io::Result<()>;
    fn observe_spawn(&self, invocation: &str, child: u32) -> io::Result<()>;
    fn audit_exit(&self, invocation: &str, exit: &str, retired: RetiredService) -> io::Result<()>;
}

/// A local fsync'd journal in one private directory. Records are created
/// once and never rewritten; the directory entry is synced after each.
pub struct FileJournal {
    directory: PathBuf,
}

impl FileJournal {
    pub fn open(directory: &Path) -> io::Result<Self> {
        let meta = std::fs::symlink_metadata(directory)?;
        require(
            directory.is_absolute()
                && meta.is_dir()
                && meta.uid() == rustix::process::getuid().as_raw()
                && meta.mode() & 0o077 == 0,
            "launch journal directory is not private to the caller",
        )?;
        Ok(Self {
            directory: directory.to_owned(),
        })
    }
    fn record(&self, name: &str, body: &str) -> io::Result<()> {
        let path = self.directory.join(format!("{name}.tmp"));
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let mut file = file;
        file.write_all(body.as_bytes())?;
        file.sync_all()?;
        fs::rename(&path, self.directory.join(name))?;
        fs::File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}

impl Journal for FileJournal {
    fn confirm_intent(&self, invocation: &str, nonce: &str, _key: ServiceKey) -> io::Result<()> {
        // The disposable record cannot hold the non-serializable key; the
        // record only marks the durable intent for this launch.
        self.record(
            &format!("intent-{invocation}"),
            &format!("run intent held before launch gate; nonce {nonce}; outcome unresolved"),
        )
    }
    fn observe_spawn(&self, invocation: &str, child: u32) -> io::Result<()> {
        self.record(
            &format!("spawn-{invocation}"),
            &format!("authenticated exec observed; child {child}"),
        )
    }
    fn audit_exit(&self, invocation: &str, exit: &str, _retired: RetiredService) -> io::Result<()> {
        // The retirement value is consumed here; the disposable record
        // cannot serialize it.
        self.record(
            &format!("exit-{invocation}"),
            &format!("authenticated target exit: {exit}"),
        )
    }
}

/// The durable-intent-gated launch flow. Every journal callback runs before
/// the frame it authorizes; a callback failure withholds the frame.
pub fn launch(
    user: u32,
    program: &std::ffi::OsStr,
    args: Vec<std::ffi::OsString>,
    journal: &impl Journal,
) -> io::Result<String> {
    let outcome = client::launch(user, program, args, journal)?;
    Ok(outcome)
}
