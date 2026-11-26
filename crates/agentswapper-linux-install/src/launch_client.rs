//! The ordinary launch client's durable journal seam and flow ordering. The
//! client commits a durable run intent before sending the launch gate, and a
//! durable spawn observation before releasing the held exec; an uncertain
//! write is an error, never a silent success. Production Store integration
//! is a separately reviewed gate; this module defines the mandatory
//! semantics and ships a local fsync'd journal for disposable launches.
use crate::client;
use agentswapper_linux_manager::{RetiredService, ServiceKey};
use agentswapper_linux_runtime::target_exit::TargetExit;
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
/// - `confirm_intent` commits the durable run intent synchronously before the
///   client sends the launch gate; its `Ok(())` is the only launch-gate
///   authority the client receives. It receives the launch's
///   one-use `ServiceKey` by value: the adapter moves it into the durable
///   scope association, where it cannot be extracted or serialized. `Ok(())`
///   is also the only point after which the journal owes a settlement; a
///   failed commit withholds the gate, and whether it leaves a run behind is
///   the adapter's contract - a `StoreJournal` plans the run and its binding
///   in that one transaction, so its failure leaves nothing.
/// - `observe_spawn` durably records the spawn observation before the client
///   releases the held exec; an uncertain write is an error.
/// - `audit_exit` commits the one-use retirement value together with the
///   authenticated target exit when the relay produced one. It runs only
///   after the client has independently observed the original scope's
///   retirement on its retained handles, on the relay's failure paths as
///   well as its success. The exit it commits is the one the whole relay
///   path produced, its own cleanup included; a launch that failed after the
///   intent, or whose relay refused an exit it had already received, passes
///   none. The retirement value authorizes exactly this commit and no other.
///   A failed commit is retried through `retry_audit`, which asks for
///   neither a new receipt nor a new exit: a `StoreJournal` retains the
///   pending association, the retirement value and the exit that went with
///   them, and reuses that whole tuple rather than a receipt that belongs to
///   another launch. The run stays unresolved, and its profile blocked, only
///   when nothing witnessed the scope's closure or the commit itself failed
///   before it landed.
///
/// An independent review (2026-11-22) fixed these signatures and the client's
/// closure order. The 2026-11-25 review of the restart-recovery groundwork
/// changed two of them: the intent and the scope binding commit in one
/// transaction, and the exit is optional so a failed launch settles its run.
/// `docs/continuation.md` records that delta.
pub trait Journal {
    fn confirm_intent(&self, invocation: &str, nonce: &str, key: ServiceKey) -> io::Result<()>;
    fn observe_spawn(&self, invocation: &str, child: u32) -> io::Result<()>;
    fn audit_exit(
        &self,
        invocation: &str,
        exit: Option<TargetExit>,
        retired: RetiredService,
    ) -> io::Result<()>;
    /// Retries a failed [`Journal::audit_exit`] with the authority that call
    /// retained, so a commit that failed for a transient reason can land
    /// without a new observation: the retirement value belongs to one launch
    /// and is never reissued. `Ok(false)` means this journal retains nothing
    /// to retry, which is the case for a journal that commits in memory or
    /// for one whose run has already resolved. A journal that cannot retry
    /// must not claim `Ok(true)`. A retry naming another invocation is an
    /// error for a journal that still retains invocation-bound state; one
    /// that holds nothing - the default implementation, or a journal whose run
    /// already resolved - answers `Ok(false)`.
    fn retry_audit(&self, _invocation: &str) -> io::Result<bool> {
        Ok(false)
    }
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
    fn audit_exit(
        &self,
        invocation: &str,
        exit: Option<TargetExit>,
        _retired: RetiredService,
    ) -> io::Result<()> {
        // The retirement value is consumed here; the disposable record
        // cannot serialize it. The pinned serialization keeps the exit
        // durable in the record, and a launch that failed after its intent
        // records that it has no authenticated exit rather than inventing
        // one.
        let encoded = match exit {
            Some(exit) => {
                serde_json::to_string(&exit).map_err(|error| io::Error::other(error.to_string()))?
            }
            None => "unknown".to_owned(),
        };
        self.record(
            &format!("exit-{invocation}"),
            &format!("authenticated target exit: {encoded}"),
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
