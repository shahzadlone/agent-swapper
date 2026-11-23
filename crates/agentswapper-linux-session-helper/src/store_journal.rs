//! The Store-backed implementation of the launch client's durable journal
//! seam. The mapping was fixed by the 2026-11-22 independent review: the
//! run intent commits the one-use key into the durable scope association
//! before the launch gate, the spawn observation precedes the held-exec
//! release, and the authenticated target exit commits together with the
//! independently observed scope retirement. A failed commit leaves the run
//! unresolved and blocks profile reuse; the review's retry contract retains
//! the original retirement value for in-place retry.
use agentswapper_core::domain::{Alias, Harness};
use agentswapper_core::store::linux_scope::TargetExit;
use agentswapper_core::store::{LocalScope, ProfileLease, Store};
use agentswapper_linux_install::launch_client::Journal;
use agentswapper_linux_manager::{RetiredService, ServiceKey};
use agentswapper_linux_runtime::target_exit::TargetExit as RuntimeExit;
use std::{
    cell::RefCell,
    io,
    path::Path,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

fn other<E: std::fmt::Display>(error: E) -> io::Error {
    io::Error::other(error.to_string())
}

fn mapped(exit: RuntimeExit) -> Option<TargetExit> {
    match exit {
        RuntimeExit::Code { code } => Some(TargetExit::Code { code }),
        RuntimeExit::Signal {
            signal,
            core_dumped,
        } if (1..=64).contains(&signal) => Some(TargetExit::Signal {
            signal,
            core_dumped,
        }),
        RuntimeExit::Signal { .. } => None,
    }
}

/// The adapter's live state. It owns the profile registration, the lease,
/// the run and the pending scope association from construction through the
/// audit; dropping the lease releases it only after the run has resolved.
pub struct StoreJournal {
    store: Mutex<Store>,
    state: RefCell<Option<LiveRun>>,
    // The Store's instance identity is retained through the pending scope's
    // own Arc; this binding keeps the adapter self-contained.
    _instance: Arc<()>,
}

struct LiveRun {
    lease: Option<ProfileLease>,
    run: String,
    pending: Option<agentswapper_core::store::linux_scope::PendingLinuxScope>,
}

impl StoreJournal {
    /// Open the Store, register (or reuse) the profile and begin the run
    /// with a fresh linux cgroup scope. The lease is held until the audit
    /// completes; an unresolved run blocks the profile's reuse by design.
    pub fn open(root: &Path, harness: Harness, alias: &str) -> io::Result<Self> {
        let alias: Alias = alias.parse().map_err(other)?;
        let mut store = Store::open(root).map_err(other)?;
        let profile = store.register(harness, alias).map_err(other)?.id;
        let lease = store.lease(profile).map_err(other)?;
        let run = store
            .begin_run_with_scope(
                &lease,
                "run",
                None,
                Some(LocalScope::LinuxCgroup { id: Uuid::new_v4() }),
            )
            .map_err(other)?;
        Ok(Self {
            store: Mutex::new(store),
            state: RefCell::new(Some(LiveRun {
                lease: Some(lease),
                run,
                pending: None,
            })),
            _instance: Arc::new(()),
        })
    }

    /// The durable run id for bounded diagnostics and the restart-recovery
    /// handoff. Recovery itself stays a separately qualified gate.
    pub fn run(&self) -> io::Result<String> {
        Ok(self
            .state
            .borrow()
            .as_ref()
            .ok_or_else(|| io::Error::other("the run already resolved"))?
            .run
            .clone())
    }
}

impl Journal for StoreJournal {
    fn confirm_intent(&self, _invocation: &str, _nonce: &str, key: ServiceKey) -> io::Result<()> {
        // The client's flow binds before the gate; the adapter commits the
        // key into the durable scope association here, where it cannot be
        // extracted or serialized. A failed bind consumes the key into the
        // pending association's error contract; the run stays unresolved and
        // is never re-launched (the review's contract).
        let mut store = self
            .store
            .lock()
            .map_err(|_| io::Error::other("the store lock was poisoned before the intent"))?;
        let mut state = self.state.borrow_mut();
        let live = state
            .as_mut()
            .ok_or_else(|| io::Error::other("the run already resolved"))?;
        let lease = live
            .lease
            .as_ref()
            .ok_or_else(|| io::Error::other("the profile lease was released before the intent"))?;
        let pending = store
            .bind_linux_scope(&live.run, lease, key)
            .map_err(other)?;
        live.pending = Some(pending);
        Ok(())
    }

    fn observe_spawn(&self, _invocation: &str, child: u32) -> io::Result<()> {
        let mut store = self
            .store
            .lock()
            .map_err(|_| io::Error::other("the store lock was poisoned before the spawn"))?;
        let run = self.run()?;
        store.observe_spawn(&run, child).map_err(other)
    }

    fn audit_exit(
        &self,
        _invocation: &str,
        exit: RuntimeExit,
        retired: RetiredService,
    ) -> io::Result<()> {
        // The exit commits together with the independently observed scope
        // retirement; the authenticated exit came from the nonce-bound
        // report that arrived before the retirement observation. The run
        // resolves here and the lease drops.
        let mut store = self
            .store
            .lock()
            .map_err(|_| io::Error::other("the store lock was poisoned before the audit"))?;
        let mut state = self.state.borrow_mut();
        let live = state
            .as_mut()
            .ok_or_else(|| io::Error::other("the run already resolved"))?;
        let pending = live
            .pending
            .as_ref()
            .ok_or_else(|| io::Error::other("the scope was never bound"))?;
        store
            .retire_linux_scope(pending, retired, mapped(exit))
            .map_err(|failure| other(failure.error))?;
        live.lease = None;
        live.pending = None;
        *state = None;
        Ok(())
    }
}
