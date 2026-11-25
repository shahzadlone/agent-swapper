//! The Store-backed implementation of the launch client's durable journal
//! seam. The mapping was fixed by the 2026-11-22 independent review: the
//! run intent commits the one-use key into the durable scope association
//! before the launch gate, the spawn observation precedes the held-exec
//! release, and the authenticated target exit commits together with the
//! independently observed scope retirement. A failed commit leaves the run
//! unresolved and blocks profile reuse; the review's retry contract retains
//! the original retirement value for in-place retry.
use agentswapper_core::Error;
use agentswapper_core::domain::{Alias, Harness};
use agentswapper_core::store::linux_scope::TargetExit;
use agentswapper_core::store::{ProfileLease, Store};
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

fn mapped(exit: Option<RuntimeExit>) -> Option<TargetExit> {
    exit.and_then(one)
}

fn one(exit: RuntimeExit) -> Option<TargetExit> {
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
    // The run id exists only once the intent commits; it survives resolution
    // so the caller can report which durable run this launch was.
    run: RefCell<Option<String>>,
    // The Store's instance identity is retained through the pending scope's
    // own Arc; this binding keeps the adapter self-contained.
    _instance: Arc<()>,
}

struct LiveRun {
    lease: Option<ProfileLease>,
    scope: Uuid,
    pending: Option<agentswapper_core::store::linux_scope::PendingLinuxScope>,
    // A failed retirement keeps the pending association, the original
    // observation and the exit that went with it, so a retry reuses the whole
    // tuple it was granted instead of accepting a new one: a fresh receipt
    // belongs to another launch and must never be charged to this run.
    retiring: Option<(
        agentswapper_core::store::linux_scope::PendingLinuxScope,
        RetiredService,
        Option<TargetExit>,
    )>,
}

impl StoreJournal {
    /// Open the Store, find the caller's registered profile and take its
    /// lease. No run is planned here: the intent and its scope binding
    /// commit together at `confirm_intent`, so a launch that fails before
    /// its intent leaves nothing behind for the profile to be blocked on.
    /// The lease is held until the audit completes, and from the intent
    /// onward an unresolved run blocks the profile's reuse by design.
    pub fn open(root: &Path, harness: Harness, alias: &str) -> io::Result<Self> {
        let alias: Alias = alias.parse().map_err(other)?;
        let store = Store::open(root).map_err(other)?;
        // The profile is the caller's existing registration: the helper
        // never creates profiles, it launches through one.
        let profile = store
            .profiles()
            .map_err(other)?
            .into_iter()
            .find(|profile| profile.alias == alias && profile.harness == harness)
            .ok_or_else(|| {
                io::Error::other("no active profile matches the requested harness and alias")
            })?
            .id;
        let lease = store.lease(profile).map_err(other)?;
        Ok(Self {
            store: Mutex::new(store),
            state: RefCell::new(Some(LiveRun {
                lease: Some(lease),
                scope: Uuid::new_v4(),
                pending: None,
                retiring: None,
            })),
            run: RefCell::new(None),
            _instance: Arc::new(()),
        })
    }

    /// The durable run id for bounded diagnostics and the restart-recovery
    /// handoff, or None when the launch never reached its intent and so has
    /// no durable run. Recovery itself stays a separately qualified gate.
    pub fn run(&self) -> Option<String> {
        self.run.borrow().clone()
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
        let scope = live.scope;
        let pending = store.begin_linux_run(lease, scope, key).map_err(other)?;
        *self.run.borrow_mut() = Some(pending.run_id().to_owned());
        live.pending = Some(pending);
        Ok(())
    }

    fn observe_spawn(&self, _invocation: &str, child: u32) -> io::Result<()> {
        let mut store = self
            .store
            .lock()
            .map_err(|_| io::Error::other("the store lock was poisoned before the spawn"))?;
        let run = self
            .run()
            .ok_or_else(|| io::Error::other("the spawn was observed before the intent"))?;
        store.observe_spawn(&run, child).map_err(other)
    }

    fn audit_exit(
        &self,
        _invocation: &str,
        exit: Option<RuntimeExit>,
        retired: RetiredService,
    ) -> io::Result<()> {
        // The retirement commits with the independently observed scope
        // closure; the authenticated exit came from the nonce-bound report
        // that arrived before the observation, and a launch that failed
        // after its intent has none. The run resolves here and the lease
        // drops. A retry after a failed commit reuses the retained pair: the
        // same pending association and the same original observation.
        let mut store = self
            .store
            .lock()
            .map_err(|_| io::Error::other("the store lock was poisoned before the audit"))?;
        let mut state = self.state.borrow_mut();
        let live = state
            .as_mut()
            .ok_or_else(|| io::Error::other("the run already resolved"))?;
        let (pending, retired, exit) = match live.retiring.take() {
            // A retry runs on the retained tuple, whatever the caller passes.
            Some(retained) => retained,
            None => (
                live.pending
                    .take()
                    .ok_or_else(|| io::Error::other("the scope was never bound"))?,
                retired,
                mapped(exit),
            ),
        };
        match store.retire_linux_scope(&pending, retired, exit) {
            Ok(()) => {
                live.lease = None;
                live.pending = None;
                live.retiring = None;
                *state = None;
                Ok(())
            }
            // The retirement is already durable: a lost acknowledgement is
            // the same commit, and reporting it as a failure would keep the
            // lease for the rest of the process's life.
            Err(failure) if matches!(failure.error, Error::ScopeAlreadyRetired) => {
                live.lease = None;
                live.pending = None;
                live.retiring = None;
                *state = None;
                Ok(())
            }
            Err(failure) => {
                live.retiring = Some((pending, failure.retired, exit));
                Err(other(failure.error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// The intent is the durable record's only beginning: opening the journal
    /// and failing before it must not leave a run that blocks the profile.
    /// The old adapter planned the run at open, so a launch refused before its
    /// gate - a signal owner it cannot claim, an endpoint that refuses, a
    /// terminal that closes - left the profile blocked behind a run nothing
    /// would ever resolve.
    #[test]
    fn a_launch_that_never_reaches_its_intent_leaves_no_unfinished_run() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("state");
        let profile = {
            let mut store = Store::open(&root).unwrap();
            store
                .register(Harness::Claude, "work".parse().unwrap())
                .unwrap()
                .id
        };
        let journal = StoreJournal::open(&root, Harness::Claude, "work").unwrap();
        assert_eq!(journal.run(), None);
        drop(journal);
        let mut store = Store::open(&root).unwrap();
        // An unresolved run would refuse this; the profile must be usable.
        let lease = store.lease(profile).unwrap();
        let scope = Uuid::new_v4();
        store
            .begin_run_with_scope(
                &lease,
                "run",
                None,
                Some(agentswapper_core::store::LocalScope::LinuxCgroup { id: scope }),
            )
            .unwrap();
    }
}
