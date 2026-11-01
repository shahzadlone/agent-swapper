//! Durable Linux admission diagnostics. Only the qualification consumer accepts
//! opaque runtime receipts; these serializable fields confer no authority.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LinuxBinding {
    pub unit: String,
    pub invocation: [u8; 16],
    pub user: u32,
    pub guardian: u32,
    pub device: u64,
    pub inode: u64,
}
impl LinuxBinding {
    pub(super) fn validate(&self) -> Result<()> {
        if self.unit.len() > 255
            || !self
                .unit
                .strip_suffix(".service")
                .is_some_and(|stem| !stem.is_empty())
            || !self
                .unit
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:@\\-".contains(&byte))
            || self.invocation == [0; 16]
            || self.user == 0
            || self.user > i32::MAX as u32
            || self.guardian <= 1
            || self.guardian > i32::MAX as u32
            || self.device == 0
            || self.inode == 0
        {
            return Err(Error::CorruptRegistry);
        }
        Ok(())
    }
}

#[cfg(all(target_os = "linux", feature = "linux-journal-qualification"))]
pub(super) use live::PendingLinuxScope;

#[cfg(all(target_os = "linux", feature = "linux-journal-qualification"))]
mod live {
    use super::*;
    use crate::store::{Event, LocalScope, ProfileLease, Store};
    use agentswapper_linux_manager::{RetiredService, ServiceKey};
    use std::sync::Arc;
    use uuid::Uuid;

    /// Original live association. It cannot be serialized or reconstructed by
    /// reopening the registry after a crash.
    pub(crate) struct PendingLinuxScope {
        store: Arc<()>,
        key: ServiceKey,
        run: String,
        scope: Uuid,
        binding: LinuxBinding,
    }
    #[must_use = "failed completion retains its original retirement value for retry"]
    pub(crate) struct ScopeRetireFailure {
        pub error: Error,
        pub retired: RetiredService,
    }
    impl std::fmt::Debug for ScopeRetireFailure {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ScopeRetireFailure")
                .field("error", &self.error)
                .finish_non_exhaustive()
        }
    }
    impl Store {
        pub(crate) fn bind_linux_scope(
            &mut self,
            run: &str,
            lease: &ProfileLease,
            key: ServiceKey,
        ) -> Result<PendingLinuxScope> {
            let record = self.run(run)?;
            let Some(LocalScope::LinuxCgroup { id: scope }) = record.local_scope else {
                return Err(Error::ScopeReceiptMismatch);
            };
            if record.profile_id != lease.profile
                || record.outcome.is_some()
                || record.observed_pid.is_some()
            {
                return Err(Error::Busy);
            }
            let identity = key.identity();
            let (device, inode) = key.directory_identity();
            let binding = LinuxBinding {
                unit: identity.unit,
                invocation: identity.invocation,
                user: identity.user,
                guardian: identity.main_pid,
                device,
                inode,
            };
            self.record_lifecycle(Event::LinuxScopeBound {
                id: run.to_owned(),
                binding: binding.clone(),
            })?;
            Ok(PendingLinuxScope {
                store: Arc::clone(&self.scope_instance),
                key,
                run: run.to_owned(),
                scope,
                binding,
            })
        }

        pub(crate) fn retire_linux_scope(
            &mut self,
            pending: &PendingLinuxScope,
            retired: RetiredService,
        ) -> std::result::Result<(), Box<ScopeRetireFailure>> {
            let result = (|| -> Result<()> {
                if !Arc::ptr_eq(&self.scope_instance, &pending.store)
                    || !retired.matches(&pending.key)
                {
                    return Err(Error::ScopeReceiptMismatch);
                }
                let observed = retired.observation();
                let identity = retired.identity();
                let binding = LinuxBinding {
                    unit: identity.unit,
                    invocation: identity.invocation,
                    user: identity.user,
                    guardian: identity.main_pid,
                    device: observed.device,
                    inode: observed.inode,
                };
                if binding != pending.binding
                    || !observed.original_directory_removed
                    || !observed.main_pidfd_exited
                {
                    return Err(Error::ScopeReceiptMismatch);
                }
                // The event and its projection commit atomically. Unknown target
                // exit remains NULL; only the independently observed scope closes.
                self.record_lifecycle(Event::LinuxScopeRetired {
                    id: pending.run.clone(),
                    scope: pending.scope,
                    binding,
                })
            })();
            match result {
                Ok(()) => Ok(()),
                Err(error) => Err(Box::new(ScopeRetireFailure { error, retired })),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{
        Harness,
        store::{Event, LocalScope, ProcessCustody, RunCompletion, Store},
    };
    use uuid::Uuid;

    fn binding() -> LinuxBinding {
        LinuxBinding {
            unit: "aswp@1-42-1000.service".into(),
            invocation: [7; 16],
            user: 1000,
            guardian: 42,
            device: 25,
            inode: 128,
        }
    }

    #[test]
    fn retirement_without_target_status_closes_only_the_original_run() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        let profile = store
            .register(Harness::Codex, "work".parse().unwrap())
            .unwrap();
        let lease = store.lease(profile.id).unwrap();
        let scope = Uuid::new_v4();
        let run = store
            .begin_run_with_scope(
                &lease,
                "run",
                None,
                Some(LocalScope::LinuxCgroup { id: scope }),
            )
            .unwrap();
        let finish = Event::LinuxScopeRetired {
            id: run.clone(),
            scope,
            binding: binding(),
        };
        assert!(store.record(finish.clone()).is_err());
        store
            .record(Event::LinuxScopeBound {
                id: run.clone(),
                binding: binding(),
            })
            .unwrap();
        store.observe_spawn(&run, 43).unwrap();
        assert!(
            store
                .finish_run(run.clone(), RunCompletion::ChildExited(0))
                .is_err()
        );
        store.record(finish.clone()).unwrap();
        let record = store.run(&run).unwrap();
        assert_eq!(record.custody, ProcessCustody::LocalScopeEmpty);
        assert_eq!(record.exit_code, None);
        assert_eq!(record.observed_pid, Some(43));
        assert!(matches!(store.lease(profile.id), Err(Error::Busy)));
        drop(lease);
        assert!(store.unfinished().unwrap().is_empty());
        let lease = store.lease(profile.id).unwrap();
        let next = store.begin_run(&lease, "run").unwrap();
        assert!(store.record(finish).is_err());
        assert!(store.observe_spawn(&run, 44).is_err());
        assert!(store.attest_stopped(&run).is_err());
        assert_eq!(store.run(&next).unwrap().custody, ProcessCustody::Unknown);
        assert!(store.verify().unwrap().consistent);
    }

    #[test]
    fn mismatched_retirement_rolls_back_every_event_and_projection() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        let profile = store
            .register(Harness::Claude, "work".parse().unwrap())
            .unwrap();
        let lease = store.lease(profile.id).unwrap();
        let scope = Uuid::new_v4();
        let run = store
            .begin_run_with_scope(
                &lease,
                "run",
                None,
                Some(LocalScope::LinuxCgroup { id: scope }),
            )
            .unwrap();
        store
            .record(Event::LinuxScopeBound {
                id: run.clone(),
                binding: binding(),
            })
            .unwrap();
        let events = store.verify().unwrap().events;
        for field in 0..8 {
            let mut wrong = binding();
            let mut claimed_scope = scope;
            match field {
                0 => wrong.unit = "other@1.service".into(),
                1 => wrong.invocation[0] ^= 1,
                2 => wrong.user += 1,
                3 => wrong.guardian += 1,
                4 => wrong.device += 1,
                5 => wrong.inode += 1,
                6 => claimed_scope = Uuid::new_v4(),
                _ => claimed_scope = Uuid::nil(),
            }
            assert!(
                store
                    .record(Event::LinuxScopeRetired {
                        id: run.clone(),
                        scope: claimed_scope,
                        binding: wrong
                    })
                    .is_err()
            );
            assert_eq!(store.verify().unwrap().events, events);
            assert_eq!(store.run(&run).unwrap().custody, ProcessCustody::Unknown);
        }
        // Retirement before a target was observed also preserves an unknown
        // target outcome. Scope emptiness does not imply successful execution.
        store
            .record(Event::LinuxScopeRetired {
                id: run.clone(),
                scope,
                binding: binding(),
            })
            .unwrap();
        assert_eq!(store.run(&run).unwrap().exit_code, None);
        assert_eq!(store.run(&run).unwrap().observed_pid, None);
        assert!(store.verify().unwrap().consistent);
    }
}
