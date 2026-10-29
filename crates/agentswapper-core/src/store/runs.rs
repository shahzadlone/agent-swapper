use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(test)]
use super::RunCompletion;
use super::{Store, journal};
use crate::{Alias, Error, Harness, ProfileId, Result};

#[cfg(test)]
mod scope_tests;

/// Durable local-process observations never establish external-work custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessCustody {
    Unknown,
    ExitedUncontained,
    ExternalRuntimeUnknown,
    NeverStarted,
    AttestedStopped,
    LocalScopeEmpty,
}

/// Planned local process ownership. This metadata is not a stop receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalScope {
    WindowsJob { id: Uuid },
    LinuxCgroup { id: Uuid },
}

impl LocalScope {
    pub fn id(&self) -> Uuid {
        match self {
            Self::WindowsJob { id } | Self::LinuxCgroup { id } => *id,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunRecord {
    pub id: String,
    pub profile_id: ProfileId,
    pub alias: Alias,
    pub harness: Harness,
    pub kind: String,
    pub started_at: String,
    pub spawned_at: Option<String>,
    /// Diagnostic observation only. Never use a stored PID to signal a process.
    pub observed_pid: Option<u32>,
    pub exit_code: Option<i32>,
    pub outcome: Option<String>,
    pub custody: ProcessCustody,
    pub gents_session: Option<super::GentsSession>,
    pub local_scope: Option<LocalScope>,
}

impl Store {
    /// Recent runs include retired profiles and use a single verified snapshot.
    pub fn runs(&self, limit: u16) -> Result<Vec<RunRecord>> {
        if !(1..=200).contains(&limit) {
            return Err(Error::InvalidHistoryLimit);
        }
        self.read_runs(None, limit)
    }

    pub fn run(&self, id: &str) -> Result<RunRecord> {
        let id = Uuid::parse_str(id)
            .map_err(|_| Error::RunNotFound)?
            .to_string();
        self.read_runs(Some(&id), 1)?
            .pop()
            .ok_or(Error::RunNotFound)
    }

    fn read_runs(&self, id: Option<&str>, limit: u16) -> Result<Vec<RunRecord>> {
        let snapshot = self.db.unchecked_transaction()?;
        if !journal::verify_snapshot(&snapshot)?.consistent {
            return Err(Error::ProjectionMismatch);
        }
        let runs = query_runs(&snapshot, id, limit)?;
        snapshot.commit()?;
        Ok(runs)
    }
}

fn query_runs(db: &Connection, id: Option<&str>, limit: u16) -> Result<Vec<RunRecord>> {
    let mut query = db.prepare("SELECT r.id,r.profile,p.alias,p.harness,r.kind,r.started_at,r.spawned_at,r.observed_pid,r.exit_code,r.outcome,r.gents_session,r.local_scope FROM main.runs r JOIN main.profiles p ON p.id=r.profile JOIN main.event_log e ON json_extract(e.payload,'$.type')='run_planned' AND json_extract(e.payload,'$.id')=r.id WHERE (?1 IS NULL OR r.id=?1) ORDER BY e.sequence DESC LIMIT ?2")?;
    let mut rows = query.query(params![id, limit])?;
    let mut records = Vec::new();
    while let Some(row) = rows.next()? {
        let profile: String = row.get(1)?;
        let alias: String = row.get(2)?;
        let harness: String = row.get(3)?;
        let outcome: Option<String> = row.get(9)?;
        let custody = match outcome.as_deref() {
            Some("spawn_failed" | "user_attested_stopped") if harness == "gents" => {
                ProcessCustody::ExternalRuntimeUnknown
            }
            None => ProcessCustody::Unknown,
            Some("exited") => ProcessCustody::ExitedUncontained,
            Some("local_scope_empty") => ProcessCustody::LocalScopeEmpty,
            Some("external_client_exited") => ProcessCustody::ExternalRuntimeUnknown,
            Some("spawn_failed") => ProcessCustody::NeverStarted,
            Some("user_attested_stopped") => ProcessCustody::AttestedStopped,
            _ => return Err(Error::CorruptRegistry),
        };
        records.push(RunRecord {
            id: row.get(0)?,
            profile_id: profile.parse()?,
            alias: alias.parse()?,
            harness: harness.parse()?,
            kind: row.get(4)?,
            started_at: row.get(5)?,
            spawned_at: row.get(6)?,
            observed_pid: row.get(7)?,
            exit_code: row.get(8)?,
            outcome,
            custody,
            local_scope: row
                .get::<_, Option<String>>(11)?
                .map(|json| serde_json::from_str(&json))
                .transpose()
                .map_err(|_| Error::CorruptRegistry)?,
            gents_session: row
                .get::<_, Option<String>>(10)?
                .map(|json| serde_json::from_str(&json))
                .transpose()
                .map_err(|_| Error::CorruptRegistry)?,
        });
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::Harness;

    #[test]
    fn linux_scope_cannot_be_finished_with_a_windows_or_uncontained_receipt() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        let profile = store
            .register(Harness::Codex, "work".parse().unwrap())
            .unwrap();
        let lease = store.lease(profile.id).unwrap();
        let scope = Uuid::new_v4();
        let id = store
            .begin_run_with_scope(
                &lease,
                "run",
                None,
                Some(LocalScope::LinuxCgroup { id: scope }),
            )
            .unwrap();
        store.observe_spawn(&id, 42).unwrap();
        assert!(
            store
                .finish_run(id.clone(), RunCompletion::ChildExited(0))
                .is_err()
        );
        assert!(
            store
                .record(crate::store::Event::RunFinished {
                    id: id.clone(),
                    exit_code: 0,
                    outcome: "local_scope_empty".to_owned(),
                    stopped_scope: Some(scope),
                })
                .is_err()
        );
        assert_eq!(store.run(&id).unwrap().custody, ProcessCustody::Unknown);
        assert!(store.verify().unwrap().consistent);
    }

    #[test]
    fn observations_do_not_promote_direct_exits_or_attestations_to_verified_custody() {
        let temp = tempfile::tempdir().unwrap();
        let mut s = Store::open(&temp.path().join("state")).unwrap();
        let p = s
            .register(Harness::Claude, "work".parse().unwrap())
            .unwrap();
        for (outcome, code, custody) in [
            ("exited", 0, ProcessCustody::ExitedUncontained),
            (
                "user_attested_stopped",
                125,
                ProcessCustody::AttestedStopped,
            ),
            ("spawn_failed", 126, ProcessCustody::NeverStarted),
        ] {
            let lease = s.lease(p.id).unwrap();
            let id = s.begin_run(&lease, "run").unwrap();
            assert_eq!(s.run(&id).unwrap().custody, ProcessCustody::Unknown);
            assert!(
                s.finish_run(id.clone(), RunCompletion::ChildExited(0))
                    .is_err()
            );
            if outcome != "spawn_failed" {
                s.observe_spawn(&id, 42).unwrap();
                let record = s.run(&id).unwrap();
                assert_eq!(record.custody, ProcessCustody::Unknown);
                assert_eq!(record.observed_pid, Some(42));
                assert!(record.spawned_at.is_some());
                assert!(s.observe_spawn(&id, 43).is_err());
                assert!(
                    s.finish_run(id.clone(), RunCompletion::FailedToSpawn)
                        .is_err()
                );
            }
            s.finish_run(
                id.clone(),
                match outcome {
                    "exited" => RunCompletion::ChildExited(code),
                    "spawn_failed" => RunCompletion::FailedToSpawn,
                    _ => RunCompletion::OperatorAttested,
                },
            )
            .unwrap();
            assert_eq!(s.run(&id).unwrap().custody, custody);
            assert!(s.observe_spawn(&id, 42).is_err());
            drop(lease);
        }
        s.remove(&p.alias).unwrap();
        assert_eq!(s.runs(2).unwrap().len(), 2);
        assert_eq!(s.runs(200).unwrap().len(), 3);
        assert!(matches!(s.runs(0), Err(Error::InvalidHistoryLimit)));
        assert!(matches!(s.run("invalid"), Err(Error::RunNotFound)));
        assert!(s.verify().unwrap().consistent);
    }

    #[test]
    fn history_uses_journal_order_across_clock_rewind_and_vacuum() {
        let temp = tempfile::tempdir().unwrap();
        let mut s = Store::open(&temp.path().join("state")).unwrap();
        let p = s.register(Harness::Codex, "work".parse().unwrap()).unwrap();
        let lease = s.lease(p.id).unwrap();
        let first = s.begin_run(&lease, "run").unwrap();
        s.finish_run(first.clone(), RunCompletion::FailedToSpawn)
            .unwrap();
        let second = s.begin_run(&lease, "run").unwrap();
        s.db.execute_batch("DROP TRIGGER event_no_update;").unwrap();
        s.db.execute("UPDATE main.event_log SET recorded_at='1999-01-01T00:00:00.000Z' WHERE json_extract(payload,'$.type')='run_planned' AND json_extract(payload,'$.id')=?1",[&second]).unwrap();
        s.db.execute(
            "UPDATE main.runs SET started_at='1999-01-01T00:00:00.000Z' WHERE id=?1",
            [&second],
        )
        .unwrap();
        s.db.execute_batch("CREATE TRIGGER event_no_update BEFORE UPDATE ON event_log BEGIN SELECT RAISE(ABORT, 'append-only event log'); END; VACUUM;").unwrap();
        assert_eq!(s.runs(1).unwrap()[0].id, second);
        assert_eq!(s.run(&first.to_uppercase()).unwrap().id, first);
    }
}

#[cfg(test)]
mod engine_custody_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn journal_refuses_cross_engine_exit_labels_and_unobserved_clients() {
        let temp = tempfile::tempdir().unwrap();
        let mut s = Store::open(&temp.path().join("state")).unwrap();
        let native = s
            .register(Harness::Codex, "native".parse().unwrap())
            .unwrap();
        let external = s
            .register_gents(
                "external".parse().unwrap(),
                crate::GentsBinding::new(
                    "127.0.0.1:9191".parse().unwrap(),
                    "agent".parse().unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        for profile in [native, external] {
            let lease = s.lease(profile.id).unwrap();
            let id = s.begin_run(&lease, "run").unwrap();
            assert!(
                s.finish_run(id.clone(), RunCompletion::ExternalClientExited(0))
                    .is_err()
            );
            s.observe_spawn(&id, 42).unwrap();
            if profile.harness == Harness::Gents {
                assert!(
                    s.finish_run(id.clone(), RunCompletion::ChildExited(0))
                        .is_err()
                );
                s.finish_run(id.clone(), RunCompletion::ExternalClientExited(7))
                    .unwrap();
                let record = s.run(&id).unwrap();
                assert_eq!(record.exit_code, Some(7));
                assert_eq!(record.custody, ProcessCustody::ExternalRuntimeUnknown);
            } else {
                assert!(
                    s.finish_run(id.clone(), RunCompletion::ExternalClientExited(0))
                        .is_err()
                );
                s.finish_run(id, RunCompletion::ChildExited(0)).unwrap();
            }
            drop(lease);
            assert!(s.lease(profile.id).is_ok());
            assert!(s.verify().unwrap().consistent);
        }
    }
}
