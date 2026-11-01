//! Databases produced by clean historical executables, not downgraded current DDL.
#![allow(clippy::unwrap_used)]
use super::*;
use crate::{Store, store::ProcessCustody};

#[test]
fn historical_cli_databases_preserve_history_pending_work_and_backups() {
    let fixtures: [(i64, &[u8], &str); 3] = [
        (
            5,
            include_bytes!("../../../tests/fixtures/historical/schema-5.sqlite3"),
            include_str!("../../../tests/fixtures/historical/schema-5.json"),
        ),
        (
            6,
            include_bytes!("../../../tests/fixtures/historical/schema-6.sqlite3"),
            include_str!("../../../tests/fixtures/historical/schema-6.json"),
        ),
        (
            7,
            include_bytes!("../../../tests/fixtures/historical/schema-7.sqlite3"),
            include_str!("../../../tests/fixtures/historical/schema-7.json"),
        ),
    ];
    for (schema, bytes, provenance) in fixtures {
        let provenance: serde_json::Value = serde_json::from_str(provenance).unwrap();
        assert_eq!(provenance["schema"], schema);
        assert_eq!(provenance["sha256"], format!("{:x}", Sha256::digest(bytes)));
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("state");
        // Initialize a private destination using the platform's normal path and
        // ACL policy; all handles close before copying the historical database.
        drop(Store::open(&root).unwrap());
        let path = root.join("registry.sqlite3");
        std::fs::write(&path, bytes).unwrap();
        let original = super::super::open_registry_read_only(&path).unwrap();
        assert_eq!(
            original
                .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            schema
        );
        let before = history(&original);
        drop(original);
        let upgraded = Store::open(&root).unwrap();
        for profile in upgraded.profiles().unwrap() {
            // The portable fixture contains metadata only, never vendor files.
            private_fs::directory(&root.join("profiles").join(profile.id.to_string()), true)
                .unwrap();
        }
        upgraded.check().unwrap();
        assert_eq!(upgraded.verify().unwrap().schema_version, SCHEMA);
        assert_eq!(upgraded.verify().unwrap().events, 7);
        assert_eq!(history(&upgraded.db), before);
        let records = upgraded.runs(20).unwrap();
        assert_eq!(records.len(), 2);
        for record in &records {
            assert!(record.local_scope.is_none() && record.gents_session.is_none());
            assert!(record.observed_pid.is_some() && record.spawned_at.is_some());
            if record.alias.to_string() == "fixture-completed" {
                assert_eq!(record.exit_code, Some(7));
                assert_eq!(record.outcome.as_deref(), Some("exited"));
                assert_eq!(record.custody, ProcessCustody::ExitedUncontained);
                drop(upgraded.lease(record.profile_id).unwrap());
            } else {
                assert_eq!(record.alias.to_string(), "fixture-pending");
                assert_eq!(record.exit_code, None);
                assert_eq!(record.outcome, None);
                assert_eq!(record.custody, ProcessCustody::Unknown);
                assert!(matches!(
                    upgraded.lease(record.profile_id),
                    Err(Error::Busy)
                ));
            }
        }
        assert_eq!(upgraded.unfinished().unwrap().len(), 1);
        let copies: Vec<_> = std::fs::read_dir(root.join("registry-backups"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(copies.len(), 1);
        let backup = super::super::open_registry_read_only(&copies[0]).unwrap();
        assert_eq!(
            backup
                .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            schema
        );
        assert_eq!(history(&backup), before);
        drop(backup);
        drop(upgraded);
        let reopened = Store::open(&root).unwrap();
        reopened.check().unwrap();
        assert_eq!(reopened.unfinished().unwrap().len(), 1);
        assert_eq!(history(&reopened.db), before);
    }
}

fn history(db: &Connection) -> Vec<(i64, String, String)> {
    let mut query = db
        .prepare("SELECT sequence,payload,recorded_at FROM event_log ORDER BY sequence")
        .unwrap();
    query
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}
