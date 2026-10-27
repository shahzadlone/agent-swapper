#![allow(clippy::unwrap_used)]

use super::*;
use crate::{Harness, Store};
use proptest::prelude::*;
use rusqlite::params;

fn setup() -> (tempfile::TempDir, Store) {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("state")).unwrap();
    (temp, store)
}

fn event_count(db: &Connection) -> i64 {
    db.query_row("SELECT count(*) FROM event_log", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn thousand_event_replay_preserves_all_columns_and_unfinished_runs() {
    let (temp, mut s) = setup();
    for index in 0..100 {
        let p = s
            .register(
                Harness::ALL[index % 3],
                format!("p-{index}").parse().unwrap(),
            )
            .unwrap();
        s.map(&p.alias, temp.path()).unwrap();
        s.rename(&p.alias, format!("renamed-{index}").parse().unwrap())
            .unwrap();
        let p = s
            .profiles()
            .unwrap()
            .into_iter()
            .find(|x| x.id == p.id)
            .unwrap();
        s.enable(&p.alias, false).unwrap();
        s.enable(&p.alias, true).unwrap();
        let lease = s.lease(p.id).unwrap();
        let run = s
            .begin_run(&lease, if index % 2 == 0 { "run" } else { "login" })
            .unwrap();
        s.finish_run(run, 7, "exited").unwrap();
        drop(lease);
        s.unmap(temp.path()).unwrap();
        s.map(&p.alias, temp.path()).unwrap();
        s.remove(&p.alias).unwrap();
    }
    let p = s
        .register(Harness::Codex, "pending".parse().unwrap())
        .unwrap();
    let lease = s.lease(p.id).unwrap();
    s.begin_run(&lease, "run").unwrap();
    let before = projection_dump(&s.db).unwrap();
    // Any accidental write to live projections makes verification fail.
    for table in ["profiles", "runs", "mappings"] {
        for action in ["INSERT", "UPDATE", "DELETE"] {
            s.db.execute_batch(&format!("CREATE TEMP TRIGGER guard_{table}_{action} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'verification must not write'); END;")).unwrap();
        }
    }
    let report = s.verify().unwrap();
    assert!(report.consistent);
    assert_eq!(report.events, 1002);
    assert_eq!(projection_dump(&s.db).unwrap(), before);
    assert_eq!(s.unfinished().unwrap().len(), 1);
}

#[test]
fn mismatched_projection_blocks_launch_without_appending_an_intent() {
    let (_temp, mut s) = setup();
    let p = s
        .register(Harness::Claude, "work".parse().unwrap())
        .unwrap();
    let lease = s.lease(p.id).unwrap();
    s.db.execute("UPDATE profiles SET alias='tampered'", [])
        .unwrap();
    let report = s.verify().unwrap();
    assert!(!report.consistent);
    assert_eq!(report.mismatched_tables, ["profiles"]);
    assert!(matches!(
        s.begin_run(&lease, "run"),
        Err(Error::ProjectionMismatch)
    ));
    assert_eq!(event_count(&s.db), 1);
    assert!(s.unfinished().unwrap().is_empty());
}

#[test]
fn malformed_journals_and_newer_schema_fail_closed() {
    for (payload, timestamp, sequence) in [
        (
            r#"{"type":"future_event"}"#.to_owned(),
            "2026-01-01T00:00:00.000Z",
            2,
        ),
        (
            r#"{"type":"enabled","id":"00000000-0000-0000-0000-000000000000","enabled":true}"#
                .to_owned(),
            "2026-01-01T00:00:00.000Z",
            2,
        ),
        (
            r#"{"type":"unmapped","directory":"relative"}"#.to_owned(),
            "2026-01-01T00:00:00.000Z",
            2,
        ),
        (
            " ".repeat(MAX_EVENT_BYTES + 1) + "{}",
            "2026-01-01T00:00:00.000Z",
            2,
        ),
        (
            r#"{"type":"run_planned","id":"invalid","kind":"run"}"#.to_owned(),
            "bad",
            2,
        ),
    ] {
        let (_temp, mut s) = setup();
        s.register(Harness::Claude, "work".parse().unwrap())
            .unwrap();
        s.db.execute(
            "INSERT INTO event_log(sequence,payload,recorded_at) VALUES(?1,?2,?3)",
            params![sequence, payload, timestamp],
        )
        .unwrap();
        assert!(s.verify().is_err());
    }
    let (_temp, mut s) = setup();
    s.db.execute("INSERT INTO event_log(sequence,payload) VALUES(2,'{}')", [])
        .unwrap();
    assert!(matches!(s.verify(), Err(Error::CorruptRegistry)));
    s.db.pragma_update(None, "user_version", 999).unwrap();
    assert!(matches!(
        s.register(Harness::Kimi, "new".parse().unwrap()),
        Err(Error::NewerSchema)
    ));
    assert_eq!(event_count(&s.db), 1);
    s.db.pragma_update(None, "user_version", 1).unwrap();
    assert!(matches!(
        s.register(Harness::Kimi, "new".parse().unwrap()),
        Err(Error::RegistrySchemaChanged)
    ));
}

#[test]
fn unknown_fields_bad_timestamps_and_impossible_removals_are_rejected() {
    for fault in ["field", "timestamp", "removal"] {
        let (_temp, mut s) = setup();
        let p = s.register(Harness::Kimi, "work".parse().unwrap()).unwrap();
        if fault == "removal" {
            let lease = s.lease(p.id).unwrap();
            s.begin_run(&lease, "run").unwrap();
            let event = Event::Removed { id: p.id };
            s.db.execute(
                "INSERT INTO event_log(payload) VALUES(?1)",
                [serde_json::to_string(&event).unwrap()],
            )
            .unwrap();
        } else {
            s.db.execute_batch("DROP TRIGGER event_no_update").unwrap();
            if fault == "field" {
                s.db.execute(
                    "UPDATE event_log SET payload=json_set(payload,'$.profile.unrecognized',true)",
                    [],
                )
                .unwrap();
            } else {
                s.db.execute("UPDATE event_log SET recorded_at='bad'", [])
                    .unwrap();
            }
        }
        assert!(matches!(s.verify(), Err(Error::CorruptRegistry)));
    }
}

fn legacy(root: &Path) -> (Connection, String) {
    private_fs::directory(root, true).unwrap();
    let path = root.join("registry.sqlite3");
    private_fs::file(&path).unwrap();
    let db = Connection::open(path).unwrap();
    db.pragma_update(None, "journal_mode", "WAL").unwrap();
    db.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
    db.execute_batch(include_str!("../../../tests/fixtures/registry_v1.sql"))
        .unwrap();
    db.execute_batch(include_str!("../../../tests/fixtures/registry_v1_seed.sql"))
        .unwrap();
    assert!(
        std::fs::metadata(root.join("registry.sqlite3-wal"))
            .unwrap()
            .len()
            > 0
    );
    (db, "cafe0000-0000-4000-8000-000000000002".to_owned())
}

fn backups(root: &Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(root.join("registry-backups"))
        .unwrap()
        .map(|x| x.unwrap().path())
        .collect()
}

#[test]
fn v1_upgrade_backs_up_wal_and_preserves_pending_intents() {
    let temp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(temp.path()).unwrap().join("state");
    let (mut db, run) = legacy(&root);
    let before = projection_dump(&db).unwrap();
    migrate_v1(&mut db, &root).unwrap();
    assert!(verify(&db).unwrap().consistent);
    let files = backups(&root);
    assert_eq!(files.len(), 1);
    private_fs::validate_file(&files[0]).unwrap();
    let backup = Connection::open(&files[0]).unwrap();
    assert_eq!(
        backup
            .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        1
    );
    assert_eq!(projection_dump(&backup).unwrap(), before);
    assert_eq!(event_count(&backup), 2);
    let (time, exit): (String, Option<i32>) = db
        .query_row(
            "SELECT started_at,exit_code FROM runs WHERE id=?1",
            [&run],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let recorded: String = db
        .query_row(
            "SELECT recorded_at FROM event_log WHERE sequence=2",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(time, recorded);
    assert_eq!(exit, None);
    drop(backup);
    drop(db);
    let store = Store::open(&root).unwrap();
    assert!(store.verify().unwrap().consistent);
    assert_eq!(store.unfinished().unwrap()[0].id, run);
    assert_eq!(backups(&root).len(), 1);
}

#[test]
fn every_append_refuses_mismatch_and_schema_drift_without_poisoning_log() {
    for fault in ["runs", "mappings", "schema", "retired"] {
        let (temp, mut s) = setup();
        let p = s
            .register(Harness::Claude, "work".parse().unwrap())
            .unwrap();
        s.map(&p.alias, temp.path()).unwrap();
        let lease = s.lease(p.id).unwrap();
        let run = s.begin_run(&lease, "run").unwrap();
        match fault {
            "runs" => {
                s.db.execute("UPDATE runs SET started_at='changed'", [])
                    .unwrap();
            }
            "mappings" => {
                s.db.execute("DELETE FROM mappings", []).unwrap();
            }
            "schema" => {
                s.db.execute_batch("DROP INDEX unique_alias").unwrap();
            }
            "retired" => {
                s.db.execute("UPDATE profiles SET retired=1", []).unwrap();
            }
            _ => unreachable!(),
        }
        let count = event_count(&s.db);
        assert!(matches!(
            s.finish_run(run, 0, "exited"),
            Err(Error::ProjectionMismatch)
        ));
        assert!(matches!(
            s.register(Harness::Kimi, "other".parse().unwrap()),
            Err(Error::ProjectionMismatch)
        ));
        assert_eq!(event_count(&s.db), count);
        assert_eq!(replay(&s.db).unwrap().1 as i64, count);
    }
}

#[test]
fn invalid_legacy_log_and_orphan_rows_leave_source_unchanged() {
    for fault in ["unknown_event", "orphan"] {
        let temp = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(temp.path()).unwrap().join("state");
        let (db, _) = legacy(&root);
        if fault == "unknown_event" {
            db.execute(
                "INSERT INTO event_log(payload) VALUES('{\"type\":\"future\"}')",
                [],
            )
            .unwrap();
        } else {
            db.execute(
                "INSERT INTO runs(id,profile,kind,exit_code) SELECT ?1,id,'run',0 FROM profiles",
                [Uuid::new_v4().to_string()],
            )
            .unwrap();
        }
        let before = projection_dump(&db).unwrap();
        let events = event_count(&db);
        drop(db);
        assert!(Store::open(&root).is_err());
        let db = Connection::open(root.join("registry.sqlite3")).unwrap();
        assert_eq!(
            db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            1
        );
        assert_eq!(projection_dump(&db).unwrap(), before);
        assert_eq!(event_count(&db), events);
    }
}

#[test]
fn interleaved_pending_runs_and_failed_appends_keep_a_contiguous_log() {
    let (temp, mut s) = setup();
    let first = s
        .register(Harness::Claude, "first".parse().unwrap())
        .unwrap();
    let second = s
        .register(Harness::Codex, "second".parse().unwrap())
        .unwrap();
    let lease_a = s.lease(first.id).unwrap();
    let lease_b = s.lease(second.id).unwrap();
    let a = s.begin_run(&lease_a, "run").unwrap();
    let b = s.begin_run(&lease_b, "login").unwrap();
    let before = event_count(&s.db);
    assert!(matches!(
        s.register(Harness::Kimi, first.alias.clone()),
        Err(Error::DuplicateAlias)
    ));
    assert!(matches!(s.unmap(temp.path()), Err(Error::MappingNotFound)));
    assert!(matches!(
        s.record(Event::Removed { id: first.id }),
        Err(Error::Busy)
    ));
    assert_eq!(event_count(&s.db), before);
    s.finish_run(b, 0, "exited").unwrap();
    assert!(s.verify().unwrap().consistent);
    assert_eq!(s.unfinished().unwrap()[0].id, a);
    s.finish_run(a, 126, "spawn_failed").unwrap();
    assert!(s.verify().unwrap().consistent);
}

#[test]
fn failed_migration_rolls_back_every_source_write_and_retains_backup() {
    let temp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(temp.path()).unwrap().join("state");
    let (mut db, _) = legacy(&root);
    db.execute_batch("CREATE TRIGGER injected_failure BEFORE UPDATE ON runs BEGIN SELECT RAISE(ABORT,'injected write failure'); END;").unwrap();
    let before = projection_dump(&db).unwrap();
    assert!(migrate_v1(&mut db, &root).is_err());
    assert_eq!(projection_dump(&db).unwrap(), before);
    assert_eq!(
        db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        1
    );
    assert_eq!(event_count(&db), 2);
    assert_eq!(backups(&root).len(), 1);
    drop(db);
    for _ in 0..2 {
        assert!(Store::open(&root).is_err());
    }
    assert_eq!(backups(&root).len(), 1);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn arbitrary_valid_lifecycles_replay_exactly(operations in prop::collection::vec(0_u8..8, 0..40)) {
        let (temp, mut s) = setup();
        let mut p = s.register(Harness::Claude, "work".parse().unwrap()).unwrap();
        for (index, op) in operations.into_iter().enumerate() {
            match op {
                0 => { p = s.rename(&p.alias, format!("p-{index}").parse().unwrap()).unwrap(); }
                1 => { p = s.enable(&p.alias, !p.enabled).unwrap(); }
                2 => { s.map(&p.alias, temp.path()).unwrap(); }
                3 => { if !s.mappings().unwrap().is_empty() { s.unmap(temp.path()).unwrap(); } }
                4..=6 if p.enabled => {
                    let lease = s.lease(p.id).unwrap();
                    let id = s.begin_run(&lease, if op == 4 { "login" } else { "run" }).unwrap();
                    let (code, outcome) = match op { 4 => (126,"spawn_failed"), 5 => (125,"user_attested_stopped"), _ => (0,"exited") };
                    s.finish_run(id, code, outcome).unwrap();
                }
                7 => { s.remove(&p.alias).unwrap(); p = s.register(Harness::ALL[index%3], "work".parse().unwrap()).unwrap(); }
                _ => {}
            }
            prop_assert!(s.verify().unwrap().consistent);
        }
    }
}
