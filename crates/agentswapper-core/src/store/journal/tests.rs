#![allow(clippy::unwrap_used)]

use super::*;
use crate::{Harness, Store, store::RunCompletion};
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
                Harness::NATIVE[index % 3],
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
        s.observe_spawn(&run, index as u32 + 1).unwrap();
        s.finish_run(run, RunCompletion::ChildExited(7)).unwrap();
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
    // SQLite itself rejects a write to the source connection during verify.
    s.db.pragma_update(None, "query_only", true).unwrap();
    let report = s.verify().unwrap();
    assert!(report.consistent);
    assert_eq!(report.events, 1102);
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
    configure(&db).unwrap();
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

fn old_dump(db: &Connection) -> Result<Vec<Vec<Vec<rusqlite::types::Value>>>> {
    projection_dump_with_run_fields(
        db,
        "id,alias,harness,enabled,retired",
        "id,profile,kind,exit_code,outcome,started_at",
    )
}

#[test]
fn v1_upgrade_backs_up_wal_and_preserves_pending_intents() {
    let temp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(temp.path()).unwrap().join("state");
    let (mut db, run) = legacy(&root);
    let before = old_dump(&db).unwrap();
    migrate(&mut db, &root, 1).unwrap();
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
    assert_eq!(old_dump(&backup).unwrap(), before);
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
            s.finish_run(run, RunCompletion::ChildExited(0)),
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
fn peer_connection_edits_invalidate_a_previously_verified_writer() {
    for edit in [
        "UPDATE profiles SET alias='tampered'",
        "DROP INDEX unique_alias",
        "INSERT INTO event_log(payload) VALUES('{}')",
    ] {
        let (_temp, mut first) = setup();
        first
            .register(Harness::Claude, "work".parse().unwrap())
            .unwrap();
        let peer = Connection::open(first.root().join("registry.sqlite3")).unwrap();
        peer.execute_batch(edit).unwrap();
        let count = event_count(&peer);
        assert!(matches!(
            first.register(Harness::Codex, "other".parse().unwrap()),
            Err(Error::ProjectionMismatch | Error::CorruptRegistry)
        ));
        assert_eq!(event_count(&peer), count);
    }
}

#[test]
fn peer_commits_and_rolled_back_attempts_preserve_full_replay() {
    let (_temp, mut first) = setup();
    let p = first
        .register(Harness::Claude, "work".parse().unwrap())
        .unwrap();
    let mut peer = Store::open(first.root()).unwrap();
    peer.rename(&p.alias, "renamed".parse().unwrap()).unwrap();
    first
        .register(Harness::Codex, "other".parse().unwrap())
        .unwrap();
    assert!(matches!(
        first.register(Harness::Kimi, "other".parse().unwrap()),
        Err(Error::DuplicateAlias)
    ));
    first.enable(&"renamed".parse().unwrap(), false).unwrap();
    peer.register(Harness::Kimi, "last".parse().unwrap())
        .unwrap();
    assert!(first.verify().unwrap().consistent);
    assert!(peer.verify().unwrap().consistent);
    assert_eq!(event_count(&first.db), 5);
}

#[test]
fn cached_writer_checks_peer_commit_after_acquiring_the_write_lock() {
    let (_temp, mut first) = setup();
    first
        .register(Harness::Claude, "work".parse().unwrap())
        .unwrap();
    let mut peer = Connection::open(first.root().join("registry.sqlite3")).unwrap();
    let tx = peer
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    tx.execute("UPDATE profiles SET alias='tampered'", [])
        .unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let worker_barrier = barrier.clone();
    let worker = std::thread::spawn(move || {
        worker_barrier.wait();
        first.register(Harness::Codex, "other".parse().unwrap())
    });
    barrier.wait();
    tx.commit().unwrap();
    assert!(matches!(
        worker.join().unwrap(),
        Err(Error::ProjectionMismatch)
    ));
    assert_eq!(event_count(&peer), 1);
}

#[test]
fn cached_writes_refuse_temporary_shadows_and_changed_connection_semantics() {
    let (_temp, mut s) = setup();
    s.register(Harness::Claude, "work".parse().unwrap())
        .unwrap();
    s.db.execute("CREATE TEMP TABLE profiles(id TEXT)", [])
        .unwrap();
    assert_eq!(
        s.verify().unwrap().mismatched_tables,
        ["temp.sqlite_schema"]
    );
    assert!(matches!(
        s.register(Harness::Codex, "other".parse().unwrap()),
        Err(Error::ProjectionMismatch)
    ));
    assert_eq!(event_count(&s.db), 1);
    for (name, value) in [
        ("foreign_keys", false),
        ("recursive_triggers", false),
        ("ignore_check_constraints", true),
        ("defer_foreign_keys", true),
    ] {
        let (_temp, mut s) = setup();
        s.register(Harness::Claude, "work".parse().unwrap())
            .unwrap();
        s.db.pragma_update(None, name, value).unwrap();
        assert!(
            matches!(
                s.register(Harness::Codex, "other".parse().unwrap()),
                Err(Error::RegistryConnectionChanged)
            ),
            "{name}"
        );
        assert_eq!(event_count(&s.db), 1);
    }
}

#[test]
fn baseline_reuse_and_invalidation_are_exercised_including_commit_failure() {
    let (_temp, mut s) = setup();
    let p = s
        .register(Harness::Claude, "work".parse().unwrap())
        .unwrap();
    assert_eq!(s.full_write_checks, 1);
    s.enable(&p.alias, false).unwrap();
    assert_eq!(s.full_write_checks, 1);
    assert!(matches!(
        s.register(Harness::Codex, p.alias.clone()),
        Err(Error::DuplicateAlias)
    ));
    s.enable(&p.alias, true).unwrap();
    assert_eq!(s.full_write_checks, 2);
    // SQLite rejects commit after the stamp was captured. No success baseline
    // may be published for that transaction.
    let before = event_count(&s.db);
    s.db.commit_hook(Some(|| true)).unwrap();
    assert!(
        s.register(Harness::Kimi, "aborted".parse().unwrap())
            .is_err()
    );
    s.db.commit_hook(None::<fn() -> bool>).unwrap();
    assert_eq!(event_count(&s.db), before);
    s.register(Harness::Kimi, "last".parse().unwrap()).unwrap();
    assert_eq!(s.full_write_checks, 3);
    let peer = Connection::open(s.root().join("registry.sqlite3")).unwrap();
    peer.execute(
        "UPDATE profiles SET alias='tampered' WHERE alias='last'",
        [],
    )
    .unwrap();
    assert!(matches!(
        s.register(Harness::Codex, "after".parse().unwrap()),
        Err(Error::ProjectionMismatch)
    ));
    assert_eq!(s.full_write_checks, 4);
}

#[test]
fn warm_cache_still_refuses_a_peer_schema_version_change() {
    let (_temp, mut s) = setup();
    s.register(Harness::Claude, "work".parse().unwrap())
        .unwrap();
    let peer = Connection::open(s.root().join("registry.sqlite3")).unwrap();
    peer.pragma_update(None, "user_version", 999).unwrap();
    assert!(matches!(
        s.register(Harness::Kimi, "after".parse().unwrap()),
        Err(Error::NewerSchema)
    ));
    assert_eq!(event_count(&peer), 1);
}

#[test]
fn schema_comparison_preserves_token_boundaries_and_quoted_contents() {
    assert_ne!(
        sql_tokens("enabled INTEGERNOT NULL"),
        sql_tokens("enabled INTEGER NOT NULL")
    );
    assert_ne!(sql_tokens("DEFAULT 'a b'"), sql_tokens("DEFAULT 'ab'"));
    assert_eq!(sql_tokens("CHECK (a > 0)"), sql_tokens("CHECK(a>0)"));
    let (_temp, s) = setup();
    s.db.execute_batch("PRAGMA writable_schema=ON; UPDATE sqlite_schema SET sql=replace(sql,'enabled INTEGER NOT NULL','enabled INTEGERNOT NULL') WHERE name='profiles'; PRAGMA writable_schema=OFF;").unwrap();
    assert_eq!(s.verify().unwrap().mismatched_tables, ["sqlite_schema"]);
    let (_temp, s) = setup();
    s.db.execute("CREATE TABLE sqliteXextra(value TEXT)", [])
        .unwrap();
    assert_eq!(s.verify().unwrap().mismatched_tables, ["sqlite_schema"]);
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
        let before = old_dump(&db).unwrap();
        let events = event_count(&db);
        drop(db);
        assert!(Store::open(&root).is_err());
        let db = Connection::open(root.join("registry.sqlite3")).unwrap();
        assert_eq!(
            db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            1
        );
        assert_eq!(old_dump(&db).unwrap(), before);
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
    s.observe_spawn(&b, 42).unwrap();
    s.finish_run(b, RunCompletion::ChildExited(0)).unwrap();
    assert!(s.verify().unwrap().consistent);
    assert_eq!(s.unfinished().unwrap()[0].id, a);
    s.finish_run(a, RunCompletion::FailedToSpawn).unwrap();
    assert!(s.verify().unwrap().consistent);
}

#[test]
fn failed_migration_rolls_back_every_source_write_and_retains_backup() {
    let temp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(temp.path()).unwrap().join("state");
    let (mut db, _) = legacy(&root);
    db.execute_batch("CREATE TRIGGER injected_failure BEFORE UPDATE ON runs BEGIN SELECT RAISE(ABORT,'injected write failure'); END;").unwrap();
    let before = old_dump(&db).unwrap();
    assert!(migrate(&mut db, &root, 1).is_err());
    assert_eq!(old_dump(&db).unwrap(), before);
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

#[test]
fn v2_upgrade_preserves_history_without_inventing_spawn_observations() {
    let temp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(temp.path()).unwrap().join("state");
    private_fs::directory(&root, true).unwrap();
    let path = root.join("registry.sqlite3");
    private_fs::file(&path).unwrap();
    let db = Connection::open(&path).unwrap();
    db.execute_batch(include_str!("../../../tests/fixtures/registry_v2.sql"))
        .unwrap();
    db.execute_batch(include_str!("../../../tests/fixtures/registry_v2_seed.sql"))
        .unwrap();
    db.execute(
        "UPDATE runs SET started_at=(SELECT recorded_at FROM event_log WHERE sequence=2)",
        [],
    )
    .unwrap();
    let before = old_dump(&db).unwrap();
    drop(db);
    let s = Store::open(&root).unwrap();
    let run = s.runs(20).unwrap().pop().unwrap();
    assert_eq!(run.custody, crate::store::ProcessCustody::Unknown);
    assert_eq!(run.observed_pid, None);
    assert_eq!(run.spawned_at, None);
    assert_eq!(old_dump(&s.db).unwrap(), before);
    let files = backups(&root);
    assert_eq!(files.len(), 1);
    assert!(
        files[0]
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("schema-2-")
    );
    let backup = Connection::open(&files[0]).unwrap();
    assert_eq!(old_dump(&backup).unwrap(), before);
    assert_eq!(
        backup
            .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        2
    );
}

#[test]
fn both_legacy_versions_preserve_every_historical_outcome() {
    use crate::store::ProcessCustody;
    for (ddl, seed) in [
        (
            include_str!("../../../tests/fixtures/registry_v1.sql"),
            include_str!("../../../tests/fixtures/registry_v1_seed.sql"),
        ),
        (
            include_str!("../../../tests/fixtures/registry_v2.sql"),
            include_str!("../../../tests/fixtures/registry_v2_seed.sql"),
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(temp.path()).unwrap().join("state");
        private_fs::directory(&root, true).unwrap();
        private_fs::file(&root.join("registry.sqlite3")).unwrap();
        let db = Connection::open(root.join("registry.sqlite3")).unwrap();
        db.execute_batch(ddl).unwrap();
        db.execute_batch(seed).unwrap();
        db.execute_batch(include_str!(
            "../../../tests/fixtures/registry_legacy_outcomes.sql"
        ))
        .unwrap();
        drop(db);
        let s = Store::open(&root).unwrap();
        let records = s.runs(20).unwrap();
        assert_eq!(
            records.iter().map(|r| r.custody).collect::<Vec<_>>(),
            [
                ProcessCustody::Unknown,
                ProcessCustody::AttestedStopped,
                ProcessCustody::NeverStarted,
                ProcessCustody::ExitedUncontained,
            ]
        );
        assert!(
            records
                .iter()
                .all(|r| r.observed_pid.is_none() && r.spawned_at.is_none())
        );
        assert_eq!(s.unfinished().unwrap().len(), 1);
        assert!(s.verify().unwrap().consistent);
    }
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
                    if op != 4 { s.observe_spawn(&id,index as u32 + 1).unwrap(); }
                    let (code, outcome) = match op { 4 => (126,"spawn_failed"), 5 => (125,"user_attested_stopped"), _ => (0,"exited") };
                    s.finish_run(id, match outcome { "exited"=>RunCompletion::ChildExited(code), "spawn_failed"=>RunCompletion::FailedToSpawn, _=>RunCompletion::OperatorAttested }).unwrap();
                }
                7 => { s.remove(&p.alias).unwrap(); p = s.register(Harness::NATIVE[index%3], "work".parse().unwrap()).unwrap(); }
                _ => {}
            }
            prop_assert!(s.verify().unwrap().consistent);
        }
    }
}

fn legacy_v3(root: &Path) -> Connection {
    private_fs::directory(root, true).unwrap();
    private_fs::file(&root.join("registry.sqlite3")).unwrap();
    let db = Connection::open(root.join("registry.sqlite3")).unwrap();
    configure(&db).unwrap();
    db.pragma_update(None, "journal_mode", "WAL").unwrap();
    db.execute_batch(include_str!("../../../tests/fixtures/registry_v3.sql"))
        .unwrap();
    db.execute_batch(include_str!("../../../tests/fixtures/registry_v2_seed.sql"))
        .unwrap();
    db.execute_batch("INSERT INTO event_log(payload) VALUES('{\"type\":\"run_spawned\",\"id\":\"cafe0000-0000-4000-8000-000000000002\",\"pid\":42}');
        UPDATE runs SET observed_pid=42,spawned_at=(SELECT recorded_at FROM event_log WHERE sequence=3);").unwrap();
    db.execute_batch(r#"
        INSERT INTO event_log(payload) VALUES('{"type":"registered","profile":{"id":"cafe0000-0000-4000-8000-000000000005","alias":"side","harness":"codex","enabled":true}}');
        INSERT INTO profiles(id,alias,harness,enabled) VALUES('cafe0000-0000-4000-8000-000000000005','side','codex',1);
        INSERT INTO event_log(payload) VALUES('{"type":"run_planned","id":"cafe0000-0000-4000-8000-000000000006","profile":"cafe0000-0000-4000-8000-000000000005","kind":"run","requires_spawn_observation":true}');
        INSERT INTO runs(id,profile,kind,started_at,requires_spawn_observation) VALUES('cafe0000-0000-4000-8000-000000000006','cafe0000-0000-4000-8000-000000000005','run',(SELECT recorded_at FROM event_log WHERE sequence=5),1);
        INSERT INTO event_log(payload) VALUES('{"type":"run_spawned","id":"cafe0000-0000-4000-8000-000000000006","pid":123}');
        UPDATE runs SET observed_pid=123,spawned_at=(SELECT recorded_at FROM event_log WHERE sequence=6) WHERE id='cafe0000-0000-4000-8000-000000000006';
        INSERT INTO event_log(payload) VALUES('{"type":"run_finished","id":"cafe0000-0000-4000-8000-000000000006","exit_code":7,"outcome":"exited"}');
        UPDATE runs SET exit_code=7,outcome='exited' WHERE id='cafe0000-0000-4000-8000-000000000006';
        INSERT INTO event_log(payload) VALUES('{"type":"removed","id":"cafe0000-0000-4000-8000-000000000005"}');
        UPDATE profiles SET retired=1 WHERE id='cafe0000-0000-4000-8000-000000000005';
        INSERT INTO event_log(payload) VALUES('{"type":"registered","profile":{"id":"cafe0000-0000-4000-8000-000000000007","alias":"side","harness":"kimi","enabled":true}}');
        INSERT INTO profiles(id,alias,harness,enabled) VALUES('cafe0000-0000-4000-8000-000000000007','side','kimi',1);
    "#).unwrap();
    let directory = root.parent().unwrap().to_str().unwrap();
    let mapping = serde_json::json!({"type":"mapped","profile":"cafe0000-0000-4000-8000-000000000007","directory":directory});
    db.execute(
        "INSERT INTO event_log(payload) VALUES(?1)",
        [mapping.to_string()],
    )
    .unwrap();
    db.execute(
        "INSERT INTO mappings(directory,profile) VALUES(?1,'cafe0000-0000-4000-8000-000000000007')",
        [directory],
    )
    .unwrap();
    db
}

fn v3_dump(db: &Connection) -> Vec<Vec<Vec<Value>>> {
    projection_dump_with_run_fields(db, "id,alias,harness,enabled,retired", "id,profile,kind,exit_code,outcome,started_at,observed_pid,spawned_at,requires_spawn_observation").unwrap()
}

#[test]
fn v3_upgrade_preserves_observed_pending_run_and_exact_backup() {
    let temp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(temp.path()).unwrap().join("state");
    let mut db = legacy_v3(&root);
    let before = v3_dump(&db);
    migrate(&mut db, &root, 3).unwrap();
    assert_eq!(v3_dump(&db), before);
    assert_eq!(verify(&db).unwrap().schema_version, 6);
    assert!(verify(&db).unwrap().consistent);
    assert_eq!(backups(&root).len(), 1);
    let backup = Connection::open(&backups(&root)[0]).unwrap();
    assert_eq!(v3_dump(&backup), before);
    assert_eq!(
        backup
            .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        3
    );
    assert_eq!(event_count(&backup), 10);
    assert!(
        db.prepare("PRAGMA foreign_key_check")
            .unwrap()
            .query([])
            .unwrap()
            .next()
            .unwrap()
            .is_none()
    );
}

#[test]
fn v3_migration_does_not_erase_projection_or_schema_tampering() {
    for mutation in [
        "UPDATE profiles SET alias='tampered' WHERE alias='legacy'",
        "UPDATE runs SET observed_pid=99",
        "CREATE INDEX injected ON runs(kind)",
        "DROP INDEX unique_alias",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(temp.path()).unwrap().join("state");
        let mut db = legacy_v3(&root);
        db.execute_batch(mutation).unwrap();
        let before = v3_dump(&db);
        let schema = schema_dump(&db).unwrap();
        assert!(migrate(&mut db, &root, 3).is_err(), "{mutation}");
        assert_eq!(v3_dump(&db), before);
        assert_eq!(schema_dump(&db).unwrap(), schema);
        assert_eq!(
            db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            3
        );
        assert_eq!(backups(&root).len(), 1);
    }
}

#[test]
fn gents_rebinding_is_leased_durable_and_keeps_home_identity() {
    use crate::GentsBinding;
    let binding = |port| {
        GentsBinding::new(
            format!("127.0.0.1:{port}").parse().unwrap(),
            "web_persona".parse().unwrap(),
        )
        .unwrap()
    };
    let (_temp, mut s) = setup();
    let p = s
        .register_gents("relay".parse().unwrap(), binding(9191))
        .unwrap();
    let home = s.profile_home(p.id).unwrap();
    assert!(
        s.record(Event::RunPlanned {
            local_scope: None,
            id: Uuid::new_v4().to_string(),
            profile: p.id,
            kind: "run".to_owned(),
            requires_spawn_observation: false,
            gents_session: None,
        })
        .is_err()
    );
    assert!(matches!(
        s.register_gents("duplicate".parse().unwrap(), binding(9191)),
        Err(Error::DuplicateRuntime)
    ));
    let lease = s.lease(p.id).unwrap();
    assert!(matches!(
        s.bind_gents(&p.alias, binding(9192)),
        Err(Error::Busy)
    ));
    let run = s.begin_run(&lease, "run").unwrap();
    drop(lease);
    assert!(matches!(
        s.bind_gents(&p.alias, binding(9192)),
        Err(Error::Busy)
    ));
    s.attest_stopped(&run).unwrap();
    assert_eq!(
        s.run(&run).unwrap().custody,
        crate::store::ProcessCustody::ExternalRuntimeUnknown
    );
    let updated = s.bind_gents(&p.alias, binding(9192)).unwrap();
    assert_eq!(updated.id, p.id);
    assert_eq!(s.profile_home(updated.id).unwrap(), home);
    assert_eq!(updated.gents, Some(binding(9192)));
    assert!(s.verify().unwrap().consistent);
    let other = s
        .register_gents("other".parse().unwrap(), binding(9193))
        .unwrap();
    assert!(matches!(
        s.bind_gents(&p.alias, binding(9193)),
        Err(Error::DuplicateRuntime)
    ));
    s.remove(&other.alias).unwrap();
    assert_eq!(s.bind_gents(&p.alias, binding(9193)).unwrap().id, p.id);
    assert!(s.verify().unwrap().consistent);
    s.db.execute(
        "UPDATE profiles SET gents=json_set(gents,'$.address','127.0.0.1:9999')",
        [],
    )
    .unwrap();
    assert_eq!(s.verify().unwrap().mismatched_tables, ["profiles"]);
    assert!(matches!(
        s.enable(&p.alias, false),
        Err(Error::ProjectionMismatch)
    ));
}

#[test]
fn v3_with_v1_default_and_appended_columns_upgrades_without_losing_history() {
    let temp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(temp.path()).unwrap().join("state");
    let (mut db, _) = legacy(&root);
    // Exact prior 1->3 migration shape from f780f97: retain the unused default.
    db.execute_batch("UPDATE runs SET started_at=(SELECT recorded_at FROM event_log WHERE sequence=2);
        ALTER TABLE runs ADD COLUMN observed_pid INTEGER CHECK(observed_pid>0);
        ALTER TABLE runs ADD COLUMN spawned_at TEXT;
        ALTER TABLE runs ADD COLUMN requires_spawn_observation INTEGER NOT NULL DEFAULT 0 CHECK(requires_spawn_observation IN (0,1));
        PRAGMA user_version=3;").unwrap();
    let before = v3_dump(&db);
    migrate(&mut db, &root, 3).unwrap();
    assert_eq!(v3_dump(&db), before);
    assert!(verify(&db).unwrap().consistent);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]
    #[test]
    fn gents_lifecycles_rebind_and_replay(operations in prop::collection::vec(0_u8..9, 0..24)) {
        let (_temp, mut s) = setup();
        let binding = |port| crate::GentsBinding::new(format!("127.0.0.1:{port}").parse().unwrap(), "web_persona".parse().unwrap()).unwrap();
        let mut p = s.register_gents("relay".parse().unwrap(), binding(9191)).unwrap();
        for (index, op) in operations.into_iter().enumerate() {
            match op {
                0 => p = s.bind_gents(&p.alias, binding(9191 + index)).unwrap(),
                1 => p = s.enable(&p.alias, !p.enabled).unwrap(),
                2..=4 if p.enabled => {
                    let lease = s.lease(p.id).unwrap();
                    let id = s.begin_run(&lease, "run").unwrap();
                    if op != 2 { s.observe_spawn(&id, index as u32 + 1).unwrap(); }
                    s.finish_run(id.clone(), match op {
                        2 => RunCompletion::FailedToSpawn,
                        3 => RunCompletion::OperatorAttested,
                        _ => RunCompletion::ExternalClientExited(0),
                    }).unwrap();
                    prop_assert_eq!(s.run(&id).unwrap().custody, crate::store::ProcessCustody::ExternalRuntimeUnknown);
                }
                7..=8 if p.enabled => {
                    let session = if op == 7 {
                        match s.latest_gents_session(p.id) {
                            Ok(candidate) => crate::store::GentsSession::new(candidate.session.id(), p.gents.clone().unwrap(), Some(candidate.run_id)),
                            Err(Error::NoRecordedSession | Error::SessionNotResumable | Error::SessionBindingChanged) => {
                                prop_assert!(s.verify().unwrap().consistent);
                                continue;
                            }
                            Err(error) => return Err(TestCaseError::fail(error.to_string())),
                        }
                    } else {
                        crate::store::GentsSession::new(Uuid::new_v4(), p.gents.clone().unwrap(), None)
                    };
                    let lease = s.lease(p.id).unwrap();
                    let id = s.begin_run_with_session(&lease, "run", Some(session)).unwrap();
                    s.observe_spawn(&id, index as u32 + 1).unwrap();
                    s.finish_run(id, RunCompletion::ExternalClientExited(0)).unwrap();
                }
                5 => p = s.rename(&p.alias, format!("relay-{index}").parse().unwrap()).unwrap(),
                6 => { s.remove(&p.alias).unwrap(); p = s.register_gents("relay".parse().unwrap(), binding(9191)).unwrap(); }
                _ => {}
            }
            prop_assert!(s.verify().unwrap().consistent);
        }
    }
}

fn legacy_v4(root: &Path) -> Connection {
    private_fs::directory(root, true).unwrap();
    private_fs::file(&root.join("registry.sqlite3")).unwrap();
    let db = Connection::open(root.join("registry.sqlite3")).unwrap();
    configure(&db).unwrap();
    db.pragma_update(None, "journal_mode", "WAL").unwrap();
    db.execute_batch(include_str!("../../../tests/fixtures/registry_v4.sql"))
        .unwrap();
    db.execute_batch(include_str!("../../../tests/fixtures/registry_v4_seed.sql"))
        .unwrap();
    db
}
fn v4_dump(db: &Connection) -> Vec<Vec<Vec<Value>>> {
    projection_dump_with_run_fields(db, "id,alias,harness,enabled,retired,gents", "id,profile,kind,exit_code,outcome,started_at,observed_pid,spawned_at,requires_spawn_observation").unwrap()
}

#[test]
fn v4_upgrade_preserves_gents_binding_and_native_pending_history_without_inventing_sessions() {
    let temp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(temp.path()).unwrap().join("state");
    let mut db = legacy_v4(&root);
    let before = v4_dump(&db);
    migrate(&mut db, &root, 4).unwrap();
    assert_eq!(v4_dump(&db), before);
    assert!(verify(&db).unwrap().consistent);
    assert_eq!(verify(&db).unwrap().schema_version, 6);
    assert_eq!(backups(&root).len(), 1);
    let backup = Connection::open(&backups(&root)[0]).unwrap();
    assert_eq!(v4_dump(&backup), before);
    assert_eq!(
        backup
            .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        4
    );
    assert_eq!(event_count(&backup), 8);
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT count(*) FROM runs WHERE gents_session IS NOT NULL",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
    // Migration still leaves the legacy gents session explicitly unknown.
    assert!(matches!(
        super::super::sessions::latest(
            &db,
            "cafe0000-0000-4000-8000-000000000001".parse().unwrap()
        ),
        Err(Error::NoRecordedSession)
    ));
}

#[test]
fn v4_failed_migration_rolls_back_schema_and_rows_and_keeps_backup() {
    for mutation in [
        "UPDATE profiles SET gents=json_set(gents,'$.agent','tampered') WHERE harness='gents'",
        "UPDATE runs SET observed_pid=99",
        "CREATE INDEX injected ON runs(kind)",
        "DROP INDEX unique_gents_address",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(temp.path()).unwrap().join("state");
        let mut db = legacy_v4(&root);
        db.execute_batch(mutation).unwrap();
        let before = v4_dump(&db);
        let schema = schema_dump(&db).unwrap();
        assert!(migrate(&mut db, &root, 4).is_err(), "{mutation}");
        assert_eq!(v4_dump(&db), before);
        assert_eq!(schema_dump(&db).unwrap(), schema);
        assert_eq!(
            db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            4
        );
        assert_eq!(backups(&root).len(), 1);
    }
}

#[test]
fn migrated_pending_gents_run_requires_reconciliation_and_retains_unknown_session() {
    let temp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(temp.path()).unwrap().join("state");
    let db = legacy_v4(&root);
    db.execute_batch(r#"
        INSERT INTO event_log(payload,recorded_at) VALUES('{"type":"run_planned","id":"cafe0000-0000-4000-8000-000000000009","profile":"cafe0000-0000-4000-8000-000000000001","kind":"run","requires_spawn_observation":true}', '2026-01-01T00:00:08.000Z');
        INSERT INTO runs(id,profile,kind,started_at,requires_spawn_observation) VALUES('cafe0000-0000-4000-8000-000000000009','cafe0000-0000-4000-8000-000000000001','run','2026-01-01T00:00:08.000Z',1);
    "#).unwrap();
    drop(db);
    let mut s = Store::open(&root).unwrap();
    let p = s.find(&"relay".parse().unwrap()).unwrap();
    // Fixture creates the vendor home that a real schema-4 profile already owns.
    private_fs::directory(&root.join("profiles").join(p.id.to_string()), true).unwrap();
    assert!(matches!(
        s.latest_gents_session(p.id),
        Err(Error::NoRecordedSession)
    ));
    assert!(matches!(s.lease(p.id), Err(Error::Busy)));
    s.attest_stopped("cafe0000-0000-4000-8000-000000000009")
        .unwrap();
    assert!(matches!(
        s.latest_gents_session(p.id),
        Err(Error::NoRecordedSession)
    ));
    let lease = s.lease(p.id).unwrap();
    let session = crate::store::GentsSession::new(Uuid::new_v4(), p.gents.unwrap(), None);
    let id = s
        .begin_run_with_session(&lease, "run", Some(session.clone()))
        .unwrap();
    s.observe_spawn(&id, 44).unwrap();
    s.finish_run(id, RunCompletion::ExternalClientExited(0))
        .unwrap();
    assert_eq!(s.latest_gents_session(p.id).unwrap().session, session);
}

fn legacy_v5(root: &Path) -> Connection {
    let mut store = Store::open(root).unwrap();
    let native = store
        .register(Harness::Codex, "native".parse().unwrap())
        .unwrap();
    let external = store
        .register_gents(
            "external".parse().unwrap(),
            crate::GentsBinding::new("127.0.0.1:9191".parse().unwrap(), "agent".parse().unwrap())
                .unwrap(),
        )
        .unwrap();
    {
        let lease = store.lease(external.id).unwrap();
        let session =
            crate::store::GentsSession::new(Uuid::new_v4(), external.gents.unwrap(), None);
        let id = store
            .begin_run_with_session(&lease, "run", Some(session))
            .unwrap();
        store.observe_spawn(&id, 42).unwrap();
        store
            .finish_run(id, RunCompletion::ExternalClientExited(0))
            .unwrap();
    }
    {
        let lease = store.lease(native.id).unwrap();
        store.begin_run(&lease, "run").unwrap();
    }
    // No scope metadata was emitted. Restore the exact previous projection DDL.
    store.db.execute_batch("DROP INDEX unique_local_scope; ALTER TABLE runs DROP COLUMN local_scope; PRAGMA user_version=5;").unwrap();
    let expected = Connection::open_in_memory().unwrap();
    expected
        .execute_batch(include_str!("../schema_v5.sql"))
        .unwrap();
    assert_eq!(
        schema_dump(&store.db).unwrap(),
        schema_dump(&expected).unwrap()
    );
    store.db
}

fn v5_dump(db: &Connection) -> Vec<Vec<Vec<Value>>> {
    projection_dump_with_run_fields(db, "id,alias,harness,enabled,retired,gents", "id,profile,kind,exit_code,outcome,started_at,observed_pid,spawned_at,requires_spawn_observation,gents_session").unwrap()
}

#[test]
fn v5_migration_keeps_sessions_and_pending_intents_without_inventing_custody() {
    let temp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(temp.path()).unwrap().join("state");
    let mut db = legacy_v5(&root);
    let before = v5_dump(&db);
    migrate(&mut db, &root, 5).unwrap();
    assert_eq!(v5_dump(&db), before);
    assert!(verify(&db).unwrap().consistent);
    assert_eq!(verify(&db).unwrap().schema_version, 6);
    assert_eq!(backups(&root).len(), 1);
    let backup = Connection::open(&backups(&root)[0]).unwrap();
    assert_eq!(v5_dump(&backup), before);
    assert_eq!(
        backup
            .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        5
    );
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT count(*) FROM runs WHERE local_scope IS NOT NULL",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
    drop(db);
    let store = Store::open(&root).unwrap();
    let native = store.find(&"native".parse().unwrap()).unwrap();
    assert!(matches!(store.lease(native.id), Err(Error::Busy)));
    let external = store.find(&"external".parse().unwrap()).unwrap();
    assert!(store.latest_gents_session(external.id).is_ok());
}

#[test]
fn v5_failed_migration_preserves_original_schema_rows_and_backup() {
    for mutation in [
        "UPDATE runs SET observed_pid=99 WHERE observed_pid IS NOT NULL",
        "UPDATE runs SET gents_session=json_set(gents_session,'$.id','cafe0000-0000-4000-8000-000000000099') WHERE gents_session IS NOT NULL",
        "CREATE INDEX injected ON runs(kind)",
        "DROP INDEX unique_gents_address",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(temp.path()).unwrap().join("state");
        let mut db = legacy_v5(&root);
        db.execute_batch(mutation).unwrap();
        let before = v5_dump(&db);
        let schema = schema_dump(&db).unwrap();
        assert!(migrate(&mut db, &root, 5).is_err(), "{mutation}");
        assert_eq!(v5_dump(&db), before);
        assert_eq!(schema_dump(&db).unwrap(), schema);
        assert_eq!(
            db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            5
        );
        assert_eq!(backups(&root).len(), 1);
    }
}
