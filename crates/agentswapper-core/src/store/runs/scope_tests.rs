#![allow(clippy::unwrap_used)]
use super::*;
use crate::store::{Event, RunCompletion};

fn finished(id: &str, scope: Option<Uuid>, outcome: &str) -> Event {
    Event::RunFinished {
        id: id.to_owned(),
        exit_code: 0,
        outcome: outcome.to_owned(),
        stopped_scope: scope,
    }
}

#[test]
fn local_stop_requires_observed_pid_matching_scope_and_single_completion() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(&temp.path().join("state")).unwrap();
    let profile = store
        .register(Harness::Codex, "work".parse().unwrap())
        .unwrap();
    let lease = store.lease(profile.id).unwrap();
    let scope = LocalScope::WindowsJob { id: Uuid::new_v4() };
    let id = store
        .begin_run_with_scope(&lease, "run", None, Some(scope.clone()))
        .unwrap();
    assert_eq!(store.run(&id).unwrap().local_scope, Some(scope.clone()));
    assert_eq!(store.run(&id).unwrap().custody, ProcessCustody::Unknown);
    // Tests exercise replay validation directly. Production can emit this
    // outcome only by consuming the nonconstructible backend receipt.
    assert!(
        store
            .record(finished(&id, Some(scope.id()), "local_scope_empty"))
            .is_err()
    );
    assert!(
        store
            .finish_run(id.clone(), RunCompletion::FailedToSpawn)
            .is_err()
    );
    store.observe_spawn(&id, 42).unwrap();
    for event in [
        finished(&id, Some(Uuid::new_v4()), "local_scope_empty"),
        finished(&id, None, "local_scope_empty"),
        finished(&id, Some(Uuid::nil()), "local_scope_empty"),
        finished(&id, Some(scope.id()), "exited"),
        finished(&id, None, "exited"),
        finished(&id, None, "external_client_exited"),
    ] {
        assert!(store.record(event).is_err());
    }
    let completion = finished(&id, Some(scope.id()), "local_scope_empty");
    store.record(completion.clone()).unwrap();
    assert_eq!(
        store.run(&id).unwrap().custody,
        ProcessCustody::LocalScopeEmpty
    );
    assert!(store.record(completion).is_err());
    assert!(
        store
            .begin_run_with_scope(&lease, "run", None, Some(scope))
            .is_err()
    );
    assert!(store.verify().unwrap().consistent);
    drop(lease);
    assert!(store.lease(profile.id).is_ok());
}

#[test]
fn scope_cannot_attach_to_gents_legacy_or_uncontained_runs() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(&temp.path().join("state")).unwrap();
    let native = store
        .register(Harness::Claude, "native".parse().unwrap())
        .unwrap();
    let external = store
        .register_gents(
            "external".parse().unwrap(),
            crate::GentsBinding::new("127.0.0.1:9191".parse().unwrap(), "agent".parse().unwrap())
                .unwrap(),
        )
        .unwrap();
    for profile in [&native, &external] {
        let lease = store.lease(profile.id).unwrap();
        let scope = LocalScope::WindowsJob { id: Uuid::new_v4() };
        let event = Event::RunPlanned {
            id: Uuid::new_v4().to_string(),
            profile: profile.id,
            kind: "run".into(),
            requires_spawn_observation: profile.harness == Harness::Gents,
            gents_session: None,
            local_scope: Some(scope.clone()),
        };
        assert!(store.record(event).is_err());
        let id = store.begin_run(&lease, "run").unwrap();
        store.observe_spawn(&id, 42).unwrap();
        assert!(
            store
                .record(finished(&id, Some(scope.id()), "local_scope_empty"))
                .is_err()
        );
        store
            .finish_run(id, RunCompletion::OperatorAttested)
            .unwrap();
    }
    assert!(store.verify().unwrap().consistent);
}

#[test]
fn unresolved_scope_survives_reopen_and_attestation_never_becomes_empty_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    let mut store = Store::open(&root).unwrap();
    let profile = store
        .register(Harness::Kimi, "work".parse().unwrap())
        .unwrap();
    let lease = store.lease(profile.id).unwrap();
    let scope = LocalScope::WindowsJob { id: Uuid::new_v4() };
    let id = store
        .begin_run_with_scope(&lease, "run", None, Some(scope.clone()))
        .unwrap();
    drop(lease);
    drop(store);
    let mut store = Store::open(&root).unwrap();
    assert!(matches!(store.lease(profile.id), Err(Error::Busy)));
    assert_eq!(store.run(&id).unwrap().custody, ProcessCustody::Unknown);
    store.attest_stopped(&id).unwrap();
    let run = store.run(&id).unwrap();
    assert_eq!(run.custody, ProcessCustody::AttestedStopped);
    assert_eq!(run.local_scope, Some(scope));
    assert!(store.verify().unwrap().consistent);
}

#[test]
fn replay_rejects_relabelled_stop_receipt_and_projection_tampering() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(&temp.path().join("state")).unwrap();
    let profile = store
        .register(Harness::Codex, "work".parse().unwrap())
        .unwrap();
    let lease = store.lease(profile.id).unwrap();
    let scope = LocalScope::WindowsJob { id: Uuid::new_v4() };
    let id = store
        .begin_run_with_scope(&lease, "run", None, Some(scope.clone()))
        .unwrap();
    store.observe_spawn(&id, 42).unwrap();
    store
        .record(finished(&id, Some(scope.id()), "local_scope_empty"))
        .unwrap();
    store
        .db
        .execute(
            "UPDATE runs SET local_scope=json_set(local_scope,'$.id',?1)",
            [Uuid::new_v4().to_string()],
        )
        .unwrap();
    assert!(!store.verify().unwrap().consistent);
    store
        .db
        .execute(
            "UPDATE runs SET local_scope=?1",
            [serde_json::to_string(&scope).unwrap()],
        )
        .unwrap();
    store
        .db
        .execute_batch("DROP TRIGGER event_no_update;")
        .unwrap();
    store.db.execute("UPDATE event_log SET payload=json_set(payload,'$.stopped_scope',?1) WHERE json_extract(payload,'$.type')='run_finished'", [Uuid::new_v4().to_string()]).unwrap();
    assert!(matches!(store.verify(), Err(Error::CorruptRegistry)));
}
