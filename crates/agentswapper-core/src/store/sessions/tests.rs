#![allow(clippy::unwrap_used)]
use super::*;
use crate::{
    Profile,
    store::{Event, ProcessCustody, RunCompletion},
};

fn binding(port: u16) -> GentsBinding {
    GentsBinding::new(
        format!("127.0.0.1:{port}").parse().unwrap(),
        "worker".parse().unwrap(),
    )
    .unwrap()
}
fn setup() -> (tempfile::TempDir, Store, Profile) {
    let temp = tempfile::tempdir().unwrap();
    let mut store = Store::open(&temp.path().join("state")).unwrap();
    let profile = store
        .register_gents("relay".parse().unwrap(), binding(9191))
        .unwrap();
    (temp, store, profile)
}
fn complete(store: &mut Store, p: &Profile, session: Option<GentsSession>) -> Uuid {
    let lease = store.lease(p.id).unwrap();
    let run = store
        .begin_run_with_session(&lease, "run", session)
        .unwrap();
    store.observe_spawn(&run, 42).unwrap();
    store
        .finish_run(run.clone(), RunCompletion::ExternalClientExited(0))
        .unwrap();
    run.parse().unwrap()
}
fn new_session() -> GentsSession {
    GentsSession::new(Uuid::new_v4(), binding(9191), None)
}

#[test]
fn resume_chain_is_durable_replayable_and_survives_rename() {
    let (temp, mut s, p) = setup();
    let session = new_session();
    let first = complete(&mut s, &p, Some(session.clone()));
    let renamed = s.rename(&p.alias, "renamed".parse().unwrap()).unwrap();
    assert_eq!(s.latest_gents_session(p.id).unwrap().run_id, first);
    let second = complete(
        &mut s,
        &renamed,
        Some(GentsSession::new(session.id, binding(9191), Some(first))),
    );
    let third = complete(
        &mut s,
        &renamed,
        Some(GentsSession::new(session.id, binding(9191), Some(second))),
    );
    drop(s);
    let s = Store::open(&temp.path().join("state")).unwrap();
    let candidate = s.latest_gents_session(p.id).unwrap();
    assert_eq!(candidate.run_id, third);
    assert_eq!(candidate.session.id, session.id);
    assert_eq!(candidate.session.resumed_from, Some(second));
    let run = s.run(&third.to_string()).unwrap();
    assert_eq!(run.alias, renamed.alias);
    assert_eq!(run.custody, ProcessCustody::ExternalRuntimeUnknown);
    // Read-only source verification also reconstructs prior resume decisions.
    s.db.pragma_update(None, "query_only", true).unwrap();
    assert!(s.verify().unwrap().consistent);
}

#[test]
fn latest_attempt_never_falls_back_past_uncertain_failed_or_legacy_runs() {
    for outcome in ["pending", "spawn_failed", "attested", "nonzero", "legacy"] {
        let (_temp, mut s, p) = setup();
        assert!(matches!(
            s.latest_gents_session(p.id),
            Err(Error::NoRecordedSession)
        ));
        complete(&mut s, &p, Some(new_session()));
        let lease = s.lease(p.id).unwrap();
        let session = (outcome != "legacy").then(new_session);
        let run = s
            .begin_run_with_session(&lease, "run", session.clone())
            .unwrap();
        assert_eq!(s.run(&run).unwrap().gents_session, session);
        match outcome {
            "pending" => {}
            "spawn_failed" => s.finish_run(run, RunCompletion::FailedToSpawn).unwrap(),
            "attested" => s.finish_run(run, RunCompletion::OperatorAttested).unwrap(),
            _ => {
                s.observe_spawn(&run, 43).unwrap();
                s.finish_run(
                    run,
                    RunCompletion::ExternalClientExited(if outcome == "nonzero" { 7 } else { 0 }),
                )
                .unwrap();
            }
        }
        drop(lease);
        if outcome == "legacy" {
            assert!(matches!(
                s.latest_gents_session(p.id),
                Err(Error::NoRecordedSession)
            ));
        } else {
            assert!(
                matches!(
                    s.latest_gents_session(p.id),
                    Err(Error::SessionNotResumable)
                ),
                "{outcome}"
            );
        }
        assert!(s.verify().unwrap().consistent);
    }
}

#[test]
fn stale_sources_wrong_sessions_and_other_profiles_cannot_append_resume_intents() {
    let (_temp, mut s, p) = setup();
    let original = new_session();
    let first = complete(&mut s, &p, Some(original.clone()));
    let second = complete(&mut s, &p, Some(new_session()));
    let latest = s.latest_gents_session(p.id).unwrap();
    let other = s
        .register_gents("other".parse().unwrap(), binding(9192))
        .unwrap();
    for (profile, session, expected) in [
        (
            p.id,
            GentsSession::new(original.id, binding(9191), Some(first)),
            "stale_session",
        ),
        (
            p.id,
            GentsSession::new(Uuid::new_v4(), binding(9191), Some(second)),
            "stale_session",
        ),
        (
            other.id,
            GentsSession::new(latest.session.id, binding(9192), Some(second)),
            "no_recorded_session",
        ),
        (
            p.id,
            GentsSession::new(latest.session.id, binding(9192), Some(second)),
            "session_binding_changed",
        ),
    ] {
        let before = s.verify().unwrap().events;
        let lease = s.lease(profile).unwrap();
        assert_eq!(
            s.begin_run_with_session(&lease, "run", Some(session))
                .unwrap_err()
                .code(),
            expected
        );
        assert_eq!(s.verify().unwrap().events, before);
        assert!(s.unfinished().unwrap().is_empty());
    }
    let rebound = s.bind_gents(&p.alias, binding(9193)).unwrap();
    assert!(matches!(
        s.latest_gents_session(p.id),
        Err(Error::SessionBindingChanged)
    ));
    // An explicit session under a consciously selected binding is allowed.
    complete(
        &mut s,
        &rebound,
        Some(GentsSession::new(original.id, binding(9193), None)),
    );
    assert_eq!(
        s.latest_gents_session(p.id).unwrap().session.binding,
        binding(9193)
    );
}

#[test]
fn native_intents_reject_gents_metadata_and_pending_intents_survive_reopen() {
    let (temp, mut s, p) = setup();
    let native = s
        .register(Harness::Claude, "native".parse().unwrap())
        .unwrap();
    assert!(matches!(
        s.latest_gents_session(native.id),
        Err(Error::UnsupportedSession)
    ));
    let lease = s.lease(native.id).unwrap();
    assert!(matches!(
        s.begin_run_with_session(&lease, "run", Some(new_session())),
        Err(Error::EngineMismatch)
    ));
    drop(lease);
    let lease = s.lease(p.id).unwrap();
    let session = new_session();
    let id = s
        .begin_run_with_session(&lease, "run", Some(session.clone()))
        .unwrap();
    drop(lease);
    drop(s); // Supervisor loss before spawn: metadata persists, no retry.
    let s = Store::open(&temp.path().join("state")).unwrap();
    let run = s.run(&id).unwrap();
    assert_eq!(run.gents_session, Some(session));
    assert_eq!(run.observed_pid, None);
    assert!(matches!(s.lease(p.id), Err(Error::Busy)));
    assert!(matches!(
        s.latest_gents_session(p.id),
        Err(Error::SessionNotResumable)
    ));
}

#[test]
fn replay_rejects_a_resume_reference_not_valid_at_that_point_in_history() {
    let (_temp, mut s, p) = setup();
    let session = new_session();
    let first = complete(&mut s, &p, Some(session.clone()));
    complete(&mut s, &p, Some(new_session()));
    // Append directly, bypassing record's validation; verification must still fail.
    let event = Event::RunPlanned {
        id: Uuid::new_v4().to_string(),
        profile: p.id,
        kind: "run".to_owned(),
        requires_spawn_observation: true,
        gents_session: Some(GentsSession::new(session.id, binding(9191), Some(first))),
    };
    s.db.execute(
        "INSERT INTO event_log(payload) VALUES(?1)",
        [serde_json::to_string(&event).unwrap()],
    )
    .unwrap();
    assert!(matches!(s.verify(), Err(Error::CorruptRegistry)));
}

#[test]
fn resume_uses_journal_order_across_clock_changes_and_rejects_projection_tampering() {
    let (_temp, mut s, p) = setup();
    complete(&mut s, &p, Some(new_session()));
    let id = Uuid::new_v4();
    let session = new_session();
    let event = Event::RunPlanned {
        id: id.to_string(),
        profile: p.id,
        kind: "run".to_owned(),
        requires_spawn_observation: true,
        gents_session: Some(session.clone()),
    };
    // Emulate the system clock moving backwards between two legitimate runs.
    let earlier = "2000-01-01T00:00:00.000Z";
    let tx = s.db.transaction().unwrap();
    tx.execute(
        "INSERT INTO event_log(payload,recorded_at) VALUES(?1,?2)",
        rusqlite::params![serde_json::to_string(&event).unwrap(), earlier],
    )
    .unwrap();
    crate::store::apply(&tx, &event, earlier).unwrap();
    tx.commit().unwrap();
    s.observe_spawn(&id.to_string(), 43).unwrap();
    s.finish_run(id.to_string(), RunCompletion::ExternalClientExited(0))
        .unwrap();
    assert_eq!(s.latest_gents_session(p.id).unwrap().run_id, id);
    assert_eq!(s.run(&id.to_string()).unwrap().started_at, earlier);
    // Syntactically valid metadata must still equal journal replay.
    s.db.execute(
        "UPDATE runs SET gents_session=json_set(gents_session,'$.id',?1) WHERE id=?2",
        rusqlite::params![Uuid::new_v4().to_string(), id.to_string()],
    )
    .unwrap();
    assert!(matches!(
        s.latest_gents_session(p.id),
        Err(Error::ProjectionMismatch)
    ));
    assert!(matches!(s.runs(20), Err(Error::ProjectionMismatch)));
}

#[test]
fn restoring_an_exact_binding_allows_explicit_manual_resume_without_identity_claims() {
    let (_temp, mut s, p) = setup();
    let first = complete(&mut s, &p, Some(new_session()));
    s.bind_gents(&p.alias, binding(9192)).unwrap();
    assert!(matches!(
        s.latest_gents_session(p.id),
        Err(Error::SessionBindingChanged)
    ));
    s.bind_gents(&p.alias, binding(9191)).unwrap();
    let candidate = s.latest_gents_session(p.id).unwrap();
    assert_eq!(candidate.run_id, first);
    complete(
        &mut s,
        &p,
        Some(GentsSession::new(
            candidate.session.id,
            binding(9191),
            Some(first),
        )),
    );
    assert!(s.verify().unwrap().consistent);
}

#[test]
fn tampered_source_projections_block_selection_and_intent_append() {
    for mutation in [
        "UPDATE runs SET gents_session=json_set(gents_session,'$.id','cafe0000-0000-4000-8000-000000000001')",
        "UPDATE runs SET exit_code=7",
        "UPDATE runs SET outcome='user_attested_stopped'",
    ] {
        let (_temp, mut s, p) = setup();
        let first = complete(&mut s, &p, Some(new_session()));
        let candidate = s.latest_gents_session(p.id).unwrap();
        let lease = s.lease(p.id).unwrap();
        let before: i64 =
            s.db.query_row("SELECT count(*) FROM event_log", [], |r| r.get(0))
                .unwrap();
        s.db.execute_batch(mutation).unwrap();
        assert!(matches!(
            s.latest_gents_session(p.id),
            Err(Error::ProjectionMismatch)
        ));
        assert!(matches!(
            s.begin_run_with_session(
                &lease,
                "run",
                Some(GentsSession::new(
                    candidate.session.id,
                    binding(9191),
                    Some(first)
                ))
            ),
            Err(Error::ProjectionMismatch)
        ));
        let after: i64 =
            s.db.query_row("SELECT count(*) FROM event_log", [], |r| r.get(0))
                .unwrap();
        assert_eq!(before, after);
    }
}

#[test]
fn replay_refuses_invalid_session_shapes_even_without_matching_projections() {
    for shape in [
        "wrong_profile",
        "wrong_session",
        "wrong_binding",
        "failed_source",
    ] {
        let (_temp, mut s, p) = setup();
        let session = new_session();
        let source = complete(&mut s, &p, Some(session.clone()));
        let other = s
            .register_gents("other".parse().unwrap(), binding(9192))
            .unwrap();
        let (profile, metadata) = match shape {
            "wrong_profile" => (
                other.id,
                GentsSession::new(session.id, binding(9192), Some(source)),
            ),
            "wrong_session" => (
                p.id,
                GentsSession::new(Uuid::new_v4(), binding(9191), Some(source)),
            ),
            "wrong_binding" => (
                p.id,
                GentsSession::new(session.id, binding(9192), Some(source)),
            ),
            _ => {
                let lease = s.lease(p.id).unwrap();
                let failed = s
                    .begin_run_with_session(&lease, "run", Some(session.clone()))
                    .unwrap();
                s.finish_run(failed.clone(), RunCompletion::FailedToSpawn)
                    .unwrap();
                (
                    p.id,
                    GentsSession::new(session.id, binding(9191), Some(failed.parse().unwrap())),
                )
            }
        };
        let event = Event::RunPlanned {
            id: Uuid::new_v4().to_string(),
            profile,
            kind: "run".to_owned(),
            requires_spawn_observation: true,
            gents_session: Some(metadata),
        };
        s.db.execute(
            "INSERT INTO event_log(payload) VALUES(?1)",
            [serde_json::to_string(&event).unwrap()],
        )
        .unwrap();
        assert!(matches!(s.verify(), Err(Error::CorruptRegistry)), "{shape}");
    }
}
