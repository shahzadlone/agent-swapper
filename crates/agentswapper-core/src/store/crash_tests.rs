//! Real process termination during transactional journal and projection writes.
#![allow(clippy::unwrap_used)]
use super::*;
use std::{
    fs,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const CHILD: &str = "store::crash_tests::crash_child";
const WAIT: Duration = Duration::from_secs(15);

fn binding(port: u16) -> crate::GentsBinding {
    crate::GentsBinding::new(
        format!("127.0.0.1:{port}").parse().unwrap(),
        "worker".parse().unwrap(),
    )
    .unwrap()
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "fixture entry point invoked by the crash-recovery test"]
fn crash_child() {
    let root = PathBuf::from(std::env::var_os("ASWP_CRASH_ROOT").unwrap());
    let action = std::env::var("ASWP_CRASH_ACTION").unwrap();
    let stage = std::env::var("ASWP_CRASH_STAGE").unwrap();
    let run = std::env::var("ASWP_CRASH_RUN").unwrap();
    let marker = root.parent().unwrap().join("reached");
    let mut store = Store::open(&root).unwrap();
    let profile = store
        .profiles()
        .unwrap()
        .into_iter()
        .find(|p| p.alias.to_string() == "work")
        .unwrap();
    let lease = match action.as_str() {
        "register" | "rename" | "disable" | "remove" | "rebind" => None,
        "plan" | "gents-plan" => Some(store.lease(profile.id).unwrap()),
        // These cases model the existing launcher's already-held lease after
        // a durable intent. `lease` intentionally refuses unfinished runs.
        _ => Some(store.acquire_lease(profile.id).unwrap()),
    };
    if stage != "committed" {
        let wanted = if stage == "event" {
            "event_log"
        } else if stage == "mapping" {
            "mappings"
        } else if matches!(
            action.as_str(),
            "register" | "rename" | "disable" | "remove" | "rebind"
        ) {
            "profiles"
        } else {
            "runs"
        };
        store
            .db
            .update_hook(Some(move |_, database: &str, table: &str, _| {
                if database == "main" && table == wanted {
                    let _ = fs::write(&marker, b"reached");
                    loop {
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }))
            .unwrap();
    }
    match action.as_str() {
        "register" => {
            store
                .register(Harness::Codex, "new".parse().unwrap())
                .unwrap();
        }
        "rename" => {
            store
                .rename(&profile.alias, "renamed".parse().unwrap())
                .unwrap();
        }
        "disable" => {
            store.enable(&profile.alias, false).unwrap();
        }
        "remove" => {
            store.remove(&profile.alias).unwrap();
        }
        "rebind" => {
            store.bind_gents(&profile.alias, binding(9192)).unwrap();
        }
        "plan" => {
            store.begin_run(lease.as_ref().unwrap(), "run").unwrap();
        }
        "gents-plan" => {
            let session = GentsSession::new(Uuid::new_v4(), profile.gents.unwrap(), None);
            store
                .begin_run_with_session(lease.as_ref().unwrap(), "run", Some(session))
                .unwrap();
        }
        "spawn" => {
            store.observe_spawn(&run, 42).unwrap();
        }
        "finish" => {
            store
                .finish_run(run, RunCompletion::ChildExited(7))
                .unwrap();
        }
        _ => panic!("unknown fixture action"),
    }
    if stage == "committed" {
        fs::write(root.parent().unwrap().join("reached"), b"committed").unwrap();
        loop {
            thread::sleep(Duration::from_millis(100));
        }
    }
    panic!("requested write hook was not reached");
}

#[test]
#[ignore = "subprocess crash-recovery matrix; run explicitly"]
fn crash_lifecycle_reopens_consistently() {
    let trials: usize = std::env::var("ASWP_JOURNAL_CRASH_TRIALS")
        .unwrap_or_else(|_| "28".into())
        .parse()
        .unwrap();
    assert!((28..=1000).contains(&trials));
    let cases = [
        ("register", "event"),
        ("register", "projection"),
        ("register", "committed"),
        ("rename", "event"),
        ("rename", "projection"),
        ("rename", "committed"),
        ("disable", "event"),
        ("disable", "projection"),
        ("disable", "committed"),
        ("remove", "event"),
        ("remove", "projection"),
        ("remove", "mapping"),
        ("remove", "committed"),
        ("rebind", "event"),
        ("rebind", "projection"),
        ("rebind", "committed"),
        ("plan", "event"),
        ("plan", "projection"),
        ("plan", "committed"),
        ("gents-plan", "event"),
        ("gents-plan", "projection"),
        ("gents-plan", "committed"),
        ("spawn", "event"),
        ("spawn", "projection"),
        ("spawn", "committed"),
        ("finish", "event"),
        ("finish", "projection"),
        ("finish", "committed"),
    ];
    for index in 0..trials {
        let (action, stage) = cases[index % cases.len()];
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("state");
        let mut store = Store::open(&root).unwrap();
        let profile = if matches!(action, "rebind" | "gents-plan") {
            store
                .register_gents("work".parse().unwrap(), binding(9191))
                .unwrap()
        } else {
            store
                .register(Harness::Claude, "work".parse().unwrap())
                .unwrap()
        };
        if action == "remove" {
            store.map(&profile.alias, temp.path()).unwrap();
        }
        let run = if matches!(action, "spawn" | "finish") {
            let lease = store.lease(profile.id).unwrap();
            let id = store.begin_run(&lease, "run").unwrap();
            if action == "finish" {
                store.observe_spawn(&id, 42).unwrap();
            }
            id
        } else {
            String::new()
        };
        let count: i64 = store
            .db
            .query_row("SELECT count(*) FROM event_log", [], |r| r.get(0))
            .unwrap();
        let before_profiles = serde_json::to_value(store.profiles().unwrap()).unwrap();
        let before_runs = serde_json::to_value(store.runs(200).unwrap()).unwrap();
        let before_mappings = serde_json::to_value(store.mappings().unwrap()).unwrap();
        drop(store);

        let mut child = OwnedChild(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", CHILD, "--ignored", "--nocapture"])
                .env("ASWP_CRASH_ROOT", &root)
                .env("ASWP_CRASH_ACTION", action)
                .env("ASWP_CRASH_STAGE", stage)
                .env("ASWP_CRASH_RUN", &run)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let marker = temp.path().join("reached");
        let deadline = Instant::now() + WAIT;
        while !marker.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "fixture exited early: {action}/{stage}"
            );
            assert!(
                Instant::now() < deadline,
                "fixture timed out: {action}/{stage}"
            );
            thread::sleep(Duration::from_millis(5));
        }
        child.0.kill().unwrap();
        child.0.wait().unwrap();

        let recovered = Store::open(&root).unwrap();
        assert!(
            recovered.verify().unwrap().consistent,
            "inconsistent recovery: {action}/{stage}"
        );
        let after: i64 = recovered
            .db
            .query_row("SELECT count(*) FROM event_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            after,
            count + i64::from(stage == "committed"),
            "event count: {action}/{stage}"
        );
        if stage != "committed" {
            assert_eq!(
                serde_json::to_value(recovered.profiles().unwrap()).unwrap(),
                before_profiles
            );
            assert_eq!(
                serde_json::to_value(recovered.runs(200).unwrap()).unwrap(),
                before_runs
            );
            assert_eq!(
                serde_json::to_value(recovered.mappings().unwrap()).unwrap(),
                before_mappings
            );
        } else {
            match action {
                "register" => assert_eq!(recovered.profiles().unwrap().len(), 2),
                "rename" => assert_eq!(
                    recovered.profiles().unwrap()[0].alias.to_string(),
                    "renamed"
                ),
                "disable" => assert!(!recovered.profiles().unwrap()[0].enabled),
                "remove" => {
                    assert!(recovered.profiles().unwrap().is_empty());
                    assert!(recovered.mappings().unwrap().is_empty());
                }
                "rebind" => assert_eq!(
                    recovered.profiles().unwrap()[0]
                        .gents
                        .as_ref()
                        .unwrap()
                        .address()
                        .port(),
                    9192
                ),
                "plan" => assert_eq!(recovered.unfinished().unwrap().len(), 1),
                "gents-plan" => assert!(recovered.runs(1).unwrap()[0].gents_session.is_some()),
                "spawn" => assert_eq!(recovered.run(&run).unwrap().observed_pid, Some(42)),
                "finish" => assert_eq!(recovered.run(&run).unwrap().exit_code, Some(7)),
                _ => unreachable!(),
            }
        }
        if recovered.unfinished().unwrap().is_empty() {
            assert!(
                recovered.lease(profile.id).is_ok(),
                "lease not released: {action}/{stage}"
            );
        } else {
            assert!(
                matches!(recovered.lease(profile.id), Err(Error::Busy)),
                "unfinished run did not fence reuse: {action}/{stage}"
            );
        }
    }
}
