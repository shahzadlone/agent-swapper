//! Actual handover exports beneath public-read and owner-rights directories.

use super::*;
use agentswapper_core::{
    Harness, Profile,
    handover::{
        HandoverPack, WorkspaceAnchor, write_ciphertext, write_ciphertext_cancellable, write_pickup,
    },
};
use std::{cell::Cell, path::PathBuf};

pub(super) struct Fixture {
    controls: Vec<PathBuf>,
    files: Vec<PathBuf>,
}

pub(super) struct Custody {
    artifacts: Vec<(PathBuf, Vec<u8>)>,
    _fixture: tempfile::TempDir,
}

impl Fixture {
    pub(super) fn prepare(policy: &SecurityPolicy) -> (Self, Custody) {
        let fixture = tempfile::Builder::new()
            .prefix("aswp-handover-output-")
            .tempdir_in(std::env::var_os("USERPROFILE").unwrap())
            .unwrap();
        let source = Profile {
            id: "3aadf862-c620-4e3a-a8db-10756d6cce71".parse().unwrap(),
            alias: "fictional".parse().unwrap(),
            harness: Harness::Claude,
            enabled: true,
            gents: None,
        };
        let pack = HandoverPack::new(
            &source,
            WorkspaceAnchor {
                directory: fixture.path().to_owned(),
                head: None,
            },
            "fictional private pickup canary".to_owned(),
        )
        .unwrap();
        let report = pack.reconcile(Harness::Codex, fixture.path()).unwrap();
        let mut artifacts = Vec::new();
        let mut controls = Vec::new();
        for (name, sddl) in [
            (
                "owner-rights",
                format!(
                    "O:{}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)",
                    policy.owner.sddl()
                ),
            ),
            (
                "public-read",
                format!(
                    "O:{}D:P(A;OICI;FA;;;{})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x001200a9;;;WD)",
                    policy.owner.sddl(),
                    policy.owner.sddl()
                ),
            ),
            (
                "private",
                format!(
                    "O:{}D:P(A;OICI;FA;;;{})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
                    policy.owner.sddl(),
                    policy.owner.sddl()
                ),
            ),
            (
                "inherit-only-write",
                format!(
                    "O:{}D:P(A;OICI;FA;;;{})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;FA;;;WD)",
                    policy.owner.sddl(),
                    policy.owner.sddl()
                ),
            ),
        ] {
            let parent = fixture.path().join(name);
            let descriptor = LocalDescriptor::from_sddl(&sddl).unwrap();
            let directory = create(&parent, ObjectKind::Directory, &descriptor).unwrap();
            let guard = policy.open_publication_parent(&parent).unwrap();
            let (empty, empty_path, _parent) = policy
                .create_publication_file(&guard, OsStr::new("before-bytes.txt"))
                .unwrap()
                .into_parts();
            assert_eq!(empty.metadata().unwrap().len(), 0);
            policy.validate_handle(&empty, ObjectKind::File).unwrap();
            drop(empty);
            std::fs::remove_file(empty_path).unwrap();
            drop(guard);
            let original = LocalDescriptor::from_file(&directory)
                .unwrap()
                .bytes()
                .unwrap()
                .to_vec();
            let control = parent.join("public-control.txt");
            let public = LocalDescriptor::from_sddl(&format!(
                "O:{}D:P(A;;FA;;;{})(A;;FR;;;WD)",
                policy.owner.sddl(),
                policy.owner.sddl()
            ))
            .unwrap();
            let mut file = create(&control, ObjectKind::File, &public).unwrap();
            file.write_all(b"reachable handover control").unwrap();
            drop(file);
            controls.push(control);
            let encrypted =
                write_ciphertext(&parent.join("fixture.age"), b"fictional ciphertext").unwrap();
            assert_eq!(
                std::fs::read(&encrypted.path).unwrap(),
                b"fictional ciphertext"
            );
            let pickup = write_pickup(
                &parent.join("HANDOVER_PICKUP.md"),
                &pack,
                &report,
                None,
                || false,
            )
            .unwrap();
            for path in [encrypted.path, pickup.path] {
                let file = File::open(&path).unwrap();
                policy.validate_handle(&file, ObjectKind::File).unwrap();
                artifacts.push((path.clone(), std::fs::read(&path).unwrap()));
            }
            assert_eq!(
                artifacts.last().unwrap().1,
                pack.render_pickup(&report).as_bytes()
            );
            // Inspect the actual temporary file after bytes exist, before
            // cancellation. Refuse any inherited public-read permission.
            let observed = Cell::new(false);
            let cancelled = parent.join("cancelled.age");
            let result =
                write_ciphertext_cancellable(&cancelled, b"cancelled private canary", || {
                    let temporary = std::fs::read_dir(&parent)
                        .unwrap()
                        .filter_map(|e| e.ok())
                        .find(|e| {
                            e.file_name()
                                .to_string_lossy()
                                .starts_with(".aswp-handover-")
                        });
                    if let Some(entry) = temporary {
                        let file = File::open(entry.path()).unwrap();
                        policy.validate_handle(&file, ObjectKind::File).unwrap();
                        assert!(file.metadata().unwrap().len() > 0);
                        observed.set(true);
                        true
                    } else {
                        false
                    }
                });
            assert!(matches!(result, Err(agentswapper_core::Error::Cancelled)));
            assert!(observed.get());
            assert!(!cancelled.exists());
            // Create a destination after the early existence check, forcing
            // the authoritative no-clobber rename and its cleanup path.
            let race = parent.join("raced.age");
            let created = Cell::new(false);
            let result = write_ciphertext_cancellable(&race, b"must not replace", || {
                if !created.get()
                    && std::fs::read_dir(&parent).unwrap().any(|entry| {
                        entry
                            .unwrap()
                            .file_name()
                            .to_string_lossy()
                            .starts_with(".aswp-handover-")
                    })
                {
                    let mut file = create(
                        &race,
                        ObjectKind::File,
                        &policy.creation_descriptor(ObjectKind::File).unwrap(),
                    )
                    .unwrap();
                    file.write_all(b"destination race canary").unwrap();
                    created.set(true);
                }
                false
            });
            assert!(created.get());
            assert!(matches!(
                result,
                Err(agentswapper_core::Error::OutputExists)
            ));
            let race_file = File::open(&race).unwrap();
            policy
                .validate_handle(&race_file, ObjectKind::File)
                .unwrap();
            let before = LocalDescriptor::from_file(&race_file)
                .unwrap()
                .bytes()
                .unwrap()
                .to_vec();
            assert!(matches!(
                write_ciphertext(&race, b"must not replace"),
                Err(agentswapper_core::Error::OutputExists)
            ));
            assert_eq!(std::fs::read(&race).unwrap(), b"destination race canary");
            assert_eq!(
                LocalDescriptor::from_file(&race_file)
                    .unwrap()
                    .bytes()
                    .unwrap(),
                before
            );
            drop(race_file);
            std::fs::remove_file(race).unwrap();
            assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 3);
            assert_eq!(
                LocalDescriptor::from_file(&directory)
                    .unwrap()
                    .bytes()
                    .unwrap(),
                original
            );
        }
        // Mutation rights on the leaf cannot be made safe by the child ACL.
        // Refuse without repairing it or writing a temporary/destination file.
        for rights in ["FA", "0x001200ad"] {
            let path = fixture.path().join(format!("refused-{rights}"));
            let descriptor = LocalDescriptor::from_sddl(&format!(
                "O:{}D:P(A;;FA;;;{})(A;;{rights};;;WD)",
                policy.owner.sddl(),
                policy.owner.sddl()
            ))
            .unwrap();
            let directory = create(&path, ObjectKind::Directory, &descriptor).unwrap();
            let before = LocalDescriptor::from_file(&directory)
                .unwrap()
                .bytes()
                .unwrap()
                .to_vec();
            assert!(matches!(
                write_ciphertext(&path.join("refused.age"), b"must not be written"),
                Err(agentswapper_core::Error::UnprotectedHandoverOutput)
            ));
            assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);
            assert_eq!(
                LocalDescriptor::from_file(&directory)
                    .unwrap()
                    .bytes()
                    .unwrap(),
                before
            );
        }
        let files = artifacts.iter().map(|(path, _)| path.clone()).collect();
        (
            Self { controls, files },
            Custody {
                artifacts,
                _fixture: fixture,
            },
        )
    }

    pub(super) fn probe_as_other_user(&self) {
        for control in &self.controls {
            assert_eq!(
                std::fs::read(control).unwrap(),
                b"reachable handover control"
            );
            denied(
                File::create(control.parent().unwrap().join("injected.txt")),
                "inject publication directory",
            );
        }
        for file in &self.files {
            denied(File::open(file), "read published handover");
            denied(
                std::fs::OpenOptions::new().write(true).open(file),
                "write published handover",
            );
            denied(std::fs::remove_file(file), "delete published handover");
        }
        println!(
            "::notice title=Windows handover separate identity::temporary standard user reached every parent control but could not inject children or read/write/delete actual ciphertext or plaintext pickup exports after publication handles closed"
        );
    }
}

impl Custody {
    pub(super) fn verify(&self) {
        for (path, bytes) in &self.artifacts {
            assert_eq!(std::fs::read(path).unwrap(), *bytes);
        }
        println!(
            "::notice title=Windows handover publication::protected creation and actual exports passed under private, public-read, OW and inherit-only-write parents; cancellation and losing-publication cleanup passed; broad and AD4 leaves refused without repair; original artifacts preserved"
        );
    }
}

#[test]
fn handover_exports_have_private_creation_and_preserve_destination_acls() {
    let policy = SecurityPolicy::for_current_process().unwrap();
    let (_, custody) = Fixture::prepare(&policy);
    custody.verify();
}
