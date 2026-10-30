//! Actual core storage under candidate custody, using only fictional profiles.
//! This test dependency does not make core depend on the security candidate.

use super::*;
use agentswapper_core::{
    Harness, ProfileId, Store,
    config::{ConfigKey, ConfigStore},
    store::ProfileLease,
};
use std::path::PathBuf;

pub(super) struct Fixture {
    root: PathBuf,
    files: Vec<PathBuf>,
    directories: Vec<PathBuf>,
    public: PathBuf,
}

pub(super) struct Custody {
    // Actual consumers close before the root's handles; fixture cleanup last.
    store: Store,
    _lease: ProfileLease,
    root: PrivateRoot,
    profile: ProfileId,
    _fixture: tempfile::TempDir,
}

impl Fixture {
    pub(super) fn prepare(policy: &SecurityPolicy) -> (Self, Custody) {
        let fixture = tempfile::Builder::new()
            .prefix("aswp-core-storage-")
            .tempdir_in(std::env::var_os("USERPROFILE").unwrap())
            .unwrap();
        let root = policy
            .open_or_create_private_root(&fixture.path().join("private"))
            .unwrap();
        let mut store = Store::open(root.path()).unwrap();
        let profile = store
            .register(Harness::Claude, "fictional-profile".parse().unwrap())
            .unwrap();
        let lease = store.lease(profile.id).unwrap();
        let config = ConfigStore::new(root.path()).unwrap();
        config.set(ConfigKey::UiMask, "true").unwrap();
        config.set(ConfigKey::HistoryLimit, "23").unwrap();
        let profile_name = profile.id.to_string();
        let profiles = policy
            .open_existing_inherited_directory_at(root.directory(), OsStr::new("profiles"))
            .unwrap();
        let home = policy
            .open_existing_inherited_directory_at(&profiles, OsStr::new(&profile_name))
            .unwrap();
        let locks = policy
            .open_existing_inherited_directory_at(root.directory(), OsStr::new("locks"))
            .unwrap();
        let home_path = store.profile_home(profile.id).unwrap();
        std::fs::write(
            home_path.join("fictional.txt"),
            b"fictional provider-owned state",
        )
        .unwrap();
        drop(
            policy
                .open_existing_inherited_file_at(
                    &home,
                    OsStr::new("fictional.txt"),
                    FileAccess::ReadOnly,
                )
                .unwrap(),
        );
        drop(
            policy
                .open_existing_inherited_file_at(
                    &locks,
                    OsStr::new(&format!("{profile_name}.lock")),
                    FileAccess::ReadOnly,
                )
                .unwrap(),
        );
        let mut files = Vec::new();
        for name in [
            "registry.sqlite3",
            "registry.sqlite3-wal",
            "registry.sqlite3-shm",
            "registry.lock",
            "config.json",
            "config.lock",
        ] {
            drop(
                policy
                    .open_existing_inherited_file_at(
                        root.directory(),
                        OsStr::new(name),
                        FileAccess::ReadOnly,
                    )
                    .unwrap(),
            );
            files.push(root.path().join(name));
        }
        files.push(home_path.join("fictional.txt"));
        files.push(
            root.path()
                .join("locks")
                .join(format!("{profile_name}.lock")),
        );
        let public = home_path.join("public.txt");
        let broad =
            LocalDescriptor::from_sddl(&format!("O:{}D:P(A;;FA;;;WD)", policy.owner.sddl()))
                .unwrap();
        let mut control =
            create_at(&home, OsStr::new("public.txt"), ObjectKind::File, &broad).unwrap();
        control
            .write_all(b"reachable core profile control")
            .unwrap();
        drop(control);
        store.check().unwrap();
        let probe = Self {
            root: root.path().to_path_buf(),
            files,
            directories: vec![
                root.path().join("profiles"),
                root.path().join("locks"),
                home_path,
            ],
            public,
        };
        (
            probe,
            Custody {
                store,
                _lease: lease,
                root,
                profile: profile.id,
                _fixture: fixture,
            },
        )
    }

    pub(super) fn probe_as_other_user(&self) {
        assert_eq!(
            std::fs::read(&self.public).unwrap(),
            b"reachable core profile control"
        );
        for path in &self.files {
            denied(File::open(path), "read actual core private storage");
            denied(
                std::fs::OpenOptions::new().write(true).open(path),
                "write actual core private storage",
            );
            denied(
                std::fs::remove_file(path),
                "delete actual core private storage",
            );
        }
        for path in self.directories.iter().chain(std::iter::once(&self.root)) {
            denied(
                File::create(path.join("injected.txt")),
                "inject actual core private directory",
            );
            denied(
                std::fs::rename(path, path.with_extension("moved")),
                "rename actual core private directory",
            );
        }
        println!(
            "::notice title=Windows core storage separate identity::temporary standard user reached the actual profile's public control but could not read/write/delete registry, settings, lock or fictional vendor files, inject children or rename private directories"
        );
    }
}

impl Custody {
    pub(super) fn verify(&self) {
        self.store.check().unwrap();
        let rows = self.store.profiles().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, self.profile);
        assert_eq!(rows[0].alias.to_string(), "fictional-profile");
        let config = ConfigStore::new(self.root.path()).unwrap();
        let preferences = config.load().unwrap();
        assert!(preferences.ui_mask());
        assert_eq!(preferences.history_limit(), 23);
        let home = self.store.profile_home(self.profile).unwrap();
        assert_eq!(
            std::fs::read(home.join("fictional.txt")).unwrap(),
            b"fictional provider-owned state"
        );
        for path in [
            self.root.path().to_path_buf(),
            self.root.path().join("profiles"),
            self.root.path().join("locks"),
            home,
        ] {
            assert!(!path.join("injected.txt").exists());
            assert!(!path.with_extension("moved").exists());
        }
        // A second real store must verify and see the same committed registry
        // while the first connection, candidate custody and lease stay alive.
        let reopened = Store::open(self.root.path()).unwrap();
        reopened.check().unwrap();
        assert_eq!(reopened.profiles().unwrap()[0].id, self.profile);
        println!(
            "::notice title=Windows core storage compatibility::actual registry replay and reopen, configuration replacement, profile registration and live lease preserved; all expected files had exact inherited grants; fixture owns the external root guard, production core still does not"
        );
    }
}

#[test]
fn actual_core_storage_preserves_data_under_candidate_root_custody() {
    let policy = SecurityPolicy::for_current_process().unwrap();
    let (_, custody) = Fixture::prepare(&policy);
    custody.verify();
}
