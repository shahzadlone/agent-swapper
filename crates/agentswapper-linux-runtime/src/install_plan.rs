//! Producer-side plan for one fixed installation generation. This module
//! derives the documented fixed layout, generates the deterministic unit
//! texts and manifest for the readers in this crate to validate, and stages
//! files with same-directory atomic renames plus rollback. It never touches
//! an existing file and performs no service control; executing the plan is a
//! separate explicit administrator action.
use crate::installed_manifest::VERSION;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{OpenOptions, Permissions},
    io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
};

const SCHEMA: u32 = 1;
const PROTOCOL: u32 = 1;
const SELECTOR_SCHEMA: u32 = 1;

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "installation plan identity is invalid",
    )
}

fn ordinary(user: u32, group: u32) -> bool {
    user != 0 && group != 0 && user <= i32::MAX as u32 && group <= i32::MAX as u32
}

fn valid_generation(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

/// The three executable roles of one generation. Distinct bytes are expected;
/// the manifest records each role's digest separately.
pub struct Assets {
    pub guardian: Vec<u8>,
    pub session_helper: Vec<u8>,
    pub exec_shim: Vec<u8>,
}

/// Fixed location set for one generation. Production paths are absolute and
/// match the installed readers exactly.
#[derive(Clone, Debug)]
pub struct Layout {
    root: PathBuf,
    user: u32,
    group: u32,
    generation: String,
}

impl Layout {
    /// The documented production layout under `/`.
    pub fn fixed(user: u32, group: u32, generation: &str) -> io::Result<Self> {
        if !ordinary(user, group) || !valid_generation(generation) {
            return Err(invalid());
        }
        Ok(Self {
            root: PathBuf::from("/"),
            user,
            group,
            generation: generation.to_owned(),
        })
    }
    /// A disposable root for transaction tests and disposable fixtures. Never
    /// ships a production path.
    #[cfg(any(feature = "qualification", test))]
    #[cfg_attr(
        not(feature = "qualification"),
        doc = "\n```compile_fail,E0599\nuse agentswapper_linux_runtime::install_plan::Layout;\nfn custom_root() { let _ = Layout::for_qualification; }\n```"
    )]
    pub fn for_qualification(
        root: &std::path::Path,
        user: u32,
        group: u32,
        generation: &str,
    ) -> io::Result<Self> {
        if !ordinary(user, group) || !valid_generation(generation) {
            return Err(invalid());
        }
        Ok(Self {
            root: root.to_owned(),
            user,
            group,
            generation: generation.to_owned(),
        })
    }
    pub fn identity(&self) -> (u32, u32) {
        (self.user, self.group)
    }
    pub fn generation(&self) -> &str {
        &self.generation
    }
    pub fn unit_stem(&self) -> String {
        format!("agentswapper-{}-{}", self.user, self.generation)
    }
    fn installations(&self) -> PathBuf {
        self.root
            .join("etc/agentswapper/installations")
            .join(self.user.to_string())
    }
    pub fn selector(&self) -> PathBuf {
        self.installations().join("active.json")
    }
    pub fn manifest(&self) -> PathBuf {
        self.installations()
            .join(format!("{}.json", self.generation))
    }
    pub fn image(&self, role: &str) -> PathBuf {
        self.root
            .join("usr/libexec/agentswapper")
            .join(self.user.to_string())
            .join(&self.generation)
            .join(role)
    }
    pub fn service_template(&self) -> PathBuf {
        self.root
            .join("etc/systemd/system")
            .join(format!("{}@.service", self.unit_stem()))
    }
    pub fn socket_unit(&self) -> PathBuf {
        self.root
            .join("etc/systemd/system")
            .join(format!("{}.socket", self.unit_stem()))
    }
    pub fn endpoint(&self) -> PathBuf {
        self.root
            .join("run/agentswapper")
            .join(self.user.to_string())
            .join(format!("{}.sock", self.generation))
    }
    fn directories(&self) -> Vec<PathBuf> {
        let terminal = [
            self.root.join("etc/systemd/system"),
            self.root
                .join("etc/agentswapper/installations")
                .join(self.user.to_string()),
            self.root
                .join("usr/libexec/agentswapper")
                .join(self.user.to_string())
                .join(&self.generation),
        ];
        let mut result: Vec<PathBuf> = Vec::new();
        for directory in terminal {
            let relative = match directory.strip_prefix(&self.root) {
                Ok(relative) => relative,
                Err(_) => continue,
            };
            let mut prefix = self.root.clone();
            for part in relative.components() {
                prefix.push(part);
                if !result.contains(&prefix) {
                    result.push(prefix.clone());
                }
            }
        }
        result
    }
    /// The exact loaded socket configuration the manager policy validates:
    /// one sequential-packet listener at the derived endpoint, the exact
    /// numeric identity, mode 0600, directory mode 0755 and removal on stop.
    pub fn socket_unit_text(&self) -> String {
        format!(
            "[Unit]\n\
             Description=AgentSwapper managed activation endpoint for user {} (generation {})\n\
             \n\
             [Socket]\n\
             ListenSequentialPacket={}\n\
             SocketUser={}\n\
             SocketGroup={}\n\
             SocketMode=0600\n\
             Accept=yes\n\
             MaxConnections=4\n\
             TriggerLimitIntervalSec=30s\n\
             TriggerLimitBurst=56\n\
             RemoveOnStop=yes\n\
             \n\
             [Install]\n\
             WantedBy=sockets.target\n",
            self.user,
            self.generation,
            self.endpoint().display(),
            self.user,
            self.group,
        )
    }
    /// The service template the activated guardian binds. The production
    /// helper entry contract may revise `ExecStart` in a later generation;
    /// each generation regenerates its own units.
    pub fn service_template_text(&self) -> String {
        format!(
            "[Unit]\n\
             Description=AgentSwapper managed guardian for user {} (generation {})\n\
             CollectMode=inactive-or-failed\n\
             \n\
             [Service]\n\
             Type=exec\n\
             Restart=no\n\
             User={}\n\
             Group={}\n\
             ExecStart={}\n\
             StandardInput=socket\n\
             StandardOutput=socket\n\
             StandardError=journal\n\
             Slice=system.slice\n\
             Delegate=no\n\
             KillMode=control-group\n\
             SendSIGKILL=yes\n\
             TimeoutStartSec=10s\n\
             TimeoutStopSec=2s\n\
             NoNewPrivileges=yes\n\
             CapabilityBoundingSet=\n\
             AmbientCapabilities=\n\
             UMask=0077\n",
            self.user,
            self.generation,
            self.user,
            self.group,
            self.image("guardian").display(),
        )
    }
    fn hashes(assets: &Assets) -> [String; 3] {
        [
            hex(&Sha256::digest(&assets.guardian)),
            hex(&Sha256::digest(&assets.session_helper)),
            hex(&Sha256::digest(&assets.exec_shim)),
        ]
    }
    /// The exact manifest document the installed readers accept. Unknown or
    /// missing fields would refuse at read time, so the writer emits only the
    /// documented schema.
    pub fn manifest_bytes(&self, assets: &Assets) -> io::Result<Vec<u8>> {
        let [guardian, session_helper, exec_shim] = Self::hashes(assets);
        #[derive(Serialize)]
        #[serde(rename_all = "snake_case")]
        struct Manifest {
            schema: u32,
            protocol: u32,
            version: &'static str,
            generation: String,
            user: u32,
            group: u32,
            guardian_sha256: String,
            session_helper_sha256: String,
            exec_shim_sha256: String,
            service_template_sha256: String,
            socket_unit_sha256: String,
        }
        let document = Manifest {
            schema: SCHEMA,
            protocol: PROTOCOL,
            version: VERSION,
            generation: self.generation.clone(),
            user: self.user,
            group: self.group,
            guardian_sha256: guardian,
            session_helper_sha256: session_helper,
            exec_shim_sha256: exec_shim,
            service_template_sha256: hex(&Sha256::digest(self.service_template_text().as_bytes())),
            socket_unit_sha256: hex(&Sha256::digest(self.socket_unit_text().as_bytes())),
        };
        serde_json::to_vec(&document).map_err(|error| io::Error::other(error.to_string()))
    }
    fn selector_bytes(&self) -> io::Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Selector {
            schema: u32,
            generation: String,
        }
        serde_json::to_vec(&Selector {
            schema: SELECTOR_SCHEMA,
            generation: self.generation.clone(),
        })
        .map_err(|error| io::Error::other(error.to_string()))
    }
    /// Stage the three images and both unit files. Every final path must be
    /// absent: an existing generation is never overwritten or re-linked. Each
    /// file is written to a temporary sibling, synced, given its final mode,
    /// renamed into place and verified as a single-link regular file. A
    /// failure rolls back everything this call created, including directories.
    pub fn stage(&self, assets: &Assets) -> io::Result<Staged> {
        let manifest = self.manifest_bytes(assets)?;
        let service_text = self.service_template_text();
        let socket_text = self.socket_unit_text();
        let files = [
            (self.image("guardian"), assets.guardian.as_slice(), 0o755),
            (
                self.image("session-helper"),
                assets.session_helper.as_slice(),
                0o755,
            ),
            (self.image("exec-shim"), assets.exec_shim.as_slice(), 0o755),
            (self.service_template(), service_text.as_bytes(), 0o644),
            (self.socket_unit(), socket_text.as_bytes(), 0o644),
        ];
        let mut staged = Staged {
            layout: self.clone(),
            manifest,
            files: Vec::new(),
            directories: Vec::new(),
        };
        staged.ensure_directories()?;
        for (path, bytes, mode) in files {
            staged.write_new(path, bytes, mode)?;
        }
        Ok(staged)
    }
}

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One completed generation staging. The manifest and selector are written
/// only by [`Staged::activate`]; dropping or rolling back removes every file
/// this transaction created and never touches pre-existing paths.
#[must_use = "a staged generation must be activated or rolled back"]
pub struct Staged {
    layout: Layout,
    manifest: Vec<u8>,
    files: Vec<PathBuf>,
    directories: Vec<PathBuf>,
}

impl Staged {
    fn ensure_directories(&mut self) -> io::Result<()> {
        for directory in self.layout.directories() {
            match std::fs::symlink_metadata(&directory) {
                Ok(meta) => {
                    if !meta.is_dir() {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "installation plan path is not a directory",
                        ));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    std::fs::create_dir(&directory)?;
                    std::fs::set_permissions(&directory, Permissions::from_mode(0o755))?;
                    self.directories.push(directory);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    fn write_new(&mut self, path: PathBuf, bytes: &[u8], mode: u32) -> io::Result<()> {
        if std::fs::symlink_metadata(&path).is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "installation plan refuses to replace an existing generation file",
            ));
        }
        self.write_replacing(path, bytes, mode, false).map(drop)
    }
    /// Atomically write `path`. With `replace`, an existing selector is
    /// replaced by rename and the completed name is not rolled back; without
    /// it the caller has already refused an existing file. Any failure before
    /// the rename leaves the previous file untouched.
    fn write_replacing(
        &mut self,
        path: PathBuf,
        bytes: &[u8],
        mode: u32,
        replace: bool,
    ) -> io::Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("installation plan file lacks a parent"))?;
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default();
        let temporary = parent.join(format!(".aswp-stage-{}-{}", std::process::id(), unique));
        let write = || -> io::Result<()> {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(mode))?;
            rustix::io::write(&file, bytes)?;
            rustix::fs::fsync(&file)?;
            std::fs::rename(&temporary, &path)?;
            // Sync the parent directory so the rename survives a crash.
            rustix::fs::fsync(&std::fs::File::open(parent)?)?;
            let meta = std::fs::symlink_metadata(&path)?;
            if !meta.is_file()
                || meta.mode() & 0o7777 != mode
                || (!replace && meta.nlink() != 1)
                || meta.size() as usize != bytes.len()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "staged installation file failed its single-link verification",
                ));
            }
            Ok(())
        };
        match write() {
            Ok(()) => {
                if !replace {
                    self.files.push(path);
                }
                Ok(())
            }
            Err(error) => {
                let _ = std::fs::remove_file(&temporary);
                Err(error)
            }
        }
    }
    /// Write the generation manifest and then atomically replace the selector.
    /// Existing generations stay untouched; only the selector name changes.
    /// Any failure rolls back the manifest and this transaction's files.
    pub fn activate(mut self) -> io::Result<Layout> {
        let manifest = self.layout.manifest();
        let selector = self.layout.selector();
        let bytes = self.manifest.clone();
        let result = (|| {
            self.write_new(manifest, &bytes, 0o644)?;
            self.write_replacing(selector, &self.layout.selector_bytes()?, 0o644, true)
        })();
        match result {
            Ok(()) => {
                self.files.clear();
                self.directories.clear();
                Ok(self.layout.clone())
            }
            Err(error) => {
                let _ = self.remove();
                Err(error)
            }
        }
    }
    /// Remove every file and empty directory this transaction created.
    pub fn rollback(mut self) -> io::Result<()> {
        self.remove()
    }
    fn remove(&mut self) -> io::Result<()> {
        let mut first = Ok(());
        for path in self.files.drain(..).rev() {
            if let Err(error) = std::fs::remove_file(&path)
                && error.kind() != io::ErrorKind::NotFound
                && first.is_ok()
            {
                first = Err(error);
            }
        }
        for directory in self.directories.drain(..).rev() {
            if let Err(error) = std::fs::remove_dir(&directory)
                && error.kind() != io::ErrorKind::NotFound
                && first.is_ok()
            {
                first = Err(error);
            }
        }
        first
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    const GENERATION: &str = "00112233445566778899aabbccddeeff";
    const NEXT: &str = "112233445566778899aabbccddeeff00";

    fn assets() -> Assets {
        Assets {
            guardian: b"guardian-image".to_vec(),
            session_helper: b"session-helper-image".to_vec(),
            exec_shim: b"exec-shim-image".to_vec(),
        }
    }

    #[test]
    fn fixed_layout_matches_the_installed_readers() -> io::Result<()> {
        let layout = Layout::fixed(1000, 1001, GENERATION)?;
        assert_eq!(
            layout.unit_stem(),
            "agentswapper-1000-00112233445566778899aabbccddeeff"
        );
        for (actual, expected) in [
            (
                layout.service_template(),
                "/etc/systemd/system/agentswapper-1000-00112233445566778899aabbccddeeff@.service",
            ),
            (
                layout.socket_unit(),
                "/etc/systemd/system/agentswapper-1000-00112233445566778899aabbccddeeff.socket",
            ),
            (
                layout.endpoint(),
                "/run/agentswapper/1000/00112233445566778899aabbccddeeff.sock",
            ),
            (
                layout.image("guardian"),
                "/usr/libexec/agentswapper/1000/00112233445566778899aabbccddeeff/guardian",
            ),
            (
                layout.image("session-helper"),
                "/usr/libexec/agentswapper/1000/00112233445566778899aabbccddeeff/session-helper",
            ),
            (
                layout.image("exec-shim"),
                "/usr/libexec/agentswapper/1000/00112233445566778899aabbccddeeff/exec-shim",
            ),
            (
                layout.manifest(),
                "/etc/agentswapper/installations/1000/00112233445566778899aabbccddeeff.json",
            ),
            (
                layout.selector(),
                "/etc/agentswapper/installations/1000/active.json",
            ),
        ] {
            assert_eq!(actual, Path::new(expected));
        }
        assert!(Layout::fixed(0, 1001, GENERATION).is_err());
        assert!(Layout::fixed(1000, 0, GENERATION).is_err());
        assert!(Layout::fixed(1000, 1001, "../escape").is_err());
        assert!(Layout::fixed(1000, 1001, "00112233445566778899aabbccddeef").is_err());
        Ok(())
    }

    #[test]
    fn unit_texts_pin_the_validated_configuration() -> io::Result<()> {
        let layout = Layout::fixed(1000, 1001, GENERATION)?;
        assert_eq!(
            layout.socket_unit_text(),
            format!(
                "[Unit]\n\
                 Description=AgentSwapper managed activation endpoint for user 1000 \
                 (generation {GENERATION})\n\
                 \n\
                 [Socket]\n\
                 ListenSequentialPacket=/run/agentswapper/1000/{GENERATION}.sock\n\
                 SocketUser=1000\n\
                 SocketGroup=1001\n\
                 SocketMode=0600\n\
                 Accept=yes\n\
                 MaxConnections=4\n\
                 TriggerLimitIntervalSec=30s\n\
                 TriggerLimitBurst=56\n\
                 RemoveOnStop=yes\n\
                 \n\
                 [Install]\n\
                 WantedBy=sockets.target\n"
            )
        );
        let template = layout.service_template_text();
        assert!(template.contains("User=1000\nGroup=1001\n"));
        assert!(template.contains(
            "ExecStart=/usr/libexec/agentswapper/1000/00112233445566778899aabbccddeeff/guardian\n"
        ));
        assert!(
            template
                .contains("NoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\n")
        );
        assert!(!template.contains("Environment=") && !template.contains("RuntimeMaxSec="));
        Ok(())
    }

    #[test]
    fn manifest_and_selector_match_the_reader_schema() -> io::Result<()> {
        let layout = Layout::fixed(1000, 1001, GENERATION)?;
        let manifest: serde_json::Value =
            serde_json::from_slice(&layout.manifest_bytes(&assets())?)?;
        let keys = [
            "schema",
            "protocol",
            "version",
            "generation",
            "user",
            "group",
            "guardian_sha256",
            "session_helper_sha256",
            "exec_shim_sha256",
            "service_template_sha256",
            "socket_unit_sha256",
        ];
        assert_eq!(
            manifest.as_object().map(|object| object.len()),
            Some(keys.len())
        );
        for key in keys {
            assert!(manifest.get(key).is_some(), "missing {key}");
        }
        assert_eq!(manifest["version"], VERSION);
        assert_eq!(manifest["generation"], GENERATION);
        assert_eq!(manifest["user"], 1000);
        assert_eq!(manifest["group"], 1001);
        let text_digest = |text: String| hex(&Sha256::digest(text.as_bytes()));
        assert_eq!(
            manifest["service_template_sha256"],
            text_digest(layout.service_template_text())
        );
        assert_eq!(
            manifest["socket_unit_sha256"],
            text_digest(layout.socket_unit_text())
        );
        let image_digest = |bytes: &[u8]| hex(&Sha256::digest(bytes));
        let parsed = assets();
        assert_eq!(manifest["guardian_sha256"], image_digest(&parsed.guardian));
        assert_eq!(
            manifest["session_helper_sha256"],
            image_digest(&parsed.session_helper)
        );
        assert_eq!(
            manifest["exec_shim_sha256"],
            image_digest(&parsed.exec_shim)
        );
        let selector: serde_json::Value = serde_json::from_slice(&layout.selector_bytes()?)?;
        assert_eq!(
            selector,
            serde_json::json!({"schema": 1, "generation": GENERATION})
        );
        Ok(())
    }

    #[test]
    fn staging_activates_one_generation_and_never_overwrites() -> io::Result<()> {
        let root = tempfile::tempdir()?;
        let layout = Layout::for_qualification(root.path(), 1000, 1001, GENERATION)?;
        let staged = layout.stage(&assets())?;
        staged.activate()?;
        for (path, mode) in [
            (layout.image("guardian"), 0o755),
            (layout.image("session-helper"), 0o755),
            (layout.image("exec-shim"), 0o755),
            (layout.service_template(), 0o644),
            (layout.socket_unit(), 0o644),
            (layout.manifest(), 0o644),
            (layout.selector(), 0o644),
        ] {
            let meta = fs::symlink_metadata(&path)?;
            assert_eq!(meta.mode() & 0o7777, mode, "{path:?}");
            assert_eq!(meta.nlink(), 1, "{path:?}");
        }
        assert_eq!(
            fs::read(layout.image("guardian"))?,
            b"guardian-image".to_vec()
        );
        assert_eq!(
            fs::read(layout.service_template())?,
            layout.service_template_text().into_bytes()
        );
        assert_eq!(
            fs::read(layout.socket_unit())?,
            layout.socket_unit_text().into_bytes()
        );
        assert_eq!(fs::read(layout.selector())?, layout.selector_bytes()?);
        // Restaging the same generation refuses and leaves nothing behind.
        assert!(layout.stage(&assets()).is_err());
        assert!(fs::read(layout.image("guardian")).is_ok());
        // A distinct generation stages and selects independently.
        let next = Layout::for_qualification(root.path(), 1000, 1001, NEXT)?;
        next.stage(&assets())?.activate()?;
        let selection: serde_json::Value = serde_json::from_slice(&fs::read(next.selector())?)?;
        assert_eq!(selection["generation"], NEXT);
        assert!(
            fs::read(layout.manifest()).is_ok(),
            "old generation preserved"
        );
        assert!(fs::read(next.manifest()).is_ok());
        Ok(())
    }

    #[test]
    fn interrupted_staging_and_activation_roll_back_completely() -> io::Result<()> {
        let root = tempfile::tempdir()?;
        // An existing final file refuses staging; nothing may be left behind.
        let blocked = Layout::for_qualification(root.path(), 1000, 1001, GENERATION)?;
        let image_parent = blocked
            .image("guardian")
            .parent()
            .ok_or_else(|| io::Error::other("image path lacks a parent"))?
            .to_path_buf();
        fs::create_dir_all(&image_parent)?;
        fs::write(blocked.image("guardian"), b"pre-existing")?;
        assert!(blocked.stage(&assets()).is_err());
        assert!(!blocked.service_template().exists());
        assert!(!blocked.manifest().exists());
        // An existing selector is atomically replaced on activation.
        let layout = Layout::for_qualification(root.path(), 1000, 1001, NEXT)?;
        let selector_parent = layout
            .selector()
            .parent()
            .ok_or_else(|| io::Error::other("selector path lacks a parent"))?
            .to_path_buf();
        fs::create_dir_all(&selector_parent)?;
        fs::write(layout.selector(), b"pre-existing selection")?;
        let staged = layout.stage(&assets())?;
        staged.activate()?;
        let selection: serde_json::Value = serde_json::from_slice(&fs::read(layout.selector())?)?;
        assert_eq!(selection["generation"], NEXT);
        assert!(layout.image("guardian").exists());
        assert!(layout.manifest().exists());
        Ok(())
    }

    #[test]
    fn failed_activation_rolls_back_this_transactions_files() -> io::Result<()> {
        let root = tempfile::tempdir()?;
        let layout = Layout::for_qualification(root.path(), 1000, 1001, GENERATION)?;
        // Make the selector parent unwritable so the activation rename fails
        // after the manifest and staged files already exist.
        let selector_parent = layout
            .selector()
            .parent()
            .ok_or_else(|| io::Error::other("selector path lacks a parent"))?
            .to_path_buf();
        fs::create_dir_all(&selector_parent)?;
        fs::set_permissions(&selector_parent, fs::Permissions::from_mode(0o500))?;
        let staged = layout.stage(&assets())?;
        let activated = staged.activate();
        fs::set_permissions(&selector_parent, fs::Permissions::from_mode(0o755))?;
        assert!(activated.is_err());
        assert!(!layout.image("guardian").exists());
        assert!(!layout.manifest().exists());
        assert!(!layout.socket_unit().exists());
        for directory in [
            root.path()
                .join("usr/libexec/agentswapper/1000/00112233445566778899aabbccddeeff"),
            root.path().join("usr/libexec/agentswapper/1000"),
            root.path().join("usr/libexec/agentswapper"),
        ] {
            assert!(!directory.exists(), "{directory:?} survived rollback");
        }
        Ok(())
    }
}
