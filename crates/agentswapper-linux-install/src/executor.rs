//! Installation, removal and verification of one fixed generation. The
//! executor runs as root and owns the documented fixed layout; verification
//! runs as the ordinary caller through the installed readers and the
//! authenticated manager transport. Nothing here launches a target or grants
//! execution permission.
use crate::control::Control;
use agentswapper_linux_runtime::{
    install_plan::{Assets, Layout},
    installed_manifest::InstalledManifest,
    installed_selection::SelectedInstallation,
};
use std::{
    fs,
    io::{self, Read},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

const IMAGE_LIMIT: usize = 128 * 1024 * 1024;

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    require(
        meta.is_file() && meta.len() <= IMAGE_LIMIT as u64,
        "installer image is not a bounded regular file",
    )?;
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    fs::File::open(path)?.read_to_end(&mut bytes)?;
    require(
        bytes.len() == meta.len() as usize,
        "installer image changed size",
    )?;
    Ok(bytes)
}

/// Stage, activate and load one generation from three image files. The
/// generation becomes the active selection; existing generations are never
/// touched and the manager reloads before the new socket unit starts.
pub fn install(
    control: &impl Control,
    images: [&Path; 3],
    user: u32,
    group: u32,
    generation: &str,
) -> io::Result<Layout> {
    let layout = Layout::fixed(user, group, generation)?;
    let assets = Assets {
        guardian: read_bounded(images[0])?,
        session_helper: read_bounded(images[1])?,
        exec_shim: read_bounded(images[2])?,
    };
    // The endpoint parent must exist as root-owned protected ancestry before
    // the manager creates the socket inside it.
    let endpoint_parent = endpoint_parent(&layout)?;
    match fs::symlink_metadata(&endpoint_parent) {
        Ok(meta) => require(
            meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
            "endpoint parent is not root-owned protected ancestry",
        )?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(&endpoint_parent)?;
            fs::set_permissions(&endpoint_parent, fs::Permissions::from_mode(0o755))?;
        }
        Err(error) => return Err(error),
    }
    layout.stage(&assets)?.activate()?;
    control.reload()?;
    control.enable_now(&socket_unit(&layout))?;
    Ok(layout)
}

/// Stop and remove one generation. The active selection is never removed;
/// the manifest must still open so a removal always starts from a readable
/// generation record.
pub fn remove(control: &impl Control, user: u32, group: u32, generation: &str) -> io::Result<()> {
    let layout = Layout::fixed(user, group, generation)?;
    refuse_active(&layout)?;
    InstalledManifest::open(user, group, generation)?;
    remove_staged(&layout, control)
}

/// Deselect one generation: stop its socket unit and remove the selector,
/// keeping every staged file. This is the administrator's way out of the
/// active-generation removal refusal.
pub fn deactivate(
    control: &impl Control,
    user: u32,
    group: u32,
    generation: &str,
) -> io::Result<()> {
    let layout = Layout::fixed(user, group, generation)?;
    control.disable_now(&socket_unit(&layout))?;
    control.reload()?;
    match fs::symlink_metadata(layout.selector()) {
        Ok(meta) => require(meta.is_file(), "the selector is not a regular file")?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    fs::remove_file(layout.selector())
}

fn refuse_active(layout: &Layout) -> io::Result<()> {
    let selector = layout.selector();
    let bytes = match fs::read(&selector) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::other(format!("invalid generation selector: {error}")))?;
    require(
        value["generation"] != layout.generation(),
        "refusing to remove the active generation; select another first",
    )
}

fn remove_staged(layout: &Layout, control: &impl Control) -> io::Result<()> {
    control.disable_now(&socket_unit(layout))?;
    control.reload()?;
    for path in [
        layout.manifest(),
        layout.image("guardian"),
        layout.image("session-helper"),
        layout.image("exec-shim"),
        layout.service_template(),
        layout.socket_unit(),
    ] {
        let meta = fs::symlink_metadata(&path)?;
        require(meta.is_file(), "installation removal found a non-file path")?;
        fs::remove_file(&path)?;
    }
    if let Some(directory) = layout.image("guardian").parent() {
        // Only the per-generation directory is pruned; shared parents stay.
        fs::remove_dir(directory).ok();
    }
    Ok(())
}

fn socket_unit(layout: &Layout) -> String {
    format!("{}.socket", layout.unit_stem())
}

fn endpoint_parent(layout: &Layout) -> io::Result<std::path::PathBuf> {
    layout
        .endpoint()
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::other("endpoint path lacks a parent"))
}

/// Verify the current installation as the ordinary caller: capture the
/// namespace origin, read the selector and its retained artifacts, and
/// observe the loaded socket policy through one authenticated manager
/// connection. Returned facts are diagnostics only.
pub async fn verify(user: u32, group: u32) -> io::Result<String> {
    require(
        ordinary(user, group),
        "verification requires an ordinary identity",
    )?;
    let selection = SelectedInstallation::open()?;
    require(
        selection.artifacts().manifest().identity() == (user, group),
        "the selected installation belongs to another identity",
    )?;
    let policy = agentswapper_linux_manager::SocketPolicy::installed(&selection)?;
    let (manager, sender, _) = agentswapper_linux_manager::connect().await?;
    let observed =
        agentswapper_linux_manager::LoadedSocket::observe(&manager, sender.as_str(), policy)
            .await?;
    observed.recheck(&manager).await?;
    let fact = observed.fact();
    manager.close().await.map_err(io::Error::other)?;
    serde_json::to_string(&fact).map_err(|error| io::Error::other(error.to_string()))
}

fn ordinary(user: u32, group: u32) -> bool {
    user != 0 && group != 0 && user <= i32::MAX as u32 && group <= i32::MAX as u32
}

#[cfg(all(test, target_os = "linux", feature = "qualification"))]
mod tests {
    use super::*;
    use crate::control::Control;
    use std::path::PathBuf;

    const GENERATION: &str = "00112233445566778899aabbccddeeff";
    const NEXT: &str = "112233445566778899aabbccddeeff00";

    struct Recorded {
        calls: std::sync::Mutex<Vec<String>>,
        fail_enable: bool,
    }
    impl Recorded {
        fn new() -> Self {
            Self {
                calls: std::sync::Mutex::new(Vec::new()),
                fail_enable: false,
            }
        }
    }
    fn calls(recorded: &Recorded) -> std::sync::MutexGuard<'_, Vec<String>> {
        // A poisoned lock still holds the recorded calls; recover them.
        match recorded.calls.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    impl Control for Recorded {
        fn reload(&self) -> io::Result<()> {
            calls(self).push("daemon-reload".to_owned());
            Ok(())
        }
        fn enable_now(&self, unit: &str) -> io::Result<()> {
            if self.fail_enable {
                return Err(io::Error::other("control refused"));
            }
            calls(self).push(format!("enable {unit}"));
            Ok(())
        }
        fn disable_now(&self, unit: &str) -> io::Result<()> {
            calls(self).push(format!("disable {unit}"));
            Ok(())
        }
    }

    fn image(root: &std::path::Path, name: &str, role: u8) -> io::Result<PathBuf> {
        let path = root.join(name);
        fs::write(&path, [b'i', role, b'!'])?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        Ok(path)
    }

    fn tempdir_root() -> io::Result<PathBuf> {
        let root = tempfile::tempdir()?;
        let path = root.path().to_path_buf();
        // The temporary directory must outlive the transaction; leak it and
        // let the test process exit reclaim it.
        std::mem::forget(root);
        Ok(path)
    }

    /// The production executor derives a fixed `/` layout; these tests run
    /// the identical staging, activation, endpoint-parent and control
    /// ordering over a disposable root.
    fn install_transaction(
        root: &std::path::Path,
        control: &impl Control,
        images: [&std::path::Path; 3],
        user: u32,
        group: u32,
        generation: &str,
    ) -> io::Result<Layout> {
        let layout = Layout::for_qualification(root, user, group, generation)?;
        let assets = Assets {
            guardian: read_bounded(images[0])?,
            session_helper: read_bounded(images[1])?,
            exec_shim: read_bounded(images[2])?,
        };
        // The production endpoint-parent precondition is a root-only check;
        // these ordinary-user tests cover the staging and control ordering.
        layout.stage(&assets)?.activate()?;
        control.reload()?;
        control.enable_now(&socket_unit(&layout))?;
        Ok(layout)
    }

    #[test]
    fn install_stages_loads_and_refuses_replacement() -> io::Result<()> {
        let root = tempdir_root()?;
        let guardian = image(&root, "guardian-src", 1)?;
        let helper = image(&root, "helper-src", 2)?;
        let shim = image(&root, "shim-src", 3)?;
        let control = Recorded::new();
        let staged = install_transaction(
            &root,
            &control,
            [&guardian, &helper, &shim],
            1000,
            1001,
            GENERATION,
        )?;
        let calls = calls(&control).clone();
        assert_eq!(
            calls,
            vec![
                "daemon-reload".to_owned(),
                "enable agentswapper-1000-00112233445566778899aabbccddeeff.socket".to_owned(),
            ]
        );
        assert!(staged.manifest().exists());
        assert!(staged.image("guardian").exists());
        // Restaging the same generation refuses and leaves the files intact.
        assert!(
            install_transaction(
                &root,
                &control,
                [&guardian, &helper, &shim],
                1000,
                1001,
                GENERATION
            )
            .is_err()
        );
        assert!(staged.image("guardian").exists());
        Ok(())
    }

    #[test]
    fn failed_service_control_keeps_the_staged_generation_selectable() -> io::Result<()> {
        let root = tempdir_root()?;
        let guardian = image(&root, "guardian-src", 1)?;
        let helper = image(&root, "helper-src", 2)?;
        let shim = image(&root, "shim-src", 3)?;
        let control = Recorded {
            calls: std::sync::Mutex::new(Vec::new()),
            fail_enable: true,
        };
        // Staging and activation commit before service control; its refusal
        // is reported and the complete generation stays selected.
        let result = install_transaction(
            &root,
            &control,
            [&guardian, &helper, &shim],
            1000,
            1001,
            GENERATION,
        );
        assert!(result.is_err());
        let layout = Layout::for_qualification(&root, 1000, 1001, GENERATION)?;
        assert!(layout.manifest().exists());
        assert!(layout.image("guardian").exists());
        Ok(())
    }

    #[test]
    fn removal_refuses_the_active_generation_and_prunes_inactive_ones() -> io::Result<()> {
        let root = tempdir_root()?;
        let guardian = image(&root, "guardian-src", 1)?;
        let helper = image(&root, "helper-src", 2)?;
        let shim = image(&root, "shim-src", 3)?;
        let control = Recorded::new();
        let active = install_transaction(
            &root,
            &control,
            [&guardian, &helper, &shim],
            1000,
            1001,
            GENERATION,
        )?;
        let next = install_transaction(
            &root,
            &control,
            [&guardian, &helper, &shim],
            1000,
            1001,
            NEXT,
        )?;
        // After the upgrade the selector names the second generation; the
        // active generation is never removed.
        assert!(refuse_active(&next).is_err());
        assert!(next.manifest().exists());
        // The previously active generation is now inactive and removable.
        remove_staged(&active, &control)?;
        assert!(!active.manifest().exists());
        assert!(!active.image("guardian").exists());
        assert!(!active.service_template().exists());
        let calls = calls(&control).clone();
        assert!(calls.contains(
            &"disable agentswapper-1000-00112233445566778899aabbccddeeff.socket".to_owned()
        ));
        // A missing selector leaves removal unblocked.
        fs::remove_file(next.selector())?;
        assert!(refuse_active(&next).is_ok());
        Ok(())
    }
}
