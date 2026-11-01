//! Protected generation selection for a new admission. Active runs retain their
//! admitted artifact generation independently of subsequent selector updates.
use crate::{
    installed_artifacts::InstalledArtifacts,
    installed_config::ProtectedConfig,
    installed_manifest::{InstalledManifest, valid_generation},
};
use serde::Deserialize;
use std::{
    io,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    schema: u32,
    generation: String,
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "installed generation selector is invalid",
    )
}
impl Selection {
    fn parse(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > 16 * 1024 {
            return Err(invalid());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if value.schema != 1 || !valid_generation(&value.generation) {
            return Err(invalid());
        }
        Ok(value)
    }
}
fn identity() -> io::Result<(u32, u32)> {
    use rustix::process::{getegid, geteuid, getgid, getuid};
    let (user, group) = (getuid(), getgid());
    if user != geteuid()
        || group != getegid()
        || user.as_raw() == 0
        || group.as_raw() == 0
        || user.as_raw() > i32::MAX as u32
        || group.as_raw() > i32::MAX as u32
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "installed selection requires an ordinary matching identity",
        ));
    }
    Ok((user.as_raw(), group.as_raw()))
}

/// A root-protected selection and the corresponding retained artifacts for the
/// current ordinary caller. Namespace provenance is still a prerequisite.
/// This object does not authenticate a loaded service or authorize execution.
///
/// ```
/// use agentswapper_linux_runtime::installed_selection::SelectedInstallation;
/// fn accepts_selection(_: &SelectedInstallation) {}
/// ```
/// ```compile_fail,E0277
/// use agentswapper_linux_runtime::installed_selection::SelectedInstallation;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<SelectedInstallation>();
/// ```
#[cfg_attr(
    not(feature = "qualification"),
    doc = "\n```compile_fail,E0599\nuse agentswapper_linux_runtime::installed_selection::SelectedInstallation;\nfn custom_path() { let _ = SelectedInstallation::open_for_qualification; }\n```\n```compile_fail,E0599\nuse agentswapper_linux_runtime::installed_selection::SelectedInstallation;\nfn custom_paths() { let _ = SelectedInstallation::open_paths_for_qualification; }\n```"
)]
#[must_use = "retain the selector until the new admission is complete"]
pub struct SelectedInstallation {
    selector: ProtectedConfig,
    selector_path: PathBuf,
    artifacts: InstalledArtifacts,
}
impl SelectedInstallation {
    /// No environment variable, caller-supplied UID, generation or path can
    /// override this ordinary-user installation selection.
    pub fn open() -> io::Result<Self> {
        let (user, group) = identity()?;
        let path = PathBuf::from(format!(
            "/etc/agentswapper/installations/{user}/active.json"
        ));
        Self::read(&path, |generation| {
            InstalledArtifacts::open(InstalledManifest::open(user, group, generation)?)
        })
    }
    fn read(
        path: &Path,
        load: impl FnOnce(&str) -> io::Result<InstalledArtifacts>,
    ) -> io::Result<Self> {
        let selector = ProtectedConfig::open(path)?;
        let selection = Selection::parse(&selector.read()?)?;
        let artifacts = load(&selection.generation)?;
        let value = Self {
            selector,
            selector_path: path.to_owned(),
            artifacts,
        };
        value.require_current()?;
        Ok(value)
    }
    /// A disposable, protected fixture layout; absent from normal builds.
    #[cfg(feature = "qualification")]
    pub fn open_for_qualification(directory: &Path) -> io::Result<Self> {
        let (user, group) = identity()?;
        Self::read(&directory.join("active.json"), |generation| {
            let manifest = InstalledManifest::open_for_qualification(
                &directory.join(format!("{generation}.json")),
                user,
                group,
                generation,
            )?;
            InstalledArtifacts::open_for_qualification(manifest, &directory.join(generation))
        })
    }
    pub fn require_current(&self) -> io::Result<()> {
        self.selector.require_current(&self.selector_path)?;
        self.artifacts.require_current()?;
        self.selector.require_current(&self.selector_path)
    }
    /// Layout override for fixed, disposable hosted fixtures only. Absent from
    /// ordinary builds; identity, generation, ownership and hash checks remain.
    /// The selected manifest is `<manifest_prefix>.<generation>.json`, so an
    /// upgrade need not replace a manifest retained by an admitted generation.
    #[cfg(feature = "qualification")]
    pub fn open_paths_for_qualification(
        selector: &Path,
        manifest_prefix: &Path,
        images: [&Path; 3],
        units: [&Path; 2],
    ) -> io::Result<Self> {
        let (user, group) = identity()?;
        Self::read(selector, |generation| {
            let mut manifest = manifest_prefix.as_os_str().to_owned();
            manifest.push(format!(".{generation}.json"));
            InstalledArtifacts::open_paths_for_qualification(
                InstalledManifest::open_for_qualification(
                    Path::new(&manifest),
                    user,
                    group,
                    generation,
                )?,
                images,
                units,
            )
        })
    }
    pub fn artifacts(&self) -> &InstalledArtifacts {
        &self.artifacts
    }
    /// Recheck before handing the admitted generation to its active-run owner.
    /// That owner retains these assets, rather than selecting a newer generation
    /// during a live run. This transition itself does not admit a process.
    pub fn into_artifacts(self) -> io::Result<InstalledArtifacts> {
        self.require_current()?;
        Ok(self.artifacts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const GENERATION: &str = "00112233445566778899aabbccddeeff";
    #[test]
    fn selector_refuses_unbounded_ambiguous_or_path_like_generations() -> io::Result<()> {
        let valid = format!("{{\"schema\":1,\"generation\":\"{GENERATION}\"}}");
        assert_eq!(Selection::parse(valid.as_bytes())?.generation, GENERATION);
        let bad = [
            valid.replace("schema\":1", "schema\":2"),
            valid.replace(GENERATION, "../other"),
            valid.replace(GENERATION, &"0".repeat(32)),
            valid.replace(GENERATION, &GENERATION.to_uppercase()),
            valid.replacen('{', "{\"schema\":1,", 1),
            valid.replacen('{', "{\"unknown\":\"private-canary\",", 1),
            "{}".to_owned(),
            " ".repeat(16 * 1024 + 1),
        ];
        for bytes in bad {
            let error = Selection::parse(bytes.as_bytes())
                .err()
                .ok_or_else(|| io::Error::other("invalid selector accepted"))?;
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(
                error.to_string(),
                "installed generation selector is invalid"
            );
        }
        Ok(())
    }
}
