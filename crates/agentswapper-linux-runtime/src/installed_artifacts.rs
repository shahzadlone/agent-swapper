//! Retained manifest and matching artifacts. Generation selection, namespace
//! trust, manager-loaded policy and execution admission remain separate gates.
use crate::{
    installed_config::ProtectedConfig, installed_image::ProtectedImage,
    installed_manifest::InstalledManifest,
};
use std::{io, path::PathBuf};

struct Paths {
    guardian: PathBuf,
    session_helper: PathBuf,
    exec_shim: PathBuf,
    service_template: PathBuf,
    socket_unit: PathBuf,
}
impl Paths {
    fn installed(manifest: &InstalledManifest) -> Self {
        Self {
            guardian: manifest.guardian().0,
            session_helper: manifest.session_helper().0,
            exec_shim: manifest.exec_shim().0,
            service_template: manifest.service_template().0,
            socket_unit: manifest.socket_unit().0,
        }
    }
}

/// A protected manifest and its five matching retained files. This value is
/// neither execution permission nor evidence that the manager loaded these
/// bytes. The caller must establish trusted namespace and selector provenance.
///
/// ```
/// use agentswapper_linux_runtime::installed_artifacts::InstalledArtifacts;
/// fn accepts_artifacts(_: &InstalledArtifacts) {}
/// ```
/// ```compile_fail,E0277
/// use agentswapper_linux_runtime::installed_artifacts::InstalledArtifacts;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<InstalledArtifacts>();
/// ```
#[cfg_attr(
    not(feature = "qualification"),
    doc = "\n```compile_fail,E0599\nuse agentswapper_linux_runtime::installed_artifacts::InstalledArtifacts;\nfn custom_path() { let _ = InstalledArtifacts::open_for_qualification; }\n```"
)]
#[must_use = "retain the manifest and artifact handles through admission"]
pub struct InstalledArtifacts {
    manifest: InstalledManifest,
    paths: Paths,
    guardian: ProtectedImage,
    session_helper: ProtectedImage,
    exec_shim: ProtectedImage,
    service_template: ProtectedConfig,
    socket_unit: ProtectedConfig,
}
impl InstalledArtifacts {
    pub fn open(manifest: InstalledManifest) -> io::Result<Self> {
        let paths = Paths::installed(&manifest);
        Self::read(manifest, paths)
    }
    fn read(manifest: InstalledManifest, paths: Paths) -> io::Result<Self> {
        manifest.require_current()?;
        let guardian = ProtectedImage::open(&paths.guardian)?;
        guardian.require_sha256(manifest.guardian().1)?;
        let session_helper = ProtectedImage::open(&paths.session_helper)?;
        session_helper.require_sha256(manifest.session_helper().1)?;
        let exec_shim = ProtectedImage::open(&paths.exec_shim)?;
        exec_shim.require_sha256(manifest.exec_shim().1)?;
        let service_template = ProtectedConfig::open(&paths.service_template)?;
        service_template.require_sha256(manifest.service_template().1)?;
        let socket_unit = ProtectedConfig::open(&paths.socket_unit)?;
        socket_unit.require_sha256(manifest.socket_unit().1)?;
        let value = Self {
            manifest,
            paths,
            guardian,
            session_helper,
            exec_shim,
            service_template,
            socket_unit,
        };
        value.require_current()?;
        Ok(value)
    }
    /// Disposable fixture locations are absent from normal builds.
    #[cfg(feature = "qualification")]
    pub fn open_for_qualification(
        manifest: InstalledManifest,
        directory: &std::path::Path,
    ) -> io::Result<Self> {
        Self::read(
            manifest,
            Paths {
                guardian: directory.join("guardian"),
                session_helper: directory.join("session-helper"),
                exec_shim: directory.join("exec-shim"),
                service_template: directory.join("fixture@.service"),
                socket_unit: directory.join("fixture.socket"),
            },
        )
    }
    pub fn require_current(&self) -> io::Result<()> {
        self.manifest.require_current()?;
        self.guardian.require_current(&self.paths.guardian)?;
        self.session_helper
            .require_current(&self.paths.session_helper)?;
        self.exec_shim.require_current(&self.paths.exec_shim)?;
        self.service_template
            .require_current(&self.paths.service_template)?;
        self.socket_unit.require_current(&self.paths.socket_unit)?;
        self.manifest.require_current()
    }
    pub fn manifest(&self) -> &InstalledManifest {
        &self.manifest
    }
    pub fn service_template_path(&self) -> &std::path::Path {
        &self.paths.service_template
    }
    pub fn guardian(&self) -> &ProtectedImage {
        &self.guardian
    }
    pub fn session_helper(&self) -> &ProtectedImage {
        &self.session_helper
    }
    pub fn exec_shim(&self) -> &ProtectedImage {
        &self.exec_shim
    }
    pub fn service_template(&self) -> &ProtectedConfig {
        &self.service_template
    }
    pub fn socket_unit(&self) -> &ProtectedConfig {
        &self.socket_unit
    }
}
