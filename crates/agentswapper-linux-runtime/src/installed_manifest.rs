//! Bounded installation metadata from a fixed protected location. Reading this
//! manifest does not authenticate its images, loaded units or an execution scope.
use crate::installed_config::ProtectedConfig;
use serde::Deserialize;
use std::{
    io,
    path::{Path, PathBuf},
};

const SCHEMA: u32 = 1;
const PROTOCOL: u32 = 1;
/// Installation artifacts must match this runtime build's package version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: u32,
    protocol: u32,
    version: String,
    generation: String,
    user: u32,
    group: u32,
    guardian_sha256: String,
    session_helper_sha256: String,
    exec_shim_sha256: String,
    service_template_sha256: String,
    socket_unit_sha256: String,
}

fn invalid() -> io::Error {
    // Do not echo file contents or unexpected strings into startup diagnostics.
    io::Error::new(
        io::ErrorKind::InvalidData,
        "installed manifest is invalid or incompatible",
    )
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}
fn ordinary(user: u32, group: u32) -> bool {
    user != 0 && group != 0 && user <= i32::MAX as u32 && group <= i32::MAX as u32
}
pub(crate) fn valid_generation(value: &str) -> bool {
    hex(value, 32)
}
impl Document {
    fn unit_stem(&self) -> String {
        format!("agentswapper-{}-{}", self.user, self.generation)
    }
    fn unit_path(&self, suffix: &str) -> PathBuf {
        PathBuf::from(format!("/etc/systemd/system/{}{suffix}", self.unit_stem()))
    }
    fn endpoint(&self) -> PathBuf {
        PathBuf::from(format!(
            "/run/agentswapper/{}/{}.sock",
            self.user, self.generation
        ))
    }
    fn image(&self, name: &str) -> PathBuf {
        PathBuf::from(format!(
            "/usr/libexec/agentswapper/{}/{}/{name}",
            self.user, self.generation
        ))
    }
    fn parse(bytes: &[u8], user: u32, group: u32, generation: &str) -> io::Result<Self> {
        if bytes.len() > 16 * 1024 || !ordinary(user, group) || !hex(generation, 32) {
            return Err(invalid());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if value.schema != SCHEMA
            || value.protocol != PROTOCOL
            || value.version != VERSION
            || value.user != user
            || value.group != group
            || value.generation != generation
            || [
                &value.guardian_sha256,
                &value.session_helper_sha256,
                &value.exec_shim_sha256,
                &value.service_template_sha256,
                &value.socket_unit_sha256,
            ]
            .iter()
            .any(|hash| !hex(hash, 64))
        {
            return Err(invalid());
        }
        Ok(value)
    }
}

/// Expected hashes and derived fixed paths, not proof that those files match.
/// The caller must independently establish a trusted namespace.
///
/// ```
/// use agentswapper_linux_runtime::installed_manifest::InstalledManifest;
/// fn accepts_manifest(_: &InstalledManifest) {}
/// ```
#[cfg_attr(
    not(feature = "qualification"),
    doc = "\n```compile_fail,E0599\nuse agentswapper_linux_runtime::installed_manifest::InstalledManifest;\nfn custom_path() { let _ = InstalledManifest::open_for_qualification; }\n```"
)]
pub struct InstalledManifest {
    file: ProtectedConfig,
    path: PathBuf,
    document: Document,
}
impl InstalledManifest {
    /// The root-owned selector that chooses a generation is a separate gate.
    /// A caller-supplied generation cannot grant execution authority.
    pub fn open(user: u32, group: u32, generation: &str) -> io::Result<Self> {
        if !ordinary(user, group) || !hex(generation, 32) {
            return Err(invalid());
        }
        let path = PathBuf::from(format!(
            "/etc/agentswapper/installations/{user}/{generation}.json"
        ));
        Self::read(&path, user, group, generation)
    }
    fn read(path: &Path, user: u32, group: u32, generation: &str) -> io::Result<Self> {
        let file = ProtectedConfig::open(path)?;
        let document = Document::parse(&file.read()?, user, group, generation)?;
        file.require_current(path)?;
        Ok(Self {
            file,
            path: path.to_owned(),
            document,
        })
    }
    /// Custom locations exist only for disposable qualification fixtures.
    #[cfg(feature = "qualification")]
    pub fn open_for_qualification(
        path: &Path,
        user: u32,
        group: u32,
        generation: &str,
    ) -> io::Result<Self> {
        Self::read(path, user, group, generation)
    }
    pub fn require_current(&self) -> io::Result<()> {
        self.file.require_current(&self.path)
    }
    pub fn generation(&self) -> &str {
        &self.document.generation
    }
    pub fn identity(&self) -> (u32, u32) {
        (self.document.user, self.document.group)
    }
    pub fn unit_stem(&self) -> String {
        self.document.unit_stem()
    }
    pub fn endpoint(&self) -> PathBuf {
        self.document.endpoint()
    }
    pub fn guardian(&self) -> (PathBuf, &str) {
        (
            self.document.image("guardian"),
            &self.document.guardian_sha256,
        )
    }
    pub fn session_helper(&self) -> (PathBuf, &str) {
        (
            self.document.image("session-helper"),
            &self.document.session_helper_sha256,
        )
    }
    pub fn exec_shim(&self) -> (PathBuf, &str) {
        (
            self.document.image("exec-shim"),
            &self.document.exec_shim_sha256,
        )
    }
    pub fn service_template(&self) -> (PathBuf, &str) {
        (
            self.document.unit_path("@.service"),
            &self.document.service_template_sha256,
        )
    }
    pub fn socket_unit(&self) -> (PathBuf, &str) {
        (
            self.document.unit_path(".socket"),
            &self.document.socket_unit_sha256,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const GENERATION: &str = "00112233445566778899aabbccddeeff";
    fn valid() -> serde_json::Value {
        serde_json::json!({"schema":1,"protocol":1,"version":env!("CARGO_PKG_VERSION"),"generation":GENERATION,
            "user":1000,"group":1001,"guardian_sha256":"a".repeat(64),"session_helper_sha256":"b".repeat(64),
            "exec_shim_sha256":"c".repeat(64),"service_template_sha256":"d".repeat(64),"socket_unit_sha256":"e".repeat(64)})
    }
    #[test]
    fn production_layout_uses_uid_generation_and_administrator_units() -> io::Result<()> {
        // Test validated metadata's path contract without fabricating a
        // protected file, selected installation or service admission value.
        let document = Document::parse(&serde_json::to_vec(&valid())?, 1000, 1001, GENERATION)?;
        for (actual, expected) in [
            (
                document.unit_path("@.service"),
                "/etc/systemd/system/agentswapper-1000-00112233445566778899aabbccddeeff@.service",
            ),
            (
                document.unit_path(".socket"),
                "/etc/systemd/system/agentswapper-1000-00112233445566778899aabbccddeeff.socket",
            ),
            (
                document.endpoint(),
                "/run/agentswapper/1000/00112233445566778899aabbccddeeff.sock",
            ),
            (
                document.image("guardian"),
                "/usr/libexec/agentswapper/1000/00112233445566778899aabbccddeeff/guardian",
            ),
            (
                document.image("session-helper"),
                "/usr/libexec/agentswapper/1000/00112233445566778899aabbccddeeff/session-helper",
            ),
            (
                document.image("exec-shim"),
                "/usr/libexec/agentswapper/1000/00112233445566778899aabbccddeeff/exec-shim",
            ),
        ] {
            assert_eq!(actual, Path::new(expected));
        }
        Ok(())
    }
    #[test]
    fn manifest_refuses_incompatible_identity_protocol_and_artifacts() -> io::Result<()> {
        let good = serde_json::to_vec(&valid())?;
        Document::parse(&good, 1000, 1001, GENERATION)?;
        for (key, bad) in [
            ("schema", serde_json::json!(2)),
            ("protocol", serde_json::json!(0)),
            ("version", serde_json::json!("other")),
            ("user", serde_json::json!(0)),
            ("group", serde_json::json!(1000)),
            ("generation", serde_json::json!("../other")),
            (
                "generation",
                serde_json::json!("112233445566778899aabbccddeeff0011"),
            ),
            ("guardian_sha256", serde_json::json!("a".repeat(63))),
            ("session_helper_sha256", serde_json::json!("A".repeat(64))),
            ("exec_shim_sha256", serde_json::json!("0".repeat(64))),
            ("service_template_sha256", serde_json::json!("x".repeat(64))),
            ("socket_unit_sha256", serde_json::json!(false)),
            ("unknown", serde_json::json!("secret-canary")),
        ] {
            let mut value = valid();
            value[key] = bad;
            let error = Document::parse(&serde_json::to_vec(&value)?, 1000, 1001, GENERATION)
                .err()
                .ok_or_else(|| io::Error::other("invalid manifest accepted"))?;
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(
                error.to_string(),
                "installed manifest is invalid or incompatible"
            );
        }
        for (user, group, generation) in [
            (0, 1001, GENERATION),
            (1000, 0, GENERATION),
            (1000, 1001, "../escape"),
            (1000, 1001, "00000000000000000000000000000000"),
        ] {
            assert!(Document::parse(&good, user, group, generation).is_err());
        }
        assert!(Document::parse(&[b' '; 16 * 1024 + 1], 1000, 1001, GENERATION).is_err());
        let duplicate =
            String::from_utf8(good)
                .map_err(io::Error::other)?
                .replacen('{', "{\"schema\":1,", 1);
        assert!(Document::parse(duplicate.as_bytes(), 1000, 1001, GENERATION).is_err());
        Ok(())
    }
}
