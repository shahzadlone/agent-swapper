//! Local profile metadata. Vendor credentials remain owned by the native CLI.
//!
//! No quota or account identity is inferred from the presence of a directory.
pub mod domain;
pub mod launch;
mod private_fs;
pub mod store;

pub use domain::{Alias, Harness, Profile, ProfileId};
pub use store::Store;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "alias must start with a lowercase letter and contain 1-32 lowercase letters, digits, or hyphens"
    )]
    InvalidAlias,
    #[error("profile not found; use `aswp list` to see registered aliases")]
    NotFound,
    #[error("directory mapping not found; use `aswp map` to inspect registered mappings")]
    MappingNotFound,
    #[error("unfinished run not found; use `aswp status` to inspect run IDs")]
    RunNotFound,
    #[error("alias already registered; choose another alias")]
    DuplicateAlias,
    #[error("profile is disabled; enable it before launching")]
    Disabled,
    #[error("profile is busy or has an unfinished run; inspect `aswp status` before continuing")]
    Busy,
    #[error("unsafe state path or permissions; use a private, local directory with no symlinks")]
    UnsafePath,
    #[error("profile directory is missing; restore it rather than silently creating a new login")]
    MissingProfileDirectory,
    #[error("registry schema is newer than this binary; update AgentSwapper")]
    NewerSchema,
    #[error("registry contains invalid metadata; restore a known-good backup")]
    CorruptRegistry,
    #[error("native CLI was not found; install it or supply --executable with an absolute path")]
    ExecutableNotFound,
    #[error("executable must be a regular native program; shell and batch shims are unsupported")]
    UnsafeExecutable,
    #[error(
        "inherited routing or authentication variable {0} conflicts with the selected profile; unset it before launching"
    )]
    EnvironmentConflict(&'static str),
    #[error(
        "native profile isolation is unverified; inspect --dry-run, then explicitly opt in with --experimental-native"
    )]
    UnverifiedNative,
    #[error(
        "interactive mode requires a terminal and cannot be combined with --json; use `aswp list --json` or `aswp run --dry-run --json`"
    )]
    InteractiveMode,
    #[error("path cannot be represented without loss; use a UTF-8 state or mapping path")]
    NonUtf8Path,
    #[error("storage operation failed")]
    Database(#[from] rusqlite::Error),
    #[error("filesystem or process operation failed")]
    Io(#[from] std::io::Error),
    #[error("serialization failed")]
    Json(#[from] serde_json::Error),
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidAlias => "invalid_alias",
            Self::NotFound => "profile_not_found",
            Self::MappingNotFound => "mapping_not_found",
            Self::RunNotFound => "run_not_found",
            Self::DuplicateAlias => "duplicate_alias",
            Self::Disabled => "profile_disabled",
            Self::Busy => "profile_busy",
            Self::UnsafePath => "unsafe_state_path",
            Self::MissingProfileDirectory => "profile_dir_missing",
            Self::NewerSchema => "newer_schema",
            Self::CorruptRegistry => "corrupt_registry",
            Self::ExecutableNotFound => "executable_not_found",
            Self::UnsafeExecutable => "unsafe_executable",
            Self::EnvironmentConflict(_) => "environment_conflict",
            Self::UnverifiedNative => "native_unverified",
            Self::InteractiveMode => "interactive_mode",
            Self::NonUtf8Path => "non_utf8_path",
            Self::Database(_) => "database_error",
            Self::Io(_) => "io_error",
            Self::Json(_) => "serialization_error",
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Render untrusted strings without terminal control sequences.
pub fn terminal_text(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}
