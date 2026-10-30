//! Local profile metadata. Vendor credentials remain owned by the native CLI.
//!
//! No quota or account identity is inferred from the presence of a directory.
pub mod config;
pub mod domain;
pub mod handover;
pub mod launch;
mod private_fs;
pub mod store;
pub mod supervision;
#[cfg(windows)]
#[doc(hidden)]
#[path = "launch/windows_terminal.rs"]
pub mod windows_console;

pub use domain::{Alias, ExecutionEngine, GentsAgentId, GentsBinding, Harness, Profile, ProfileId};
pub use store::Store;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unknown preference; supported keys: history.limit, ui.mask")]
    UnknownConfigKey,
    #[error(
        "invalid preference value; history.limit accepts integers 1-200 and ui.mask accepts true or false"
    )]
    InvalidConfigValue,
    #[error("config.json is invalid; preserve it and inspect `aswp config path` before editing")]
    InvalidConfig,
    #[error(
        "config.json exceeds this build's 4 KiB limit; preserve the file and check whether a newer AgentSwapper is required"
    )]
    ConfigTooLarge,
    #[error("config.json uses a newer format; update AgentSwapper before changing preferences")]
    NewerConfig,
    #[error("preferences are busy; another config writer holds the lock")]
    ConfigBusy,
    #[error(
        "preferences were replaced, but directory synchronization failed; read them back before retrying"
    )]
    ConfigDurability,
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
    #[error("registry contains invalid metadata; preserve the state directory before recovery")]
    CorruptRegistry,
    #[error(
        "registry projections disagree with the journal; preserve the state and run `aswp registry verify` before launching"
    )]
    ProjectionMismatch,
    #[error("registry schema changed while this process was open; restart AgentSwapper")]
    RegistrySchemaChanged,
    #[error("registry connection settings changed; restart AgentSwapper before writing")]
    RegistryConnectionChanged,
    #[error("registry event exceeds the 64 KiB metadata limit")]
    RegistryEventTooLarge,
    #[error("run history limit must be between 1 and 200")]
    InvalidHistoryLimit,
    #[error("native CLI was not found; install it or supply --executable with an absolute path")]
    ExecutableNotFound,
    #[error(
        "executable path or permissions are unsafe; use a trusted executable (Unix scripts supported, Windows requires .exe); batch and PowerShell shims are refused"
    )]
    UnsafeExecutable,
    #[error(
        "inherited routing or authentication variable {0} conflicts with the selected profile; unset it before launching"
    )]
    EnvironmentConflict(&'static str),
    #[error(
        "a shared Anthropic profile may override the Claude login; review it, then use --allow-claude-shared-auth to permit this launch"
    )]
    ClaudeSharedAuthPresent,
    #[error(
        "could not check the shared Anthropic profile location; review it, then use --allow-claude-shared-auth to permit this launch"
    )]
    ClaudeSharedAuthUnknown,
    #[error(
        "Kimi may inspect legacy data in the user's home; review the migration risk, then use --allow-kimi-legacy to permit this launch"
    )]
    KimiLegacyPresent,
    #[error(
        "could not determine whether Kimi legacy data is present; check the user's home, then use --allow-kimi-legacy to permit this launch"
    )]
    KimiLegacyUnknown,
    #[error(
        "native profile isolation is unverified; inspect --dry-run, then explicitly opt in with --experimental-native"
    )]
    UnverifiedNative,
    #[error(
        "gents integration is unverified; inspect --dry-run, then explicitly opt in with --experimental-gents; the external runtime may keep working after chat exits"
    )]
    UnverifiedGents,
    #[error(
        "engine binding requires gents with an explicit loopback IP:port (nonzero port) and agent; native profiles cannot carry a gents binding"
    )]
    InvalidEngineBinding,
    #[error("gents agent ID must contain 1-128 printable ASCII characters without whitespace")]
    InvalidGentsAgent,
    #[error(
        "gents runtime.json must be a private regular file with home and graphql fields matching this profile; initialize and start the dedicated runtime, or update its binding with `aswp profile bind`"
    )]
    GentsRuntimeMismatch,
    #[error(
        "another active gents profile already uses this runtime address; each home needs its own listener"
    )]
    DuplicateRuntime,
    #[error("requested execution engine does not match the registered profile")]
    EngineMismatch,
    #[error(
        "gents profiles accept no forwarded arguments or native login; initialize and authenticate the dedicated home with gents separately; use run --resume or run --session UUID for continuity"
    )]
    UnsupportedGentsOperation,
    #[error("--session and --resume are supported only for the gents engine")]
    UnsupportedSession,
    #[error(
        "windows-job containment requires Windows and a native profile; gents runtime work is externally owned"
    )]
    UnsupportedContainment,
    #[error("windows-job containment requires a process-lifetime root Job before launch")]
    WindowsRootRequired,
    #[error(
        "could not confirm completion of supervised run {run_id}; inspect `aswp runs {run_id}` and verify its processes have stopped before manual recovery"
    )]
    SupervisionIncomplete {
        run_id: String,
        #[source]
        source: Box<Error>,
    },
    #[error(
        "no tracked gents session for the latest run; start a new chat or explicitly select --session UUID"
    )]
    NoRecordedSession,
    #[error(
        "latest gents client did not record a successful exit; inspect `aswp runs` and runtime work before explicitly selecting a session"
    )]
    SessionNotResumable,
    #[error(
        "gents binding changed since that session; inspect the runtime and agent before explicitly selecting --session UUID"
    )]
    SessionBindingChanged,
    #[error(
        "a newer run changed the resume selection; inspect `aswp runs` and build a fresh launch plan"
    )]
    StaleSession,
    #[error(
        "interactive mode requires a terminal and cannot be combined with --json; use `aswp list --json` or `aswp run --dry-run --json`"
    )]
    InteractiveMode,
    #[error("path cannot be represented without loss; use a UTF-8 state or mapping path")]
    NonUtf8Path,
    #[error(
        "handover input is too large; notes are limited to 256 KiB and encrypted packs to 1 MiB plus framing"
    )]
    HandoverTooLarge,
    #[error(
        "handover input must be a regular task note outside authentication and application-state directories"
    )]
    UnsafeHandoverInput,
    #[error(
        "pickup output must be a new HANDOVER*.md or PICKUP*.md file outside known agent homes and application state"
    )]
    UnsafeHandoverOutput,
    #[error(
        "handover file must be regular; symbolic links and Windows cloud/reparse files are unsupported in this preview"
    )]
    UnsafeHandoverFile,
    #[error(
        "handover data is invalid or uses an unsupported schema; no imported content was executed"
    )]
    InvalidHandover,
    #[error("could not authenticate and decrypt the handover; check the passphrase and file")]
    HandoverDecryption,
    #[error("handover encryption work factor exceeds the supported resource limit")]
    HandoverWorkFactor,
    #[error("handover output already exists; choose a new path rather than overwriting it")]
    OutputExists,
    #[error(
        "use a unique passphrase of at least 16 characters, entered at the hidden prompt or through --passphrase-stdin"
    )]
    InvalidPassphrase,
    #[error(
        "passphrase input requires a terminal, or --passphrase-stdin with a pipe; passphrases never belong in arguments"
    )]
    PassphraseInput,
    #[error("passphrases did not match; no handover file was written")]
    PassphraseMismatch,
    #[error("cancelled; no handover file was written")]
    Cancelled,
    #[error(
        "unsupported key in hidden passphrase entry; retry or provide one line through --passphrase-stdin"
    )]
    UnsupportedPasswordKey,
    #[error("hidden input cleanup failed; check your terminal before continuing")]
    SecretInputCleanup,
    #[error("storage operation failed")]
    Database(#[from] rusqlite::Error),
    #[error("filesystem or process operation failed")]
    Io(#[from] std::io::Error),
    #[error("terminal settings could not be restored; restore your terminal before continuing")]
    TerminalRestore,
    #[error("serialization failed")]
    Json(#[from] serde_json::Error),
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownConfigKey => "unknown_config_key",
            Self::TerminalRestore => "terminal_restore_failed",
            Self::SecretInputCleanup => "secret_input_cleanup_failed",
            Self::InvalidConfigValue => "invalid_config_value",
            Self::InvalidConfig => "invalid_config",
            Self::ConfigTooLarge => "config_too_large",
            Self::NewerConfig => "newer_config",
            Self::ConfigBusy => "config_busy",
            Self::ConfigDurability => "config_durability_uncertain",
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
            Self::ProjectionMismatch => "projection_mismatch",
            Self::RegistrySchemaChanged => "registry_schema_changed",
            Self::RegistryConnectionChanged => "registry_connection_changed",
            Self::RegistryEventTooLarge => "registry_event_too_large",
            Self::InvalidHistoryLimit => "invalid_history_limit",
            Self::ExecutableNotFound => "executable_not_found",
            Self::UnsafeExecutable => "unsafe_executable",
            Self::EnvironmentConflict(_) => "environment_conflict",
            Self::ClaudeSharedAuthPresent => "claude_shared_auth_present",
            Self::ClaudeSharedAuthUnknown => "claude_shared_auth_unknown",
            Self::KimiLegacyPresent => "kimi_legacy_present",
            Self::KimiLegacyUnknown => "kimi_legacy_unknown",
            Self::UnverifiedNative => "native_unverified",
            Self::UnverifiedGents => "gents_unverified",
            Self::InvalidEngineBinding => "invalid_engine_binding",
            Self::InvalidGentsAgent => "invalid_gents_agent",
            Self::GentsRuntimeMismatch => "gents_runtime_mismatch",
            Self::DuplicateRuntime => "duplicate_runtime",
            Self::EngineMismatch => "engine_mismatch",
            Self::UnsupportedGentsOperation => "unsupported_gents_operation",
            Self::UnsupportedSession => "unsupported_session",
            Self::UnsupportedContainment => "unsupported_containment",
            Self::WindowsRootRequired => "windows_root_required",
            Self::SupervisionIncomplete { .. } => "supervision_incomplete",
            Self::NoRecordedSession => "no_recorded_session",
            Self::SessionNotResumable => "session_not_resumable",
            Self::SessionBindingChanged => "session_binding_changed",
            Self::StaleSession => "stale_session",
            Self::InteractiveMode => "interactive_mode",
            Self::NonUtf8Path => "non_utf8_path",
            Self::HandoverTooLarge => "handover_too_large",
            Self::UnsafeHandoverInput => "unsafe_handover_input",
            Self::UnsafeHandoverOutput => "unsafe_handover_output",
            Self::UnsafeHandoverFile => "unsafe_handover_file",
            Self::InvalidHandover => "invalid_handover",
            Self::HandoverDecryption => "handover_decryption_failed",
            Self::HandoverWorkFactor => "handover_work_factor",
            Self::OutputExists => "output_exists",
            Self::InvalidPassphrase => "invalid_passphrase",
            Self::PassphraseInput => "passphrase_input",
            Self::PassphraseMismatch => "passphrase_mismatch",
            Self::Cancelled => "cancelled",
            Self::UnsupportedPasswordKey => "unsupported_password_key",
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
            if c.is_control() || invisible_control(c) {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

pub(crate) fn invisible_control(c: char) -> bool {
    matches!(c, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}' | '\u{e0000}'..='\u{e007f}')
}
