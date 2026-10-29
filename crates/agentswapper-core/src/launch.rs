use std::{
    ffi::{OsStr, OsString},
    io::Read,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

use serde::Serialize;

use crate::{Error, ExecutionEngine, Harness, Profile, Result, Store, store::RunCompletion};
use uuid::Uuid;

mod executable;
#[cfg(unix)]
mod terminal;

/// The executable and environment used by execute(). Arguments are deliberately
/// excluded from Debug and serialization: user-supplied arguments may be secrets.
pub struct LaunchPlan {
    profile: Profile,
    program: PathBuf,
    home: PathBuf,
    cwd: PathBuf,
    args: Vec<OsString>,
    login: bool,
    session: Option<Uuid>,
    resumed_from: Option<Uuid>,
    selection: Option<SessionSelection>,
    containment: Option<Containment>,
    allow_kimi_legacy: bool,
    allow_claude_shared_auth: bool,
}

/// Explicit experimental local-process backend; unsupported hosts never fall back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Containment {
    WindowsJob,
}

impl Containment {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WindowsJob => "windows_job",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionSelection {
    New,
    Explicit,
    Resume,
}

fn check_kimi_legacy_home(home: &Path) -> Result<()> {
    if !home.is_absolute() || home.to_str().is_none() {
        return Err(Error::KimiLegacyUnknown);
    }
    match std::fs::symlink_metadata(home.join(".kimi")) {
        Ok(_) => Err(Error::KimiLegacyPresent),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Error::KimiLegacyUnknown),
    }
}

fn check_claude_shared_root(root: &Path) -> Result<()> {
    if !root.is_absolute() || root.to_str().is_none() {
        return Err(Error::ClaudeSharedAuthUnknown);
    }
    for path in [
        root.join("active_config"),
        root.join("configs/default.json"),
    ] {
        match std::fs::symlink_metadata(path) {
            Ok(_) => return Err(Error::ClaudeSharedAuthPresent),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::ClaudeSharedAuthUnknown),
        }
    }
    Ok(())
}

impl SessionSelection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Explicit => "explicit",
            Self::Resume => "resume",
        }
    }
}

#[derive(Serialize)]
pub struct LaunchPreview<'a> {
    pub profile: &'a Profile,
    pub program: &'a Path,
    pub profile_home: &'a Path,
    pub home_variable: Option<&'static str>,
    pub working_directory: &'a Path,
    pub argument_count: usize,
    pub operation: &'static str,
    pub isolation: &'static str,
    pub quota: &'static str,
    pub containment: &'static str,
    /// Whether the Kimi legacy-home preflight will be required at launch.
    pub kimi_legacy_preflight: &'static str,
    /// Whether the Claude shared-profile preflight will be required at launch.
    pub claude_shared_auth_preflight: &'static str,
    pub engine: ExecutionEngine,
    pub runtime_owner: &'static str,
    pub workspace_owner: &'static str,
    pub session: Option<Uuid>,
    pub resumed_from: Option<Uuid>,
    pub session_selection: Option<SessionSelection>,
    pub session_reserved: bool,
}

impl LaunchPlan {
    pub fn build(
        store: &Store,
        profile: Profile,
        executable: Option<&Path>,
        cwd: &Path,
        args: Vec<OsString>,
        login: bool,
    ) -> Result<Self> {
        profile.validate()?;
        let registered = store
            .profiles()?
            .into_iter()
            .find(|p| p.id == profile.id)
            .ok_or(Error::NotFound)?;
        if registered.harness != profile.harness || registered.gents != profile.gents {
            return Err(Error::EngineMismatch);
        }
        let profile = registered;
        if profile.harness == Harness::Gents && (login || !args.is_empty()) {
            return Err(Error::UnsupportedGentsOperation);
        }
        if !profile.enabled {
            return Err(Error::Disabled);
        }
        let home = store.profile_home(profile.id)?;
        let program = match executable {
            Some(path) if path.is_absolute() => path.to_owned(),
            Some(_) => return Err(Error::UnsafeExecutable),
            None => discover(profile.harness).ok_or(Error::ExecutableNotFound)?,
        };
        executable::validate(&program)?;
        let session = (profile.harness == Harness::Gents).then(Uuid::new_v4);
        let args = if let Some(binding) = &profile.gents {
            vec![
                "chat".into(),
                "--home".into(),
                home.as_os_str().to_owned(),
                "--graphql".into(),
                binding.graphql_url().into(),
                format!("--agent-id={}", binding.agent()).into(),
            ]
        } else if login {
            profile
                .harness
                .login_args()
                .iter()
                .map(OsString::from)
                .collect()
        } else {
            args
        };
        Ok(Self {
            profile,
            program,
            home,
            cwd: dunce::simplified(cwd).to_owned(),
            args,
            login,
            session,
            resumed_from: None,
            selection: session.map(|_| SessionSelection::New),
            containment: None,
            allow_kimi_legacy: false,
            allow_claude_shared_auth: false,
        })
    }

    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// Explicitly allow Kimi to inspect its legacy home during this launch.
    pub fn with_kimi_legacy_access(mut self, allow: bool) -> Self {
        self.allow_kimi_legacy = allow;
        self
    }

    /// Explicitly allow the shared Anthropic profile for this launch.
    pub fn with_claude_shared_auth_access(mut self, allow: bool) -> Self {
        self.allow_claude_shared_auth = allow;
        self
    }

    /// Check only for the documented default profile indicators, without
    /// opening or reading any credentials or profile contents.
    pub fn check_claude_shared_auth(&self) -> Result<()> {
        if self.profile.harness != Harness::Claude || self.allow_claude_shared_auth {
            return Ok(());
        }
        #[cfg(windows)]
        let (variable, suffix) = ("APPDATA", "Anthropic");
        #[cfg(not(windows))]
        let (variable, suffix) = ("HOME", ".config/anthropic");
        let home = PathBuf::from(std::env::var_os(variable).ok_or(Error::ClaudeSharedAuthUnknown)?);
        if !home.is_absolute() || home.to_str().is_none() {
            return Err(Error::ClaudeSharedAuthUnknown);
        }
        check_claude_shared_root(&home.join(suffix))
    }

    /// Metadata-only preflight; does not read, modify or migrate vendor data.
    pub fn check_kimi_legacy(&self) -> Result<()> {
        if self.profile.harness != Harness::Kimi || self.allow_kimi_legacy {
            return Ok(());
        }
        #[cfg(windows)]
        let variable = "USERPROFILE";
        #[cfg(not(windows))]
        let variable = "HOME";
        // Node may fall back to the effective user's account directory when
        // this variable is absent. Do not guess it using a different resolver.
        let home = PathBuf::from(std::env::var_os(variable).ok_or(Error::KimiLegacyUnknown)?);
        check_kimi_legacy_home(&home)
    }

    /// Local Job ownership never contains an externally owned gents runtime.
    pub fn with_containment(mut self, containment: Option<Containment>) -> Result<Self> {
        if containment.is_some() && (!cfg!(windows) || self.profile.harness == Harness::Gents) {
            return Err(Error::UnsupportedContainment);
        }
        self.containment = containment;
        Ok(self)
    }

    /// Continue or create the explicit gents session; native formats differ.
    pub fn with_session(mut self, session: Option<Uuid>) -> Result<Self> {
        if let Some(session) = session {
            if self.profile.harness != Harness::Gents {
                return Err(Error::UnsupportedSession);
            }
            self.session = Some(session);
            self.resumed_from = None;
            self.selection = Some(SessionSelection::Explicit);
        }
        Ok(self)
    }

    /// Resolve the latest attempt only when its tracked client succeeded. The event transaction
    /// rechecks this source under the lease; previews do not reserve a session.
    pub fn with_latest_gents_session(mut self, store: &Store) -> Result<Self> {
        if self.profile.harness != Harness::Gents {
            return Err(Error::UnsupportedSession);
        }
        let candidate = store.latest_gents_session(self.profile.id)?;
        if self.profile.gents.as_ref() != Some(candidate.session.binding()) {
            return Err(Error::SessionBindingChanged);
        }
        self = self.with_session(Some(candidate.session.id()))?;
        self.resumed_from = Some(candidate.run_id);
        self.selection = Some(SessionSelection::Resume);
        Ok(self)
    }

    pub fn preview(&self) -> LaunchPreview<'_> {
        LaunchPreview {
            profile: &self.profile,
            program: &self.program,
            profile_home: &self.home,
            home_variable: (self.profile.harness != Harness::Gents)
                .then(|| self.profile.harness.home_variable()),
            working_directory: &self.cwd,
            argument_count: self.args.len() + if self.session.is_some() { 2 } else { 0 },
            operation: if self.login { "login" } else { "run" },
            isolation: "unverified",
            quota: "unknown",
            containment: self.containment.map_or("none", Containment::as_str),
            kimi_legacy_preflight: match (self.profile.harness, self.allow_kimi_legacy) {
                (Harness::Kimi, true) => "bypassed",
                (Harness::Kimi, false) => "required",
                _ => "not_applicable",
            },
            claude_shared_auth_preflight: match (
                self.profile.harness,
                self.allow_claude_shared_auth,
            ) {
                (Harness::Claude, true) => "bypassed",
                (Harness::Claude, false) => "required",
                _ => "not_applicable",
            },
            engine: self.profile.harness.engine(),
            runtime_owner: if self.profile.harness == Harness::Gents {
                "external_gents_runtime"
            } else {
                "native_cli"
            },
            workspace_owner: if self.profile.harness == Harness::Gents {
                "gents_agent_configuration"
            } else {
                "native_cli_working_directory"
            },
            session: self.session,
            resumed_from: self.resumed_from,
            session_selection: self.selection,
            session_reserved: false,
        }
    }

    /// Requires explicit opt-in until version/platform isolation gates pass.
    /// The intent is durable before spawning; ambiguous failures leave it pending.
    /// The caller must arrange foreground interrupt handling. The CLI catches
    /// default SIGINT and preserves an existing disposition on Unix.
    pub fn execute(&self, store: &mut Store, experimental: bool) -> Result<i32> {
        if self.profile.harness == Harness::Gents {
            return Err(Error::UnverifiedGents);
        }
        if !experimental {
            return Err(Error::UnverifiedNative);
        }
        self.check_environment(|key| std::env::var_os(key))?;
        self.check_claude_shared_auth()?;
        self.check_kimi_legacy()?;
        self.execute_prepared(store)
    }

    /// Opt-in applies only to the attached gents client, never to native launches.
    pub fn execute_gents(&self, store: &mut Store, experimental: bool) -> Result<i32> {
        if self.profile.harness != Harness::Gents {
            return Err(Error::EngineMismatch);
        }
        if !experimental {
            return Err(Error::UnverifiedGents);
        }
        self.check_environment(|key| std::env::var_os(key))?;
        self.execute_prepared(store)
    }

    fn execute_prepared(&self, store: &mut Store) -> Result<i32> {
        let lease = store.lease(self.profile.id)?;
        // Binding changes take the same lease. Refuse a plan built before a
        // rebind, even if its original runtime record still matches its old URL.
        let current = store
            .profiles()?
            .into_iter()
            .find(|p| p.id == self.profile.id)
            .ok_or(Error::NotFound)?;
        if current.harness != self.profile.harness || current.gents != self.profile.gents {
            return Err(Error::EngineMismatch);
        }
        // A plan may outlive an installer update or a permissions change. Check
        // again before recording intent or spawning, preserving the invocation
        // path for programs whose behavior depends on their installed name.
        executable::validate(&self.program)?;
        // The original preflight can become stale while waiting for the lease.
        // This narrows, but cannot remove, the race with external changes.
        self.check_kimi_legacy()?;
        self.check_claude_shared_auth()?;
        if self.profile.harness == Harness::Gents && !self.check_gents_runtime()? {
            return Err(Error::GentsRuntimeMismatch);
        }
        let gents_session = match (self.session, &self.profile.gents) {
            (Some(id), Some(binding)) => Some(crate::store::GentsSession::new(
                id,
                binding.clone(),
                self.resumed_from,
            )),
            (None, None) => None,
            _ => return Err(Error::InvalidEngineBinding),
        };
        #[cfg(windows)]
        if self.containment == Some(Containment::WindowsJob) {
            return self.execute_windows_job(store, &lease);
        }
        #[cfg(unix)]
        let terminal = terminal::ForegroundTerminal::capture()?;
        let id = store.begin_run_with_session(
            &lease,
            if self.login { "login" } else { "run" },
            gents_session,
        )?;
        let child = self.command().spawn();
        let mut child = match child {
            Ok(child) => child,
            Err(error) => {
                store.finish_run(id, RunCompletion::FailedToSpawn)?;
                return Err(error.into());
            }
        };
        if let Err(error) = store.observe_spawn(&id, child.id()) {
            // The durable intent remains unresolved. Only signal the owned,
            // unreaped direct child; descendant custody is still unknown.
            let _ = child.kill();
            let stopped = child.wait().is_ok();
            #[cfg(unix)]
            if stopped && let Some(terminal) = terminal {
                let _ = terminal.restore();
            }
            #[cfg(not(unix))]
            let _ = stopped;
            return Err(error);
        }
        // No transaction is held while a native interactive CLI owns the terminal.
        // A wait error or supervisor crash leaves an unfinished intent, blocking reuse.
        let status = child.wait()?;
        #[cfg(unix)]
        let terminal_result = terminal
            .map(terminal::ForegroundTerminal::restore)
            .transpose();
        let code = exit_code(status);
        let completion = if self.profile.harness == Harness::Gents {
            RunCompletion::ExternalClientExited(code)
        } else {
            RunCompletion::ChildExited(code)
        };
        store.finish_run(id, completion)?;
        #[cfg(unix)]
        terminal_result.map_err(|_| Error::TerminalRestore)?;
        drop(lease);
        Ok(code)
    }

    #[cfg(windows)]
    fn execute_windows_job(
        &self,
        store: &mut Store,
        lease: &crate::store::ProfileLease,
    ) -> Result<i32> {
        use crate::{store::LocalScope, supervision::windows_job::WindowsJob};
        if self.profile.harness == Harness::Gents {
            return Err(Error::UnsupportedContainment);
        }
        let scope = WindowsJob::create()?;
        let id = store.begin_run_with_scope(
            lease,
            if self.login { "login" } else { "run" },
            None,
            Some(LocalScope::WindowsJob { id: scope.id() }),
        )?;
        let execute = || -> Result<i32> {
            let mut admission_error = None;
            let spawned = scope.spawn(self.command(), |pid| {
                store.observe_spawn(&id, pid).map_err(|error| {
                    admission_error = Some(error);
                    std::io::Error::other("durable process admission failed")
                })
            });
            // Any spawn/wrapping error may follow partial admission or resume.
            // Preserve intent even if kill-on-close was requested: no empty receipt.
            let mut child = spawned.map_err(|error| admission_error.unwrap_or(Error::Io(error)))?;
            let code = exit_code(child.wait()?);
            let receipt = child.stop_and_observe()?;
            store.finish_run(id.clone(), RunCompletion::LocalScopeStopped(code, receipt))?;
            Ok(code)
        };
        execute().map_err(|source| Error::SupervisionIncomplete {
            run_id: id,
            source: Box::new(source),
        })
    }

    pub fn check_environment(&self, lookup: impl Fn(&OsStr) -> Option<OsString>) -> Result<()> {
        // Gents receives an allowlist, so inherited native auth/routing values
        // cannot reach it. Native clients retain their existing conflict policy.
        for &key in self.profile.harness.conflicts() {
            if lookup(OsStr::new(key)).is_some() {
                return Err(Error::EnvironmentConflict(key));
            }
        }
        Ok(())
    }

    /// Local consistency only: a matching file does not authenticate the listener.
    /// Missing state is useful in a setup preview but blocks a real gents launch.
    pub fn check_gents_runtime(&self) -> Result<bool> {
        let Some(binding) = &self.profile.gents else {
            return Ok(true);
        };
        let path = self.home.join("runtime.json");
        crate::private_fs::reject_links(&path).map_err(|_| Error::GentsRuntimeMismatch)?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            );
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(
                windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
            );
        }
        let file = match options.open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(Error::GentsRuntimeMismatch),
        };
        let metadata = file.metadata().map_err(|_| Error::GentsRuntimeMismatch)?;
        crate::private_fs::validate_snapshot_metadata(&metadata)
            .map_err(|_| Error::GentsRuntimeMismatch)?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0
                || winapi_util::file::information(&file)
                    .map_err(|_| Error::GentsRuntimeMismatch)?
                    .number_of_links()
                    > 1
            {
                return Err(Error::GentsRuntimeMismatch);
            }
        }
        let mut bytes = Vec::new();
        file.take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::GentsRuntimeMismatch)?;
        if bytes.len() > 65536 {
            return Err(Error::GentsRuntimeMismatch);
        }
        #[derive(serde::Deserialize)]
        struct RuntimeState {
            home: PathBuf,
            graphql: String,
        }
        let state: RuntimeState =
            serde_json::from_slice(&bytes).map_err(|_| Error::GentsRuntimeMismatch)?;
        // The reviewed gents 0.21.0 writes unbracketed IPv6 in runtime.json.
        // Accept only the exact equivalent of our validated binding; argv still
        // receives the proper bracketed URL. No general malformed-URL fallback.
        let legacy_ipv6 = binding.address().is_ipv6()
            && state.graphql
                == format!(
                    "http://{}:{}/api/v0/graphql",
                    binding.address().ip(),
                    binding.address().port()
                );
        if state.graphql != binding.graphql_url() && !legacy_ipv6 {
            return Err(Error::GentsRuntimeMismatch);
        }
        if !state.home.is_absolute()
            || dunce::canonicalize(&state.home).map_err(|_| Error::GentsRuntimeMismatch)?
                != self.home
        {
            return Err(Error::GentsRuntimeMismatch);
        }
        Ok(true)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        for harness in crate::Harness::ALL {
            command.env_remove(harness.home_variable());
        }
        command.args(&self.args).current_dir(&self.cwd);
        if let Some(session) = self.session {
            command.arg("--session-id").arg(session.to_string());
        }
        if self.profile.harness == Harness::Gents {
            // Keep only terminal/OS integration. In particular, never inherit
            // provider secrets, dynamic-loader hooks, proxies or GENTS_* routing.
            command.env_clear();
            for key in [
                "PATH",
                "HOME",
                "USERPROFILE",
                "TERM",
                "COLORTERM",
                "TERM_PROGRAM",
                "LANG",
                "LC_ALL",
                "LC_CTYPE",
                "LC_MESSAGES",
                "TZ",
                "NO_COLOR",
                "TMP",
                "TEMP",
                "TMPDIR",
                "SystemRoot",
                "WINDIR",
                "SYSTEMDRIVE",
                "APPDATA",
                "LOCALAPPDATA",
            ] {
                if let Some(value) = std::env::var_os(key) {
                    command.env(key, value);
                }
            }
        } else {
            command.env(self.profile.harness.home_variable(), &self.home);
        }
        command
    }
}

pub fn discover(harness: crate::Harness) -> Option<PathBuf> {
    discover_named(&harness.to_string())
}

pub(crate) fn discover_named(name: &str) -> Option<PathBuf> {
    // A minimal Windows environment may omit PATHEXT. Select native programs
    // explicitly rather than requiring shell-extension discovery.
    #[cfg(windows)]
    let name = format!("{name}.exe");
    let path = std::env::var_os("PATH")?;
    let absolute = std::env::split_paths(&path)
        .filter(|entry| entry.is_absolute())
        .collect::<Vec<_>>();
    let search = std::env::join_paths(absolute).ok()?;
    which::which_in(name, Some(search), std::env::current_dir().ok()?).ok()
}

fn exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        128 + status.signal().unwrap_or(0)
    }
    #[cfg(not(unix))]
    125
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::Harness;

    #[test]
    fn claude_shared_profile_check_refuses_default_or_active_without_reading_them() {
        let temp = tempfile::tempdir().unwrap();
        assert!(check_claude_shared_root(temp.path()).is_ok());
        assert!(matches!(
            check_claude_shared_root(Path::new("relative")),
            Err(Error::ClaudeSharedAuthUnknown)
        ));
        std::fs::create_dir(temp.path().join("configs")).unwrap();
        std::fs::write(temp.path().join("configs/default.json"), b"private").unwrap();
        assert!(matches!(
            check_claude_shared_root(temp.path()),
            Err(Error::ClaudeSharedAuthPresent)
        ));
        std::fs::remove_file(temp.path().join("configs/default.json")).unwrap();
        std::fs::write(temp.path().join("active_config"), b"private").unwrap();
        assert!(matches!(
            check_claude_shared_root(temp.path()),
            Err(Error::ClaudeSharedAuthPresent)
        ));
        assert_eq!(
            std::fs::read(temp.path().join("active_config")).unwrap(),
            b"private"
        );
    }

    #[test]
    fn kimi_legacy_check_only_accepts_a_known_absolute_home_without_a_legacy_entry() {
        let temp = tempfile::tempdir().unwrap();
        assert!(check_kimi_legacy_home(temp.path()).is_ok());
        assert!(matches!(
            check_kimi_legacy_home(Path::new("relative")),
            Err(Error::KimiLegacyUnknown)
        ));
        std::fs::write(temp.path().join(".kimi"), b"unchanged").unwrap();
        assert!(matches!(
            check_kimi_legacy_home(temp.path()),
            Err(Error::KimiLegacyPresent)
        ));
        assert_eq!(
            std::fs::read(temp.path().join(".kimi")).unwrap(),
            b"unchanged"
        );
    }

    #[cfg(unix)]
    #[test]
    fn kimi_legacy_check_refuses_dangling_links_and_non_utf8_home() {
        use std::os::unix::{ffi::OsStringExt, fs::symlink};
        let temp = tempfile::tempdir().unwrap();
        symlink(temp.path().join("missing"), temp.path().join(".kimi")).unwrap();
        assert!(matches!(
            check_kimi_legacy_home(temp.path()),
            Err(Error::KimiLegacyPresent)
        ));
        let invalid = temp.path().join(OsString::from_vec(vec![0xff]));
        assert!(matches!(
            check_kimi_legacy_home(&invalid),
            Err(Error::KimiLegacyUnknown)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn launch_rechecks_changed_executable_permissions_before_journaling() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        let profile = store
            .register(Harness::Codex, "work".parse().unwrap())
            .unwrap();
        let binary = temp.path().join("agent");
        std::fs::write(&binary, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let entry = temp.path().join("entry");
        symlink(&binary, &entry).unwrap();
        let plan = LaunchPlan::build(
            &store,
            profile.clone(),
            Some(&entry),
            temp.path(),
            vec![],
            false,
        )
        .unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            plan.execute_prepared(&mut store),
            Err(Error::UnsafeExecutable)
        ));
        assert!(store.runs(1).unwrap().is_empty());
        assert!(store.lease(profile.id).is_ok());
    }

    #[test]
    fn spawn_error_keeps_original_io_kind_and_records_never_started() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        let p = store
            .register(Harness::Kimi, "work".parse().unwrap())
            .unwrap();
        let directory = temp.path().join("removed-cwd");
        std::fs::create_dir(&directory).unwrap();
        let binary = std::env::current_exe().unwrap();
        let plan = LaunchPlan::build(
            &store,
            p.clone(),
            Some(&binary),
            &directory,
            Vec::new(),
            false,
        )
        .unwrap()
        .with_kimi_legacy_access(true);
        std::fs::remove_dir(&directory).unwrap();
        let expected = plan.command().spawn().unwrap_err();
        // No child can start, and this private entry avoids inspecting real
        // inherited auth variables in an otherwise credential-free unit test.
        let error = plan.execute_prepared(&mut store).unwrap_err();
        match error {
            Error::Io(error) => {
                assert_eq!(error.kind(), expected.kind());
                assert_eq!(error.raw_os_error(), expected.raw_os_error());
            }
            other => panic!("expected the original spawn error, got {other:?}"),
        }
        let run = store.runs(1).unwrap().pop().unwrap();
        assert_eq!(run.custody, crate::store::ProcessCustody::NeverStarted);
        assert_eq!(run.observed_pid, None);
        assert!(store.lease(p.id).is_ok());
    }

    #[test]
    fn preview_redacts_arguments_and_reports_unknowns() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        let p = store
            .register(Harness::Claude, "work".parse().unwrap())
            .unwrap();
        let binary = std::env::current_exe().unwrap();
        let plan = LaunchPlan::build(
            &store,
            p,
            Some(&binary),
            temp.path(),
            vec!["secret-canary".into()],
            false,
        )
        .unwrap();
        let preview = serde_json::to_string(&plan.preview()).unwrap();
        assert!(!preview.contains("secret-canary"));
        assert!(preview.contains("unknown"));
        assert!(preview.contains("unverified"));
        assert!(matches!(
            plan.execute(&mut store, false),
            Err(Error::UnverifiedNative)
        ));
        assert!(store.unfinished().unwrap().is_empty());
        let conflict = plan
            .check_environment(|key| (key == "ANTHROPIC_API_KEY").then(|| "secret-canary".into()))
            .unwrap_err();
        assert!(!conflict.to_string().contains("secret-canary"));
    }

    #[cfg(windows)]
    #[test]
    fn supervised_spawn_error_preserves_intent_without_inventing_empty_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        let profile = store
            .register(Harness::Codex, "work".parse().unwrap())
            .unwrap();
        let cwd = temp.path().join("removed-cwd");
        std::fs::create_dir(&cwd).unwrap();
        let plan = LaunchPlan::build(
            &store,
            profile.clone(),
            Some(&std::env::current_exe().unwrap()),
            &cwd,
            Vec::new(),
            false,
        )
        .unwrap()
        .with_containment(Some(Containment::WindowsJob))
        .unwrap();
        std::fs::remove_dir(&cwd).unwrap();
        let error = plan.execute_prepared(&mut store).unwrap_err();
        let run = store.runs(1).unwrap().pop().unwrap();
        assert_eq!(error.code(), "supervision_incomplete");
        assert!(error.to_string().contains(&format!("aswp runs {}", run.id)));
        match error {
            Error::SupervisionIncomplete { run_id, source } => {
                assert_eq!(run_id, run.id);
                assert!(matches!(*source, Error::Io(_)));
            }
            other => panic!("unexpected failure: {other:?}"),
        }
        assert_eq!(run.custody, crate::store::ProcessCustody::Unknown);
        assert!(run.local_scope.is_some());
        assert_eq!(run.observed_pid, None);
        assert!(matches!(store.lease(profile.id), Err(Error::Busy)));
        store.attest_stopped(&run.id).unwrap();
        assert_eq!(
            store.run(&run.id).unwrap().custody,
            crate::store::ProcessCustody::AttestedStopped
        );
    }
}

#[cfg(test)]
mod engine_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn matching_runtime(plan: &LaunchPlan) {
        let file = crate::private_fs::file(&plan.home.join("runtime.json")).unwrap();
        serde_json::to_writer(
            file,
            &serde_json::json!({
                "home": plan.home,
                "graphql": plan.profile.gents.as_ref().unwrap().graphql_url()
            }),
        )
        .unwrap();
    }

    #[test]
    fn core_opt_ins_cannot_authorize_the_other_engine_and_stale_binding_cannot_launch() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        let binding = |port| {
            crate::GentsBinding::new(
                format!("127.0.0.1:{port}").parse().unwrap(),
                "worker".parse().unwrap(),
            )
            .unwrap()
        };
        let p = store
            .register_gents("relay".parse().unwrap(), binding(9191))
            .unwrap();
        let binary = std::env::current_exe().unwrap();
        let plan = LaunchPlan::build(&store, p.clone(), Some(&binary), temp.path(), vec![], false)
            .unwrap();
        assert!(matches!(
            plan.execute(&mut store, true),
            Err(Error::UnverifiedGents)
        ));
        assert!(matches!(
            plan.execute_gents(&mut store, false),
            Err(Error::UnverifiedGents)
        ));
        store.bind_gents(&p.alias, binding(9192)).unwrap();
        assert!(matches!(
            plan.execute_prepared(&mut store),
            Err(Error::EngineMismatch)
        ));
        assert!(store.runs(20).unwrap().is_empty());
        let p = store
            .register(Harness::Codex, "native".parse().unwrap())
            .unwrap();
        let plan = LaunchPlan::build(&store, p, Some(&binary), temp.path(), vec![], false).unwrap();
        assert!(matches!(
            plan.execute_gents(&mut store, true),
            Err(Error::EngineMismatch)
        ));
        assert!(store.runs(20).unwrap().is_empty());
    }

    #[test]
    fn resume_plan_is_rechecked_after_another_run_before_spawn() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        let binding =
            crate::GentsBinding::new("127.0.0.1:9191".parse().unwrap(), "worker".parse().unwrap())
                .unwrap();
        let p = store
            .register_gents("relay".parse().unwrap(), binding.clone())
            .unwrap();
        let complete = |s: &mut Store| {
            let lease = s.lease(p.id).unwrap();
            let id = s
                .begin_run_with_session(
                    &lease,
                    "run",
                    Some(crate::store::GentsSession::new(
                        Uuid::new_v4(),
                        binding.clone(),
                        None,
                    )),
                )
                .unwrap();
            s.observe_spawn(&id, 42).unwrap();
            s.finish_run(id, RunCompletion::ExternalClientExited(0))
                .unwrap();
        };
        complete(&mut store);
        let binary = std::env::current_exe().unwrap();
        let plan = LaunchPlan::build(&store, p.clone(), Some(&binary), temp.path(), vec![], false)
            .unwrap()
            .with_latest_gents_session(&store)
            .unwrap();
        matching_runtime(&plan);
        let old_source = plan.preview().resumed_from.unwrap();
        let mut peer = Store::open(&temp.path().join("state")).unwrap();
        complete(&mut peer);
        assert_ne!(store.latest_gents_session(p.id).unwrap().run_id, old_source);
        assert!(matches!(
            plan.execute_prepared(&mut store),
            Err(Error::StaleSession)
        ));
        assert_eq!(store.runs(20).unwrap().len(), 2);
        assert!(store.unfinished().unwrap().is_empty());
        assert!(store.verify().unwrap().consistent);
    }

    #[test]
    fn external_failed_spawn_records_only_client_failure() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open(&temp.path().join("state")).unwrap();
        let p = store
            .register_gents(
                "relay".parse().unwrap(),
                crate::GentsBinding::new(
                    "127.0.0.1:9191".parse().unwrap(),
                    "worker".parse().unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let cwd = temp.path().join("gone");
        std::fs::create_dir(&cwd).unwrap();
        let binary = std::env::current_exe().unwrap();
        let plan =
            LaunchPlan::build(&store, p.clone(), Some(&binary), &cwd, vec![], false).unwrap();
        assert!(matches!(
            plan.execute_prepared(&mut store),
            Err(Error::GentsRuntimeMismatch)
        ));
        assert!(store.runs(1).unwrap().is_empty());
        matching_runtime(&plan);
        std::fs::remove_dir(cwd).unwrap();
        assert!(matches!(
            plan.execute_prepared(&mut store),
            Err(Error::Io(_))
        ));
        let run = store.runs(1).unwrap().pop().unwrap();
        assert_eq!(run.outcome.as_deref(), Some("spawn_failed"));
        assert_eq!(
            run.custody,
            crate::store::ProcessCustody::ExternalRuntimeUnknown
        );
        assert_eq!(run.observed_pid, None);
        assert!(store.lease(p.id).is_ok());
    }
}
