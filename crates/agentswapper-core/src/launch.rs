use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

use serde::Serialize;

use crate::{Error, Profile, Result, Store, store::RunCompletion};

/// The executable and environment used by execute(). Arguments are deliberately
/// excluded from Debug and serialization: user-supplied arguments may be secrets.
pub struct LaunchPlan {
    pub profile: Profile,
    program: PathBuf,
    home: PathBuf,
    cwd: PathBuf,
    args: Vec<OsString>,
    login: bool,
}

#[derive(Serialize)]
pub struct LaunchPreview<'a> {
    pub profile: &'a Profile,
    pub program: &'a Path,
    pub profile_home: &'a Path,
    pub home_variable: &'static str,
    pub working_directory: &'a Path,
    pub argument_count: usize,
    pub operation: &'static str,
    pub isolation: &'static str,
    pub quota: &'static str,
    pub containment: &'static str,
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
        if !profile.enabled {
            return Err(Error::Disabled);
        }
        let home = store.profile_home(profile.id)?;
        let program = match executable {
            Some(path) if path.is_absolute() => path.to_owned(),
            Some(_) => return Err(Error::UnsafeExecutable),
            None => discover(profile.harness).ok_or(Error::ExecutableNotFound)?,
        };
        let resolved = dunce::canonicalize(&program).map_err(|_| Error::ExecutableNotFound)?;
        validate_executable(&resolved)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            for path in [&resolved, program.parent().ok_or(Error::UnsafeExecutable)?] {
                let meta = path.metadata()?;
                if meta.permissions().mode() & 0o022 != 0
                    || (meta.uid() != 0 && meta.uid() != rustix::process::geteuid().as_raw())
                {
                    return Err(Error::UnsafeExecutable);
                }
            }
        }
        let args = if login {
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
        })
    }

    pub fn preview(&self) -> LaunchPreview<'_> {
        LaunchPreview {
            profile: &self.profile,
            program: &self.program,
            profile_home: &self.home,
            home_variable: self.profile.harness.home_variable(),
            working_directory: &self.cwd,
            argument_count: self.args.len(),
            operation: if self.login { "login" } else { "run" },
            isolation: "unverified",
            quota: "unknown",
            containment: "none",
        }
    }

    /// Requires explicit opt-in until version/platform isolation gates pass.
    /// The intent is durable before spawning; ambiguous failures leave it pending.
    /// The caller installs a catching interrupt handler before using foreground
    /// mode. The CLI does this without changing the child's exec disposition.
    pub fn execute(&self, store: &mut Store, experimental: bool) -> Result<i32> {
        if !experimental {
            return Err(Error::UnverifiedNative);
        }
        self.check_environment(|key| std::env::var_os(key))?;
        self.execute_prepared(store)
    }

    fn execute_prepared(&self, store: &mut Store) -> Result<i32> {
        let lease = store.lease(self.profile.id)?;
        let id = store.begin_run(&lease, if self.login { "login" } else { "run" })?;
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
            let _ = child.wait();
            return Err(error);
        }
        // No transaction is held while a native interactive CLI owns the terminal.
        // A wait error or supervisor crash leaves an unfinished intent, blocking reuse.
        let status = child.wait()?;
        let code = exit_code(status);
        store.finish_run(id, RunCompletion::ChildExited(code))?;
        drop(lease);
        Ok(code)
    }

    pub fn check_environment(&self, lookup: impl Fn(&OsStr) -> Option<OsString>) -> Result<()> {
        for &key in self.profile.harness.conflicts() {
            if lookup(OsStr::new(key)).is_some() {
                return Err(Error::EnvironmentConflict(key));
            }
        }
        Ok(())
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        for harness in crate::Harness::ALL {
            command.env_remove(harness.home_variable());
        }
        command
            .args(&self.args)
            .current_dir(&self.cwd)
            .env(self.profile.harness.home_variable(), &self.home);
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

fn validate_executable(path: &Path) -> Result<()> {
    if !path.is_file() {
        return Err(Error::UnsafeExecutable);
    }
    let extension = path.extension().and_then(OsStr::to_str).unwrap_or_default();
    if ["cmd", "bat", "ps1"]
        .iter()
        .any(|e| extension.eq_ignore_ascii_case(e))
    {
        return Err(Error::UnsafeExecutable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.metadata()?.permissions().mode() & 0o111 == 0 {
            return Err(Error::UnsafeExecutable);
        }
    }
    #[cfg(windows)]
    if !extension.eq_ignore_ascii_case("exe") {
        return Err(Error::UnsafeExecutable);
    }
    Ok(())
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
        .unwrap();
        std::fs::remove_dir(&directory).unwrap();
        // No child can start, and this private entry avoids inspecting real
        // inherited auth variables in an otherwise credential-free unit test.
        let error = plan.execute_prepared(&mut store).unwrap_err();
        assert!(matches!(error,Error::Io(ref e) if e.kind()==std::io::ErrorKind::NotFound));
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
}
