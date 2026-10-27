//! Shared entry point for both command names. JSON is an unstable v0 contract.
mod handover_cli;
mod tui;

use std::{
    ffi::OsString,
    io::{self, IsTerminal, Write},
    path::PathBuf,
};

use agentswapper_core::{
    Alias, Error, Harness, Profile, Result, Store,
    launch::{LaunchPlan, discover},
    terminal_text,
};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use serde::Serialize;
use serde_json::json;

#[derive(Parser)]
#[command(
    version,
    about = "Switch agents. Keep your place.",
    after_help = "Developer preview: native isolation is unverified. No automatic switching yet."
)]
struct Cli {
    /// Private local state directory (absolute path).
    #[arg(long, global = true, env = "AGENTSWAPPER_STATE_DIR")]
    state_dir: Option<PathBuf>,
    /// Machine-readable output. Schema v0 is unstable.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(flatten)]
    Registry(RegistryCommands),
    /// Create, inspect, and reconcile encrypted manual handover packs.
    Handover {
        #[command(subcommand)]
        command: handover_cli::HandoverCommands,
    },
}

#[derive(Subcommand)]
enum RegistryCommands {
    /// Inspect registry consistency by replaying its journal in memory.
    Registry {
        #[command(subcommand)]
        command: RegistryMaintenance,
    },
    /// Register and manage profiles. Registration does not authenticate an account.
    Profile {
        #[command(subcommand)]
        command: ProfileCommands,
    },
    /// List profiles, account verification, and quota.
    #[command(alias = "ls")]
    List,
    /// Show profiles and unfinished native runs.
    Status,
    /// Inspect recent runs or one run ID, including process-custody observations.
    Runs {
        id: Option<String>,
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u16).range(1..=200))]
        limit: u16,
    },
    /// Check local storage and discover native CLIs without executing them.
    Doctor,
    /// Resolve an unfinished run only after you have stopped its native processes.
    Recover {
        run_id: String,
        /// Assert that the agent and every descendant have stopped. This is recorded.
        #[arg(long, required = true)]
        confirm_stopped: bool,
    },
    /// Launch the selected profile, or the nearest directory mapping.
    Run {
        profile: Option<Alias>,
        #[command(flatten)]
        launch: LaunchArgs,
        /// Arguments passed directly to the native CLI, without a shell.
        #[arg(last = true)]
        args: Vec<OsString>,
    },
    /// Authenticate using the native CLI in the selected profile.
    Login {
        profile: Alias,
        #[command(flatten)]
        launch: LaunchArgs,
    },
    /// Bind a directory to a profile; omit the profile to list mappings.
    Map {
        profile: Option<Alias>,
        directory: Option<PathBuf>,
    },
    /// Remove the mapping for this directory.
    Unmap { directory: Option<PathBuf> },
    /// Browse profiles and launch preflight in the terminal dashboard.
    Tui,
}

#[derive(Subcommand)]
enum RegistryMaintenance {
    /// Compare every projection with the event journal without rewriting it.
    Verify,
}

#[derive(clap::Args)]
struct LaunchArgs {
    /// Preview the executable and profile paths. Argument contents are redacted.
    #[arg(long)]
    dry_run: bool,
    /// Opt in to unverified native profile isolation. No automatic swapping.
    #[arg(long)]
    experimental_native: bool,
    /// Absolute path to a trusted executable instead of PATH discovery.
    #[arg(long)]
    executable: Option<PathBuf>,
}

#[derive(Subcommand)]
enum ProfileCommands {
    /// Create an empty profile. Run `aswp login ALIAS` to authenticate later.
    Add {
        #[arg(value_parser = parse_harness)]
        harness: Harness,
        #[arg(long)]
        alias: Alias,
    },
    /// Rename the label without changing profile identity or files.
    Alias { profile: Alias, alias: Alias },
    /// Allow future launches.
    Enable { profile: Alias },
    /// Block future launches. Does not stop an existing native session.
    Disable { profile: Alias },
    /// Unregister the profile. Retains vendor files and does not revoke login.
    Remove { profile: Alias },
    /// Show a registered profile.
    Show { profile: Alias },
}

fn parse_harness(value: &str) -> std::result::Result<Harness, String> {
    value
        .parse()
        .map_err(|_| "choose claude, codex, or kimi".to_owned())
}

pub fn main_entry(name: &'static str) -> i32 {
    let command = Cli::command().bin_name(name);
    let matches = match command.try_get_matches() {
        Ok(matches) => matches,
        Err(error) => {
            let code = error.exit_code();
            let _ = error.print();
            return code;
        }
    };
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(error) => {
            let code = error.exit_code();
            let _ = error.print();
            return code;
        }
    };
    let json_mode = cli.json;
    let strict_stdout = matches!(
        &cli.command,
        Some(Commands::Handover {
            command: handover_cli::HandoverCommands::Pickup { .. }
        })
    );
    if cli.command.is_none() {
        let result = if json_mode {
            emit(
                true,
                &json!({"name": name, "status": "developer_preview", "hint": "use --help for commands"}),
                "",
            )
        } else {
            Cli::command()
                .bin_name(name)
                .write_long_help(&mut io::stdout())
                .map_err(Error::from)
        };
        return if result.is_ok() { 0 } else { 125 };
    }
    match dispatch(cli) {
        Ok(code) => code,
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe && !strict_stdout => 0,
        Err(error) => {
            if json_mode {
                let _ = emit(
                    true,
                    &json!({"error": {"code": error.code(), "message": error.to_string()}}),
                    "",
                );
            } else {
                let _ = writeln!(io::stderr(), "error: {error}");
            }
            match error {
                Error::ExecutableNotFound => 127,
                Error::UnsafeExecutable => 126,
                Error::Cancelled => 130,
                _ => 125,
            }
        }
    }
}

fn dispatch(cli: Cli) -> Result<i32> {
    let command = match cli.command {
        Some(Commands::Handover { command }) => {
            return handover_cli::dispatch(command, cli.json, cli.state_dir);
        }
        Some(Commands::Registry(command)) => command,
        None => return Ok(0),
    };
    let root = match cli.state_dir {
        Some(root) => root,
        None => Store::default_root()?,
    };
    let mut store = Store::open(&root)?;
    let cwd = std::env::current_dir()?;
    match command {
        RegistryCommands::Registry {
            command: RegistryMaintenance::Verify,
        } => {
            let report = store.verify()?;
            let text = if report.consistent {
                format!(
                    "Registry verified: {} events; all projections match.",
                    report.events
                )
            } else {
                format!(
                    "Registry mismatch: {}. Preserve the state directory before recovery.",
                    report.mismatched_tables.join(", ")
                )
            };
            emit(cli.json, &report, &text)?;
            return Ok(if report.consistent { 0 } else { 125 });
        }
        RegistryCommands::Profile { command } => match command {
            ProfileCommands::Add { harness, alias } => {
                let p = store.register(harness, alias)?;
                show_profile(
                    cli.json,
                    &p,
                    &format!(
                        "Registered {} ({harness}). Account unverified. Next: aswp login {} --dry-run",
                        p.alias, p.alias
                    ),
                )?;
            }
            ProfileCommands::Alias { profile, alias } => {
                let p = store.rename(&profile, alias)?;
                show_profile(
                    cli.json,
                    &p,
                    &format!("Renamed {profile} to {}. Profile files retained.", p.alias),
                )?;
            }
            ProfileCommands::Enable { ref profile } | ProfileCommands::Disable { ref profile } => {
                let enabled = matches!(command, ProfileCommands::Enable { .. });
                let p = store.enable(profile, enabled)?;
                show_profile(
                    cli.json,
                    &p,
                    &format!(
                        "{}: {}",
                        p.alias,
                        if enabled {
                            "enabled"
                        } else {
                            "disabled; existing sessions continue"
                        }
                    ),
                )?;
            }
            ProfileCommands::Remove { profile } => {
                store.remove(&profile)?;
                emit(
                    cli.json,
                    &json!({"removed": profile, "vendorFilesRetained": true}),
                    &format!(
                        "Unregistered {profile}. Vendor files retained; server-side login is unchanged."
                    ),
                )?;
            }
            ProfileCommands::Show { profile } => {
                let p = store.find(&profile)?;
                show_profile(cli.json, &p, &profile_line(&p))?;
            }
        },
        RegistryCommands::List => {
            let profiles = store.profiles()?;
            let data: Vec<_> = profiles.iter().map(profile_view).collect();
            let text = if profiles.is_empty() {
                "No profiles yet. Start with: aswp profile add claude --alias work".to_owned()
            } else {
                format!(
                    "PROFILE          HARNESS   STATUS     ACCOUNT       QUOTA\n{}",
                    profiles
                        .iter()
                        .map(profile_line)
                        .collect::<Vec<_>>()
                        .join("\n")
                )
            };
            emit(cli.json, &data, &text)?;
        }
        RegistryCommands::Status => {
            let profiles = store.profiles()?;
            let unfinished = store.unfinished()?;
            let text = format!(
                "{} profiles. {} unfinished runs. Quota: unknown.\n{}",
                profiles.len(),
                unfinished.len(),
                if unfinished.is_empty() {
                    "No unresolved launch intents.".to_owned()
                } else {
                    unfinished.iter().map(|r| format!("{}: unfinished {} ({}) - reuse blocked; previous child custody is unknown", r.alias, terminal_text(&r.kind), r.id)).collect::<Vec<_>>().join("\n")
                }
            );
            emit(
                cli.json,
                &json!({"profiles": profiles.iter().map(profile_view).collect::<Vec<_>>(), "unfinishedRuns": unfinished}),
                &text,
            )?;
        }
        RegistryCommands::Runs { id, limit } => {
            if let Some(id) = id {
                let record = store.run(&id)?;
                let text = run_line(&record);
                emit(cli.json, &record, &text)?;
            } else {
                let records = store.runs(limit)?;
                let text = if records.is_empty() {
                    "No runs recorded. Inspect a launch with: aswp run PROFILE --dry-run".to_owned()
                } else {
                    records.iter().map(run_line).collect::<Vec<_>>().join("\n")
                };
                emit(cli.json, &records, &text)?;
            }
        }
        RegistryCommands::Doctor => {
            let issue = store
                .check()
                .err()
                .map(|error| json!({"code":error.code(),"message":error.to_string()}));
            let health = if issue.is_some() {
                "needs_attention"
            } else {
                "ok"
            };
            let executables: Vec<_> = Harness::ALL.into_iter().map(|h| json!({"harness":h,"executable":discover(h),"isolation":"unverified","version":"not_probed"})).collect();
            let pending = store.unfinished()?.len();
            emit(
                cli.json,
                &json!({"storage":health,"issue":issue, "profilePermissions": if cfg!(unix) {"posix_checked"} else {"acl_not_verified"},"executables":executables,"unfinishedRuns":pending,"containment":"none"}),
                &format!(
                    "Storage integrity: {health}\nNative CLIs: {}\nProfile isolation: unverified\nVersions: not probed\nProcess containment: none\nUnfinished runs: {pending}\n{}\n{}",
                    Harness::ALL
                        .into_iter()
                        .map(|h| format!(
                            "{h}={}",
                            if discover(h).is_some() {
                                "found"
                            } else {
                                "missing"
                            }
                        ))
                        .collect::<Vec<_>>()
                        .join(", "),
                    if cfg!(unix) {
                        "Private POSIX modes checked."
                    } else {
                        "Windows ACL isolation has not been verified."
                    },
                    issue
                        .as_ref()
                        .and_then(|value| value["message"].as_str())
                        .unwrap_or("No local storage issue detected.")
                ),
            )?;
            return Ok(if issue.is_some() { 125 } else { 0 });
        }
        RegistryCommands::Recover {
            run_id,
            confirm_stopped,
        } => {
            if !confirm_stopped {
                return Err(Error::Busy);
            }
            store.attest_stopped(&run_id)?;
            emit(
                cli.json,
                &json!({"runId":run_id,"outcome":"user_attested_stopped"}),
                "Recorded your stopped-process attestation. Profile reuse is permitted; descendant custody was not independently verified.",
            )?;
        }
        RegistryCommands::Run {
            profile,
            launch,
            args,
        } => {
            let p = match profile {
                Some(alias) => store.find(&alias)?,
                None => {
                    let p = store.resolve_mapping(&cwd)?;
                    writeln!(
                        io::stderr(),
                        "Using mapped profile: {} ({})",
                        p.alias,
                        p.harness
                    )?;
                    p
                }
            };
            return launch_native(&mut store, p, launch, args, false, cli.json);
        }
        RegistryCommands::Login { profile, launch } => {
            let p = store.find(&profile)?;
            return launch_native(&mut store, p, launch, vec![], true, cli.json);
        }
        RegistryCommands::Map {
            profile: Some(alias),
            directory,
        } => {
            store.map(&alias, directory.as_deref().unwrap_or(&cwd))?;
            emit(
                cli.json,
                &json!({"mapped": alias}),
                &format!("Directory mapped to {alias}."),
            )?;
        }
        RegistryCommands::Map {
            profile: None,
            directory,
        } => {
            if directory.is_some() {
                return Err(Error::NotFound);
            }
            let mappings = store.mappings()?;
            let text = if mappings.is_empty() {
                "No directory mappings. Use: aswp map ALIAS [DIRECTORY]".to_owned()
            } else {
                mappings
                    .iter()
                    .map(|m| format!("{} -> {}", terminal_text(&m.directory), m.alias))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            emit(cli.json, &mappings, &text)?;
        }
        RegistryCommands::Unmap { directory } => {
            store.unmap(directory.as_deref().unwrap_or(&cwd))?;
            emit(
                cli.json,
                &json!({"unmapped": true}),
                "Directory mapping removed.",
            )?;
        }
        RegistryCommands::Tui => {
            if cli.json || !io::stdin().is_terminal() || !io::stdout().is_terminal() {
                return Err(Error::InteractiveMode);
            }
            tui::run(&store)?;
        }
    }
    Ok(0)
}

fn launch_native(
    store: &mut Store,
    profile: Profile,
    launch: LaunchArgs,
    args: Vec<OsString>,
    login: bool,
    json_mode: bool,
) -> Result<i32> {
    let plan = LaunchPlan::build(
        store,
        profile,
        launch.executable.as_deref(),
        &std::env::current_dir()?,
        args,
        login,
    )?;
    if launch.dry_run {
        let preview = plan.preview();
        let conflicts = plan
            .check_environment(|key| std::env::var_os(key))
            .err()
            .map(|e| e.to_string());
        emit(
            json_mode,
            &json!({"plan":preview,"environmentConflict":conflicts}),
            &format!(
                "{} {}\nProgram: {}\n{}={}\nArguments: {} (contents redacted)\nIsolation: unverified. Quota: unknown. Containment: none.\n{}",
                preview.operation,
                preview.profile.alias,
                terminal_text(&preview.program.display().to_string()),
                preview.home_variable,
                terminal_text(&preview.profile_home.display().to_string()),
                preview.argument_count,
                conflicts
                    .as_deref()
                    .unwrap_or("No known inherited routing conflict.")
            ),
        )?;
        return Ok(0);
    }
    if json_mode {
        return Err(Error::InteractiveMode);
    }
    if !launch.experimental_native {
        return Err(Error::UnverifiedNative);
    }
    writeln!(
        io::stderr(),
        "Experimental native launch: {} ({}). Profile isolation unverified; no process containment or automatic swapping.",
        plan.profile.alias,
        plan.profile.harness
    )?;
    ctrlc::set_handler(|| {})
        .map_err(|_| Error::Io(io::Error::other("could not install interrupt handler")))?;
    plan.execute(store, true)
}

fn run_line(run: &agentswapper_core::store::RunRecord) -> String {
    use agentswapper_core::store::ProcessCustody;
    let custody = match run.custody {
        ProcessCustody::Unknown => "unknown; descendant custody unresolved",
        ProcessCustody::ExitedUncontained => "child exited; descendants unverified",
        ProcessCustody::NeverStarted => "native process did not start",
        ProcessCustody::AttestedStopped => "operator attested stopped; not independently verified",
    };
    format!(
        "{}  {} / {} / {}\n  {} | exit={}\n  Custody: {}\n  Observed PID={} (may be reused; do not signal this ID)",
        run.id,
        run.alias,
        run.harness,
        terminal_text(&run.kind),
        terminal_text(&run.started_at),
        run.exit_code
            .map_or_else(|| "pending".to_owned(), |code| code.to_string()),
        custody,
        run.observed_pid
            .map_or_else(|| "unrecorded".to_owned(), |pid| pid.to_string())
    )
}

fn profile_view(p: &Profile) -> serde_json::Value {
    json!({"profile":p,"account":"unverified","quota":"unknown","isolation":"unverified"})
}

fn profile_line(p: &Profile) -> String {
    format!(
        "{:<16} {:<9} {:<10} unverified    unknown",
        p.alias.to_string(),
        p.harness.to_string(),
        if p.enabled { "enabled" } else { "disabled" }
    )
}

fn show_profile(json_mode: bool, p: &Profile, text: &str) -> Result<()> {
    emit(json_mode, &profile_view(p), text)
}

fn emit(json_mode: bool, data: &impl Serialize, text: &str) -> Result<()> {
    let mut out = io::stdout().lock();
    if json_mode {
        serde_json::to_writer(&mut out, &json!({"schemaVersion":0,"data":data}))?;
        writeln!(out)?;
    } else {
        writeln!(out, "{text}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn command_contract_is_internally_consistent() {
        Cli::command().debug_assert();
    }
    #[test]
    fn terminal_control_characters_are_escaped() {
        assert_eq!(terminal_text("name\x1b[31m\n"), "name\\u{1b}[31m\\n");
    }
}
