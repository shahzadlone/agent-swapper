//! Shared entry point for both command names. JSON is an unstable v0 contract.
mod config_cli;
mod engines;
mod handover_cli;
#[cfg(unix)]
mod terminal_signals;
mod tui;

use std::{
    ffi::OsString,
    io::{self, IsTerminal, Write},
    path::PathBuf,
};

use agentswapper_core::{
    Alias, Error, ExecutionEngine, GentsAgentId, GentsBinding, Harness, Profile, Result, Store,
    launch::{Containment, LaunchPlan, discover},
    terminal_text,
};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use serde::Serialize;
use serde_json::json;

#[derive(Parser)]
#[command(
    version,
    about = "Switch agents. Keep your place.",
    after_help = "Run without a command in a terminal to open the dashboard.\nDeveloper preview: engine integrations are unverified. No automatic switching yet."
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
    /// Inspect or change non-secret CLI preferences.
    Config {
        #[command(subcommand)]
        command: Option<config_cli::ConfigCommands>,
    },
    /// Compare execution engines, ownership, benefits and limitations.
    Engines,
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
    /// Show profiles and unfinished client runs.
    Status,
    /// Inspect recent runs or one run ID, including process-custody observations.
    Runs {
        id: Option<String>,
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..=200))]
        limit: Option<u16>,
    },
    /// Check local storage and discover native CLIs without executing them.
    Doctor,
    /// Resolve an unfinished run only after you have stopped its client processes.
    Recover {
        run_id: String,
        /// Attest the client and its descendants stopped; external gents runtime custody stays unknown.
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
    Tui {
        /// Start with profile aliases hidden, overriding ui.mask.
        #[arg(long, conflicts_with = "show_aliases")]
        mask: bool,
        /// Start with profile aliases visible, overriding ui.mask.
        #[arg(long)]
        show_aliases: bool,
    },
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
    /// Allow Kimi to inspect legacy data in the user's home for this launch.
    #[arg(long, requires = "experimental_native")]
    allow_kimi_legacy: bool,
    /// Allow Claude to use an Anthropic profile shared outside the selected home.
    #[arg(long, requires = "experimental_native")]
    allow_claude_shared_auth: bool,
    /// Opt in to an attached gents chat client. External work may outlive it.
    #[arg(long, conflicts_with = "experimental_native")]
    experimental_gents: bool,
    /// Windows native only: own a Job; kill remaining local descendants on CLI exit.
    #[arg(long, value_parser = parse_containment, conflicts_with = "experimental_gents")]
    experimental_containment: Option<Containment>,
    /// Require this engine to match the registered profile.
    #[arg(long, value_parser = parse_engine)]
    engine: Option<ExecutionEngine>,
    /// Continue or create a gents session UUID; the profile binding selects its agent.
    #[arg(long)]
    session: Option<uuid::Uuid>,
    /// Gents only: resume the latest attempt if its client succeeded and binding matches.
    #[arg(long, conflicts_with = "session")]
    resume: bool,
    /// Absolute path to a trusted executable instead of PATH discovery.
    #[arg(long)]
    executable: Option<PathBuf>,
}

#[derive(Subcommand)]
enum ProfileCommands {
    /// Create an empty native or gents profile. Registration does not authenticate.
    Add {
        #[arg(value_parser = parse_harness)]
        harness: Option<Harness>,
        /// Choose native or gents. Native is the default unless HARNESS is gents.
        #[arg(long, value_parser = parse_engine)]
        engine: Option<ExecutionEngine>,
        /// Explicit gents runtime address, e.g. 127.0.0.1:9191 (loopback only).
        #[arg(long, requires = "agent")]
        address: Option<std::net::SocketAddr>,
        /// Gents agent ID: exact, case-sensitive; 1-128 printable ASCII characters.
        #[arg(long, requires = "address")]
        agent: Option<GentsAgentId>,
        #[arg(long)]
        alias: Alias,
    },
    /// Rebind a gents home to its runtime and agent; does not stop external work.
    Bind {
        profile: Alias,
        #[arg(long)]
        address: std::net::SocketAddr,
        #[arg(long)]
        agent: GentsAgentId,
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
        .map_err(|_| "choose claude, codex, kimi, or gents".to_owned())
}

fn parse_engine(value: &str) -> std::result::Result<ExecutionEngine, String> {
    value
        .parse()
        .map_err(|_| "choose native or gents".to_owned())
}

fn parse_containment(value: &str) -> std::result::Result<Containment, String> {
    match value {
        "windows-job" => Ok(Containment::WindowsJob),
        _ => {
            Err("supported experimental backend: windows-job (Windows native profiles only)".into())
        }
    }
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
    let mut cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(error) => {
            let code = error.exit_code();
            let _ = error.print();
            return code;
        }
    };
    let json_mode = cli.json;
    if cli.command.is_none()
        && !json_mode
        && io::stdin().is_terminal()
        && io::stdout().is_terminal()
    {
        cli.command = Some(Commands::Registry(RegistryCommands::Tui {
            mask: false,
            show_aliases: false,
        }));
    }
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
        Some(Commands::Config { command }) => {
            return config_cli::dispatch(command, cli.state_dir, cli.json);
        }
        Some(Commands::Engines) => {
            return engines::show(cli.json);
        }
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
            ProfileCommands::Add {
                harness,
                alias,
                engine,
                address,
                agent,
            } => {
                let engine = engine
                    .unwrap_or_else(|| harness.map_or(ExecutionEngine::Native, Harness::engine));
                let p = match (engine, harness, address, agent) {
                    (
                        ExecutionEngine::Gents,
                        None | Some(Harness::Gents),
                        Some(address),
                        Some(agent),
                    ) => store.register_gents(alias, GentsBinding::new(address, agent)?)?,
                    (ExecutionEngine::Native, Some(harness), None, None)
                        if harness != Harness::Gents =>
                    {
                        store.register(harness, alias)?
                    }
                    _ => return Err(Error::InvalidEngineBinding),
                };
                let home = store.profile_home(p.id)?;
                let next = if p.harness == Harness::Gents {
                    format!(
                        "Initialize and authenticate gents separately in this home, then start its local runtime. Inspect: aswp run {} --dry-run",
                        p.alias
                    )
                } else {
                    format!("Next: aswp login {} --dry-run", p.alias)
                };
                emit(
                    cli.json,
                    &json!({"profile":p,"engine":p.harness.engine(),"profileHome":home,"account":"unverified","quota":"unknown","isolation":"unverified"}),
                    &format!(
                        "Registered {} ({} / {}). Account unverified.\nHome: {}\n{next}",
                        p.alias,
                        p.harness.engine(),
                        p.harness,
                        terminal_text(&home.display().to_string())
                    ),
                )?;
            }
            ProfileCommands::Bind {
                profile,
                address,
                agent,
            } => {
                let p = store.bind_gents(&profile, GentsBinding::new(address, agent)?)?;
                show_profile(
                    cli.json,
                    &p,
                    &format!(
                        "Rebound {}. Home and credentials retained. This does not stop or move work in the external runtime. Inspect: aswp run {} --dry-run",
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
                let external = store.find(&profile)?.harness == Harness::Gents;
                store.remove(&profile)?;
                let engine_note = if external {
                    " Keychain items retained. External runtimes are not stopped."
                } else {
                    ""
                };
                emit(
                    cli.json,
                    &json!({"removed": profile, "vendorFilesRetained": true}),
                    &format!(
                        "Unregistered {profile}. Vendor files retained; server-side login is unchanged.{engine_note}"
                    ),
                )?;
            }
            ProfileCommands::Show { profile } => {
                let p = store.find(&profile)?;
                let home = store.profile_home(p.id)?;
                let binding = p.gents.as_ref().map(|g| format!("\nRuntime: {} | Agent: {}\nWorkspace and permissions: gents agent configuration; external runtime.", g.address(), g.agent())).unwrap_or_default();
                emit(
                    cli.json,
                    &json!({"profile":p,"engine":p.harness.engine(),"profileHome":home,"account":"unverified","quota":"unknown","isolation":"unverified"}),
                    &format!(
                        "{}\nEngine: {}\nHome: {}{binding}",
                        profile_line(&p),
                        p.harness.engine(),
                        terminal_text(&home.display().to_string())
                    ),
                )?;
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
                let limit = match limit {
                    Some(limit) => limit,
                    None => agentswapper_core::config::ConfigStore::new(store.root())?
                        .load()?
                        .history_limit(),
                };
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
            let preferences_issue = agentswapper_core::config::ConfigStore::new(store.root())
                .and_then(|config| config.load())
                .err()
                .map(|error| json!({"code":error.code(),"message":error.to_string()}));
            let preferences_health = if preferences_issue.is_some() {
                "needs_attention"
            } else {
                "ok"
            };
            let executables: Vec<_> = Harness::ALL.into_iter().map(|h| json!({"harness":h,"executable":discover(h),"isolation":"unverified","version":"not_probed"})).collect();
            let pending = store.unfinished()?.len();
            let available_containment: &[&str] = if cfg!(windows) { &["windows_job"] } else { &[] };
            emit(
                cli.json,
                &json!({"storage":health,"issue":issue,"preferences":{"status":preferences_health,"issue":preferences_issue}, "profilePermissions": if cfg!(unix) {"posix_checked"} else {"acl_not_verified"},"executables":executables,"unfinishedRuns":pending,"containment":"none","availableExperimentalContainment":available_containment}),
                &format!(
                    "Storage integrity: {health}\nPreferences: {preferences_health}\nAgent CLIs: {}\nProfile isolation: unverified\nVersions: not probed\nDefault containment: none\nExperimental local backends: {}\nUnfinished runs: {pending}\n{}\n{}",
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
                    if available_containment.is_empty() {
                        "none".to_owned()
                    } else {
                        available_containment.join(", ")
                    },
                    if cfg!(unix) {
                        "Private POSIX modes checked."
                    } else {
                        "Windows ACL isolation has not been verified."
                    },
                    issue
                        .as_ref()
                        .or(preferences_issue.as_ref())
                        .and_then(|value| value["message"].as_str())
                        .unwrap_or("No local storage issue detected.")
                ),
            )?;
            return Ok(if issue.is_some() || preferences_issue.is_some() {
                125
            } else {
                0
            });
        }
        RegistryCommands::Recover {
            run_id,
            confirm_stopped,
        } => {
            if !confirm_stopped {
                return Err(Error::Busy);
            }
            let external = store.run(&run_id)?.harness == Harness::Gents;
            store.attest_stopped(&run_id)?;
            emit(
                cli.json,
                &json!({"runId":run_id,"outcome":"user_attested_stopped"}),
                if external {
                    "Recorded your client-stop attestation. Client reuse is permitted; external runtime custody remains unknown and work may continue."
                } else {
                    "Recorded your stopped-process attestation. Profile reuse is permitted; descendant custody was not independently verified."
                },
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
            return launch_profile(&mut store, p, launch, args, false, cli.json);
        }
        RegistryCommands::Login { profile, launch } => {
            let p = store.find(&profile)?;
            return launch_profile(&mut store, p, launch, vec![], true, cli.json);
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
        RegistryCommands::Tui { mask, show_aliases } => {
            if cli.json || !io::stdin().is_terminal() || !io::stdout().is_terminal() {
                return Err(Error::InteractiveMode);
            }
            let masked = if mask {
                true
            } else if show_aliases {
                false
            } else {
                agentswapper_core::config::ConfigStore::new(store.root())?
                    .load()?
                    .ui_mask()
            };
            tui::run(&mut store, masked)?;
        }
    }
    Ok(0)
}

fn launch_profile(
    store: &mut Store,
    profile: Profile,
    launch: LaunchArgs,
    args: Vec<OsString>,
    login: bool,
    json_mode: bool,
) -> Result<i32> {
    let engine = profile.harness.engine();
    if launch.engine.is_some_and(|requested| requested != engine) {
        return Err(Error::EngineMismatch);
    }
    if login && (launch.session.is_some() || launch.resume) {
        return Err(Error::UnsupportedSession);
    }
    let mut plan = LaunchPlan::build(
        store,
        profile,
        launch.executable.as_deref(),
        &std::env::current_dir()?,
        args,
        login,
    )?
    .with_session(launch.session)?
    .with_containment(launch.experimental_containment)?
    .with_kimi_legacy_access(launch.allow_kimi_legacy)
    .with_claude_shared_auth_access(launch.allow_claude_shared_auth);
    if launch.resume {
        plan = plan.with_latest_gents_session(store)?;
    }
    if launch.dry_run {
        let preview = plan.preview();
        let runtime_check = if engine == ExecutionEngine::Gents {
            Some(match plan.check_gents_runtime() {
                Ok(true) => "recorded home and address match; listener unverified".to_owned(),
                Ok(false) => {
                    "runtime.json missing; start the dedicated runtime before launching".to_owned()
                }
                Err(error) => error.to_string(),
            })
        } else {
            None
        };
        let scope = if engine == ExecutionEngine::Gents {
            let binding = preview
                .profile
                .gents
                .as_ref()
                .ok_or(Error::InvalidEngineBinding)?;
            format!(
                "\nEngine: gents (attached chat client)\nRuntime: {} | Agent: {}\nHome is passed with --home. Workspace and permissions belong to the gents agent configuration, not this client directory.\nClient exit does not stop the external runtime. Listener unverified; gents presents this home's authentication to the bound address.\nRuntime check: {}\nSession: {}\nSelection: {}; source run: {}\nPreview only; no session is reserved.",
                binding.address(),
                binding.agent(),
                runtime_check.as_deref().unwrap_or("not checked"),
                preview
                    .session
                    .map_or_else(|| "none".to_owned(), |id| id.to_string()),
                preview
                    .session_selection
                    .map_or("none", |selection| selection.as_str()),
                preview
                    .resumed_from
                    .map_or_else(|| "none".to_owned(), |id| id.to_string())
            )
        } else if launch.experimental_containment.is_some() {
            "\nEngine: native\nRemaining local Job descendants will be terminated when the initial CLI exits. External work is unverified; ambiguous failures keep the run unresolved.".to_owned()
        } else {
            "\nEngine: native".to_owned()
        };
        let conflicts = plan
            .check_environment(|key| std::env::var_os(key))
            .err()
            .map(|e| e.to_string());
        let legacy = plan.check_kimi_legacy().err().map(|e| e.to_string());
        let shared_auth = plan.check_claude_shared_auth().err().map(|e| e.to_string());
        emit(
            json_mode,
            &json!({"plan":preview,"environmentConflict":conflicts,"runtimeCheck":runtime_check,"kimiLegacyRisk":legacy,"claudeSharedAuthRisk":shared_auth}),
            &format!(
                "{} {}\nProgram: {}\n{}={}\nArguments: {} (contents redacted)\nIsolation: unverified. Quota: unknown. Containment: {}.{scope}\n{}",
                preview.operation,
                preview.profile.alias,
                terminal_text(&preview.program.display().to_string()),
                preview.home_variable.unwrap_or("--home"),
                terminal_text(&preview.profile_home.display().to_string()),
                preview.argument_count,
                preview.containment,
                conflicts
                    .as_deref()
                    .unwrap_or("No known inherited routing conflict.")
            ),
        )?;
        if let Some(legacy) = legacy
            && !json_mode
        {
            writeln!(io::stdout(), "{legacy}")?;
        }
        if let Some(shared_auth) = shared_auth
            && !json_mode
        {
            writeln!(io::stdout(), "{shared_auth}")?;
        }
        return Ok(0);
    }
    if json_mode {
        return Err(Error::InteractiveMode);
    }
    match engine {
        ExecutionEngine::Native if !launch.experimental_native => {
            return Err(Error::UnverifiedNative);
        }
        ExecutionEngine::Gents if !launch.experimental_gents => return Err(Error::UnverifiedGents),
        _ => {}
    }
    writeln!(
        io::stderr(),
        "Experimental {engine} launch: {} ({}). Isolation unverified; containment: {}; no automatic swapping.",
        plan.profile().alias,
        plan.profile().harness,
        plan.preview().containment
    )?;
    if launch.experimental_containment.is_some() {
        writeln!(
            io::stderr(),
            "Remaining local Job descendants will be terminated when the initial CLI exits. External work is unverified; ambiguous failures keep the run unresolved."
        )?;
    }
    if engine == ExecutionEngine::Gents {
        let preview = plan.preview();
        writeln!(
            io::stderr(),
            "Attached chat client only. Gents owns credentials, tools, permissions and the configured agent workspace. External runtime work may continue after this client exits.\nSession: {} ({})",
            preview
                .session
                .map_or_else(|| "none".to_owned(), |id| id.to_string()),
            preview
                .session_selection
                .map_or("none", |selection| selection.as_str()),
        )?;
    }
    install_launch_interrupt_handler()?;
    match engine {
        ExecutionEngine::Native => plan.execute(store, true),
        ExecutionEngine::Gents => plan.execute_gents(store, true),
    }
}

fn install_launch_interrupt_handler() -> Result<()> {
    #[cfg(unix)]
    {
        // A fresh process can inherit SIG_IGN across exec. Installing a new
        // handler over it would make exec reset the child's disposition to
        // SIG_DFL. Preserve any existing disposition; if it belongs to an
        // embedding host, that host retains responsibility for its behavior.
        match ctrlc::try_set_handler(|| {}) {
            Ok(()) | Err(ctrlc::Error::MultipleHandlers) => Ok(()),
            Err(_) => Err(Error::Io(io::Error::other(
                "could not install interrupt handler",
            ))),
        }
    }
    #[cfg(not(unix))]
    {
        ctrlc::set_handler(|| {})
            .map_err(|_| Error::Io(io::Error::other("could not install interrupt handler")))
    }
}

fn run_line(run: &agentswapper_core::store::RunRecord) -> String {
    use agentswapper_core::store::ProcessCustody;
    let custody = match run.custody {
        ProcessCustody::Unknown => "unknown; descendant custody unresolved",
        ProcessCustody::ExternalRuntimeUnknown => {
            "external runtime unknown; work may continue independently of this client"
        }
        ProcessCustody::LocalScopeEmpty => {
            "owned local Job observed empty; external work unverified"
        }
        ProcessCustody::ExitedUncontained => "child exited; descendants unverified",
        ProcessCustody::NeverStarted => "native process did not start",
        ProcessCustody::AttestedStopped => "operator attested stopped; not independently verified",
    };
    let session = run
        .gents_session
        .as_ref()
        .map(|s| {
            format!(
                "\n  Gents session={} | agent={} | runtime={} | resumed from={}",
                s.id(),
                s.binding().agent(),
                s.binding().address(),
                s.resumed_from()
                    .map_or_else(|| "none".to_owned(), |id| id.to_string())
            )
        })
        .unwrap_or_default();
    format!(
        "{}  {} / {} / {}\n  {} | exit={} | outcome={}\n  Custody: {}\n  Observed PID={} (may be reused; do not signal this ID){session}",
        run.id,
        run.alias,
        run.harness,
        terminal_text(&run.kind),
        terminal_text(&run.started_at),
        run.exit_code
            .map_or_else(|| "pending".to_owned(), |code| code.to_string()),
        terminal_text(run.outcome.as_deref().unwrap_or("pending")),
        custody,
        run.observed_pid
            .map_or_else(|| "unrecorded".to_owned(), |pid| pid.to_string())
    )
}

fn profile_view(p: &Profile) -> serde_json::Value {
    json!({"profile":p,"engine":p.harness.engine(),"account":"unverified","quota":"unknown","isolation":"unverified"})
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
