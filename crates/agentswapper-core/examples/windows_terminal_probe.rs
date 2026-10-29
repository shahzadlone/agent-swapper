//! Provider-free native launch checks in a disposable Windows console.
#![forbid(unsafe_code)]

#[cfg(not(windows))]
fn main() {
    println!("Windows-only console probe; no provider was launched.");
}

#[cfg(windows)]
fn main() {
    match probe::run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            let detail = error
                .to_string()
                .replace('%', "%25")
                .replace('\r', "%0D")
                .replace('\n', "%0A");
            eprintln!("::error title=Windows console restoration::{detail}");
            std::process::exit(1);
        }
    }
}

#[cfg(windows)]
mod probe {
    use agentswapper_core::{Harness, Store, store::ProcessCustody};
    use serde_json::{Value, json};
    use std::{
        fs::{self, File, OpenOptions},
        io::{self, Read},
        os::windows::process::CommandExt,
        path::{Path, PathBuf},
        process::{Command, Stdio},
        time::Duration,
    };
    use wait_timeout::ChildExt;
    use winapi_util::console;
    use windows_sys::Win32::System::{
        Console::{
            ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_WRAP_AT_EOL_OUTPUT,
        },
        Threading::CREATE_NEW_CONSOLE,
    };

    fn require(condition: bool, message: &str) -> io::Result<()> {
        if condition {
            Ok(())
        } else {
            Err(io::Error::other(message))
        }
    }

    fn console_file(name: &str) -> io::Result<File> {
        OpenOptions::new().read(true).write(true).open(name)
    }

    fn command(program: &Path, directory: &Path) -> Command {
        let mut command = Command::new(program);
        command.env_clear();
        for key in ["SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        for key in ["HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"] {
            command.env(key, directory.join("home"));
        }
        command.current_dir(directory);
        command
    }

    fn agent(directory: &Path, trial: &str) -> io::Result<()> {
        require(
            matches!(
                trial,
                "direct-console"
                    | "direct-stderr"
                    | "direct-redirected"
                    | "job-console"
                    | "job-stderr"
                    | "job-redirected"
            ),
            "invalid console fixture trial",
        )?;
        let input = console_file(r"\\.\CONIN$")?;
        let output = console_file(r"\\.\CONOUT$")?;
        let input_before = console::mode(&input)?;
        let output_before = console::mode(&output)?;
        let input_changed =
            input_before & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
        let output_changed = output_before ^ ENABLE_WRAP_AT_EOL_OUTPUT;
        require(
            input_changed != input_before && output_changed != output_before,
            "fixture must change both console modes",
        )?;
        console::set_mode(&input, input_changed)?;
        console::set_mode(&output, output_changed)?;
        require(
            console::mode(&input)? == input_changed && console::mode(&output)? == output_changed,
            "agent console changes did not persist",
        )?;
        fs::write(
            directory.join(format!("{trial}.json")),
            serde_json::to_vec(&json!({
                "inputBefore":input_before, "inputChanged":input_changed,
                "outputBefore":output_before, "outputChanged":output_changed
            }))
            .map_err(io::Error::other)?,
        )?;
        // Exit without restoring anything. AgentSwapper must restore the exact
        // parent modes before reporting the child outcome.
        Ok(())
    }

    fn attached(cli: &Path, directory: &Path) -> io::Result<()> {
        let input = console_file(r"\\.\CONIN$")?;
        let output = console_file(r"\\.\CONOUT$")?;
        let before = (console::mode(&input)?, console::mode(&output)?);
        {
            let mut store = Store::open(&directory.join("state")).map_err(io::Error::other)?;
            store
                .register(Harness::Codex, "fixture".parse().map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
        }
        let mut trials = Vec::new();
        for job in [false, true] {
            for streams in ["console", "stderr", "redirected"] {
                let trial = format!("{}-{streams}", if job { "job" } else { "direct" });
                let mut launch = command(cli, directory);
                launch
                    .arg("--state-dir")
                    .arg(directory.join("state"))
                    .args(["run", "fixture", "--experimental-native", "--executable"])
                    .arg(std::env::current_exe()?);
                if job {
                    launch.args(["--experimental-containment", "windows-job"]);
                }
                launch
                    .arg("--")
                    .arg("__fixture_agent")
                    .arg(directory)
                    .arg(&trial);
                launch.stdin(if streams == "console" {
                    Stdio::from(input.try_clone()?)
                } else {
                    Stdio::null()
                });
                launch.stdout(if streams == "console" {
                    Stdio::from(output.try_clone()?)
                } else {
                    Stdio::null()
                });
                launch.stderr(if streams == "redirected" {
                    Stdio::null()
                } else {
                    Stdio::from(output.try_clone()?)
                });
                let mut child = launch.spawn()?;
                let status = match child.wait_timeout(Duration::from_secs(15))? {
                    Some(status) => status,
                    None => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "native console fixture did not exit",
                        ));
                    }
                };
                require(
                    status.code() == Some(42),
                    &format!("{trial}: native launch did not preserve exit 42"),
                )?;
                let evidence: Value =
                    serde_json::from_slice(&fs::read(directory.join(format!("{trial}.json")))?)
                        .map_err(io::Error::other)?;
                require(
                    evidence["inputBefore"] == before.0 && evidence["outputBefore"] == before.1,
                    "agent did not start with the parent's exact console modes",
                )?;
                require(
                    (console::mode(&input)?, console::mode(&output)?) == before,
                    &format!("{trial}: console modes were not restored"),
                )?;
                let store = Store::open(&directory.join("state")).map_err(io::Error::other)?;
                let runs = store.runs(1).map_err(io::Error::other)?;
                let run = runs
                    .first()
                    .ok_or_else(|| io::Error::other("console run was not journaled"))?;
                require(
                    run.exit_code == Some(42)
                        && run.custody
                            == if job {
                                ProcessCustody::LocalScopeEmpty
                            } else {
                                ProcessCustody::ExitedUncontained
                            },
                    "console fixture custody or exit observation mismatch",
                )?;
                require(
                    store.verify().map_err(io::Error::other)?.consistent,
                    "console journal does not verify",
                )?;
                trials.push(trial);
            }
        }
        fs::write(
            directory.join("report.json"),
            serde_json::to_vec(&trials).map_err(io::Error::other)?,
        )?;
        Ok(())
    }

    pub(super) fn run() -> io::Result<i32> {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        if args.len() == 3 && args[0] == "__fixture_agent" {
            agent(
                Path::new(&args[1]),
                args[2]
                    .to_str()
                    .ok_or_else(|| io::Error::other("invalid trial"))?,
            )?;
            return Ok(42);
        }
        if args.len() == 3 && args[0] == "__fixture_console" {
            attached(Path::new(&args[1]), Path::new(&args[2]))?;
            return Ok(0);
        }
        require(
            args.len() == 1,
            "Usage: windows_terminal_probe PATH_TO_ASWP",
        )?;
        let cli: PathBuf = dunce::canonicalize(&args[0])?;
        agentswapper_core::supervision::windows_job::install_process_root()
            .map_err(io::Error::other)?;
        let temp = tempfile::tempdir()?;
        fs::create_dir(temp.path().join("home"))?;
        let diagnostics = File::create(temp.path().join("diagnostics.txt"))?;
        let mut launch = command(&std::env::current_exe()?, temp.path());
        launch
            .arg("__fixture_console")
            .arg(&cli)
            .arg(temp.path())
            .creation_flags(CREATE_NEW_CONSOLE)
            .stdin(Stdio::null())
            .stdout(diagnostics.try_clone()?)
            .stderr(diagnostics);
        let mut child = launch.spawn()?;
        let status = match child.wait_timeout(Duration::from_secs(100))? {
            Some(status) => status,
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "disposable console did not exit",
                ));
            }
        };
        if !status.success() {
            let mut detail = String::new();
            File::open(temp.path().join("diagnostics.txt"))?
                .take(4096)
                .read_to_string(&mut detail)?;
            return Err(io::Error::other(format!(
                "disposable console failed: {detail}"
            )));
        }
        let trials: Vec<String> =
            serde_json::from_slice(&fs::read(temp.path().join("report.json"))?)
                .map_err(io::Error::other)?;
        require(trials.len() == 6, "console fixture omitted a trial")?;
        for trial in trials {
            println!(
                "::notice title=Windows console restoration::{trial}: exact input/output modes and journal outcome passed"
            );
        }
        Ok(0)
    }
}
