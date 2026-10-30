//! A private ConPTY coordinator and fake agents; never invokes a provider.
#![forbid(unsafe_code)]

#[cfg(not(windows))]
fn main() {
    println!("Windows-only dashboard fixture; no provider was launched.");
}

#[cfg(windows)]
fn main() {
    match probe::run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("dashboard fixture failed: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(windows)]
mod probe {
    use serde_json::json;
    use std::{
        fs::{self, File, OpenOptions},
        io,
        path::Path,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    use winapi_util::console;
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_WRAP_AT_EOL_OUTPUT,
    };

    fn require(condition: bool, message: &str) -> io::Result<()> {
        if condition {
            Ok(())
        } else {
            Err(io::Error::other(message))
        }
    }

    fn device(name: &str) -> io::Result<File> {
        OpenOptions::new().read(true).write(true).open(name)
    }

    fn queue_helper(root: &Path, input: &File, phase: &str) -> io::Result<()> {
        let request = root.join("fixture-queue.json");
        if request.exists() {
            let args: Vec<String> =
                serde_json::from_slice(&fs::read(request)?).map_err(io::Error::other)?;
            require(args.len() == 3, "invalid queue helper command")?;
            let status = Command::new(&args[0])
                .arg(&args[1])
                .arg(phase)
                .arg(root)
                .arg(&args[2])
                .stdin(Stdio::from(input.try_clone()?))
                .status()?;
            require(status.success(), "queued-input helper failed")?;
        }
        Ok(())
    }

    fn agent(name: &str) -> io::Result<i32> {
        let root =
            std::env::var_os("HOME").ok_or_else(|| io::Error::other("fixture HOME missing"))?;
        let root = Path::new(&root);
        let count = root.join("sequence");
        let number = match fs::read_to_string(&count) {
            Ok(value) => value.parse::<u32>().map_err(io::Error::other)? + 1,
            Err(error) if error.kind() == io::ErrorKind::NotFound => 1,
            Err(error) => return Err(error),
        };
        let args: Vec<_> = std::env::args().skip(1).collect();
        let input = device(r"\\.\CONIN$")?;
        let output = device(r"\\.\CONOUT$")?;
        let before = console::mode(&input)?;
        let output_before = console::mode(&output)?;
        require(
            before & (ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT)
                == ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT,
            "agent inherited dashboard raw input",
        )?;
        let home = if name == "gents" {
            let index = args
                .iter()
                .position(|value| value == "--home")
                .ok_or_else(|| io::Error::other("gents fixture missing home"))?;
            args.get(index + 1)
                .cloned()
                .ok_or_else(|| io::Error::other("gents fixture missing home value"))?
        } else {
            std::env::var(match name {
                "claude" => "CLAUDE_CONFIG_DIR",
                "codex" => "CODEX_HOME",
                "kimi" => "KIMI_CODE_HOME",
                _ => return Err(io::Error::other("invalid agent")),
            })
            .map_err(io::Error::other)?
        };
        console::set_mode(&input, before & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT))?;
        console::set_mode(&output, output_before ^ ENABLE_WRAP_AT_EOL_OUTPUT)?;
        fs::write(&count, number.to_string())?;
        fs::write(
            root.join(format!("launch-{number}.json")),
            serde_json::to_vec(&json!({
                "agent":name,"args":args,"home":home,"inputMode":before,"outputMode":output_before,
                "cwd":std::env::current_dir()?
            }))
            .map_err(io::Error::other)?,
        )?;
        let deadline = Instant::now() + Duration::from_secs(30);
        while !root.join(format!("stop-{number}")).exists() {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "fixture agent did not receive its stop marker or Ctrl-C",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(if name == "claude" && args.is_empty() {
            42
        } else {
            0
        })
    }

    fn host(cli: &Path, root: &Path, handover: bool) -> io::Result<i32> {
        require(
            std::env::var("ASWP_CONPTY_FIXTURE").as_deref() == Ok("1"),
            "host role requires the isolated ConPTY fixture",
        )?;
        require(
            std::env::var_os("HOME").is_some_and(|home| Path::new(&home) == root),
            "fixture HOME does not match its root",
        )?;
        agentswapper_core::supervision::windows_job::install_process_root()
            .map_err(io::Error::other)?;
        ctrlc::set_handler(|| {}).map_err(io::Error::other)?;
        let input = device(r"\\.\CONIN$")?;
        let output = device(r"\\.\CONOUT$")?;
        // Deliberately retain line/echo while disabling processed input. A
        // generic disable_raw_mode would incorrectly turn processed input on.
        if handover {
            console::set_mode(&input, console::mode(&input)? & !ENABLE_PROCESSED_INPUT)?;
        }
        let before = (console::mode(&input)?, console::mode(&output)?);
        let (arguments, expected): (Vec<String>, i32) = if handover {
            serde_json::from_slice(&fs::read(root.join("fixture-command.json"))?)
                .map_err(io::Error::other)?
        } else {
            (Vec::new(), 0)
        };
        if handover {
            queue_helper(root, &input, "__queue")?;
        }
        let child_input = if handover && root.join("fixture-readonly-input").exists() {
            OpenOptions::new().read(true).open(r"\\.\CONIN$")?
        } else {
            input.try_clone()?
        };
        let mut child = Command::new(cli)
            .arg("--state-dir")
            .arg(root.join("state"))
            .args(arguments)
            .current_dir(root.join("workspace"))
            .stdin(Stdio::from(child_input))
            .stdout(Stdio::from(output.try_clone()?))
            .stderr(Stdio::from(output.try_clone()?))
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(90);
        let mut observed = None;
        let mut request = 0_u32;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "dashboard did not exit",
                ));
            }
            if root.join(format!("mode-request-{}", request + 1)).exists() {
                require(request < 64, "mode observation exceeded fixture budget")?;
                request += 1;
            }
            if request != 0 {
                // Requests are immutable, payload-free markers. Observe modes
                // until the next numbered request without replacing open files.
                let current = (request, console::mode(&input)?, console::mode(&output)?);
                if observed.as_ref() != Some(&current) {
                    fs::write(
                        root.join("mode-response.json"),
                        serde_json::to_vec(&json!({
                            "request":current.0,"inputMode":current.1,"outputMode":current.2
                        }))
                        .map_err(io::Error::other)?,
                    )?;
                    observed = Some(current);
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let after = (console::mode(&input)?, console::mode(&output)?);
        if handover {
            queue_helper(root, &input, "__inspect_queue")?;
        }
        fs::write(
            root.join("console-result.json"),
            serde_json::to_vec(&json!({
                "exitCode":status.code(),"inputBefore":before.0,"inputAfter":after.0,
                "outputBefore":before.1,"outputAfter":after.1
            }))
            .map_err(io::Error::other)?,
        )?;
        require(
            status.code() == Some(expected) && before == after,
            "CLI exit status or exact console restoration did not match",
        )?;
        Ok(0)
    }

    pub(super) fn run() -> io::Result<i32> {
        let executable = std::env::current_exe()?;
        let name = executable
            .file_stem()
            .and_then(|name| name.to_str())
            .ok_or_else(|| io::Error::other("invalid fixture name"))?;
        if matches!(name, "claude" | "codex" | "kimi" | "gents") {
            return agent(name);
        }
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        require(
            args.len() == 3 && (args[0] == "__fixture_host" || args[0] == "__handover_host"),
            "use tools/check_windows_dashboard_conpty.py to run this fixture",
        )?;
        host(
            Path::new(&args[1]),
            Path::new(&args[2]),
            args[0] == "__handover_host",
        )
    }
}
