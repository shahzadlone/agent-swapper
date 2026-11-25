//! The session-helper binary: the outer owner's launch entry. Its fixed
//! modes map to the library; the Store-backed journal wires the launch
//! client's durable seam to the real Store. This binary never accepts a
//! provider command; the target program is the caller's explicit argument.
use std::process;

#[cfg(target_os = "linux")]
fn main() -> process::ExitCode {
    use agentswapper_core::domain::Harness;
    enum Mode {
        Launch(Harness, String, std::ffi::OsString, Vec<std::ffi::OsString>),
    }
    fn parse(args: &[String]) -> std::io::Result<(String, Mode)> {
        match args {
            [store_root, harness, alias, program, rest @ ..]
                if matches!(harness.as_str(), "claude" | "codex" | "kimi") =>
            {
                let harness = match harness.as_str() {
                    "claude" => Harness::Claude,
                    "codex" => Harness::Codex,
                    _ => Harness::Kimi,
                };
                Ok((
                    store_root.clone(),
                    Mode::Launch(
                        harness,
                        alias.clone(),
                        program.into(),
                        rest.iter().map(Into::into).collect(),
                    ),
                ))
            }
            _ => Err(std::io::Error::other(
                "expects launch STORE_ROOT HARNESS ALIAS PROGRAM [ARGS...]",
            )),
        }
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match parse(&args) {
        Ok((root, Mode::Launch(harness, alias, program, arguments))) => {
            let journal = agentswapper_linux_session_helper::store_journal::StoreJournal::open(
                std::path::Path::new(&root),
                harness,
                &alias,
            );
            match journal {
                Ok(journal) => {
                    let user = rustix::process::getuid().as_raw();
                    let outcome = agentswapper_linux_install::client::launch(
                        user, &program, arguments, &journal,
                    );
                    // The run id exists only once the intent committed: a
                    // launch that failed before it has no durable run at all.
                    match outcome {
                        Ok(message) => Ok(match journal.run() {
                            Some(run) => format!("{message} (durable run {run})"),
                            None => format!("{message} (no durable run)"),
                        }),
                        Err(error) => Err(error),
                    }
                }
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    };
    match result {
        Ok(message) => {
            println!("{message}");
            process::ExitCode::SUCCESS
        }
        Err(error) => {
            let diagnostic: String = error
                .to_string()
                .escape_debug()
                .take(2000)
                .collect::<String>();
            eprintln!("session helper refused: {diagnostic}");
            println!(
                "::error title=session helper::{}",
                diagnostic
                    .replace('%', "%25")
                    .replace('\r', "%0D")
                    .replace('\n', "%0A")
            );
            process::ExitCode::from(125)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> process::ExitCode {
    process::ExitCode::SUCCESS
}
