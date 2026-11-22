//! Disposable CLI for the hosted activation and launch controls. All logic
//! lives in the library modules; this binary only parses its fixed modes.
use std::process;

#[cfg(target_os = "linux")]
fn main() -> process::ExitCode {
    enum Mode {
        Bind,
        Launch(
            std::ffi::OsString,
            Vec<std::ffi::OsString>,
            std::path::PathBuf,
        ),
    }
    fn parse(args: &[String]) -> std::io::Result<(u32, Mode)> {
        match args {
            [user, verb] if verb == "bind" => {
                let user: u32 = user
                    .parse()
                    .map_err(|_| std::io::Error::other("invalid user"))?;
                Ok((user, Mode::Bind))
            }
            [user, verb, journal, program, rest @ ..] if verb == "launch" => {
                let user: u32 = user
                    .parse()
                    .map_err(|_| std::io::Error::other("invalid user"))?;
                Ok((
                    user,
                    Mode::Launch(
                        program.into(),
                        rest.iter().map(Into::into).collect(),
                        journal.into(),
                    ),
                ))
            }
            _ => Err(std::io::Error::other(
                "expects bind USER | launch USER JOURNAL PROGRAM [ARGS...]",
            )),
        }
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match parse(&args) {
        Ok((user, Mode::Bind)) => agentswapper_linux_install::client::run(user),
        Ok((user, Mode::Launch(program, arguments, journal))) => {
            let journal = agentswapper_linux_install::launch_client::FileJournal::open(&journal);
            match journal {
                Ok(journal) => agentswapper_linux_install::launch_client::launch(
                    user, &program, arguments, &journal,
                ),
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
            eprintln!("activation control refused: {diagnostic}");
            println!(
                "::error title=activation control::{}",
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
