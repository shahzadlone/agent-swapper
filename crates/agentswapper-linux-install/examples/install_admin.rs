//! Fixed administrator entry for one disposable installation lifecycle.
//! Arguments are validated identity and generation values plus image paths;
//! no other caller data reaches a command or a manifest.
use std::process;

fn main() -> process::ExitCode {
    #[cfg(target_os = "linux")]
    {
        use agentswapper_linux_install::{control::Systemd, executor};
        use std::path::PathBuf;
        let args: Vec<String> = std::env::args().skip(1).collect();
        let result = match args.as_slice() {
            [verb, user, group, generation, images @ ..]
                if images.len() == 3 && verb == "install" =>
            {
                parse(user, group, generation)
                    .and_then(|(user, group)| {
                        let images: [PathBuf; 3] = images
                            .iter()
                            .map(PathBuf::from)
                            .collect::<Vec<_>>()
                            .try_into()
                            .map_err(|_| std::io::Error::other("three image paths are required"))?;
                        executor::install(
                            &Systemd,
                            images.each_ref().map(|path| path.as_path()),
                            user,
                            group,
                            generation,
                        )
                    })
                    .map(|layout| format!("installed {}", layout.unit_stem()))
            }
            [verb, user, group, generation] if verb == "remove" || verb == "deactivate" => {
                parse(user, group, generation)
                    .and_then(|(user, group)| {
                        if verb == "remove" {
                            executor::remove(&Systemd, user, group, generation)
                        } else {
                            executor::deactivate(&Systemd, user, group, generation)
                        }
                    })
                    .map(|_| format!("{verb} complete"))
            }
            _ => Err(std::io::Error::other(
                "install expects install USER GROUP GEN IMAGE IMAGE IMAGE | remove|deactivate USER GROUP GEN",
            )),
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
                eprintln!("installation entry refused: {diagnostic}");
                println!(
                    "::error title=installation entry::{}",
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
    {
        process::ExitCode::SUCCESS
    }
}

fn parse(user: &str, group: &str, _generation: &str) -> std::io::Result<(u32, u32)> {
    let user: u32 = user
        .parse()
        .map_err(|_| std::io::Error::other("invalid user"))?;
    let group: u32 = group
        .parse()
        .map_err(|_| std::io::Error::other("invalid group"))?;
    Ok((user, group))
}
