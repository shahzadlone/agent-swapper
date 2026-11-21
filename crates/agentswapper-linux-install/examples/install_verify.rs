//! Ordinary-caller verification entry. Prints the observed socket fact as
//! JSON diagnostics; it never connects to the endpoint or starts a guardian.
use agentswapper_linux_install::executor;
use std::{io, process};

fn parse(args: &[String]) -> io::Result<(u32, u32)> {
    match args {
        [user, group] => {
            let user: u32 = user.parse().map_err(|_| io::Error::other("invalid user"))?;
            let group: u32 = group
                .parse()
                .map_err(|_| io::Error::other("invalid group"))?;
            Ok((user, group))
        }
        _ => Err(io::Error::other("verify expects USER GROUP")),
    }
}

fn main() -> process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = parse(&args).and_then(|(user, group)| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(io::Error::other)?;
        runtime.block_on(executor::verify(user, group))
    });
    match result {
        Ok(fact) => {
            println!("{fact}");
            process::ExitCode::SUCCESS
        }
        Err(error) => {
            let diagnostic: String = error
                .to_string()
                .escape_debug()
                .take(2000)
                .collect::<String>();
            eprintln!("verification refused: {diagnostic}");
            println!(
                "::error title=installation verification::{}",
                diagnostic
                    .replace('%', "%25")
                    .replace('\r', "%0D")
                    .replace('\n', "%0A")
            );
            process::ExitCode::from(125)
        }
    }
}
