//! The guardian binary entry; all logic lives in the library for review.
use std::process;

fn main() -> process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match agentswapper_linux_guardian::entry(&args) {
        Ok(()) => process::ExitCode::SUCCESS,
        Err(error) => {
            let diagnostic: String = error
                .to_string()
                .escape_debug()
                .take(2000)
                .collect::<String>();
            eprintln!("guardian refused: {diagnostic}");
            println!(
                "::error title=guardian entry::{}",
                diagnostic
                    .replace('%', "%25")
                    .replace('\r', "%0D")
                    .replace('\n', "%0A")
            );
            process::ExitCode::from(125)
        }
    }
}
