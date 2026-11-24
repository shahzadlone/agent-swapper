//! Fresh-process regression for the launch client's signal init sequence.
//! The libtest harness itself is multithreaded, so this target runs without
//! one: `cargo test` starts the driver role directly, and the driver spawns
//! the fixture role - the same production claim - in a fresh single-threaded
//! process with the default signal state, exactly what every launch
//! receives. If the stop-signal blocking ever moves ahead of the signal
//! admission again, the fixture refuses and the driver fails the workspace.
//!
//! The claimed sequence is a Linux terminal-ownership contract, so the
//! sequence lives behind a platform gate; the target stays compilable on
//! every other platform with an honest no-op main.
#[cfg(target_os = "linux")]
mod linux {
    use agentswapper_linux_runtime::{job_control, signals};

    pub(super) fn main() {
        let fixture = std::ffi::OsStr::new("fixture");
        if std::env::args_os().nth(1).as_deref() == Some(fixture) {
            fixture_role();
            return;
        }
        let run = std::env::current_exe()
            .and_then(|exe| std::process::Command::new(exe).arg(fixture).output())
            .map_err(|error| std::io::Error::other(format!("spawn fixture role: {error}")));
        let output = match run {
            Ok(output) => output,
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        };
        let witness = match String::from_utf8(output.stdout) {
            Ok(witness) => witness,
            Err(error) => {
                eprintln!("witness text: {error}");
                std::process::exit(1);
            }
        };
        match output.status.success() {
            true if witness.trim_end() == "stop-proof-mask" => {}
            true => {
                eprintln!("the claimed mask witness was not reported: {witness:?}");
                std::process::exit(1);
            }
            false => {
                eprintln!(
                    "fresh-process init sequence failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                std::process::exit(1);
            }
        }
    }

    fn fixture_role() {
        let claim = signals::Signals::claim_with_terminal_stops().and_then(|owner| {
            let blocked = job_control::stop_signals_blocked()?;
            drop(owner);
            Ok(blocked)
        });
        match claim {
            Ok(true) => println!("stop-proof-mask"),
            Ok(false) => {
                eprintln!("claim admitted but the stop-proof mask is missing");
                std::process::exit(1);
            }
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    linux::main();
}
