//! Exercises the production selection entry point in hostile hosted namespaces.
//! No installation or provider is created by this example.
#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    use agentswapper_linux_runtime::installed_selection::SelectedInstallation;
    match SelectedInstallation::open() {
        Ok(_) => {
            eprintln!("installation origin unexpectedly admitted");
            std::process::ExitCode::from(1)
        }
        Err(error) => {
            eprintln!("origin: refused: {}", error.to_string().escape_debug());
            std::process::ExitCode::from(125)
        }
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("installation origin probe requires Linux");
}
