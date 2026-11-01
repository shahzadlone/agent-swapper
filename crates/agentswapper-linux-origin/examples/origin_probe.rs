#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    use agentswapper_linux_origin::{Backend, NamespaceFact, Origin};
    fn probe(backend: Option<Backend>) -> std::io::Result<(u32, u32, Backend, [NamespaceFact; 4])> {
        #[cfg(feature = "qualification")]
        let origin = match backend {
            Some(backend) => Origin::capture_for_qualification(backend),
            None => Origin::capture(),
        }?;
        #[cfg(not(feature = "qualification"))]
        let origin = {
            let _ = backend;
            Origin::capture()?
        };
        origin.require_current()?;
        Ok((
            origin.user(),
            origin.group(),
            origin.backend(),
            origin.facts(),
        ))
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    #[cfg(feature = "qualification")]
    let (mut backend, mut nonleader) = (None, false);
    #[cfg(not(feature = "qualification"))]
    let (backend, nonleader) = (None, false);
    #[cfg(feature = "qualification")]
    for argument in &args {
        match argument.as_str() {
            "pidfd" if backend.is_none() => backend = Some(Backend::Pidfd),
            "procfs" if backend.is_none() => backend = Some(Backend::Procfs),
            "thread" if !nonleader => nonleader = true,
            _ => return std::process::ExitCode::from(2),
        }
    }
    #[cfg(not(feature = "qualification"))]
    if !args.is_empty() {
        return std::process::ExitCode::from(2);
    }
    let result = if nonleader {
        std::thread::spawn(move || probe(backend))
            .join()
            .unwrap_or_else(|_| Err(std::io::Error::other("probe thread panicked")))
    } else {
        probe(backend)
    };
    match result {
        Ok((user, group, backend, facts)) => {
            println!(
                "origin: admitted user={user} group={group} backend={backend:?} namespaces={facts:?}"
            );
            std::process::ExitCode::SUCCESS
        }
        Err(error) if error.kind() == std::io::ErrorKind::Unsupported => {
            println!("origin: unsupported");
            std::process::ExitCode::from(77)
        }
        Err(error) => {
            eprintln!("origin: refused: {}", error.to_string().escape_debug());
            std::process::ExitCode::from(125)
        }
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    println!("origin: unsupported platform");
}
