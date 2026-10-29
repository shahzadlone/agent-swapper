//! Read-only, provider-free validation of a live system-manager snapshot.
#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::io::Read;
    let mut arguments = std::env::args().skip(1);
    let invalid = || std::io::Error::other("invalid manager probe arguments");
    let unit = arguments.next().ok_or_else(invalid)?;
    let user = arguments
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(invalid)?;
    let pid = arguments
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(invalid)?;
    let invocation = arguments.next();
    if arguments.next().is_some() {
        return Err(invalid());
    }
    let mut properties = Vec::new();
    std::io::stdin().take(4097).read_to_end(&mut properties)?;
    match invocation {
        Some(invocation) => {
            agentswapper_core::supervision::linux_manager::validate_bound_properties(
                &properties,
                &unit,
                user,
                pid,
                &invocation,
            )
        }
        None => agentswapper_core::supervision::linux_manager::validate_properties(
            &properties,
            &unit,
            user,
            pid,
        ),
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Linux manager probe requires Linux");
    std::process::exit(125);
}
