//! Bounded system-manager service control. Unit names are derived from the
//! installation identity and re-validated against a strict pattern before
//! they enter a command argument; no other caller data reaches a command.
use std::{
    io::{self, Read},
    process::{Command, Stdio},
    time::Duration,
};
use wait_timeout::ChildExt;

const BOUND: Duration = Duration::from_secs(20);
const OUTPUT_LIMIT: usize = 64 * 1024;

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

fn valid_unit(unit: &str) -> bool {
    let Some(stem) = unit
        .strip_suffix(".socket")
        .or_else(|| unit.strip_suffix("@.service"))
    else {
        return false;
    };
    let mut parts = stem.split('-');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("agentswapper"), Some(user), Some(generation), None) => {
            valid_user(user) && valid_generation(generation)
        }
        _ => false,
    }
}

fn valid_user(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 10
        && user.bytes().all(|byte| byte.is_ascii_digit())
        && user != "0"
}

fn valid_generation(generation: &str) -> bool {
    generation.len() == 32
        && generation
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Service control used by the installer. Implementations must refuse
/// unexpected outcomes and never retry a partially applied change.
pub trait Control {
    fn reload(&self) -> io::Result<()>;
    fn enable_now(&self, unit: &str) -> io::Result<()>;
    fn disable_now(&self, unit: &str) -> io::Result<()>;
}

/// The real system manager over `/usr/bin/systemctl`.
pub struct Systemd;

impl Control for Systemd {
    fn reload(&self) -> io::Result<()> {
        run(&["daemon-reload"])
    }
    fn enable_now(&self, unit: &str) -> io::Result<()> {
        run(&["enable", "--now", unit])
    }
    fn disable_now(&self, unit: &str) -> io::Result<()> {
        run(&["disable", "--now", unit])
    }
}

fn run(arguments: &[&str]) -> io::Result<()> {
    for argument in arguments {
        require(
            *argument == "daemon-reload"
                || *argument == "enable"
                || *argument == "disable"
                || *argument == "--now"
                || valid_unit(argument),
            "refusing an unexpected service-control argument",
        )?;
    }
    let mut child = Command::new("/usr/bin/systemctl")
        .arg("--system")
        .arg("--no-pager")
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let outcome = child
        .wait_timeout(BOUND)
        .map_err(|error| io::Error::other(format!("service control wait failed: {error}")))?;
    let outcome = match outcome {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "service control deadline exceeded",
            ));
        }
    };
    let mut output = Vec::new();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let mut streams: [Option<Box<dyn Read>>; 2] = [
        stdout.map(|stream| Box::new(stream) as Box<dyn Read>),
        stderr.map(|stream| Box::new(stream) as Box<dyn Read>),
    ];
    for stream in streams.iter_mut().flatten() {
        let _ = stream
            .by_ref()
            .take((OUTPUT_LIMIT + 1) as u64)
            .read_to_end(&mut output);
    }
    require(
        output.len() <= OUTPUT_LIMIT,
        "service control diagnostic exceeds bounds",
    )?;
    let diagnostic: String = String::from_utf8_lossy(&output)
        .escape_debug()
        .take(1500)
        .collect();
    require(
        outcome.success(),
        format!("service control refused: {diagnostic}").as_str(),
    )
}

/// True when the manager reports the unit loaded, active and listening.
pub fn listening(unit: &str) -> io::Result<bool> {
    require(valid_unit(unit), "refusing an unexpected unit name")?;
    let mut child = Command::new("/usr/bin/systemctl")
        .arg("--system")
        .arg("--no-pager")
        .args(["is-active", unit])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let outcome = child
        .wait_timeout(BOUND)
        .map_err(|error| io::Error::other(format!("service control wait failed: {error}")))?;
    let status = match outcome {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "service control deadline exceeded",
            ));
        }
    };
    let mut output = Vec::new();
    if let Some(mut stream) = child.stdout.take() {
        let _ = stream
            .by_ref()
            .take((OUTPUT_LIMIT + 1) as u64)
            .read_to_end(&mut output);
    }
    require(
        output.len() <= OUTPUT_LIMIT,
        "service control diagnostic exceeds bounds",
    )?;
    Ok(status.success() && output.starts_with(b"active"))
}

#[allow(
    dead_code,
    reason = "generation validation is shared with future executor arguments"
)]
pub(crate) fn require_valid_unit(unit: &str) -> io::Result<()> {
    require(valid_unit(unit), "invalid installation unit name")
}

#[allow(
    dead_code,
    reason = "generation validation is shared with future executor arguments"
)]
pub(crate) fn require_valid_generation(generation: &str) -> io::Result<()> {
    require(
        valid_generation(generation),
        "invalid installation generation",
    )
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn only_derived_installation_names_reach_service_control() {
        assert!(valid_unit(
            "agentswapper-1000-00112233445566778899aabbccddeeff.socket"
        ));
        assert!(valid_unit(
            "agentswapper-1000-00112233445566778899aabbccddeeff@.service"
        ));
        for unit in [
            "agentswapper-0-00112233445566778899aabbccddeeff.socket",
            "agentswapper-1000-00112233445566778899aabbccddeeffX.socket",
            "agentswapper-1000.socket",
            "other.socket",
            "agentswapper-1000-00112233445566778899aabbccddeeff-extra.socket",
            "agentswapper--1000-00112233445566778899aabbccddeeff.socket",
            "../agentswapper.socket",
            "agentswapper-1000-00112233445566778899aabbccddeeff.socketextra",
        ] {
            assert!(!valid_unit(unit), "{unit}");
        }
        assert!(valid_generation("00112233445566778899aabbccddeeff"));
        assert!(!valid_generation("00112233445566778899aabbccddeef"));
        assert!(!valid_generation("00112233445566778899aabbccddeefff"));
    }
}
