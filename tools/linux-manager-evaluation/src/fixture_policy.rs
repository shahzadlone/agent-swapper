//! Opt-in fixture names, environment and protected-template checks.
use crate::require;
use std::{io, path::Path};

pub(crate) fn valid_prefix(prefix: &str) -> bool {
    let Some(rest) = prefix.strip_prefix("aswp-activation-") else {
        return false;
    };
    let Some((run, attempt)) = rest.split_once('-') else {
        return false;
    };
    !run.is_empty()
        && run.len() <= 24
        && !attempt.is_empty()
        && attempt.len() <= 8
        && run
            .bytes()
            .chain(attempt.bytes())
            .all(|b| b.is_ascii_digit())
}

pub(crate) fn qualified_request(prefix: &str, values: &[Option<String>; 5]) -> bool {
    valid_prefix(prefix)
        && values[0].as_deref() == Some("true")
        && values[1].as_deref() == Some("github-hosted")
        && values[2].as_deref() == Some("1")
        && values[3]
            .as_ref()
            .zip(values[4].as_ref())
            .is_some_and(|(run, attempt)| prefix == format!("aswp-activation-{run}-{attempt}"))
}

pub(crate) fn gate(prefix: &str) -> io::Result<()> {
    let values = [
        "GITHUB_ACTIONS",
        "RUNNER_ENVIRONMENT",
        "ASWP_CI_SOCKET_ACTIVATION",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
    ]
    .map(|key| std::env::var(key).ok());
    require(
        qualified_request(prefix, &values),
        "activation probe requires its opted-in disposable hosted CI fixture",
    )
}

pub(crate) fn valid_instance(unit: &str, prefix: &str) -> bool {
    unit.len() <= 255
        && unit
            .strip_prefix(&format!("{prefix}@"))
            .and_then(|rest| rest.strip_suffix(".service"))
            .is_some_and(|instance| {
                !instance.is_empty()
                    && instance
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.:\\-".contains(&b))
            })
}

// systemd's AF_UNIX Accept=yes instance includes the client credentials:
// <connection counter>-<client PID>-<client UID>. Unknown credentials refuse.
pub(crate) fn connection_instance(unit: &str, prefix: &str, pid: u32, uid: u32) -> bool {
    valid_instance(unit, prefix)
        && unit
            .strip_prefix(&format!("{prefix}@"))
            .and_then(|instance| instance.strip_suffix(&format!("-{pid}-{uid}.service")))
            .is_some_and(|counter| {
                counter
                    .parse::<u32>()
                    .is_ok_and(|value| counter == value.to_string())
            })
}

pub(crate) fn valid_scope_unit(unit: &str) -> bool {
    unit.split_once('@')
        .is_some_and(|(prefix, _)| valid_prefix(prefix) && valid_instance(unit, prefix))
}

#[allow(dead_code, reason = "only clients construct the shared binding policy")]
pub(crate) fn activated_policy(
    prefix: &str,
) -> io::Result<agentswapper_linux_manager::ServicePolicy> {
    gate(prefix)?;
    agentswapper_linux_manager::ServicePolicy::open(
        Path::new(&format!("/run/systemd/system/{prefix}@.service")),
        Path::new(&format!("/usr/lib/{prefix}.guardian")),
        agentswapper_linux_runtime::process_policy::OrdinaryCredentials::new(
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
            &rustix::process::getgroups()?
                .iter()
                .map(|id| id.as_raw())
                .collect::<Vec<_>>(),
        )?,
    )
}
