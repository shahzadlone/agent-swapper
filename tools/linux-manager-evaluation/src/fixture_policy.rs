//! Opt-in fixture names, environment and protected-template checks.
use crate::require;
use std::{fs, io, os::unix::fs::MetadataExt};

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

pub(crate) fn protected_fragment(fragment: &str) -> io::Result<()> {
    for directory in ["/", "/run", "/run/systemd", "/run/systemd/system"] {
        let meta = fs::symlink_metadata(directory)?;
        require(
            meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
            "activation template ancestor is not protected",
        )?;
    }
    let meta = fs::symlink_metadata(fragment)?;
    require(
        meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
        "activation template is not root-owned and protected",
    )
}
