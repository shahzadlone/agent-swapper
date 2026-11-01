//! Expected ordinary process credentials, independently checked through procfs.
use std::{collections::BTreeSet, io};

/// Caller-authorized UID, primary GID and maximum supplementary group set.
/// Constructing this policy is not evidence that any process satisfies it.
pub struct OrdinaryCredentials {
    user: u32,
    group: u32,
    groups: BTreeSet<u32>,
}
impl OrdinaryCredentials {
    pub fn new(user: u32, group: u32, supplementary: &[u32]) -> io::Result<Self> {
        let ordinary = |id: u32| id != 0 && id <= i32::MAX as u32;
        if !ordinary(user)
            || !ordinary(group)
            || supplementary.len() > 4096
            || !supplementary.iter().copied().all(ordinary)
        {
            return Err(io::Error::other("invalid ordinary credential policy"));
        }
        let mut groups = supplementary.iter().copied().collect::<BTreeSet<_>>();
        groups.insert(group);
        Ok(Self {
            user,
            group,
            groups,
        })
    }
    pub fn user(&self) -> u32 {
        self.user
    }
    pub fn group(&self) -> u32 {
        self.group
    }

    pub(crate) fn require_status(&self, bytes: &[u8]) -> io::Result<()> {
        let status = std::str::from_utf8(bytes).map_err(io::Error::other)?;
        for (field, expected) in [("Uid:", self.user), ("Gid:", self.group)] {
            let values = field_value(status, field)?
                .split_whitespace()
                .collect::<Vec<_>>();
            if values.len() != 4 || values.iter().any(|value| *value != expected.to_string()) {
                return Err(io::Error::other(
                    "guardian user or group differs from admitted credentials",
                ));
            }
        }
        for group in field_value(status, "Groups:")?.split_whitespace() {
            let parsed = group.parse::<u32>().map_err(io::Error::other)?;
            if parsed.to_string() != group || !self.groups.contains(&parsed) {
                return Err(io::Error::other(
                    "guardian has an unauthorized supplementary group",
                ));
            }
        }
        for field in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
            let value = field_value(status, field)?.trim();
            if value.is_empty() || value.len() > 16 || !value.bytes().all(|byte| byte == b'0') {
                return Err(io::Error::other("guardian retains Linux capabilities"));
            }
        }
        if field_value(status, "NoNewPrivs:")?.trim() != "1" {
            return Err(io::Error::other("guardian lacks no-new-privileges"));
        }
        Ok(())
    }
}

fn field_value<'a>(status: &'a str, field: &str) -> io::Result<&'a str> {
    let mut matches = status.lines().filter_map(|line| line.strip_prefix(field));
    let value = matches
        .next()
        .ok_or_else(|| io::Error::other("guardian credential field is absent"))?;
    if matches.next().is_some() {
        return Err(io::Error::other("guardian credential field is ambiguous"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    const STATUS: &str = "Uid:\t1000 1000 1000 1000\nGid:\t1001 1001 1001 1001\nGroups:\t20 1001\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";
    #[test]
    fn ordinary_credentials_reject_privilege_and_group_expansion() -> io::Result<()> {
        let policy = OrdinaryCredentials::new(1000, 1001, &[20])?;
        policy.require_status(STATUS.as_bytes())?;
        policy.require_status(STATUS.replace("20 1001", "").as_bytes())?;
        for (good, bad) in [
            ("1000 1000 1000 1000", "1000 0 1000 1000"),
            ("1001 1001 1001 1001", "1001 1001 0 1001"),
            ("20 1001", "20 1001 27"),
            ("20 1001", "020 1001"),
            ("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
        ] {
            assert!(
                policy
                    .require_status(STATUS.replace(good, bad).as_bytes())
                    .is_err()
            );
        }
        for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
            let changed = STATUS.replace(
                &format!("{field}:\t0000000000000000"),
                &format!("{field}:\t0000000000000001"),
            );
            assert!(policy.require_status(changed.as_bytes()).is_err());
        }
        for line in STATUS.lines() {
            assert!(
                policy
                    .require_status(STATUS.replace(&format!("{line}\n"), "").as_bytes())
                    .is_err()
            );
            assert!(
                policy
                    .require_status(format!("{STATUS}{line}\n").as_bytes())
                    .is_err()
            );
        }
        for (user, group, groups) in [
            (0, 1001, vec![]),
            (1000, 0, vec![]),
            (1000, 1001, vec![0]),
            (1000, 1001, vec![20; 4097]),
        ] {
            assert!(OrdinaryCredentials::new(user, group, &groups).is_err());
        }
        Ok(())
    }
}
