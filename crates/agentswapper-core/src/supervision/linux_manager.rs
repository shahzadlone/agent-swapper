//! Structural manager identity binding. Manager authentication and launch
//! integration remain separate gates; accepted text is not a custody receipt.
use std::{collections::BTreeMap, io};
use uuid::Uuid;

const MAX_PROPERTIES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Invocation {
    unit: String,
    invocation: Uuid,
    user: u32,
    main_pid: u32,
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid managed invocation properties",
    )
}

impl Invocation {
    fn parse(properties: &[u8], unit: &str, user: u32, main_pid: u32) -> io::Result<Self> {
        if properties.len() > MAX_PROPERTIES
            || user == 0
            || main_pid == 0
            || main_pid > i32::MAX as u32
        {
            return Err(invalid());
        }
        let token = unit
            .strip_prefix("aswp-managed-")
            .and_then(|name| name.strip_suffix(".service"))
            .filter(|name| {
                !name.is_empty()
                    && name.len() <= 128
                    && name.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
            .ok_or_else(invalid)?;
        if token.starts_with('-') || token.ends_with('-') {
            return Err(invalid());
        }
        let properties = std::str::from_utf8(properties).map_err(|_| invalid())?;
        let mut fields = BTreeMap::new();
        for line in properties.lines() {
            let (name, value) = line.split_once('=').ok_or_else(invalid)?;
            if fields.insert(name, value).is_some() {
                return Err(invalid());
            }
        }
        let expected = [
            "ActiveState",
            "ControlGroup",
            "Id",
            "InvocationID",
            "MainPID",
            "Transient",
            "User",
        ];
        if fields.keys().copied().ne(expected) {
            return Err(invalid());
        }
        let field = |name| fields.get(name).copied().ok_or_else(invalid);
        if field("Id")? != unit
            || field("ControlGroup")? != format!("/system.slice/{unit}")
            || field("User")? != user.to_string()
            || field("MainPID")? != main_pid.to_string()
            || field("ActiveState")? != "active"
            || field("Transient")? != "yes"
        {
            return Err(invalid());
        }
        let encoded = field("InvocationID")?;
        if encoded.len() != 32
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid());
        }
        let invocation = Uuid::parse_str(encoded).map_err(|_| invalid())?;
        if invocation.is_nil() {
            return Err(invalid());
        }
        Ok(Self {
            unit: unit.to_owned(),
            invocation,
            user,
            main_pid,
        })
    }
}

/// Check one bounded snapshot against an expected unit, ordinary user and main
/// process. The caller must authenticate the source before trusting its claims.
/// This read-only probe does not establish exec, isolation or process custody.
#[doc(hidden)]
pub fn validate_properties(
    properties: &[u8],
    unit: &str,
    user: u32,
    main_pid: u32,
) -> io::Result<()> {
    Invocation::parse(properties, unit, user, main_pid).map(|_| ())
}

/// Validate another active snapshot against the original invocation. A unit
/// recreated under the same name must never inherit the previous authority.
#[doc(hidden)]
pub fn validate_bound_properties(
    properties: &[u8],
    unit: &str,
    user: u32,
    main_pid: u32,
    expected_invocation: &str,
) -> io::Result<()> {
    let current = Invocation::parse(properties, unit, user, main_pid)?;
    if current.invocation.simple().to_string() != expected_invocation {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNIT: &str = "aswp-managed-test.service";
    fn properties() -> String {
        format!(
            "Id={UNIT}\nControlGroup=/system.slice/{UNIT}\nMainPID=42\nInvocationID={}\nTransient=yes\nUser=1000\nActiveState=active\n",
            "a".repeat(32)
        )
    }

    #[test]
    fn snapshot_binds_every_identity_component_and_rejects_duplicate_fields() -> io::Result<()> {
        let good = properties();
        validate_properties(good.as_bytes(), UNIT, 1000, 42)?;
        for (before, after) in [
            ("MainPID=42", "MainPID=43"),
            ("MainPID=42", "MainPID=042"),
            ("User=1000", "User=0"),
            ("Transient=yes", "Transient=no"),
            ("ActiveState=active", "ActiveState=inactive"),
            ("ControlGroup=/system.slice/", "ControlGroup=/other/"),
            ("Id=aswp-managed-test.service", "Id=other.service"),
        ] {
            assert!(
                validate_properties(good.replace(before, after).as_bytes(), UNIT, 1000, 42)
                    .is_err()
            );
        }
        for suffix in ["MainPID=42\n", "Unknown=value\n", "\n", "Injected\n"] {
            assert!(
                validate_properties(format!("{good}{suffix}").as_bytes(), UNIT, 1000, 42).is_err()
            );
        }
        for invocation in [
            "0".repeat(32),
            "A".repeat(32),
            "z".repeat(32),
            "a".repeat(33),
        ] {
            assert!(
                validate_properties(
                    good.replace(&"a".repeat(32), &invocation).as_bytes(),
                    UNIT,
                    1000,
                    42
                )
                .is_err()
            );
        }
        assert!(validate_properties(&vec![b'x'; MAX_PROPERTIES + 1], UNIT, 1000, 42).is_err());
        assert!(validate_properties(&[0xff], UNIT, 1000, 42).is_err());
        assert!(validate_properties(good.as_bytes(), UNIT, 0, 42).is_err());
        assert!(validate_properties(good.as_bytes(), UNIT, 1000, 0).is_err());
        Ok(())
    }

    #[test]
    fn replacement_invocation_cannot_reuse_the_original_binding() -> io::Result<()> {
        let original = properties();
        let identity = "a".repeat(32);
        validate_bound_properties(original.as_bytes(), UNIT, 1000, 42, &identity)?;
        let replacement = original.replace(&identity, &"b".repeat(32));
        assert!(
            validate_bound_properties(replacement.as_bytes(), UNIT, 1000, 42, &identity).is_err()
        );
        for invalid in [
            "".to_owned(),
            "0".repeat(32),
            "A".repeat(32),
            "a".repeat(33),
        ] {
            assert!(
                validate_bound_properties(original.as_bytes(), UNIT, 1000, 42, &invalid).is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn unsafe_unit_names_and_other_invocations_cannot_match() {
        for unit in [
            "other.service",
            "aswp-managed-../x.service",
            "aswp-managed--x.service",
            "aswp-managed-x-.service",
            "aswp-managed-.service",
            "aswp-managed-x\n.service",
        ] {
            assert!(validate_properties(properties().as_bytes(), unit, 1000, 42).is_err());
        }
        assert!(
            validate_properties(
                properties().as_bytes(),
                "aswp-managed-other.service",
                1000,
                42
            )
            .is_err()
        );
    }
}
