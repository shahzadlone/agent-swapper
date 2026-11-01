//! Authenticated invocation-retirement reads, separate from kernel custody.
use crate::linux::Manager;
use crate::linux::{
    MANAGER_PATH, SERVICE_INTERFACE, UNIT_INTERFACE, checked_reply, destination, property, require,
};
use std::io;
use zbus::{Message, OwnedObjectPath};

fn decode_invocation(value: &str) -> io::Result<Vec<u8>> {
    require(
        value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid retirement invocation",
    )?;
    let bytes = (0..32)
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).map_err(io::Error::other))
        .collect::<io::Result<Vec<_>>>()?;
    require(
        bytes.iter().any(|byte| *byte != 0),
        "zero retirement invocation",
    )?;
    Ok(bytes)
}

const ABSENT: &str = "org.freedesktop.systemd1.NoUnitForInvocationID";

fn active_identity(unit: &str, invocation: &str, pid: u32) -> io::Result<Vec<u8>> {
    require(
        !unit.is_empty()
            && unit.len() <= 255
            && unit.ends_with(".service")
            && !unit.bytes().any(|b| b == b'/' || b.is_ascii_control())
            && pid > 1
            && pid <= i32::MAX as u32,
        "invalid active invocation identity",
    )?;
    decode_invocation(invocation)
}

struct ActiveValues {
    id: String,
    first: Vec<u8>,
    main_pid: u32,
    active: String,
    last: Vec<u8>,
}
impl ActiveValues {
    fn require(&self, unit: &str, invocation: &[u8], pid: u32) -> io::Result<()> {
        require(
            self.id == unit
                && self.first == invocation
                && self.last == invocation
                && self.main_pid == pid
                && self.active == "active",
            "bound guardian invocation changed",
        )
    }
}

/// Recheck the exact active invocation through its invocation-specific path.
/// This never queries a reusable unit-name object. The caller must supply its
/// previously admitted identity, bound the whole operation and check current
/// manager ownership around separate kernel observations. Success proves no
/// installation policy, original-process custody or target execution.
pub async fn require_active(
    connection: &Manager,
    sender: &str,
    unit: &str,
    invocation: &str,
    pid: u32,
) -> io::Result<()> {
    connection.require_sender(sender)?;
    let expected = active_identity(unit, invocation, pid)?;
    let path = lookup(connection, sender, &expected)
        .await?
        .ok_or_else(|| io::Error::other("bound guardian invocation is absent"))?;
    let id = String::try_from(property(connection, sender, &path, UNIT_INTERFACE, "Id").await?)
        .map_err(io::Error::other)?;
    let first = Vec::<u8>::try_from(
        property(connection, sender, &path, UNIT_INTERFACE, "InvocationID").await?,
    )
    .map_err(io::Error::other)?;
    let main_pid =
        u32::try_from(property(connection, sender, &path, SERVICE_INTERFACE, "MainPID").await?)
            .map_err(io::Error::other)?;
    let active =
        String::try_from(property(connection, sender, &path, UNIT_INTERFACE, "ActiveState").await?)
            .map_err(io::Error::other)?;
    let last = Vec::<u8>::try_from(
        property(connection, sender, &path, UNIT_INTERFACE, "InvocationID").await?,
    )
    .map_err(io::Error::other)?;
    ActiveValues {
        id,
        first,
        main_pid,
        active,
        last,
    }
    .require(unit, &expected, pid)
}

fn lookup_result(
    result: zbus::Result<Message>,
    sender: &str,
) -> io::Result<Option<OwnedObjectPath>> {
    match result {
        Ok(reply) => checked_reply(reply, sender)?
            .body()
            .deserialize()
            .map(Some)
            .map_err(io::Error::other),
        Err(zbus::Error::MethodError(name, _, reply)) if name.as_str() == ABSENT => {
            // An unauthenticated error is not evidence of absence.
            checked_reply(reply, sender)?;
            Ok(None)
        }
        Err(error) => Err(io::Error::other(error)),
    }
}

async fn lookup(
    connection: &Manager,
    sender: &str,
    invocation: &[u8],
) -> io::Result<Option<OwnedObjectPath>> {
    connection.require_sender(sender)?;
    lookup_result(
        connection
            .connection
            .call_method(
                Some(destination(sender)?),
                MANAGER_PATH,
                Some("org.freedesktop.systemd1.Manager"),
                "GetUnitByInvocationID",
                &(invocation,),
            )
            .await,
        sender,
    )
}

/// Observe only the manager half of retirement. The handle retains its original
/// authenticated unique owner; callers must bound the enclosing operation. A true result is
/// not original-scope removal, target exit, or authority to finish a Store run.
pub async fn retired(
    connection: &Manager,
    sender: &str,
    unit: &str,
    invocation: &str,
) -> io::Result<bool> {
    connection.require_sender(sender)?;
    require(
        !unit.is_empty() && unit.len() <= 255,
        "retirement unit exceeds query bounds",
    )?;
    let invocation = decode_invocation(invocation)?;
    let Some(path) = lookup(connection, sender, &invocation).await? else {
        return Ok(true);
    };
    let observed = async {
        let id = String::try_from(property(connection, sender, &path, UNIT_INTERFACE, "Id").await?)
            .map_err(io::Error::other)?;
        let first = Vec::<u8>::try_from(
            property(connection, sender, &path, UNIT_INTERFACE, "InvocationID").await?,
        )
        .map_err(io::Error::other)?;
        let state = String::try_from(
            property(connection, sender, &path, UNIT_INTERFACE, "ActiveState").await?,
        )
        .map_err(io::Error::other)?;
        let last = Vec::<u8>::try_from(
            property(connection, sender, &path, UNIT_INTERFACE, "InvocationID").await?,
        )
        .map_err(io::Error::other)?;
        require(
            id == unit && first == invocation && last == invocation,
            "retirement manager identity changed",
        )?;
        Ok(matches!(state.as_str(), "inactive" | "failed"))
    }
    .await;
    match observed {
        Ok(retired) => Ok(retired),
        Err(error) => {
            // A unit may be collected between lookup and property reads. Only
            // a fresh, authenticated absence for this invocation can resolve
            // that race; the original property error supplies no authority.
            resolve_race(error, sender, || lookup(connection, sender, &invocation)).await
        }
    }
}

async fn resolve_race<F, Fut>(error: io::Error, sender: &str, recheck: F) -> io::Result<bool>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = io::Result<Option<OwnedObjectPath>>>,
{
    if !collection_race(&error, sender)? {
        return Err(error);
    }
    match recheck().await? {
        None => Ok(true),
        Some(_) => Err(error),
    }
}

fn collection_race(error: &io::Error, sender: &str) -> io::Result<bool> {
    match error
        .get_ref()
        .and_then(|source| source.downcast_ref::<zbus::Error>())
    {
        Some(zbus::Error::MethodError(name, _, reply))
            if matches!(
                name.as_str(),
                "org.freedesktop.DBus.Error.UnknownObject"
                    | "org.freedesktop.systemd1.NoSuchUnit"
                    | "org.freedesktop.systemd1.NoUnitForInvocationID"
            ) =>
        {
            checked_reply(reply.clone(), sender)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_queries_validate_identity_before_contacting_the_manager() -> io::Result<()> {
        let invocation = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            active_identity("aswp@test.service", invocation, 42)?.len(),
            16
        );
        for unit in ["", "x.socket", "../x.service", "x\n.service", "x\0.service"] {
            assert!(active_identity(unit, invocation, 42).is_err());
        }
        assert!(active_identity(&format!("{}.service", "x".repeat(256)), invocation, 42).is_err());
        for pid in [0, 1, i32::MAX as u32 + 1, u32::MAX] {
            assert!(active_identity("x.service", invocation, pid).is_err());
        }
        for invalid in [
            "",
            "00000000000000000000000000000000",
            "g123456789abcdef0123456789abcdef",
        ] {
            assert!(active_identity("x.service", invalid, 42).is_err());
        }
        Ok(())
    }

    #[test]
    fn active_observation_requires_every_original_identity_component() -> io::Result<()> {
        let unit = "aswp@test.service";
        let invocation = vec![7; 16];
        let good = || ActiveValues {
            id: unit.into(),
            first: invocation.clone(),
            main_pid: 42,
            active: "active".into(),
            last: invocation.clone(),
        };
        good().require(unit, &invocation, 42)?;
        for mutation in 0..6 {
            let mut seen = good();
            match mutation {
                0 => seen.id = "other.service".into(),
                1 => seen.first[0] ^= 1,
                2 => seen.main_pid += 1,
                3 => seen.active = "inactive".into(),
                4 => seen.last[0] ^= 1,
                _ => {
                    seen.first[0] ^= 1;
                    seen.last = seen.first.clone();
                }
            }
            assert!(seen.require(unit, &invocation, 42).is_err());
        }
        Ok(())
    }

    #[test]
    fn collection_race_requires_fresh_absence_and_never_rechecks_other_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = Message::method_call(MANAGER_PATH, "Get").build(&())?;
        let original = || -> Result<io::Error, Box<dyn std::error::Error>> {
            let name = "org.freedesktop.DBus.Error.UnknownObject";
            let reply = Message::error(&request.header(), name)
                .sender(":1.42")
                .build(&"collected")?;
            Ok(io::Error::other(zbus::Error::MethodError(
                name.to_owned().try_into()?,
                None,
                reply,
            )))
        };
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        assert!(runtime.block_on(resolve_race(original()?, ":1.42", || async { Ok(None) }))?);
        let still_present = runtime
            .block_on(resolve_race(original()?, ":1.42", || async {
                Ok(Some(
                    OwnedObjectPath::try_from("/still_present").map_err(io::Error::other)?,
                ))
            }))
            .err()
            .ok_or_else(|| io::Error::other("continued presence cannot retire an invocation"))?;
        assert!(
            still_present
                .get_ref()
                .is_some_and(|error| error.is::<zbus::Error>())
        );
        let failed = runtime
            .block_on(resolve_race(original()?, ":1.42", || async {
                Err(io::Error::new(io::ErrorKind::TimedOut, "recheck expired"))
            }))
            .err()
            .ok_or_else(|| io::Error::other("failed recheck cannot retire an invocation"))?;
        assert_eq!(failed.kind(), io::ErrorKind::TimedOut);
        assert_eq!(failed.to_string(), "recheck expired");
        let called = std::cell::Cell::new(false);
        let denied = runtime
            .block_on(resolve_race(
                io::Error::new(io::ErrorKind::PermissionDenied, "original refusal"),
                ":1.42",
                || {
                    called.set(true);
                    async { Ok(None) }
                },
            ))
            .err()
            .ok_or_else(|| io::Error::other("non-race errors must retain their refusal"))?;
        assert!(!called.get());
        assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(denied.to_string(), "original refusal");
        let wrong_owner = runtime.block_on(resolve_race(original()?, ":1.43", || {
            called.set(true);
            async { Ok(None) }
        }));
        assert!(wrong_owner.is_err());
        assert!(!called.get());
        Ok(())
    }

    #[test]
    fn retirement_invocations_are_bounded_before_decoding() -> io::Result<()> {
        assert_eq!(
            decode_invocation("0123456789abcdef0123456789ABCDEF")?,
            [
                1, 35, 69, 103, 137, 171, 205, 239, 1, 35, 69, 103, 137, 171, 205, 239
            ]
        );
        for value in [
            "",
            "1",
            "00000000000000000000000000000000",
            "g123456789abcdef0123456789abcdef",
            "é123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef00",
        ] {
            assert!(decode_invocation(value).is_err());
        }
        Ok(())
    }

    #[test]
    fn collected_invocation_property_error_only_allows_an_authenticated_recheck()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = Message::method_call(
            "/org/freedesktop/systemd1/unit/0123456789abcdef0123456789abcdef",
            "Get",
        )
        .build(&(UNIT_INTERFACE, "ActiveState"))?;
        let error = |sender: &str, name: &str| -> Result<io::Error, Box<dyn std::error::Error>> {
            let reply = Message::error(&request.header(), name)
                .sender(sender)
                .build(&"collected")?;
            Ok(io::Error::other(zbus::Error::MethodError(
                name.to_owned().try_into()?,
                None,
                reply,
            )))
        };
        for name in [
            ABSENT,
            "org.freedesktop.DBus.Error.UnknownObject",
            "org.freedesktop.systemd1.NoSuchUnit",
        ] {
            assert!(collection_race(&error(":1.42", name)?, ":1.42")?);
            assert!(collection_race(&error(":1.43", name)?, ":1.42").is_err());
        }
        assert!(!collection_race(
            &error(":1.42", "org.freedesktop.DBus.Error.AccessDenied")?,
            ":1.42"
        )?);
        assert!(!collection_race(
            &io::Error::new(io::ErrorKind::TimedOut, "stalled"),
            ":1.42"
        )?);
        Ok(())
    }

    #[test]
    fn absence_requires_an_authenticated_error_for_the_exact_operation()
    -> Result<(), Box<dyn std::error::Error>> {
        let request =
            Message::method_call(MANAGER_PATH, "GetUnitByInvocationID").build(&[1_u8; 16])?;
        let reply = |sender: &str, name: &str| {
            Message::error(&request.header(), name)
                .sender(sender)
                .build(&"missing")
        };
        let error = |sender: &str, name: &str| -> Result<zbus::Error, Box<dyn std::error::Error>> {
            Ok(zbus::Error::MethodError(
                name.to_owned().try_into()?,
                Some("missing".into()),
                reply(sender, name)?,
            ))
        };
        assert!(lookup_result(Err(error(":1.42", ABSENT)?), ":1.42")?.is_none());
        assert!(lookup_result(Err(error(":1.43", ABSENT)?), ":1.42").is_err());
        assert!(
            lookup_result(
                Err(error(":1.42", "org.freedesktop.DBus.Error.AccessDenied")?),
                ":1.42"
            )
            .is_err()
        );
        assert!(
            lookup_result(
                Err(error(":1.42", "org.freedesktop.DBus.Error.ServiceUnknown")?),
                ":1.42"
            )
            .is_err()
        );
        Ok(())
    }
}
