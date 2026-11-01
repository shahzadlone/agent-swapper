//! Authenticated invocation-retirement reads, separate from kernel custody.
use crate::linux::Manager;
use crate::linux::{MANAGER_PATH, UNIT_INTERFACE, checked_reply, property, require};
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
    lookup_result(
        connection
            .connection
            .call_method(
                Some(sender),
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
            if collection_race(&error, sender)?
                && lookup(connection, sender, &invocation).await?.is_none()
            {
                Ok(true)
            } else {
                Err(error)
            }
        }
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
