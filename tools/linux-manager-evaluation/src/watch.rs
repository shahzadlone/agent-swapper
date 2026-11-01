//! Bounded retirement measurement over the same connection and retained scope.
use crate::{
    Connection, MANAGER_PATH, Message, OwnedObjectPath, UNIT_INTERFACE, UnitFact, checked_reply,
    kernel, owner, property, require,
};
use std::{io, time::Duration};

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
    connection: &Connection,
    sender: &str,
    invocation: &[u8],
) -> io::Result<Option<OwnedObjectPath>> {
    lookup_result(
        connection
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

async fn manager_retired(
    connection: &Connection,
    sender: &str,
    unit: &UnitFact,
) -> io::Result<bool> {
    let invocation = (0..32)
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&unit.invocation[index..index + 2], 16).map_err(io::Error::other)
        })
        .collect::<io::Result<Vec<_>>>()?;
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
            id == unit.unit && first == invocation && last == invocation,
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

pub(crate) async fn retire(
    connection: &Connection,
    sender: &str,
    unit: &UnitFact,
    binding: &kernel::Binding,
) -> io::Result<kernel::Retirement> {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            require(
                owner(connection).await?.as_str() == sender,
                "manager owner changed while observing retirement",
            )?;
            if let Some(retirement) = binding.retirement()?
                && manager_retired(connection, sender, unit).await?
            {
                require(
                    owner(connection).await?.as_str() == sender,
                    "manager owner changed at retirement",
                )?;
                return Ok(retirement);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "retirement observation deadline exceeded",
        )
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

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
