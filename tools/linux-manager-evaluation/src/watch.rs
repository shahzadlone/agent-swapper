//! Bounded retirement measurement over the same connection and retained scope.
use crate::{Connection, UnitFact, kernel, owner, require};
use std::{io, time::Duration};

pub(crate) async fn retire(
    connection: &Connection,
    sender: &str,
    unit: &UnitFact,
    binding: &kernel::Binding,
) -> io::Result<kernel::Retirement> {
    tokio::time::timeout(Duration::from_secs(20), async {
        binding.require_manager(connection)?;
        loop {
            require(
                owner(connection).await?.as_str() == sender,
                "manager owner changed while observing retirement",
            )?;
            if let Some(retirement) = binding.retirement()?
                && agentswapper_linux_manager::invocation_retired(
                    connection,
                    sender,
                    &unit.unit,
                    &unit.invocation,
                )
                .await?
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
