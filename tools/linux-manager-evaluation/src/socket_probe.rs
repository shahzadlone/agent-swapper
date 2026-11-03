//! Read-only loaded-socket evidence. Never connects to the activation endpoint.
use crate::{fixture_policy, manager};
use std::{io, path::Path, time::Duration};

pub(crate) fn run(prefix: &str) -> io::Result<()> {
    fixture_policy::gate(prefix)?;
    let selection = fixture_policy::selected_installation(prefix)?;
    let endpoint = format!("/run/{prefix}.sock");
    let policy = manager::SocketPolicy::for_qualification(&selection, Path::new(&endpoint))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let fact = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(12), async {
            let (connection, sender, _) = manager::connect().await?;
            let observed =
                manager::LoadedSocket::observe(&connection, sender.as_str(), policy).await?;
            observed.recheck(&connection).await?;
            // A separate authenticated connection must not inherit this live
            // observation, even when the system manager has the same owner.
            let (other, _, _) = manager::connect().await?;
            let refused = observed.recheck(&other).await;
            other.close().await.map_err(io::Error::other)?;
            crate::require(
                refused.is_err_and(|error| {
                    error.to_string() == "socket observation belongs to another manager connection"
                }),
                "socket observation accepted another manager connection",
            )?;
            let fact = observed.fact();
            connection.close().await.map_err(io::Error::other)?;
            Ok::<_, io::Error>(fact)
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "socket probe deadline exceeded"))?
    })?;
    println!(
        "{}",
        serde_json::to_string(&fact).map_err(io::Error::other)?
    );
    Ok(())
}
