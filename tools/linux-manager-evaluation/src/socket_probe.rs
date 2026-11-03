//! Loaded-socket observations and fixed connection-race controls. No launch data.
use crate::{fixture_policy, manager};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use std::{
    io::{self, Read, Write},
    path::Path,
    time::Duration,
};

fn checkpoint() -> io::Result<()> {
    println!("socket: held");
    io::stdout().flush()?;
    let input = io::stdin();
    let mut ready = [PollFd::new(&input, PollFlags::IN)];
    crate::require(
        poll(
            &mut ready,
            Some(&Timespec {
                tv_sec: 20,
                tv_nsec: 0,
            }),
        )? == 1
            && ready[0].revents().contains(PollFlags::IN),
        "socket control did not release its owned checkpoint",
    )?;
    let mut byte = [0];
    input.lock().read_exact(&mut byte)?;
    crate::require(byte == *b"R", "unexpected socket checkpoint release")
}

pub(crate) fn run(prefix: &str, hold: bool) -> io::Result<()> {
    fixture_policy::gate(prefix)?;
    let selection = fixture_policy::selected_installation(prefix)?;
    let endpoint = format!("/run/{prefix}.sock");
    let policy = manager::SocketPolicy::for_qualification(&selection, Path::new(&endpoint))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let fact = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(if hold { 35 } else { 12 }), async {
            let (connection, sender, _) = manager::connect().await?;
            let observed =
                manager::LoadedSocket::observe(&connection, sender.as_str(), policy).await?;
            if hold {
                // The ordinary observer retains its original object while the
                // fixture controller may restart only its owned listening unit.
                checkpoint()?;
            }
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

pub(crate) fn connection_race(prefix: &str, phase: &str) -> io::Result<()> {
    fixture_policy::gate(prefix)?;
    crate::require(
        matches!(phase, "before" | "after"),
        "invalid endpoint race phase",
    )?;
    let selection = fixture_policy::selected_installation(prefix)?;
    let endpoint = format!("/run/{prefix}.sock");
    let policy = manager::SocketPolicy::for_qualification(&selection, Path::new(&endpoint))?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(12), async {
                let (connection, sender, _) = manager::connect().await?;
                let observed =
                    manager::LoadedSocket::observe(&connection, sender.as_str(), policy).await?;
                let result = observed
                    .connect_endpoint_with_checkpoints_for_qualification(
                        &connection,
                        || {
                            if phase == "before" {
                                checkpoint()
                            } else {
                                Ok(())
                            }
                        },
                        || {
                            if phase == "after" {
                                checkpoint()
                            } else {
                                Ok(())
                            }
                        },
                    )
                    .await;
                // Close without sending even a handshake, whether the control
                // refused correctly or a regression unexpectedly returned a socket.
            let result = result.map(drop);
                let _ = connection.close().await;
                result?;
                Err::<(), _>(io::Error::other("changed endpoint was accepted"))
            })
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "endpoint control deadline exceeded",
                )
            })?
        })
}
