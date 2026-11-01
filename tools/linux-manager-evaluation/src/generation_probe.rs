//! Fixed hosted controls for selector changes around original service admission.
use crate::{activation, fixture_policy, journal_client::Bound, require};
use agentswapper_linux_manager::{BoundService, ServiceClaim};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    time::Duration,
};

fn checkpoint() -> io::Result<()> {
    println!("generation: held");
    io::stdout().flush()?;
    let input = io::stdin();
    let mut ready = [PollFd::new(&input, PollFlags::IN)];
    require(
        poll(
            &mut ready,
            Some(&Timespec {
                tv_sec: 5,
                tv_nsec: 0,
            }),
        )? == 1
            && ready[0].revents().contains(PollFlags::IN),
        "generation control did not release its owned checkpoint",
    )?;
    let mut byte = [0];
    input.lock().read_exact(&mut byte)?;
    require(byte == *b"R", "unexpected generation checkpoint release")
}

pub(crate) fn run(mode: &str, prefix: &str, directory: &Path) -> io::Result<()> {
    fixture_policy::gate(prefix)?;
    require(
        matches!(mode, "before-final-check" | "after-bind" | "image-change"),
        "invalid generation fixture mode",
    )?;
    let meta = fs::symlink_metadata(directory)?;
    require(
        directory.is_absolute()
            && meta.is_dir()
            && meta.mode() & 0o077 == 0
            && meta.uid() == rustix::process::getuid().as_raw()
            && meta.uid() != 0,
        "generation fixture directory is not private and ordinary-owned",
    )?;
    if mode == "after-bind" {
        let lease_path = directory.join("generation-after-bind.lease");
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lease_path)?;
        lease.try_lock().map_err(io::Error::other)?;
        let mut bound = Bound::connect(prefix)?;
        let key = bound.claim_service_key()?;
        checkpoint()?;
        // A selector switch after successful bind must preserve this original
        // policy through real preparation and its target-child corroboration.
        let prepared = bound
            .prepare(lease.as_fd(), &key)
            .map_err(|failure| failure.error)?;
        drop(lease);
        let retired = prepared
            .close()
            .retire()
            .map_err(|failure| failure.error)?
            .into_service();
        require(
            retired.matches(&key),
            "generation switch replaced the original binding",
        )?;
        fs::remove_file(lease_path)?;
    } else {
        crate::prerequisites()?;
        let (socket, _, offer, policy) = activation::connect(prefix, b"BIND\n")?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let (manager, sender, _) = agentswapper_linux_manager::connect().await?;
            let result: io::Result<()> = async {
                let claim = ServiceClaim {
                    unit: &offer.unit,
                    invocation: &offer.invocation,
                    main_pid: offer.pid,
                };
                if mode == "before-final-check" {
                    let result = tokio::time::timeout(
                        Duration::from_secs(10),
                        BoundService::bind_with_checkpoint_for_qualification(
                            &manager,
                            sender.as_str(),
                            policy,
                            claim,
                            checkpoint,
                        ),
                    )
                    .await
                    .map_err(|_| io::Error::other("generation binding control expired"))?;
                    let error = result.err().ok_or_else(|| {
                        io::Error::other("selector switch during admission was accepted")
                    })?;
                    require(
                        error.to_string()
                            == "installed configuration changed since admission began",
                        "selector switch refused at the wrong boundary",
                    )?;
                    drop(socket);
                } else {
                    let mut bound = tokio::time::timeout(
                        Duration::from_secs(10),
                        BoundService::bind(&manager, sender.as_str(), policy, claim),
                    )
                    .await
                    .map_err(|_| io::Error::other("generation binding control expired"))??;
                    let key = bound.claim_key()?;
                    checkpoint()?;
                    let error =
                        bound.recheck(&manager).await.err().ok_or_else(|| {
                            io::Error::other("changed original image was accepted")
                        })?;
                    require(
                        error.to_string() == "installed image changed since admission began",
                        "changed image refused at the wrong boundary",
                    )?;
                    drop(socket);
                    let retired = bound
                        .observe_retirement(
                            &manager,
                            tokio::time::Instant::now() + Duration::from_secs(20),
                        )
                        .await?;
                    require(
                        retired.matches(&key),
                        "changed image prevented original retirement",
                    )?;
                }
                Ok(())
            }
            .await;
            let closed = manager.close().await.map_err(io::Error::other);
            result?;
            closed
        })?;
    }
    println!("generation: {mode} passed");
    Ok(())
}
