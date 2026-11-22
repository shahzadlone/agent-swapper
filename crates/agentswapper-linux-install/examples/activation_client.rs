//! Ordinary-caller activation control: authenticate the endpoint, send the
//! production bind request, validate the guardian's offer against the kernel
//! sender, bind the original service with its one-use key, and disconnect
//! cleanly. It sends no launch data, transfers no descriptor and starts no
//! workload. The service retires when the guardian sees the clean disconnect.
use std::process;

#[cfg(target_os = "linux")]
mod linux {
    use agentswapper_linux_manager::{
        BoundService, LoadedSocket, ServiceClaim, ServicePolicy, SocketPolicy,
    };
    use agentswapper_linux_runtime::activation_offer::{BIND_REQUEST, Offer, connection_unit};
    use agentswapper_linux_runtime::activation_packet;
    use agentswapper_linux_runtime::installed_selection::SelectedInstallation;
    use rustix::net::{self, SendFlags};
    use std::{io, time::Duration, time::Instant};

    fn require(ok: bool, message: &str) -> io::Result<()> {
        if ok {
            Ok(())
        } else {
            Err(io::Error::other(message))
        }
    }

    pub fn run(user: u32) -> io::Result<String> {
        let group = rustix::process::getgid().as_raw();
        let selection = SelectedInstallation::open()?;
        let generation = selection.artifacts().manifest().generation().to_owned();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(io::Error::other)?;
        runtime.block_on(async {
            let (manager, owner, _) = agentswapper_linux_manager::connect().await?;
            // The policy borrows the selection; the connection is
            // authenticated and the endpoint connected before the original
            // service binding takes over.
            let socket = {
                let policy = SocketPolicy::installed(&selection)?;
                let observed = LoadedSocket::observe(&manager, owner.as_str(), policy).await?;
                observed.connect_endpoint(&manager).await?
            };
            require(
                net::send(
                    &socket,
                    BIND_REQUEST,
                    SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
                )? == BIND_REQUEST.len(),
                "incomplete activation request",
            )?;
            let (bytes, sender) =
                activation_packet::receive(&socket, Instant::now() + Duration::from_secs(4))?;
            let offer: Offer = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            offer.client_validate(user, group, std::process::id(), sender)?;
            let expected_shape = connection_unit(user, &generation, 1, std::process::id());
            let (expected_stem, _) = expected_shape
                .split_once('@')
                .ok_or_else(|| io::Error::other("invalid connection unit shape"))?;
            if !offer.unit.starts_with(&format!("{expected_stem}@")) {
                return Err(io::Error::other(
                    "activation offer names another installation",
                ));
            }
            // The authenticated connection binds the original service before
            // any launch data could ever flow; the key is claimed once.
            let policy = ServicePolicy::installed(selection)?;
            let mut bound = BoundService::bind(
                &manager,
                owner.as_str(),
                policy,
                ServiceClaim {
                    unit: &offer.unit,
                    invocation: &offer.invocation,
                    main_pid: offer.pid,
                },
            )
            .await?;
            let key = bound.claim_key()?;
            drop(key);
            let closed = manager.close().await.map_err(io::Error::other);
            // Dropping the socket is the clean disconnect the guardian waits
            // for; the manager then retires the activated instance.
            drop(socket);
            closed?;
            Ok(format!("activation offer bound {}", offer.unit))
        })
    }
}

#[cfg(target_os = "linux")]
fn main() -> process::ExitCode {
    fn parse(args: &[String]) -> std::io::Result<u32> {
        match args {
            [user] => user
                .parse()
                .map_err(|_| std::io::Error::other("invalid user")),
            _ => Err(std::io::Error::other("bind expects USER")),
        }
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = parse(&args).and_then(linux::run);
    match result {
        Ok(message) => {
            println!("{message}");
            process::ExitCode::SUCCESS
        }
        Err(error) => {
            let diagnostic: String = error
                .to_string()
                .escape_debug()
                .take(2000)
                .collect::<String>();
            eprintln!("activation control refused: {diagnostic}");
            println!(
                "::error title=activation control::{}",
                diagnostic
                    .replace('%', "%25")
                    .replace('\r', "%0D")
                    .replace('\n', "%0A")
            );
            process::ExitCode::from(125)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> process::ExitCode {
    process::ExitCode::SUCCESS
}
