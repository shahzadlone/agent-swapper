//! Ordinary-caller activation and launch control. The bind mode
//! authenticates the endpoint, sends the bind request, validates the
//! guardian's offer against the kernel sender, binds the original service
//! with its one-use key, and disconnects cleanly. The launch mode adds the
//! zeroizing launch envelope, the run nonce, the held-exec handshake and the
//! authenticated exit report. No provider command is ever accepted here; the
//! target program is the caller's explicit disposable argument.
use std::process;

#[cfg(target_os = "linux")]
mod linux {
    use agentswapper_linux_manager::{
        BoundService, LoadedSocket, ServiceClaim, ServicePolicy, SocketPolicy,
    };
    use agentswapper_linux_runtime::activation_offer::{Offer, RUN_REQUEST, connection_unit};
    use agentswapper_linux_runtime::activation_packet;
    use agentswapper_linux_runtime::installed_selection::SelectedInstallation;
    use agentswapper_linux_runtime::launch_envelope::LaunchEnvelope;
    use agentswapper_linux_runtime::launch_protocol;
    use rustix::net::{self, SendFlags};
    use std::{
        io,
        io::Read,
        time::{Duration, Instant},
    };

    fn require(ok: bool, message: &str) -> io::Result<()> {
        if ok {
            Ok(())
        } else {
            Err(io::Error::other(message))
        }
    }

    fn nonce() -> io::Result<[u8; 16]> {
        let mut nonce = [0_u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        require(nonce.iter().any(|byte| *byte != 0), "degenerate run nonce")?;
        Ok(nonce)
    }

    struct Endpoint {
        manager: agentswapper_linux_manager::Manager,
        owner: String,
        socket: rustix::fd::OwnedFd,
        generation: String,
    }

    async fn connect_endpoint(selection: &SelectedInstallation) -> io::Result<Endpoint> {
        let generation = selection.artifacts().manifest().generation().to_owned();
        let (manager, owner, _) = agentswapper_linux_manager::connect().await?;
        let socket = {
            let policy = SocketPolicy::installed(selection)?;
            let observed = LoadedSocket::observe(&manager, owner.as_str(), policy).await?;
            observed.connect_endpoint(&manager).await?
        };
        // The guardian's offer carries kernel message credentials; they are
        // delivered only when this end enables SO_PASSCRED first. The
        // packet receive path also requires the nonblocking socket that the
        // connect produced.
        rustix::net::sockopt::set_socket_passcred(&socket, true)?;
        Ok(Endpoint {
            manager,
            owner: owner.as_str().to_owned(),
            socket,
            generation,
        })
    }

    async fn bind_original(
        manager: &agentswapper_linux_manager::Manager,
        owner: &str,
        offer: &Offer,
        selection: SelectedInstallation,
    ) -> io::Result<()> {
        let policy = ServicePolicy::installed(selection)?;
        let mut bound = BoundService::bind(
            manager,
            owner,
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
        Ok(())
    }

    pub fn run(user: u32) -> io::Result<String> {
        let group = rustix::process::getgid().as_raw();
        let selection = SelectedInstallation::open()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(io::Error::other)?;
        runtime.block_on(async {
            let endpoint = connect_endpoint(&selection).await?;
            let (bytes, sender) = activation_packet::receive(
                &endpoint.socket,
                Instant::now() + Duration::from_secs(4),
            )?;
            let offer: Offer = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            offer.client_validate(user, group, std::process::id(), sender)?;
            bind_original(&endpoint.manager, &endpoint.owner, &offer, selection).await?;
            let closed = endpoint.manager.close().await.map_err(io::Error::other);
            drop(endpoint.socket);
            closed?;
            Ok(format!("activation offer bound {}", offer.unit))
        })
    }

    pub fn launch(
        user: u32,
        program: &std::ffi::OsStr,
        args: Vec<std::ffi::OsString>,
    ) -> io::Result<String> {
        let group = rustix::process::getgid().as_raw();
        let selection = SelectedInstallation::open()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(io::Error::other)?;
        runtime.block_on(async {
            let deadline = Instant::now() + Duration::from_secs(60);
            let endpoint = connect_endpoint(&selection).await?;
            // The channel must become blocking for the launch-control frames;
            // only the connect itself needed nonblocking behavior.
            let blocking =
                rustix::fs::fcntl_getfl(&endpoint.socket)? - rustix::fs::OFlags::NONBLOCK;
            rustix::fs::fcntl_setfl(&endpoint.socket, blocking)?;
            require(
                net::send(
                    &endpoint.socket,
                    RUN_REQUEST,
                    SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
                )? == RUN_REQUEST.len(),
                "incomplete activation request",
            )?;
            let (bytes, sender) = activation_packet::receive(&endpoint.socket, deadline)?;
            let offer: Offer = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            offer.client_validate(user, group, std::process::id(), sender)?;
            let expected_shape = connection_unit(user, &endpoint.generation, 1, std::process::id());
            let (expected_stem, _) = expected_shape
                .split_once('@')
                .ok_or_else(|| io::Error::other("invalid connection unit shape"))?;
            if !offer.unit.starts_with(&format!("{expected_stem}@")) {
                return Err(io::Error::other(
                    "activation offer names another installation",
                ));
            }
            let selection = selection;
            bind_original(&endpoint.manager, &endpoint.owner, &offer, selection).await?;
            // The launch envelope travels only over this authenticated
            // channel; the target environment applies at its final exec.
            let envelope = LaunchEnvelope::capture(
                program,
                std::path::Path::new("/"),
                args,
                Vec::<(std::ffi::OsString, std::ffi::OsString)>::new(),
                Vec::<(std::ffi::OsString, Option<std::ffi::OsString>)>::new(),
            )?;
            envelope.send_to_until(&endpoint.socket, deadline)?;
            let run_nonce = nonce()?;
            launch_protocol::receive_launch_gate_open(&endpoint.socket, deadline)?;
            net::send(
                &endpoint.socket,
                &launch_protocol::launch_gate_packet(&run_nonce),
                SendFlags::NOSIGNAL,
            )?;
            let (event_nonce, child) =
                launch_protocol::receive_exec_event_open(&endpoint.socket, deadline)?;
            require(
                event_nonce == run_nonce,
                "the exec event carried a foreign nonce",
            )?;
            require(child > 1, "the exec event carried a degenerate child")?;
            // The guardian releases the held exec only after this release;
            // the authenticated exit report follows the target.
            net::send(
                &endpoint.socket,
                &launch_protocol::exec_release_packet(&run_nonce, child),
                SendFlags::NOSIGNAL,
            )?;
            let exit =
                launch_protocol::receive_exit_report(&endpoint.socket, &run_nonce, deadline)?;
            let closed = endpoint.manager.close().await.map_err(io::Error::other);
            drop(endpoint.socket);
            closed?;
            Ok(format!("target exited: {exit:?}"))
        })
    }
}

#[cfg(target_os = "linux")]
fn main() -> process::ExitCode {
    enum Launch {
        Bind,
        Start(std::ffi::OsString, Vec<std::ffi::OsString>),
    }
    fn parse(args: &[String]) -> std::io::Result<(u32, Launch)> {
        match args {
            [user, verb, program, rest @ ..] if verb == "launch" => {
                let user: u32 = user
                    .parse()
                    .map_err(|_| std::io::Error::other("invalid user"))?;
                Ok((
                    user,
                    Launch::Start(program.into(), rest.iter().map(Into::into).collect()),
                ))
            }
            [user, verb] if verb == "bind" => {
                let user: u32 = user
                    .parse()
                    .map_err(|_| std::io::Error::other("invalid user"))?;
                Ok((user, Launch::Bind))
            }
            _ => Err(std::io::Error::other(
                "expects bind USER | launch USER PROGRAM [ARGS...]",
            )),
        }
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match parse(&args) {
        Ok((user, Launch::Bind)) => linux::run(user),
        Ok((user, Launch::Start(program, arguments))) => linux::launch(user, &program, arguments),
        Err(error) => Err(error),
    };
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
