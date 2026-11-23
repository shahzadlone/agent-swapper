//! The ordinary launch client. The flow ordering is enforced by this
//! module: the durable run intent is committed before the launch gate, the
//! durable spawn observation before the held-exec release, and the
//! authenticated exit report is audited before the connection closes. The
//! caller supplies the journal implementation; a production Store adapter
//! needs an independent review (see `launch_client::Journal`).
use crate::launch_client::Journal;
use agentswapper_linux_manager::{
    BoundService, LoadedSocket, ServiceClaim, ServicePolicy, SocketPolicy,
};
use agentswapper_linux_runtime::activation_offer::{
    BIND_REQUEST, Offer, RUN_REQUEST, connection_unit,
};
use agentswapper_linux_runtime::activation_packet;
use agentswapper_linux_runtime::installed_selection::SelectedInstallation;
use agentswapper_linux_runtime::launch_envelope::LaunchEnvelope;
use agentswapper_linux_runtime::launch_protocol;
use rustix::net::{self, SendFlags};
use std::{
    io::{self, Read, Write},
    time::{Duration, Instant},
};

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

/// Relay terminal bytes between the backhauled master and this process's
/// outer terminal until the master ends. Raw modes, resize and job-control
/// handoff stay with the separately qualified relay composition; this
/// bounded path preserves byte order and final output only.
fn relay(master: &rustix::fd::OwnedFd, deadline: Instant) -> io::Result<()> {
    use std::os::fd::AsFd;
    let input = io::stdin().as_fd().try_clone_to_owned()?;
    // When the outer terminal is a real tty, run it in raw mode for the
    // target's lifetime and restore the saved attributes on every exit path.
    // Without a tty (hosted controls, pipes) the outer terminal is left
    // untouched and window-size forwarding is skipped.
    let mut outer = None;
    if rustix::termios::isatty(&input) {
        let saved = rustix::termios::tcgetattr(&input)?;
        let mut raw = saved.clone();
        raw.make_raw();
        rustix::termios::tcsetattr(&input, rustix::termios::OptionalActions::Now, &raw)?;
        outer = Some(saved);
    }
    let feeder_input = input.as_fd().try_clone_to_owned()?;
    let master_feed = master.as_fd().try_clone_to_owned()?;
    let writer = std::thread::spawn(move || -> io::Result<()> {
        let input = feeder_input;
        let mut last_size = rustix::termios::isatty(&input)
            .then(|| rustix::termios::tcgetwinsize(&input))
            .transpose()
            .ok()
            .flatten();
        let mut buffer = [0_u8; 4096];
        loop {
            if rustix::termios::isatty(&input)
                && let Ok(size) = rustix::termios::tcgetwinsize(&input)
                && last_size != Some(size)
            {
                last_size = Some(size);
                rustix::termios::tcsetwinsize(&master_feed, size)?;
            }
            let count = match rustix::io::read(&input, &mut buffer) {
                Ok(count) => count,
                // The target ended: its slave is gone and the master rejects
                // further writes. A clean relay end, not a feeder failure.
                Err(rustix::io::Errno::IO) => return Ok(()),
                Err(error) => return Err(error.into()),
            };
            if count == 0 {
                // Outer input ended: stop feeding the target without
                // shutting down its terminal.
                return Ok(());
            }
            match rustix::io::write(&master_feed, &buffer[..count]) {
                Ok(_) => {}
                Err(rustix::io::Errno::IO) => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
    });
    let mut output = io::stdout();
    let mut buffer = [0_u8; 4096];
    let mut timed_out = false;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|value| !value.is_zero());
        let Some(remaining) = remaining else {
            timed_out = true;
            break;
        };
        let timeout = rustix::event::Timespec::try_from(remaining).map_err(io::Error::other)?;
        let mut ready = [rustix::event::PollFd::new(
            master,
            rustix::event::PollFlags::IN,
        )];
        match rustix::event::poll(&mut ready, Some(&timeout)) {
            Err(rustix::io::Errno::INTR) => continue,
            value => value?,
        };
        let count = match rustix::io::read(master, &mut buffer) {
            // The last slave closed with the target: the master reports EIO
            // rather than EOF, and that is the relay's clean end.
            Err(rustix::io::Errno::IO) => break,
            Err(rustix::io::Errno::AGAIN) => continue,
            Err(rustix::io::Errno::INTR) => continue,
            value => value?,
        };
        if count == 0 {
            break;
        }
        output.write_all(&buffer[..count])?;
        output.flush()?;
    }
    // The stdin feeder is detached: it ends on its own when the outer input
    // ends or the target's terminal rejects writes, and the process exit
    // reclaims it. Joining it would hang the client on an interactive
    // terminal whose read side never closes. The outer terminal's saved
    // attributes are restored on every exit path before the relay's outcome
    // is reported.
    drop(writer);
    if let Some(saved) = &outer {
        rustix::termios::tcsetattr(&input, rustix::termios::OptionalActions::Now, saved)?;
    }
    if timed_out {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "terminal relay deadline expired",
        ));
    }
    Ok(())
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
    // delivered only when this end enables SO_PASSCRED first. The packet
    // receive path also requires the nonblocking socket that the connect
    // produced.
    rustix::net::sockopt::set_socket_passcred(&socket, true)?;
    Ok(Endpoint {
        manager,
        owner: owner.as_str().to_owned(),
        socket,
        generation,
    })
}

/// Bind the original service and hand back the retained binding together
/// with its one-use key: the key moves into the durable journal association,
/// and the retained binding observes the original scope's retirement before
/// any retirement commit is authorized.
async fn bind_original(
    manager: &agentswapper_linux_manager::Manager,
    owner: &str,
    offer: &Offer,
    selection: SelectedInstallation,
) -> io::Result<(
    agentswapper_linux_manager::BoundService,
    agentswapper_linux_manager::ServiceKey,
)> {
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
    Ok((bound, key))
}

/// Bind-only activation: authenticate the endpoint, send the bind request,
/// validate the guardian's offer against the kernel sender, and disconnect
/// cleanly. The guardian then sees the clean disconnect and its instance
/// retires.
pub fn run(user: u32) -> io::Result<String> {
    let group = rustix::process::getgid().as_raw();
    let selection = SelectedInstallation::open()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(io::Error::other)?;
    runtime.block_on(async {
        let endpoint = connect_endpoint(&selection).await?;
        require(
            net::send(
                &endpoint.socket,
                BIND_REQUEST,
                SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
            )? == BIND_REQUEST.len(),
            "incomplete activation request",
        )?;
        let (bytes, sender) =
            activation_packet::receive(&endpoint.socket, Instant::now() + Duration::from_secs(4))?;
        let offer: Offer = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        offer.client_validate(user, group, std::process::id(), sender)?;
        let closed = endpoint.manager.close().await.map_err(io::Error::other);
        drop(endpoint.socket);
        closed?;
        Ok(format!("activation offer validated {}", offer.unit))
    })
}

/// The durable-intent-gated launch flow. The target program and its
/// environment travel only inside the zeroizing envelope over the
/// authenticated channel; the target environment applies at its final exec.
pub fn launch(
    user: u32,
    program: &std::ffi::OsStr,
    args: Vec<std::ffi::OsString>,
    journal: &dyn Journal,
) -> io::Result<String> {
    let group = rustix::process::getgid().as_raw();
    let selection = SelectedInstallation::open()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(io::Error::other)?;
    runtime.block_on(async {
        let deadline = Instant::now() + Duration::from_secs(60);
        let endpoint = connect_endpoint(&selection)
            .await
            .map_err(|error| io::Error::other(format!("endpoint connect failed: {error}")))?;
        require(
            net::send(
                &endpoint.socket,
                RUN_REQUEST,
                SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
            )? == RUN_REQUEST.len(),
            "incomplete activation request",
        )?;
        let (bytes, sender) = activation_packet::receive(&endpoint.socket, deadline)
            .map_err(|error| io::Error::other(format!("activation offer missing: {error}")))?;
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
        let (mut bound, service_key) =
            bind_original(&endpoint.manager, &endpoint.owner, &offer, selection)
                .await
                .map_err(|error| io::Error::other(format!("service binding failed: {error}")))?;
        // The launch-control frames need the receive timeout, which only
        // applies to a blocking channel, and they refuse any credential
        // control data; the offer above needed the nonblocking
        // credential-enabled socket the connect produced.
        let blocking = rustix::fs::fcntl_getfl(&endpoint.socket)? - rustix::fs::OFlags::NONBLOCK;
        rustix::fs::fcntl_setfl(&endpoint.socket, blocking)?;
        rustix::net::sockopt::set_socket_passcred(&endpoint.socket, false)?;
        // The launch envelope travels only over this authenticated channel.
        let envelope = LaunchEnvelope::capture(
            program,
            std::path::Path::new("/"),
            args,
            Vec::<(std::ffi::OsString, std::ffi::OsString)>::new(),
            Vec::<(std::ffi::OsString, Option<std::ffi::OsString>)>::new(),
        )?;
        envelope
            .send_to_until(&endpoint.socket, deadline)
            .map_err(|error| io::Error::other(format!("envelope transfer failed: {error}")))?;
        let run_nonce = nonce()?;
        let nonce_hex = launch_protocol::encoded(&run_nonce);
        // The durable run intent is the only launch-gate authority; it
        // consumes the one-use key into the durable scope association.
        journal
            .confirm_intent(&offer.invocation, &nonce_hex, service_key)
            .map_err(|error| io::Error::other(format!("run intent failed: {error}")))?;
        net::send(
            &endpoint.socket,
            &launch_protocol::launch_gate_packet(&run_nonce),
            SendFlags::NOSIGNAL,
        )?;
        let (event_nonce, child) =
            launch_protocol::receive_exec_event_open(&endpoint.socket, deadline)
                .map_err(|error| io::Error::other(format!("exec event missing: {error}")))?;
        require(
            event_nonce == run_nonce,
            "the exec event carried a foreign nonce",
        )?;
        require(child > 1, "the exec event carried a degenerate child")?;
        // The durable spawn observation precedes the held-exec release.
        journal
            .observe_spawn(&offer.invocation, child)
            .map_err(|error| io::Error::other(format!("spawn observation failed: {error}")))?;
        net::send(
            &endpoint.socket,
            &launch_protocol::exec_release_packet(&run_nonce, child),
            SendFlags::NOSIGNAL,
        )?;
        // The terminal master backhaul: the client owns the master for the
        // target's lifetime and relays its bytes until the target ends.
        let master = agentswapper_linux_runtime::admission_transport::receive_until(
            &endpoint.socket,
            deadline,
        )
        .map_err(|error| io::Error::other(format!("terminal master missing: {error}")))?;
        relay(&master, deadline)?;
        let exit = launch_protocol::receive_exit_report(&endpoint.socket, &run_nonce, deadline)
            .map_err(|error| io::Error::other(format!("exit report missing: {error}")))?;
        // Clean disconnect of the activation socket only: the manager
        // connection stays open as the retirement observation's transport.
        drop(endpoint.socket);
        // Independently observe the original scope's retirement on the
        // retained binding and original handles; a received exit report
        // alone never authorizes the retirement commit.
        let retired = bound
            .observe_retirement(&endpoint.manager, tokio::time::Instant::from_std(deadline))
            .await
            .map_err(|error| io::Error::other(format!("retirement observation failed: {error}")))?;
        // The audit commits the retirement with the one-use value and
        // records the authenticated target exit; retry-safe in the adapter.
        journal
            .audit_exit(&offer.invocation, &format!("{exit:?}"), retired)
            .map_err(|error| io::Error::other(format!("exit audit failed: {error}")))?;
        let closed = endpoint.manager.close().await.map_err(io::Error::other);
        closed?;
        Ok(format!(
            "target exited: {exit:?} (run {} in {})",
            nonce_hex, offer.invocation
        ))
    })
}
