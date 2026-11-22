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
        bind_original(&endpoint.manager, &endpoint.owner, &offer, selection)
            .await
            .map_err(|error| io::Error::other(format!("service binding failed: {error}")))?;
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
        // The durable run intent is the only launch-gate authority.
        journal
            .confirm_intent(&offer.invocation, &nonce_hex)
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
        let exit = launch_protocol::receive_exit_report(&endpoint.socket, &run_nonce, deadline)
            .map_err(|error| io::Error::other(format!("exit report missing: {error}")))?;
        journal
            .audit_exit(&offer.invocation, &format!("{exit:?}"))
            .map_err(|error| io::Error::other(format!("exit audit failed: {error}")))?;
        let closed = endpoint.manager.close().await.map_err(io::Error::other);
        drop(endpoint.socket);
        closed?;
        Ok(format!(
            "target exited: {exit:?} (run {} in {})",
            nonce_hex, offer.invocation
        ))
    })
}
